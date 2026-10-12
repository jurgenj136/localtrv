"""Supervisor loop, generations, triggers and teardown of ``ZdConnection`` (spec §1.5, T13).

Private helper of ``connection.py`` (whose module docstring is the contract). ``ConnectionCore``
holds all state; ``ZdConnection`` adds the public API on top.

Supervisor (``_run``): one cycle per attempt. A cycle builds a ``Session``, runs the attempt
(resolve, connect, ``transport.open``, ``node.join``) as a child task raced against the
session's ``lost`` future (a disconnect, transport fatal or address conflict during the attempt
aborts it), and on success becomes READY and waits for ``lost``. The cycle always ends with the
ordered teardown (``_end_session``). ``stop()`` cancels the supervisor only while it waits
(``_interruptible``: attempt, READY, backoff), never inside a teardown, so the teardown order
always completes.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
from enum import Enum
from typing import TYPE_CHECKING

from bleak_retry_connector import BleakClientWithServiceCache

from vicare_local_ble.zigbee_direct.connection_backoff import Backoff, BackoffWait
from vicare_local_ble.zigbee_direct.connection_session import Session
from vicare_local_ble.zigbee_direct.connection_types import (
    AUTH_FAILURES_TO_STOP,
    BACKOFF_JITTER,
    BACKOFF_RESET_AFTER,
    BACKOFF_SCHEDULE,
    CONNECT_FAILURE_WARNING,
    CONNECT_MAX_ATTEMPTS,
    DISCONNECT_TIMEOUT,
    SEEN_SHORTEN_THRESHOLD,
    SEEN_SHORTENED_WAIT,
    ConnectionIssue,
    ConnectionState,
    ConnectionStats,
    Generation,
)
from vicare_local_ble.zigbee_direct.errors import HandshakeRejectedError, TransportError
from vicare_local_ble.zigbee_direct.node import ZigbeeDirectNode
from vicare_local_ble.zigbee_direct.transport import ZigbeeDirectTransport

if TYPE_CHECKING:
    import random
    from collections.abc import Callable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.connection_types import Connector, DeviceResolver
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.node_types import JoinInfo, NodeConfig, NodeStats
    from vicare_local_ble.zigbee_direct.transport import GattClient, SessionInfo, TransportStats
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.connection")


class ConnectionCore:
    """State and supervisor of a ``ZdConnection`` (see module docstring)."""

    def __init__(
        self,
        resolve_device: DeviceResolver,
        *,
        own_eui: Eui64,
        bak: SecretBytes,
        clock: Clock,
        node_config: NodeConfig,
        name: str,
        connector: Connector,
        recorder: NpduRecorder | None,
        rng: random.Random,
    ) -> None:
        self._resolve_device = resolve_device
        self._own_eui = own_eui
        self._bak = bak
        self._clock = clock
        self._config = node_config
        self._name = name
        self._connector = connector
        self._recorder = recorder
        self._rng = rng
        self._state = ConnectionState.IDLE
        self._state_listeners: list[Callable[[ConnectionState], None]] = []
        self._ready_listeners: list[Callable[[Generation], None]] = []
        self._issue_listeners: list[Callable[[ConnectionIssue, bool], None]] = []
        self._stats = ConnectionStats()
        self._conflicts: set[int] = set()
        self._issues: set[ConnectionIssue] = set()
        self._long_write_mtu: int | None = None
        self._session: Session | None = None
        self._current: Generation | None = None
        self._supervisor: asyncio.Task[None] | None = None
        self._first_ready: asyncio.Future[Generation] | None = None
        self._stop_done: asyncio.Future[None] | None = None
        self._stopping = False
        self._interruptible = False
        self._backoff = Backoff(BACKOFF_SCHEDULE, BACKOFF_JITTER)
        self._wait = BackoffWait(
            clock, threshold=SEEN_SHORTEN_THRESHOLD, shortened=SEEN_SHORTENED_WAIT
        )
        self._auth_streak = 0
        self._auth_error: HandshakeRejectedError | None = None
        self._connect_streak = 0
        self._cache_cleared = False
        self._last_join: JoinInfo | None = None
        self._last_node_stats: NodeStats | None = None
        self._transport_stats: TransportStats | None = None

    @property
    def node_config(self) -> NodeConfig:
        """Config the next join will use."""
        stored = self._config
        return dataclasses.replace(stored, avoid_shorts=stored.avoid_shorts | self._conflicts)

    # --- supervisor ---

    async def _run(self) -> None:
        try:
            while True:
                outcome = await self._cycle()
                if self._stopping:
                    return
                if outcome is _Outcome.AUTH_FAILED:
                    _LOGGER.warning("%s rejected the network key twice: giving up", self._name)
                    self._set_state(ConnectionState.AUTH_FAILED)
                    self._resolve_first(self._auth_error or HandshakeRejectedError("rejected"))
                    return
                if outcome is _Outcome.BACKOFF:
                    delay = self._backoff.next_delay(self._rng)
                    self._stats.backoff = delay
                    self._set_state(ConnectionState.BACKOFF)
                    _LOGGER.info("%s: next attempt in %.1f s", self._name, delay)
                    self._interruptible = True
                    try:
                        await self._wait.wait(delay)
                    finally:
                        self._interruptible = False
        except Exception:  # pragma: no cover - a bug; never leave it unlogged
            _LOGGER.exception("%s: connection supervisor failed", self._name)
        finally:
            if self._stopping:
                self._set_state(ConnectionState.STOPPED)

    async def _cycle(self) -> _Outcome:
        """One attempt and, once READY, the generation until a trigger; then the teardown."""
        session = Session()
        self._session = session
        attempt = asyncio.get_running_loop().create_task(
            self._establish(session), name=f"{self._name} attempt"
        )
        try:
            try:
                self._interruptible = True
                await asyncio.wait((attempt, session.lost), return_when=asyncio.FIRST_COMPLETED)
            finally:
                self._interruptible = False
                if not attempt.done():
                    attempt.cancel()
                await asyncio.wait((attempt,))
                error = None if attempt.cancelled() else attempt.exception()
            if session.lost.done():
                return self._failed(session.lost.result())
            if error is None:
                self._become_ready(session, attempt.result())
                self._interruptible = True
                try:
                    reason = await session.lost
                finally:
                    self._interruptible = False
                return self._failed(reason)
            return self._attempt_error(error)
        finally:
            await self._end_session(session)

    async def _establish(self, session: Session) -> JoinInfo:
        self._stats.attempts += 1
        self._set_state(ConnectionState.CONNECTING)
        try:
            device = self._resolve_device()
        except Exception as exc:
            _LOGGER.debug("device resolver raised: %s", type(exc).__name__)
            device = None
        if device is None:
            raise _AttemptFailedError("not_found")
        try:
            client = await self._connector(
                BleakClientWithServiceCache,
                device,
                self._name,
                self._on_disconnect,
                use_services_cache=True,
                max_attempts=CONNECT_MAX_ATTEMPTS,
            )
        except Exception as exc:
            self._note_connect_failure(exc)
            raise _AttemptFailedError("connect") from exc
        self._connect_streak = 0
        self._stats.connects += 1
        session.client = client
        transport = ZigbeeDirectTransport(
            client, own_eui=self._own_eui, psk=self._bak, clock=self._clock, recorder=self._recorder
        )
        session.transport = transport
        self._transport_stats = transport.stats
        transport.set_fatal_handler(lambda error: self._on_fatal(session, error))
        try:
            info = await transport.open()
        except HandshakeRejectedError:
            raise
        except TransportError as exc:
            self._stats.last_transport_error = exc.reason
            if exc.reason == "missing_characteristic" and not self._cache_cleared:
                await self._clear_cache(client)
                raise _CacheClearedError from exc
            raise _AttemptFailedError(f"transport:{exc.reason}") from exc
        except Exception as exc:
            raise _AttemptFailedError("handshake") from exc
        self._note_session(info)
        self._set_state(ConnectionState.JOINING)
        node = ZigbeeDirectNode(
            transport, clock=self._clock, config=self.node_config, rng=self._rng
        )
        session.node = node
        self._last_node_stats = node.stats
        node.on_address_conflict(lambda: self._on_conflict(session, node))
        try:
            return await node.join()
        except Exception as exc:
            raise _AttemptFailedError("join") from exc

    def _become_ready(self, session: Session, join: JoinInfo) -> None:
        node = session.node
        if node is None:  # pragma: no cover - a join result implies a node
            raise RuntimeError("READY without a node")
        self._stats.generation += 1
        gen = Generation(self._stats.generation, node, join)
        session.generation = gen
        self._current = gen
        self._last_join = join
        self._stats.ready_since = self._clock.now()
        self._stats.backoff = None
        self._auth_streak = 0
        self._cache_cleared = False
        self._set_state(ConnectionState.READY)
        _LOGGER.info("generation %d ready (own short 0x%04X)", gen.number, join.own_short)
        emit(self._ready_listeners, gen)
        self._resolve_first(gen)

    async def _end_session(self, session: Session) -> None:
        gen = session.generation
        if gen is not None and self._current is gen:
            self._current = None
            since = self._stats.ready_since
            if since is not None and self._clock.now() - since >= BACKOFF_RESET_AFTER:
                self._backoff.reset()
            self._stats.ready_since = None
            self._set_state(ConnectionState.IDLE if self._stopping else ConnectionState.BACKOFF)
            _LOGGER.info("generation %d ended", gen.number)
        snapshot = await session.teardown(self._clock, disconnect_timeout=DISCONNECT_TIMEOUT)
        if snapshot is not None:
            self._last_node_stats = snapshot
        self._session = None

    def _failed(self, reason: str) -> _Outcome:
        self._stats.last_failure = reason
        self._auth_streak = 0
        _LOGGER.info("%s: connection failed (%s)", self._name, reason)
        return _Outcome.BACKOFF

    def _attempt_error(self, error: BaseException) -> _Outcome:
        if isinstance(error, HandshakeRejectedError):
            self._auth_streak += 1
            self._stats.auth_failures += 1
            self._stats.last_failure = "auth"
            self._auth_error = error
            _LOGGER.info("%s rejected the handshake (%d in a row)", self._name, self._auth_streak)
            if self._auth_streak >= AUTH_FAILURES_TO_STOP:
                return _Outcome.AUTH_FAILED
            return _Outcome.BACKOFF
        if isinstance(error, _CacheClearedError):
            self._auth_streak = 0
            return _Outcome.IMMEDIATE
        if isinstance(error, _AttemptFailedError):
            return self._failed(error.reason)
        _LOGGER.error("unexpected attempt failure", exc_info=error)  # pragma: no cover
        return self._failed("error")  # pragma: no cover

    # --- triggers (synchronous, loop thread) ---

    def _live_session(self, gen: Generation) -> Session | None:
        session = self._session
        if session is None or session.ended or session.generation is not gen:
            return None
        return session if self._current is gen else None

    def _on_disconnect(self, client: GattClient) -> None:
        session = self._session
        if session is None or session.client is not client:
            _LOGGER.debug("ignored disconnect callback of a stale client")
            return
        if session.fail("disconnect"):
            self._stats.disconnects += 1
            _LOGGER.info("%s disconnected", self._name)

    def _on_fatal(self, session: Session, error: TransportError) -> None:
        if session is not self._session:
            _LOGGER.debug("ignored fatal transport error of a stale session")
            return
        self._stats.last_transport_error = error.reason
        if error.reason == "long_write_unsupported" and not session.ended:
            transport = session.transport
            info = transport.session if transport is not None else None
            self._long_write_mtu = info.mtu if info is not None else 0
            self._set_issue(ConnectionIssue.LONG_WRITE_UNSUPPORTED, active=True)
        session.fail(f"transport:{error.reason}")

    def _on_conflict(self, session: Session, node: ZigbeeDirectNode) -> None:
        if session is not self._session or session.conflicted or session.ended:
            return
        session.conflicted = True
        with contextlib.suppress(RuntimeError):  # no own short yet: nothing to avoid
            self._conflicts.add(node.own_short)
        if self._config.preferred_short is not None:
            self._config = dataclasses.replace(self._config, preferred_short=None)
        self._stats.address_conflicts += 1
        _LOGGER.warning("address conflict on our short: rejoining with a new one")
        session.fail("address_conflict")

    # --- helpers ---

    def _note_connect_failure(self, exc: BaseException) -> None:
        self._stats.connect_failures += 1
        self._connect_streak += 1
        _LOGGER.debug("connect failed: %s", type(exc).__name__)
        if self._connect_streak == CONNECT_FAILURE_WARNING:
            _LOGGER.warning(
                "%d connection attempts to %s failed in a row; the vendor app may be connected "
                "to it (it accepts a single client): close the app",
                CONNECT_FAILURE_WARNING,
                self._name,
            )

    def _note_session(self, info: SessionInfo) -> None:
        self._stats.mtu = info.mtu
        self._stats.mtu_low = info.mtu_low
        self._set_issue(ConnectionIssue.MTU_TOO_SMALL, active=info.mtu_low)
        if self._long_write_mtu is not None and info.mtu > self._long_write_mtu:
            self._long_write_mtu = None
            self._set_issue(ConnectionIssue.LONG_WRITE_UNSUPPORTED, active=False)

    async def _clear_cache(self, client: GattClient) -> None:
        self._cache_cleared = True
        self._stats.cache_clears += 1
        _LOGGER.info("%s: GATT characteristic missing; clearing the service cache", self._name)
        try:
            async with self._clock.timeout(DISCONNECT_TIMEOUT):
                await client.clear_cache()
        except Exception as exc:
            _LOGGER.debug("clear_cache failed: %s", type(exc).__name__)

    def _set_state(self, state: ConnectionState) -> None:
        if state is self._state:
            return
        self._state = state
        _LOGGER.info("%s: state %s", self._name, state.value)
        emit(self._state_listeners, state)

    def _set_issue(self, issue: ConnectionIssue, *, active: bool) -> None:
        if active == (issue in self._issues):
            return
        if active:
            self._issues.add(issue)
        else:
            self._issues.discard(issue)
        emit(self._issue_listeners, issue, active)

    def _resolve_first(self, result: Generation | BaseException) -> None:
        first = self._first_ready
        if first is None or first.done():
            return
        if isinstance(result, BaseException):
            first.set_exception(result)
        else:
            first.set_result(result)


class _Outcome(Enum):
    BACKOFF = "backoff"
    IMMEDIATE = "immediate"
    AUTH_FAILED = "auth_failed"


class _AttemptFailedError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _CacheClearedError(Exception):
    """Stale GATT cache cleared: reconnect at once."""


def subscribe[C](listeners: list[C], cb: C) -> Callable[[], None]:
    listeners.append(cb)

    def unsubscribe() -> None:
        with contextlib.suppress(ValueError):
            listeners.remove(cb)

    return unsubscribe


def emit(listeners: list[Callable[..., None]], *args: object) -> None:
    for cb in list(listeners):
        try:
            cb(*args)
        except Exception:
            _LOGGER.exception("connection listener raised")


__all__ = ["ConnectionCore", "emit", "subscribe"]
