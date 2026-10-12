"""Generic connection manager for one ZDD: resolve, connect, handshake, join, supervise (§1.5).

Implemented by T13 (which wires connection -> transport -> node); frozen interface (T2). No
vendor knowledge.

Per attempt
    1. ``device = resolve_device()`` (HA: a fresh ``async_ble_device_from_address(...,
       connectable=True)``, so the current best adapter/proxy is used). ``None`` -> BACKOFF with
       reason ``not_found``.
    2. ``client = await connector(BleakClientWithServiceCache, device, name, on_disconnect,
       use_services_cache=True, max_attempts=3)``; never ``ble_device_callback`` (unused by
       bleak-retry-connector 4.7.1). A fresh client per attempt.
    3. ``ZigbeeDirectTransport(client, own_eui=..., psk=bak, clock=..., recorder=...)``,
       ``set_fatal_handler``, ``await transport.open()``. A ``TransportError`` with
       ``reason="missing_characteristic"`` (stale GATT cache) -> ``await client.clear_cache()``
       once, tear the attempt down, and reconnect immediately (no backoff step). A second
       consecutive missing characteristic is treated as an ordinary failure (backoff); the
       once-flag resets after any READY.
    4. ``ZigbeeDirectNode(transport, clock=..., config=node_config, rng=...)``,
       ``node.on_address_conflict(...)``, ``await node.join()``.
    5. ``generation += 1``; state READY; ready listeners called synchronously with the new
       ``Generation``. READY means joined and routed; discovery is the bridge's business.

Teardown (disconnect, transport fatal, ``request_rejoin``, address conflict, ``stop``), in order:
    state leaves READY -> cancel the generation's spawned tasks and AWAIT them ->
    ``node.close(ConnectionLostError(...))`` -> ``transport.close()`` -> ``client.disconnect()``
    bounded to 5 s -> only then the next attempt. Disconnect callbacks for a client that is not
    the current one, and fatal/rejoin events carrying a stale generation, are ignored.

Supervisor
    One strongly referenced task started by ``start()``. Backoff 2, 5, 10, 30, 60, 120, 300 s
    (cap), +-20 % jitter from the injected rng, reset after 10 min in READY; ``notify_seen()``
    during a wait of >= 30 s shortens the remaining wait to 2 s. ``HandshakeRejectedError``
    twice in a row -> AUTH_FAILED and the supervisor stops; any other outcome resets that
    counter. Three consecutive connect failures log one WARNING suggesting the vendor app may
    hold the R0 (single client).

Short addresses (``avoid_shorts`` ownership)
    The connection keeps a private conflict set: every own short that caused an address
    conflict (node ``on_address_conflict``) is added to it, and ``preferred_short`` is cleared
    in the stored config. At each join the node config is built as the stored config with
    ``avoid_shorts = stored.avoid_shorts | conflict_set``. ``update_node_config`` (the bridge
    pushes known device shorts and the cached own short) replaces the stored fields only, so
    it can never erase the conflict set; a pushed ``preferred_short`` that is in the conflict
    set is ignored by the node anyway (it is in ``avoid_shorts``).

Size note: keep this module under ~500 lines when implemented; T13 may split the supervisor
loop and backoff into ``connection_supervisor.py`` (public names stay here).

Threading: loop thread only; every listener is called synchronously and must not await.
Logging (``vicare_local_ble.zigbee_direct.connection``): INFO state changes and generations,
WARNING repeated failures; never the network key, BAK or EUIs beyond the ZDD's.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import random
from typing import TYPE_CHECKING, Any, cast

from bleak_retry_connector import establish_connection

from vicare_local_ble.zigbee_direct.clock import LoopClock
from vicare_local_ble.zigbee_direct.connection_session import run_validation
from vicare_local_ble.zigbee_direct.connection_supervisor import ConnectionCore, emit, subscribe
from vicare_local_ble.zigbee_direct.connection_types import (
    AUTH_FAILURES_TO_STOP,
    BACKOFF_JITTER,
    BACKOFF_RESET_AFTER,
    BACKOFF_SCHEDULE,
    CONNECT_MAX_ATTEMPTS,
    DISCONNECT_TIMEOUT,
    SEEN_SHORTEN_THRESHOLD,
    SEEN_SHORTENED_WAIT,
    ConnectionIssue,
    ConnectionState,
    ConnectionStats,
    Connector,
    DeviceResolver,
    Generation,
)
from vicare_local_ble.zigbee_direct.crypto import derive_basic_authorization_key
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError
from vicare_local_ble.zigbee_direct.node import NodeConfig

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.node_types import JoinInfo, NodeStats
    from vicare_local_ble.zigbee_direct.transport import TransportStats
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

_LOGGER = logging.getLogger(__name__)


class ZdConnection(ConnectionCore):
    """Supervised, persistent Zigbee Direct connection (see module docstring).

    The BAK is derived once in ``__init__`` from ``network_key`` and ``own_eui`` and kept as
    ``SecretBytes``; ``network_key`` itself is not retained. ``rng`` (default fresh
    ``random.Random()``) drives backoff jitter and is passed to each node.
    """

    def __init__(
        self,
        resolve_device: DeviceResolver,
        *,
        own_eui: Eui64,
        network_key: SecretBytes,
        clock: Clock,
        node_config: NodeConfig | None = None,
        name: str = "ZDD",
        connector: Connector = establish_connection,
        recorder: NpduRecorder | None = None,
        rng: random.Random | None = None,
    ) -> None:
        super().__init__(
            resolve_device,
            own_eui=own_eui,
            bak=derive_basic_authorization_key(own_eui, network_key),
            clock=clock,
            node_config=node_config if node_config is not None else NodeConfig(),
            name=name,
            connector=connector,
            recorder=recorder,
            rng=rng if rng is not None else random.Random(),  # noqa: S311 - jitter only
        )

    def __repr__(self) -> str:
        return f"ZdConnection(name={self._name!r}, state={self._state.value})"

    # --- listeners ---

    def add_state_listener(self, cb: Callable[[ConnectionState], None]) -> Callable[[], None]:
        """``cb(state)`` on every state change; returns an unsubscribe callable."""
        return subscribe(self._state_listeners, cb)

    def add_ready_listener(self, cb: Callable[[Generation], None]) -> Callable[[], None]:
        """``cb(gen)`` synchronously when a generation becomes READY (before ``start`` returns
        for the first one). The listener may ``spawn`` work on ``gen``."""
        return subscribe(self._ready_listeners, cb)

    def add_issue_listener(self, cb: Callable[[ConnectionIssue, bool], None]) -> Callable[[], None]:
        """``cb(issue, active)`` when a repair condition appears (``mtu_low`` at open, a
        ``long_write_unsupported`` transport error) or clears (a later session without it).

        Issues already active are replayed to ``cb`` synchronously before this returns.
        ``mtu_too_small`` clears at a later open with a normal MTU; ``long_write_unsupported``
        clears at a later successful open whose MTU is at least the one it failed at (and is
        raised again if it fails again). ``issues`` is the current snapshot."""
        for issue in sorted(self._issues):
            emit([cb], issue, True)  # replay: a late listener still learns the active issues
        return subscribe(self._issue_listeners, cb)

    # --- generation API ---

    def spawn[T](
        self, gen: Generation, coro: Coroutine[Any, Any, T], *, name: str
    ) -> asyncio.Task[T]:
        """Run ``coro`` as a task owned by ``gen``: cancelled and awaited at its teardown.

        If ``gen`` is not the current READY generation, ``coro`` is closed and
        ``ConnectionLostError`` is raised. Task exceptions (other than cancellation) are logged
        at WARNING with the task name and otherwise swallowed; awaiting the returned task still
        re-raises them.
        """
        session = self._live_session(gen)
        if session is None:
            coro.close()
            raise ConnectionLostError(f"generation {gen.number} is not current")
        return session.spawn(coro, name)

    def request_rejoin(self, gen: Generation, reason: str) -> None:
        """Tear ``gen`` down and reconnect after the backoff; ignored if ``gen`` is stale or the
        connection is stopping. ``reason`` is a short token logged and kept in ``last_failure``
        (e.g. ``"all_valves_silent"``)."""
        session = self._live_session(gen)
        if session is None or self._stopping:
            _LOGGER.debug("ignored rejoin request for stale generation %d", gen.number)
            return
        if session.fail(f"rejoin:{reason}"):
            self._stats.rejoins += 1
            _LOGGER.info("generation %d: rejoin requested (%s)", gen.number, reason)

    def notify_seen(self) -> None:
        """An advertisement of the ZDD was seen: shorten a long backoff wait (module docstring).
        Cheap and safe to call at any rate and in any state."""
        if self._wait.shorten():
            _LOGGER.debug("device seen: backoff shortened to %.0f s", SEEN_SHORTENED_WAIT)

    def update_node_config(self, **changes: object) -> None:
        """``dataclasses.replace`` the stored node config used at the NEXT join (the current
        node keeps its config). ``TypeError`` for an unknown field. The private conflict set is
        merged into ``avoid_shorts`` at join time and is not affected (module docstring)."""
        self._config = dataclasses.replace(self._config, **cast("dict[str, Any]", changes))

    # --- lifecycle ---

    async def start(self, *, first_ready_timeout: float = 90.0) -> Generation:
        """Start the supervisor and wait for the first READY.

        Raises:
        * ``HandshakeRejectedError`` only once AUTH_FAILED is reached (the 2nd consecutive
          rejection); a single rejection is retried like any other failure.
        * ``TimeoutError`` if not READY within ``first_ready_timeout``; the supervisor keeps
          retrying in the background.
        * ``ConnectionLostError`` if ``stop()`` runs while ``start()`` is pending.
        * ``RuntimeError`` if already started.
        """
        if self._supervisor is not None or self._stopping:
            raise RuntimeError("connection already started")
        first: asyncio.Future[Generation] = asyncio.get_running_loop().create_future()
        self._first_ready = first
        self._start_supervisor()
        try:
            async with self._clock.timeout(first_ready_timeout):
                return await first
        finally:
            if self._first_ready is first:
                self._first_ready = None

    async def stop(self) -> None:
        """Idempotent: stop the supervisor, run the teardown, then state STOPPED. Leaves no
        tasks behind."""
        self._stopping = True
        self._resolve_first(ConnectionLostError("connection stopped"))
        supervisor = self._supervisor
        if supervisor is not None and not supervisor.done():
            supervisor.cancel()  # the teardown inside is protected and completes in order
        if self._finished is not None:
            # completion of the supervisor itself: a cancelled stop() never fakes it
            await asyncio.shield(self._finished)
        self._set_state(ConnectionState.STOPPED)

    # --- properties ---

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def current(self) -> Generation | None:
        """The READY generation, or ``None`` outside READY."""
        return self._current

    @property
    def issues(self) -> frozenset[ConnectionIssue]:
        """Repair issues active now (snapshot)."""
        return frozenset(self._issues)

    @property
    def stats(self) -> ConnectionStats:
        return self._stats

    @property
    def transport_stats(self) -> TransportStats | None:
        """Stats of the current (or last) transport; survives teardown (diagnostics)."""
        return self._transport_stats

    @property
    def last_join(self) -> JoinInfo | None:
        """``JoinInfo`` of the most recent successful join; survives teardown (diagnostics)."""
        return self._last_join

    @property
    def last_node_stats(self) -> NodeStats | None:
        """``NodeStats`` of the current or most recent node; survives teardown (diagnostics).
        The object is the node's live stats while READY, a final snapshot afterwards."""
        return self._last_node_stats

    @property
    def recorder(self) -> NpduRecorder | None:
        return self._recorder


async def validate_connection(
    resolve_device: DeviceResolver,
    *,
    own_eui: Eui64,
    network_key: SecretBytes,
    clock: Clock | None = None,
    connector: Connector = establish_connection,
    timeout: float = 60.0,
) -> Eui64:
    """One handshake-only attempt for the config flow; returns the ZDD EUI (from SE2).

    Resolve, connect, ``transport.open()``, ``transport.close()``, disconnect (always, bounded),
    all within ``timeout`` on ``clock`` (default ``LoopClock()``). Raises
    ``HandshakeRejectedError`` (wrong key), ``TransportError`` (``reason="not_found"`` if the
    resolver returns ``None``), ``TimeoutError``, or the connector's ``BleakError``.
    """
    return await run_validation(
        resolve_device,
        own_eui=own_eui,
        psk=derive_basic_authorization_key(own_eui, network_key),
        clock=clock if clock is not None else LoopClock(),
        connector=connector,
        timeout=timeout,
        disconnect_timeout=DISCONNECT_TIMEOUT,
        max_attempts=CONNECT_MAX_ATTEMPTS,
    )


__all__ = [
    "AUTH_FAILURES_TO_STOP",
    "BACKOFF_JITTER",
    "BACKOFF_RESET_AFTER",
    "BACKOFF_SCHEDULE",
    "CONNECT_MAX_ATTEMPTS",
    "DISCONNECT_TIMEOUT",
    "SEEN_SHORTENED_WAIT",
    "SEEN_SHORTEN_THRESHOLD",
    "ConnectionIssue",
    "ConnectionState",
    "ConnectionStats",
    "Connector",
    "DeviceResolver",
    "Generation",
    "ZdConnection",
    "validate_connection",
]
