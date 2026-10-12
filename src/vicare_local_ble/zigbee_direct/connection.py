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
loop and backoff into ``_connection_supervisor.py`` (public names stay here).

Threading: loop thread only; every listener is called synchronously and must not await.
Logging (``vicare_local_ble.zigbee_direct.connection``): INFO state changes and generations,
WARNING repeated failures; never the network key, BAK or EUIs beyond the ZDD's.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol

from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

if TYPE_CHECKING:
    import asyncio
    import random
    from collections.abc import Callable, Coroutine

    from bleak.backends.device import BLEDevice

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.errors import TransportErrorReason
    from vicare_local_ble.zigbee_direct.node import ZigbeeDirectNode
    from vicare_local_ble.zigbee_direct.node_types import JoinInfo, NodeConfig, NodeStats
    from vicare_local_ble.zigbee_direct.transport import GattClient, TransportStats
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

#: Backoff schedule in seconds (last value is the cap); +-``BACKOFF_JITTER`` applied.
BACKOFF_SCHEDULE: Final = (2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0)
BACKOFF_JITTER: Final = 0.2
#: Time in READY after which the backoff index resets.
BACKOFF_RESET_AFTER: Final = 600.0
#: ``notify_seen`` shortens waits of at least this long to ``SEEN_SHORTENED_WAIT``.
SEEN_SHORTEN_THRESHOLD: Final = 30.0
SEEN_SHORTENED_WAIT: Final = 2.0
DISCONNECT_TIMEOUT: Final = 5.0
AUTH_FAILURES_TO_STOP: Final = 2
CONNECT_MAX_ATTEMPTS: Final = 3

type DeviceResolver = Callable[[], BLEDevice | None]
"""Returns a fresh ``BLEDevice`` for the ZDD, or ``None`` if it is not currently seen."""


class Connector(Protocol):
    """How a connection attempt obtains a connected client.

    Matches ``bleak_retry_connector.establish_connection`` as the connection calls it, and
    ``vicare_local_ble.testing.fake_connector()``. ``disconnected_callback`` receives the client
    that disconnected (compared with the current client to ignore stale callbacks).
    """

    async def __call__(
        self,
        client_class: type[BleakClientWithServiceCache],
        device: BLEDevice,
        name: str,
        disconnected_callback: Callable[[GattClient], None] | None = None,
        *,
        use_services_cache: bool = True,
        max_attempts: int = CONNECT_MAX_ATTEMPTS,
    ) -> GattClient: ...


class ConnectionState(StrEnum):
    IDLE = "idle"
    CONNECTING = "connecting"
    JOINING = "joining"
    READY = "ready"
    BACKOFF = "backoff"
    AUTH_FAILED = "auth_failed"
    STOPPED = "stopped"


class ConnectionIssue(StrEnum):
    """Conditions the integration surfaces as repair issues."""

    MTU_TOO_SMALL = "mtu_too_small"
    LONG_WRITE_UNSUPPORTED = "long_write_unsupported"


@dataclass(frozen=True, slots=True)
class Generation:
    """One READY session. ``number`` increases by 1 per READY and never repeats."""

    number: int
    node: ZigbeeDirectNode
    join: JoinInfo


@dataclass(slots=True)
class ConnectionStats:
    """Counters and last values for diagnostics (no secrets, no EUIs).

    ``last_failure`` is a short reason (``not_found``, ``connect``, ``auth``, ``handshake``,
    ``join``, ``transport:<TransportErrorReason>``, ``disconnect``, ``rejoin:<reason>``,
    ``address_conflict``). ``cache_clears`` counts stale-GATT-cache recoveries.
    ``backoff`` is the current/last wait in seconds; ``mtu`` the last session's MTU.
    """

    attempts: int = 0
    connects: int = 0
    connect_failures: int = 0
    auth_failures: int = 0
    disconnects: int = 0
    rejoins: int = 0
    cache_clears: int = 0
    address_conflicts: int = 0
    generation: int = 0
    backoff: float | None = None
    last_failure: str | None = None
    last_transport_error: TransportErrorReason | None = None
    mtu: int | None = None
    mtu_low: bool = False
    ready_since: float | None = None


class ZdConnection:
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
        raise NotImplementedError("T13")

    def add_state_listener(self, cb: Callable[[ConnectionState], None]) -> Callable[[], None]:
        """``cb(state)`` on every state change; returns an unsubscribe callable."""
        raise NotImplementedError("T13")

    def add_ready_listener(self, cb: Callable[[Generation], None]) -> Callable[[], None]:
        """``cb(gen)`` synchronously when a generation becomes READY (before ``start`` returns
        for the first one). The listener may ``spawn`` work on ``gen``."""
        raise NotImplementedError("T13")

    def add_issue_listener(self, cb: Callable[[ConnectionIssue, bool], None]) -> Callable[[], None]:
        """``cb(issue, active)`` when a repair condition appears (``mtu_low`` at open, a
        ``long_write_unsupported`` transport error) or clears (a later session without it)."""
        raise NotImplementedError("T13")

    def spawn[T](
        self, gen: Generation, coro: Coroutine[Any, Any, T], *, name: str
    ) -> asyncio.Task[T]:
        """Run ``coro`` as a task owned by ``gen``: cancelled and awaited at its teardown.

        If ``gen`` is not the current READY generation, ``coro`` is closed and
        ``ConnectionLostError`` is raised. Task exceptions (other than cancellation) are logged
        at WARNING with the task name and otherwise swallowed; awaiting the returned task still
        re-raises them.
        """
        raise NotImplementedError("T13")

    def request_rejoin(self, gen: Generation, reason: str) -> None:
        """Tear ``gen`` down and reconnect after the backoff; ignored if ``gen`` is stale or the
        connection is stopping. ``reason`` is a short token logged and kept in ``last_failure``
        (e.g. ``"all_valves_silent"``)."""
        raise NotImplementedError("T13")

    def notify_seen(self) -> None:
        """An advertisement of the ZDD was seen: shorten a long backoff wait (module docstring).
        Cheap and safe to call at any rate and in any state."""
        raise NotImplementedError("T13")

    def update_node_config(self, **changes: object) -> None:
        """``dataclasses.replace`` the stored node config used at the NEXT join (the current
        node keeps its config). ``TypeError`` for an unknown field. The private conflict set is
        merged into ``avoid_shorts`` at join time and is not affected (module docstring)."""
        raise NotImplementedError("T13")

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
        raise NotImplementedError("T13")

    async def stop(self) -> None:
        """Idempotent: stop the supervisor, run the teardown, then state STOPPED. Leaves no
        tasks behind."""
        raise NotImplementedError("T13")

    @property
    def state(self) -> ConnectionState:
        raise NotImplementedError("T13")

    @property
    def current(self) -> Generation | None:
        """The READY generation, or ``None`` outside READY."""
        raise NotImplementedError("T13")

    @property
    def node_config(self) -> NodeConfig:
        """Config the next join will use."""
        raise NotImplementedError("T13")

    @property
    def stats(self) -> ConnectionStats:
        raise NotImplementedError("T13")

    @property
    def transport_stats(self) -> TransportStats | None:
        """Stats of the current (or last) transport; survives teardown (diagnostics)."""
        raise NotImplementedError("T13")

    @property
    def last_join(self) -> JoinInfo | None:
        """``JoinInfo`` of the most recent successful join; survives teardown (diagnostics)."""
        raise NotImplementedError("T13")

    @property
    def last_node_stats(self) -> NodeStats | None:
        """``NodeStats`` of the current or most recent node; survives teardown (diagnostics).
        The object is the node's live stats while READY, a final snapshot afterwards."""
        raise NotImplementedError("T13")

    @property
    def recorder(self) -> NpduRecorder | None:
        raise NotImplementedError("T13")


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
    raise NotImplementedError("T13")


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
