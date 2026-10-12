"""Value types and constants of ``ZdConnection`` (spec §1.5, T13).

Private home of names that ``connection.py`` re-exports (the public import path); split out so
the supervisor (``connection_supervisor.py``) can use them without an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from bleak.backends.device import BLEDevice
    from bleak_retry_connector import BleakClientWithServiceCache

    from vicare_local_ble.zigbee_direct.errors import TransportErrorReason
    from vicare_local_ble.zigbee_direct.node import ZigbeeDirectNode
    from vicare_local_ble.zigbee_direct.node_types import JoinInfo
    from vicare_local_ble.zigbee_direct.transport import GattClient

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
#: Seconds spawned tasks get to finish after cancellation at teardown (then WARNING).
SPAWNED_TASKS_TIMEOUT: Final = 10.0
CONNECT_MAX_ATTEMPTS: Final = 3
#: Consecutive connect failures that log the single-client WARNING.
CONNECT_FAILURE_WARNING: Final = 3

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


__all__ = [
    "AUTH_FAILURES_TO_STOP",
    "BACKOFF_JITTER",
    "BACKOFF_RESET_AFTER",
    "BACKOFF_SCHEDULE",
    "CONNECT_FAILURE_WARNING",
    "CONNECT_MAX_ATTEMPTS",
    "DISCONNECT_TIMEOUT",
    "SEEN_SHORTENED_WAIT",
    "SEEN_SHORTEN_THRESHOLD",
    "SPAWNED_TASKS_TIMEOUT",
    "ConnectionIssue",
    "ConnectionState",
    "ConnectionStats",
    "Connector",
    "DeviceResolver",
    "Generation",
]
