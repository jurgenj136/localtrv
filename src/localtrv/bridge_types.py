"""Bridge constants and frozen value types, re-exported by ``bridge``.

They live here so the ``bridge_*`` helper modules can use them without importing ``bridge``
(which imports the helpers). See the ``bridge`` module docstring for the behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from localtrv.zigbee_direct.errors import (
    RequestTimeoutError,
    RouteError,
    SequenceExhaustedError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from localtrv.valves import Valve, ValveState
    from localtrv.zigbee_direct.connection import ConnectionState
    from localtrv.zigbee_direct.types import Eui64

MISSES_UNAVAILABLE: Final = 3
SILENT_POLLS_REJOIN: Final = 2
#: Without any valve answering since the last all-silent rejoin, the next one waits
#: ``SILENT_REJOIN_BACKOFF * 2**(n-1)`` after it, capped at ``SILENT_REJOIN_BACKOFF_MAX``.
SILENT_REJOIN_BACKOFF: Final = 3600.0
SILENT_REJOIN_BACKOFF_MAX: Final = 21_600.0
SETPOINT_ACK_DEADLINE: Final = 60.0
SETPOINT_TOTAL_DEADLINE: Final = 90.0
#: Discovery retries after an incomplete topology, an identification timeout or 0 valves.
DISCOVERY_RETRY_DELAYS: Final = (300.0, 900.0, 3600.0)
TOPOLOGY_REFRESH: Final = 21_600.0
#: Identification of an unknown Device_annce sender: debounce, one at a time per EUI.
ANNCE_IDENTIFY_DEBOUNCE: Final = 10.0
#: After a failed one, the next announcement retries no earlier than this after the failure.
ANNCE_IDENTIFY_RETRY: Final = 300.0
IDENTIFY_CONCURRENCY: Final = 4
#: Basic-read timeouts after which Active_EP/Simple_Desc are sent (diagnostic only).
IDENTIFY_DIAGNOSTIC_AFTER: Final = 2


#: Errors meaning "no response from the device" for one request.
NO_RESPONSE: Final = (RequestTimeoutError, RouteError, SequenceExhaustedError)
#: NWK status "no route available": what an unestablished valve address amounts to.
_NO_ROUTE: Final = 0x00


class ValveAddressUnknownError(RouteError):
    """The valve's cached short now belongs to another valve and its own is not re-learned yet.

    Raised before anything is sent (or when the short changed owner during the request). A
    ``RouteError``, so polling counts it as no response and HA maps it to a failed write.
    """

    def __init__(self, dst: int) -> None:
        super().__init__(dst, _NO_ROUTE)
        self.args = (f"valve address unknown: 0x{dst:04X} belongs to another valve",)


class ValveAddressUnverifiedError(ValveAddressUnknownError):
    """A setpoint's address check before the write failed (no IEEE_addr answer, or another
    device answered): nothing was written. Only ``set_setpoint`` raises it, before the write."""

    def __init__(self, dst: int) -> None:
        super().__init__(dst)
        self.args = (f"valve address not verified at 0x{dst:04X}; nothing written",)


@dataclass(frozen=True, slots=True)
class SetpointStatus:
    """Setpoint transaction state of one valve.

    ``requested_c`` is set while a write is in flight; ``acknowledged_c`` once the valve
    acknowledged it; ``confirmed_c`` from the last confirming read. ``version`` increases per
    ``set_setpoint`` call; ``pending`` is True until the latest version's confirm finished.
    """

    requested_c: float | None = None
    acknowledged_c: float | None = None
    confirmed_c: float | None = None
    version: int = 0
    pending: bool = False
    confirmed_at: float | None = None


@dataclass(frozen=True, slots=True)
class TopologySummary:
    """Diagnostics-safe digest of the last ``walk_topology`` result (no extended PAN).

    ``parent_of`` maps a known valve's EUI to the short of its parent router/coordinator;
    diagnostics pseudonymise the EUIs (``valve_n``).
    """

    complete: bool
    routers: int
    neighbors: int
    parent_of: Mapping[Eui64, int] = field(default_factory=dict)
    walked_at: float | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryStatus:
    """Last discovery run and the retry schedule; times are ``Clock.now()`` values."""

    running: bool = False
    last_run: float | None = None
    complete: bool | None = None
    valves_found: int = 0
    attempts: int = 0
    next_retry: float | None = None
    topology: TopologySummary | None = None


@dataclass(frozen=True, slots=True)
class BridgeSnapshot:
    """Immutable view handed to HA (coordinator data, entities, diagnostics)."""

    connection_state: ConnectionState
    generation: int | None
    own_short: int | None
    valves: Mapping[Eui64, Valve]
    states: Mapping[Eui64, ValveState]
    available: Mapping[Eui64, bool]
    setpoints: Mapping[Eui64, SetpointStatus]
    discovery: DiscoveryStatus
    misses: Mapping[Eui64, int] = field(default_factory=dict)


__all__ = [
    "ANNCE_IDENTIFY_DEBOUNCE",
    "ANNCE_IDENTIFY_RETRY",
    "DISCOVERY_RETRY_DELAYS",
    "IDENTIFY_CONCURRENCY",
    "IDENTIFY_DIAGNOSTIC_AFTER",
    "MISSES_UNAVAILABLE",
    "NO_RESPONSE",
    "SETPOINT_ACK_DEADLINE",
    "SETPOINT_TOTAL_DEADLINE",
    "SILENT_POLLS_REJOIN",
    "SILENT_REJOIN_BACKOFF",
    "SILENT_REJOIN_BACKOFF_MAX",
    "TOPOLOGY_REFRESH",
    "BridgeSnapshot",
    "DiscoveryStatus",
    "SetpointStatus",
    "TopologySummary",
    "ValveAddressUnknownError",
    "ValveAddressUnverifiedError",
]
