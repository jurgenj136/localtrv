"""ViCareBridge: discovery, polling, setpoints and reports on top of a ZdConnection (§1.6).

Implemented by T14 (which wires bridge -> connection); frozen interface (T2). Orchestration
only: every cluster, attribute, scale, sentinel, model id and read plan comes from
``vicare_local_ble.valves``; no Zigbee literals here.

Lifecycle and ownership
    ``attach()`` registers a ready listener on the connection. On READY(gen) (sync):
    persist ``gen.join.own_short`` (``on_cache_changed``), register report / Device_annce /
    address-conflict listeners on ``gen.node`` (address conflict: forget the cached own short;
    the connection itself rejoins), then ``connection.spawn(gen, self._discover(gen))``.
    Every background coroutine (discovery, retries, identification, the initial poll,
    confirm reads, topology re-walks) is spawned on its generation, so the connection cancels
    and awaits it at teardown. Each completion checks that its generation is still current
    before mutating state; stale completions are dropped.

Polling
    ``poll()`` is driven by the HA coordinator schedule (never by pushes). Valves run in
    parallel; each first ``try``-acquires its transaction lock (busy -> skipped, neither miss
    nor success). Plans: ``valves.FAST`` every poll, ``valves.SLOW`` every
    ``SLOW_EVERY_N_POLLS``-th, ``valves.STATIC`` at discovery and every ``STATIC_REFRESH_S``.
    Any response resets ``misses``; all attempts failing -> ``misses += 1``; at
    ``MISSES_UNAVAILABLE`` the valve is unavailable and a topology walk is spawned. Not READY ->
    the cycle is skipped and every known valve counts a miss. Rejoin rule: >= 1 known valve,
    every known valve missed ``SILENT_POLLS_REJOIN`` consecutive polls, READY throughout ->
    ``connection.request_rejoin(gen, "all_valves_silent")``.

Setpoints (``set_setpoint``), per valve, in this order
    1. Validate (``KeyError`` unknown valve, ``ValueError`` non-finite) and clamp with
       ``valves.clamp_setpoint``.
    2. BEFORE waiting for the lock: ``version += 1``, ``requested_c`` = clamped value,
       ``pending = True``, ``on_update`` (the UI updates optimistically at once).
    3. Preempt: if an older version's background confirm task holds the lock, cancel it (its
       exit path releases the lock; it no longer touches ``pending``, it is not the latest).
    4. Acquire the per-valve transaction lock and write ``valves.setpoint_record`` with
       ``node.zcl_write``, all inside ``clock.timeout`` bounded by ``SETPOINT_ACK_DEADLINE``
       from step 2. If a newer version arrived meanwhile, this call still writes its own value
       (the newer write follows it under the lock; last writer wins on the valve).
    5. Success: ``acknowledged_c`` = clamped value, ``on_update``; spawn the confirm task on the
       generation and return the ``SetpointStatus``. The HA call ends here. Lock ownership
       passes to the confirm task.
    6. Confirm task: ``zcl_read(valves.CONFIRM_SETPOINT)`` bounded so it ends before
       ``SETPOINT_TOTAL_DEADLINE`` from step 2. Success -> ``confirmed_c``/``confirmed_at`` and
       ``state.setpoint_c``. Timeout or error -> acknowledged but unconfirmed (``confirmed_c``
       unchanged, never reported as confirmed).

    Every exit path runs one ``finally``: release the lock, and if this version is still the
    latest, set ``pending = False`` (and on failure before the ack also clear ``requested_c``)
    and call ``on_update``. Exit paths covered: write failure or ack deadline (then raise),
    the HA caller cancelled while waiting for the lock or the write (``CancelledError``
    propagates), ``connection.spawn`` raising ``ConnectionLostError`` between ack and confirm
    (the ack is still returned; pending cleared, no confirm), the confirm task cancelled at
    generation teardown or by preemption, and confirm success or timeout. An older version
    never overwrites a newer version's fields; only the latest version clears ``pending``.

    Raised to HA: ``ZclStatusError``, ``RequestTimeoutError`` or a bare ``TimeoutError`` (the
    ack deadline; ``RequestTimeoutError`` subclasses ``TimeoutError``, so HA catches
    ``TimeoutError``), ``ConnectionLostError``.

HA wiring (T16): ``on_update`` and ``connection.add_state_listener`` both push
``bridge.snapshot()`` to the coordinator (``async_update_listeners``, no schedule reset), so the
bridge connectivity entity flips at once on a state change, not at the next poll.

Callbacks: ``on_update(snapshot)`` after every state change (sync, must not await; cheap
``snapshot()``), ``on_new_valve(valve)`` once per newly identified valve,
``on_cache_changed(cache)`` whenever ``export_cache()`` would differ. Callback exceptions are
logged and swallowed.

Logging (``vicare_local_ble.bridge``): INFO discovery results; WARNING valve unavailable,
heating demand above the observed scale (once per valve); DEBUG ``valves.read_issues`` once per
valve and attribute. EUIs only in DEBUG.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from vicare_local_ble.bridge_cache import CACHE_VERSION, BridgeCache, CachedValve, JsonValue

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from vicare_local_ble.valves import Valve, ValveState
    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.connection import ConnectionState, ZdConnection
    from vicare_local_ble.zigbee_direct.types import Eui64

MISSES_UNAVAILABLE: Final = 3
SILENT_POLLS_REJOIN: Final = 2
SETPOINT_ACK_DEADLINE: Final = 60.0
SETPOINT_TOTAL_DEADLINE: Final = 90.0
#: Discovery retries after an incomplete topology, an identification timeout or 0 valves.
DISCOVERY_RETRY_DELAYS: Final = (300.0, 900.0, 3600.0)
TOPOLOGY_REFRESH: Final = 21_600.0
#: Identification of an unknown Device_annce sender: debounce, once per EUI per generation.
ANNCE_IDENTIFY_DEBOUNCE: Final = 10.0
IDENTIFY_CONCURRENCY: Final = 4
#: Basic-read timeouts after which Active_EP/Simple_Desc are sent (diagnostic only).
IDENTIFY_DIAGNOSTIC_AFTER: Final = 2


@dataclass(frozen=True, slots=True)
class SetpointStatus:
    """Setpoint transaction state of one valve (spec §1.6 #7).

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


class ViCareBridge:
    """Valve orchestration over one ``ZdConnection`` (see module docstring).

    ``cache`` seeds the known valves (shown at once, unavailable until polled), the ignore list
    and the preferred own short. The constructor does not touch the connection; call
    ``attach()``. Loop thread only.
    """

    def __init__(
        self,
        connection: ZdConnection,
        *,
        clock: Clock,
        cache: BridgeCache | None = None,
        on_update: Callable[[BridgeSnapshot], None] | None = None,
        on_new_valve: Callable[[Valve], None] | None = None,
        on_cache_changed: Callable[[BridgeCache], None] | None = None,
    ) -> None:
        raise NotImplementedError("T14")

    def attach(self) -> Callable[[], None]:
        """Register the connection listeners and push ``preferred_short``/``avoid_shorts`` from
        the cache with ``connection.update_node_config``. Returns a detach callable (also
        removes node listeners). Call before ``connection.start()``.

        ``avoid_shorts`` pushed by the bridge are the known device shorts only (refreshed after
        every discovery). The connection keeps its own conflict set and merges it in at each
        join, so a bridge push can never erase a conflicting short; likewise the bridge never
        re-sets ``preferred_short`` after an address conflict cleared it (it forgets the cached
        own short on the node's address-conflict callback)."""
        raise NotImplementedError("T14")

    def snapshot(self) -> BridgeSnapshot:
        """Current state; cheap, never awaits, safe in any connection state."""
        raise NotImplementedError("T14")

    async def poll(self) -> BridgeSnapshot:
        """One poll cycle (module docstring); never raises for valve failures."""
        raise NotImplementedError("T14")

    async def set_setpoint(self, eui: Eui64, celsius: float) -> SetpointStatus:
        """Write a setpoint and return at the acknowledgement (module docstring).

        Raises ``KeyError`` (unknown valve), ``ValueError`` (non-finite), ``ZclStatusError``
        (write rejected), ``RequestTimeoutError`` or bare ``TimeoutError`` (no acknowledgement
        within ``SETPOINT_ACK_DEADLINE``; HA must catch ``TimeoutError``) or
        ``ConnectionLostError`` (not READY, or lost meanwhile). ``CancelledError`` of the caller
        propagates after the cleanup described in the module docstring.
        """
        raise NotImplementedError("T14")

    def export_cache(self) -> BridgeCache:
        raise NotImplementedError("T14")


__all__ = [
    "ANNCE_IDENTIFY_DEBOUNCE",
    "CACHE_VERSION",
    "DISCOVERY_RETRY_DELAYS",
    "IDENTIFY_CONCURRENCY",
    "IDENTIFY_DIAGNOSTIC_AFTER",
    "MISSES_UNAVAILABLE",
    "SETPOINT_ACK_DEADLINE",
    "SETPOINT_TOTAL_DEADLINE",
    "SILENT_POLLS_REJOIN",
    "TOPOLOGY_REFRESH",
    "BridgeCache",
    "BridgeSnapshot",
    "CachedValve",
    "DiscoveryStatus",
    "JsonValue",
    "SetpointStatus",
    "TopologySummary",
    "ViCareBridge",
]
