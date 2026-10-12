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
    ``connection.request_rejoin(gen, "all_valves_silent")``. Without any valve answering
    since the last such rejoin, the next one also waits ``SILENT_REJOIN_BACKOFF`` doubling
    per rejoin (1 h, 2 h, 4 h, cap ``SILENT_REJOIN_BACKOFF_MAX`` 6 h; see ``bridge_poll``).

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

import logging
from typing import TYPE_CHECKING

from vicare_local_ble import bridge_discovery, bridge_poll, bridge_setpoint
from vicare_local_ble.bridge_cache import CACHE_VERSION, BridgeCache, CachedValve, JsonValue
from vicare_local_ble.bridge_state import BridgeCore
from vicare_local_ble.bridge_types import (
    ANNCE_IDENTIFY_DEBOUNCE,
    DISCOVERY_RETRY_DELAYS,
    IDENTIFY_CONCURRENCY,
    IDENTIFY_DIAGNOSTIC_AFTER,
    MISSES_UNAVAILABLE,
    SETPOINT_ACK_DEADLINE,
    SETPOINT_TOTAL_DEADLINE,
    SILENT_POLLS_REJOIN,
    SILENT_REJOIN_BACKOFF,
    SILENT_REJOIN_BACKOFF_MAX,
    TOPOLOGY_REFRESH,
    BridgeSnapshot,
    DiscoveryStatus,
    SetpointStatus,
    TopologySummary,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.valves import Valve
    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce
    from vicare_local_ble.zigbee_direct.connection import Generation, ZdConnection
    from vicare_local_ble.zigbee_direct.node import ReportEvent
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger(__name__)


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
        self._core = BridgeCore(
            connection,
            clock=clock,
            cache=cache,
            on_update=on_update,
            on_new_valve=on_new_valve,
            on_cache_changed=on_cache_changed,
        )
        self._unsubscribe: list[Callable[[], None]] = []
        self._node_unsubscribe: list[Callable[[], None]] = []

    def attach(self) -> Callable[[], None]:
        """Register the connection listeners and push ``preferred_short``/``avoid_shorts`` from
        the cache with ``connection.update_node_config``. Returns a detach callable (also
        removes node listeners). Call before ``connection.start()``.

        ``avoid_shorts`` pushed by the bridge are the known device shorts only (refreshed after
        every discovery). The connection keeps its own conflict set and merges it in at each
        join, so a bridge push can never erase a conflicting short; likewise the bridge never
        re-sets ``preferred_short`` after an address conflict cleared it (it forgets the cached
        own short on the node's address-conflict callback)."""
        core = self._core
        changes: dict[str, object] = {"avoid_shorts": core.known_shorts()}
        if core.own_short is not None:
            changes["preferred_short"] = core.own_short
        core.connection.update_node_config(**changes)
        self._unsubscribe.append(core.connection.add_ready_listener(self._on_ready))
        return self._detach

    def _detach(self) -> None:
        for unsubscribe in (*self._unsubscribe, *self._node_unsubscribe):
            unsubscribe()
        self._unsubscribe.clear()
        self._node_unsubscribe.clear()

    # --- READY (synchronous) ---

    def _on_ready(self, gen: Generation) -> None:
        core = self._core
        for unsubscribe in self._node_unsubscribe:
            unsubscribe()
        core.start_generation(gen)
        core.own_short = gen.join.own_short
        core.zdd_eui = str(gen.join.zdd_eui)
        node = gen.node
        self._node_unsubscribe = [
            node.on_report(lambda event: self._on_report(gen, event)),
            node.on_device_annce(lambda annce, _src: self._on_annce(gen, annce)),
            node.on_address_conflict(lambda: self._on_conflict(gen)),
        ]
        core.changed()
        bridge_discovery.spawn_safely(
            core, gen, bridge_discovery.discovery_task(core, gen), "vicare discovery"
        )

    def _on_report(self, gen: Generation, event: ReportEvent) -> None:
        core = self._core
        if not core.is_current(gen):
            return
        eui = core.eui_for_short(event.src_short, event.src_ieee)
        if eui is None:
            return
        changed = core.apply(eui, event.cluster, event.records, event.manufacturer_code)
        if core.responded(eui) or changed:
            core.changed()

    def _on_annce(self, gen: Generation, annce: DeviceAnnce) -> None:
        bridge_discovery.on_device_annce(self._core, gen, annce)

    def _on_conflict(self, gen: Generation) -> None:
        core = self._core
        if core.gen is not gen or core.own_short is None:
            return
        _LOGGER.info("address conflict on our short: forgetting it")
        core.own_short = None
        core.changed()

    # --- public API ---

    def snapshot(self) -> BridgeSnapshot:
        """Current state; cheap, never awaits, safe in any connection state."""
        return self._core.snapshot()

    async def poll(self) -> BridgeSnapshot:
        """One poll cycle (module docstring); never raises for valve failures."""
        return await bridge_poll.poll(self._core)

    async def set_setpoint(self, eui: Eui64, celsius: float) -> SetpointStatus:
        """Write a setpoint and return at the acknowledgement (module docstring).

        Raises ``KeyError`` (unknown valve), ``ValueError`` (non-finite), ``ZclStatusError``
        (write rejected), ``RequestTimeoutError`` or bare ``TimeoutError`` (no acknowledgement
        within ``SETPOINT_ACK_DEADLINE``; HA must catch ``TimeoutError``) or
        ``ConnectionLostError`` (not READY, or lost meanwhile). ``CancelledError`` of the caller
        propagates after the cleanup described in the module docstring.
        """
        return await bridge_setpoint.set_setpoint(self._core, eui, celsius)

    def export_cache(self) -> BridgeCache:
        return self._core.export_cache()


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
    "SILENT_REJOIN_BACKOFF",
    "SILENT_REJOIN_BACKOFF_MAX",
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
