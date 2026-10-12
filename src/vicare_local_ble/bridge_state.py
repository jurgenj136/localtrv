"""Mutable bridge state shared by the ``bridge_*`` helpers (T14; internal).

``BridgeCore`` owns every per-valve dictionary, the callbacks and the snapshot cache. Helpers
mutate it and call ``changed()`` once per state change; ``changed()`` pushes ``on_update`` and,
when the exportable cache differs, ``on_cache_changed``. Loop thread only.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections import deque
from types import MappingProxyType
from typing import TYPE_CHECKING

from vicare_local_ble import valves
from vicare_local_ble.bridge_cache import BridgeCache, CachedValve
from vicare_local_ble.bridge_types import (
    IDENTIFY_CONCURRENCY,
    MISSES_UNAVAILABLE,
    BridgeSnapshot,
    DiscoveryStatus,
    SetpointStatus,
    TopologySummary,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from vicare_local_ble.valves import Valve, ValveState
    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord, ReadAttributeStatus
    from vicare_local_ble.zigbee_direct.connection import Generation, ZdConnection
    from vicare_local_ble.zigbee_direct.discovery import Topology
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.bridge")

type _Parts = tuple[
    MappingProxyType[Eui64, Valve],
    MappingProxyType[Eui64, ValveState],
    MappingProxyType[Eui64, bool],
    MappingProxyType[Eui64, SetpointStatus],
    MappingProxyType[Eui64, int],
]


class TxLock:
    """Per-valve transaction lock with a non-blocking ``try_acquire``.

    ``release`` hands ownership straight to the oldest waiter, so there is no window in which
    the lock looks free while a woken waiter has not run yet (``asyncio.Lock`` has one).
    """

    __slots__ = ("_held", "_waiters")

    def __init__(self) -> None:
        self._held = False
        self._waiters: deque[asyncio.Future[None]] = deque()

    def locked(self) -> bool:
        return self._held

    def has_waiters(self) -> bool:
        """True while a caller waits in ``acquire`` (a setpoint behind a poll)."""
        return any(not fut.done() for fut in self._waiters)

    def try_acquire(self) -> bool:
        if self._held:
            return False
        self._held = True
        return True

    async def acquire(self) -> None:
        if not self._held:
            self._held = True
            return
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.append(fut)
        try:
            await fut
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self.release()  # ownership arrived together with the cancellation
            raise
        finally:
            if fut in self._waiters:
                self._waiters.remove(fut)

    def release(self) -> None:
        if not self._held:
            raise RuntimeError("TxLock released while not held")
        while self._waiters:
            fut = self._waiters.popleft()
            if not fut.done():
                fut.set_result(None)  # ownership passes; _held stays True
                return
        self._held = False


@dataclasses.dataclass(slots=True)
class ValveTx:
    """Setpoint bookkeeping of one valve: the lock and the running confirm task."""

    lock: TxLock = dataclasses.field(default_factory=TxLock)
    confirm: asyncio.Task[None] | None = None
    #: Value of the last write the valve acknowledged (any version).
    acked_c: float | None = None


class BridgeCore:
    """All mutable bridge state (see module docstring)."""

    def __init__(
        self,
        connection: ZdConnection,
        *,
        clock: Clock,
        cache: BridgeCache | None,
        on_update: Callable[[BridgeSnapshot], None] | None,
        on_new_valve: Callable[[Valve], None] | None,
        on_cache_changed: Callable[[BridgeCache], None] | None,
    ) -> None:
        self.connection = connection
        self.clock = clock
        self._on_update = on_update
        self._on_new_valve = on_new_valve
        self._on_cache_changed = on_cache_changed
        cache = cache if cache is not None else BridgeCache()
        self.own_short: int | None = cache.own_short
        self.zdd_eui: str | None = cache.zdd_eui
        self.valves: dict[Eui64, Valve] = {}
        for entry in cache.valves.values():
            valve = entry.to_valve()
            self.valves[valve.eui] = valve
        self.ignored: set[str] = set(cache.ignored)
        self.states: dict[Eui64, ValveState] = {eui: valves.ValveState() for eui in self.valves}
        self.available: dict[Eui64, bool] = dict.fromkeys(self.valves, False)
        self.misses: dict[Eui64, int] = dict.fromkeys(self.valves, 0)
        self.setpoints: dict[Eui64, SetpointStatus] = {e: SetpointStatus() for e in self.valves}
        self.tx: dict[Eui64, ValveTx] = {eui: ValveTx() for eui in self.valves}
        self.static_at: dict[Eui64, float] = {}
        self.discovery = DiscoveryStatus()
        self.topology: Topology | None = None
        self.walked_at: float | None = None
        #: The generation whose listeners are installed (``None`` before the first READY).
        self.gen: Generation | None = None
        self.polls = 0
        self.silent_streak = 0
        self.walking = False
        #: Clock time at which each valve's short was last learned (walk or Device_annce).
        self.short_at: dict[Eui64, float] = {}
        #: All-silent rejoins without any valve answering since, and when the last one was.
        self.silent_rejoins = 0
        self.last_silent_rejoin: float | None = None
        #: Basic-read timeouts per unknown EUI (diagnostic Active_EP/Simple_Desc trigger).
        self.basic_timeouts: dict[Eui64, int] = {}
        #: Per generation: Device_annce senders scheduled for identification, latest shorts.
        self.annce_seen: set[Eui64] = set()
        self.annce_short: dict[Eui64, int] = {}
        self.identify_sem = asyncio.Semaphore(IDENTIFY_CONCURRENCY)
        self.logged_issues: set[tuple[Eui64, int, int]] = set()
        self.demand_warned: set[Eui64] = set()
        self._snapshot_parts: _Parts | None = None
        self._exported: BridgeCache = self.export_cache()

    # --- generation helpers ---

    def start_generation(self, gen: Generation) -> None:
        """Reset the per-generation bookkeeping for a new READY generation."""
        self.gen = gen
        self.silent_streak = 0
        self.walking = False
        self.annce_seen = set()
        self.annce_short = {}
        self.identify_sem = asyncio.Semaphore(IDENTIFY_CONCURRENCY)

    def is_current(self, gen: Generation) -> bool:
        """True while ``gen`` is the connection's READY generation (stale-completion guard)."""
        return self.connection.current is gen

    # --- callbacks ---

    def changed(self) -> None:
        """A state change happened: refresh the snapshot, push it, persist if needed."""
        self._snapshot_parts = None
        if self._on_update is not None:
            try:
                self._on_update(self.snapshot())
            except Exception:
                _LOGGER.exception("on_update callback raised")
        cache = self.export_cache()
        if cache != self._exported:
            if self._on_cache_changed is not None:
                try:
                    self._on_cache_changed(cache)
                except Exception:
                    _LOGGER.exception("on_cache_changed callback raised")
                    return  # not persisted: retried at the next change
            self._exported = cache

    def new_valve(self, valve: Valve) -> None:
        if self._on_new_valve is not None:
            try:
                self._on_new_valve(valve)
            except Exception:
                _LOGGER.exception("on_new_valve callback raised")

    # --- snapshot and cache ---

    def snapshot(self) -> BridgeSnapshot:
        parts = self._snapshot_parts
        if parts is None:
            parts = (
                MappingProxyType(dict(self.valves)),
                MappingProxyType(dict(self.states)),
                MappingProxyType(dict(self.available)),
                MappingProxyType(dict(self.setpoints)),
                MappingProxyType(dict(self.misses)),
            )
            self._snapshot_parts = parts
        valve_map, states, available, setpoints, misses = parts
        current = self.connection.current
        return BridgeSnapshot(
            connection_state=self.connection.state,
            generation=None if current is None else current.number,
            own_short=self.own_short,
            valves=valve_map,
            states=states,
            available=available,
            setpoints=setpoints,
            discovery=self.discovery,
            misses=misses,
        )

    def export_cache(self) -> BridgeCache:
        return BridgeCache(
            own_short=self.own_short,
            zdd_eui=self.zdd_eui,
            valves={str(eui): CachedValve.from_valve(v) for eui, v in self.valves.items()},
            ignored=frozenset(self.ignored),
        )

    def known_shorts(self) -> frozenset[int]:
        """Device shorts the next join must avoid: valves plus every walked neighbor."""
        shorts = {v.short for v in self.valves.values()}
        if self.topology is not None:
            shorts.update(n.nwk_addr for n in self.topology.neighbors.values())
        current = self.connection.current
        own = current.join.own_short if current is not None else self.own_short
        if own is not None:
            shorts.discard(own)
        return frozenset(shorts)

    def push_avoid_shorts(self) -> None:
        self.connection.update_node_config(avoid_shorts=self.known_shorts())

    # --- valves ---

    def add_valve(self, valve: Valve) -> None:
        eui = valve.eui
        self.valves[eui] = valve
        self.states.setdefault(eui, valves.ValveState())
        self.available.setdefault(eui, False)
        self.misses.setdefault(eui, 0)
        self.setpoints.setdefault(eui, SetpointStatus())
        self.tx.setdefault(eui, ValveTx())
        self.ignored.discard(str(eui))

    def set_short(self, eui: Eui64, short: int) -> bool:
        """Adopt a short learned now; True if it changed."""
        self.short_at[eui] = self.clock.now()
        valve = self.valves[eui]
        if valve.short == short:
            return False
        _LOGGER.debug("valve %s: short 0x%04X -> 0x%04X", eui, valve.short, short)
        self.valves[eui] = dataclasses.replace(valve, short=short)
        return True

    def eui_for_short(self, short: int, ieee: Eui64 | None = None) -> Eui64 | None:
        if ieee is not None and ieee in self.valves:
            return ieee
        for eui, valve in self.valves.items():
            if valve.short == short:
                return eui
        return None

    def apply(
        self,
        eui: Eui64,
        cluster: int,
        records: Iterable[ReadAttributeStatus | AttributeRecord],
        manufacturer: int | None,
    ) -> bool:
        """``valves.apply_reads`` plus once-per-valve issue logging; True if state changed."""
        items = tuple(records)
        self.log_issues(eui, cluster, items, manufacturer)
        old = self.states[eui]
        new = valves.apply_reads(
            old, cluster, items, manufacturer=manufacturer, at=self.clock.now()
        )
        self.states[eui] = new
        return new is not old

    def log_issues(
        self,
        eui: Eui64,
        cluster: int,
        records: Iterable[ReadAttributeStatus | AttributeRecord],
        manufacturer: int | None,
    ) -> None:
        for issue in valves.read_issues(cluster, records, manufacturer=manufacturer):
            if issue.kind == "demand_scale":
                if eui not in self.demand_warned:
                    self.demand_warned.add(eui)
                    _LOGGER.warning(
                        "valve 0x%04X: heating demand above the observed scale (0-%d)",
                        self.valves[eui].short,
                        valves.HEATING_DEMAND_MAX_OBSERVED,
                    )
                continue
            key = (eui, issue.cluster, issue.attr)
            if key not in self.logged_issues:
                self.logged_issues.add(key)
                _LOGGER.debug(
                    "valve %s: attribute 0x%04X/0x%04X rejected (%s)",
                    eui,
                    issue.cluster,
                    issue.attr,
                    issue.kind,
                )

    def responded(self, eui: Eui64) -> bool:
        """A valve answered: reset its misses; True if anything changed."""
        self.silent_rejoins = 0
        if self.misses.get(eui) == 0 and self.available.get(eui):
            return False
        self.misses[eui] = 0
        self.available[eui] = True
        return True

    def missed(self, eui: Eui64) -> bool:
        """Count a miss; True exactly when the count reaches ``MISSES_UNAVAILABLE``."""
        count = self.misses.get(eui, 0) + 1
        self.misses[eui] = count
        if count < MISSES_UNAVAILABLE:
            return False
        if self.available.get(eui, False):
            self.available[eui] = False
            _LOGGER.warning(
                "valve 0x%04X unavailable after %d missed polls", self.valves[eui].short, count
            )
        return count == MISSES_UNAVAILABLE

    def set_topology(self, topology: Topology, *, started: float) -> None:
        """Adopt a walk result: refresh known valve shorts and the summary.

        A short learned at or after ``started`` (when the walk began, e.g. from a
        Device_annce) is fresher than the walk's and is kept."""
        self.topology = topology
        self.walked_at = self.clock.now()
        for eui, neighbor in topology.neighbors.items():
            if eui not in self.valves:
                continue
            learned = self.short_at.get(eui)
            if learned is not None and learned >= started:
                continue
            self.set_short(eui, neighbor.nwk_addr)
        self.summarize()

    def summarize(self) -> None:
        """Rebuild ``discovery.topology`` (``parent_of`` covers the valves known now)."""
        topology = self.topology
        if topology is None:  # pragma: no cover - called after set_topology
            return
        parent_of = {e: p for e, p in topology.parent_of.items() if e in self.valves}
        summary = TopologySummary(
            complete=topology.complete,
            routers=len(topology.routers_walked),
            neighbors=len(topology.neighbors),
            parent_of=MappingProxyType(parent_of),
            walked_at=self.walked_at,
        )
        self.discovery = dataclasses.replace(self.discovery, topology=summary)


__all__ = ["BridgeCore", "TxLock", "ValveTx"]
