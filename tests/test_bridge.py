"""ViCareBridge: discovery, retries and Device_annce, against the simulator.

Shared helpers live here (``test_bridge_*.py`` import them). A real ``ZdConnection`` runs on
``VirtualClock`` with production timings; keys and EUIs are the dummies of
``default_installation``.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest

from vicare_local_ble import bridge_discovery, valves
from vicare_local_ble.bridge import (
    ANNCE_IDENTIFY_RETRY,
    DISCOVERY_RETRY_DELAYS,
    TOPOLOGY_REFRESH,
    BridgeCache,
    BridgeSnapshot,
    ViCareBridge,
)
from vicare_local_ble.testing.scenario import default_installation
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID, ZDO_PROFILE_ID, ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrameType
from vicare_local_ble.zigbee_direct.codec.zcl import ReadAttributes, WriteAttributes, ZclFrame
from vicare_local_ble.zigbee_direct.codec.zdo import ZdoCluster
from vicare_local_ble.zigbee_direct.connection import ConnectionState, ZdConnection
from vicare_local_ble.zigbee_direct.errors import DecodeError
from vicare_local_ble.zigbee_direct.types import COORDINATOR, Eui64

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.bridge_state import BridgeCore
    from vicare_local_ble.testing.scenario import Installation
    from vicare_local_ble.valves import Valve
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.connection import Generation

LOGGER = "vicare_local_ble.bridge"
ACME_EUI = Eui64.from_str("02:00:00:00:00:02:00:01")
DEAD_EUI = Eui64.from_str("02:00:00:00:00:03:00:01")
NEW_EUI = Eui64.from_str("02:00:00:00:00:01:00:20")
FIRST_BROADCAST = 0xFFF8


@dataclass
class BRig:
    inst: Installation
    conn: ZdConnection
    bridge: ViCareBridge
    detach: Callable[[], None]
    updates: list[tuple[float, BridgeSnapshot]] = field(default_factory=list)
    new_valves: list[Valve] = field(default_factory=list)
    caches: list[BridgeCache] = field(default_factory=list)

    @property
    def clock(self) -> VirtualClock:
        return self.inst.clock

    @property
    def core(self) -> BridgeCore:
        return self.bridge._core

    def snap(self) -> BridgeSnapshot:
        return self.bridge.snapshot()

    def euis(self) -> list[Eui64]:
        return [v.eui for v in self.inst.valves]


def make_rig(
    *,
    n_valves: int = 6,
    behind_router: int = 1,
    seed: int = 0,
    cache: BridgeCache | None = None,
    setup: Callable[[Installation], None] | None = None,
    on_update: Callable[[BRig, BridgeSnapshot], None] | None = None,
    **kwargs: Any,
) -> BRig:
    inst = default_installation(n_valves=n_valves, behind_router=behind_router, seed=seed)
    if setup is not None:
        setup(inst)
    conn = ZdConnection(
        inst.resolver,
        own_eui=inst.zvd_eui,
        network_key=inst.network_key,
        clock=inst.clock,
        connector=inst.connector,
        rng=random.Random(1000 + seed),  # noqa: S311 - jitter only
        **kwargs,
    )
    holder: list[BRig] = []

    def update(snapshot: BridgeSnapshot) -> None:
        rig = holder[0]
        rig.updates.append((rig.clock.now(), snapshot))
        if on_update is not None:
            on_update(rig, snapshot)

    bridge = ViCareBridge(
        conn,
        clock=inst.clock,
        cache=cache,
        on_update=update,
        on_new_valve=lambda v: holder[0].new_valves.append(v),
        on_cache_changed=lambda c: holder[0].caches.append(c),
    )
    rig = BRig(inst, conn, bridge, lambda: None)
    holder.append(rig)
    rig.detach = bridge.attach()
    return rig


async def start(r: BRig) -> Generation:
    return await r.clock.run_task(r.conn.start())


async def stop(r: BRig) -> None:
    await r.clock.run_task(r.conn.stop())


async def run_until(clock: VirtualClock, done: Callable[[], bool], limit: float = 3600.0) -> None:
    """Advance timer by timer until ``done()``; fails after ``limit`` virtual seconds."""
    deadline = clock.now() + limit
    await clock.run_until_idle()
    while not done():
        when = clock.next_deadline()
        assert when is not None, "blocked with no timer"
        assert when <= deadline, "condition not reached in time"
        await clock.advance_to(when)


def settled(r: BRig) -> bool:
    """Discovery ran, the initial poll started and no valve transaction is open."""
    core = r.core
    return (
        core.discovery.last_run is not None
        and not core.discovery.running
        and core.polls >= 1
        and not any(tx.lock.locked() for tx in core.tx.values())
    )


async def discovered(r: BRig) -> Generation:
    """Start, then run until discovery and the initial poll are done."""
    gen = await start(r)
    await run_until(r.clock, lambda: settled(r))
    return gen


async def poll(r: BRig) -> BridgeSnapshot:
    return await r.clock.run_task(r.bridge.poll())


async def ready_again(r: BRig, after: int) -> Generation:
    await run_until(r.clock, lambda: r.conn.current is not None and r.conn.current.number > after)
    gen = r.conn.current
    assert gen is not None
    return gen


def frames(r: BRig, start: int = 0) -> list[tuple[int, ApsDataFrame]]:
    """``(dst, aps)`` of every unicast data frame the ZVD sent this session."""
    out: list[tuple[int, ApsDataFrame]] = []
    for frame in r.inst.network.received[start:]:
        if frame.frame_type is not NwkFrameType.DATA or frame.dst >= FIRST_BROADCAST:
            continue
        try:
            out.append((frame.dst, ApsDataFrame.decode(frame.payload)))
        except DecodeError:  # pragma: no cover - the node sends valid frames
            continue
    return out


def zcl_requests(
    r: BRig, start: int = 0, *, dst: int | None = None
) -> list[tuple[int, valves.ReadRequest | tuple[int, ...]]]:
    """``(dst, ReadRequest)`` for reads, ``(dst, (cluster, *values))`` for writes, in order;
    retransmits (same dst, cluster, tsn) are reported once."""
    out: list[tuple[int, valves.ReadRequest | tuple[int, ...]]] = []
    seen: set[tuple[int, int, int]] = set()
    for to, aps in frames(r, start):
        if aps.profile_id != HA_PROFILE_ID or (dst is not None and to != dst):
            continue
        zcl = ZclFrame.decode(aps.payload)
        key = (to, aps.cluster_id, zcl.header.tsn)
        if key in seen:
            continue
        seen.add(key)
        command = zcl.global_command()
        mfr = zcl.header.manufacturer_code
        if isinstance(command, ReadAttributes):
            out.append((to, valves.ReadRequest(aps.cluster_id, command.attribute_ids, mfr)))
        elif isinstance(command, WriteAttributes):
            values = tuple(rec.value for rec in command.records if isinstance(rec.value, int))
            out.append((to, (aps.cluster_id, *values)))
    return out


def zdo_requests(r: BRig, cluster: int, start: int = 0) -> list[int]:
    return [
        to
        for to, aps in frames(r, start)
        if aps.profile_id == ZDO_PROFILE_ID and aps.cluster_id == cluster
    ]


#: Reply latency as measured on hardware (median 2.1-3.8 s, max 10.2 s). The
#: simulator default (2-30 s) is pessimistic; a verified setpoint costs two round trips plus
#: any lock wait, so timing tests of queued setpoints use the measured range.
HARDWARE_LATENCY = (2.0, 10.2)


def hardware_latency(inst: Installation) -> None:
    for valve in inst.valves:
        valve.latency = HARDWARE_LATENCY


def add_acme(inst: Installation) -> None:
    """A non-Viessmann end device on the coordinator."""
    acme = SimValve(
        inst.clock,
        eui=ACME_EUI,
        short=0x2001,
        rng=random.Random(5),  # noqa: S311
        manufacturer_name="Acme",
        model_id="X1",
    )
    inst.network.add_valve(acme, parent=COORDINATOR)


def add_dead(inst: Installation) -> None:
    """A device that never answers, on the coordinator."""
    dead = SimValve(inst.clock, eui=DEAD_EUI, short=0x2002, rng=random.Random(6), drop_rate=1.0)  # noqa: S311
    inst.network.add_valve(dead, parent=COORDINATOR)


def run_times(r: BRig) -> list[tuple[float, float, int]]:
    """``(last_run, next_retry, attempts)`` of each finished discovery attempt."""
    out: list[tuple[float, float, int]] = []
    for _, snap in r.updates:
        d = snap.discovery
        if d.last_run is None or d.next_retry is None or d.running:
            continue
        entry = (d.last_run, d.next_retry, d.attempts)
        if not out or out[-1] != entry:
            out.append(entry)
    return out


# --- discovery ---------------------------------------------------------------------------------


async def test_discovery_is_spawned_and_ready_is_not_delayed() -> None:
    r = make_rig()
    states: list[tuple[ConnectionState, float]] = []
    r.conn.add_state_listener(lambda s: states.append((s, r.clock.now())))
    gen = await start(r)
    ready_at = next(t for s, t in states if s is ConnectionState.READY)
    snap = r.snap()
    assert snap.connection_state is ConnectionState.READY
    assert snap.generation == gen.number
    assert snap.own_short == gen.join.own_short
    assert snap.discovery.running
    assert snap.valves == {}
    assert zcl_requests(r) == []  # READY came before any identification read
    names = {t.get_name() for t in asyncio.all_tasks()}
    assert "vicare discovery" in names
    await run_until(r.clock, lambda: settled(r))
    assert r.snap().discovery.last_run is not None
    assert r.snap().discovery.last_run > ready_at  # type: ignore[operator]
    await stop(r)


async def test_finds_five_plus_one_valves_and_ignores_others(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    def setup(inst: Installation) -> None:
        add_acme(inst)
        add_dead(inst)

    r = make_rig(setup=setup)
    gen = await discovered(r)
    snap = r.snap()
    assert set(snap.valves) == set(r.euis())
    assert len(snap.valves) == 6
    assert sorted(v.eui.wire for v in r.new_valves) == sorted(e.wire for e in r.euis())
    assert str(ACME_EUI) in r.bridge.export_cache().ignored
    assert ACME_EUI not in snap.valves
    valve = snap.valves[r.euis()[0]]
    assert (valve.manufacturer, valve.model) == (valves.MANUFACTURER, "7637434")
    assert valve.sw_build == "01.18.0008 02.06"
    assert (valve.limits.min_c, valve.limits.max_c, valve.limits.source) == (8.0, 30.0, "limits")
    topo = snap.discovery.topology
    assert topo is not None
    router_short = next(x.short for x in r.inst.network.routers if x.eui != r.inst.zdd_eui)
    behind = r.inst.valves[-1].eui
    assert topo.parent_of[behind] == router_short
    assert all(topo.parent_of[e] == COORDINATOR for e in r.euis()[:-1])
    assert topo.routers == 3
    # The dead device timed out -> incomplete -> first retry in 5 min.
    assert snap.discovery.complete is False
    assert snap.discovery.valves_found == 6
    assert snap.discovery.next_retry == snap.discovery.last_run + DISCOVERY_RETRY_DELAYS[0]  # type: ignore[operator]
    assert all(snap.available.values())
    shorts = {v.short for v in snap.valves.values()}
    assert shorts <= r.conn.node_config.avoid_shorts
    assert gen.join.own_short not in r.conn.node_config.avoid_shorts
    assert "discovery: 6 valves, 1 ignored" in caplog.text
    assert r.inst.network_key.reveal().hex() not in caplog.text
    await stop(r)


async def test_retries_then_six_hour_refresh_when_no_valve_found() -> None:
    r = make_rig(n_valves=0, behind_router=0)
    await start(r)
    await run_until(r.clock, lambda: len(run_times(r)) >= 5, limit=2 * 86_400)
    runs = run_times(r)[:5]
    delays = [nxt - last for last, nxt, _ in runs]
    assert delays == pytest.approx([*DISCOVERY_RETRY_DELAYS, TOPOLOGY_REFRESH, TOPOLOGY_REFRESH])
    assert [a for *_, a in runs] == [1, 2, 3, 3, 3]
    # each retry started when it was scheduled (a walk takes a few seconds)
    for (_, nxt, _), (last, _, _) in itertools.pairwise(runs):
        assert nxt <= last < nxt + 60
    assert r.snap().discovery.complete is False
    await stop(r)


async def test_complete_run_refreshes_every_six_hours_without_polling() -> None:
    r = make_rig()
    await discovered(r)
    first = r.snap().discovery
    assert first.complete is True
    assert first.attempts == 0
    assert first.next_retry == first.last_run + TOPOLOGY_REFRESH  # type: ignore[operator]
    mark = len(r.inst.network.received)
    await run_until(r.clock, lambda: r.snap().discovery.last_run != first.last_run, limit=7 * 3600)
    again = r.snap().discovery
    assert first.next_retry <= again.last_run < first.next_retry + 60  # type: ignore[operator]
    assert again.next_retry == again.last_run + TOPOLOGY_REFRESH  # type: ignore[operator]
    assert zcl_requests(r, mark) == []  # all known: no identification, no extra poll
    assert zdo_requests(r, ZdoCluster.MGMT_LQI_REQ, mark)  # but the topology was walked
    await stop(r)


async def test_incomplete_topology_retries_in_five_minutes() -> None:
    def setup(inst: Installation) -> None:
        router = next(x.short for x in inst.network.routers if x.eui != inst.zdd_eui)
        inst.network.router_timeout = frozenset({router})

    r = make_rig(setup=setup)
    await discovered(r)
    d = r.snap().discovery
    assert d.topology is not None
    assert d.topology.complete is False
    assert d.complete is False
    assert len(r.snap().valves) == 5  # the valve behind the silent router is not reachable
    assert d.next_retry == d.last_run + DISCOVERY_RETRY_DELAYS[0]  # type: ignore[operator]
    await stop(r)


async def test_identification_timeouts_retry_and_diagnose(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, LOGGER)
    r = make_rig(n_valves=1, behind_router=0, setup=add_dead)
    await discovered(r)
    assert zdo_requests(r, ZdoCluster.ACTIVE_EP_REQ) == []  # first timeout: no diagnostic
    assert r.snap().discovery.attempts == 1
    await run_until(r.clock, lambda: len(run_times(r)) >= 2, limit=900)
    assert set(zdo_requests(r, ZdoCluster.ACTIVE_EP_REQ)) == {0x2002}  # after 2nd timeout
    assert "diagnostic failed" in caplog.text
    assert r.snap().discovery.attempts == 2
    assert str(DEAD_EUI) not in r.bridge.export_cache().ignored  # never answered: not ignored
    await stop(r)


async def test_device_annce_unknown_identified_after_debounce_once() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    net = r.inst.network
    newcomer = SimValve(r.clock, eui=NEW_EUI, short=0x3333, rng=random.Random(9))  # noqa: S311
    mark = len(net.received)
    t0 = r.clock.now()
    net.add_valve_later(newcomer)
    await r.clock.advance(5)
    net.valve_rejoin(newcomer, 0x3334)  # a second annce inside the debounce, new short
    await r.clock.advance_to(t0 + 9.9)
    assert zcl_requests(r, mark) == []
    await r.clock.advance_to(t0 + 10)
    assert zcl_requests(r, mark) == [(0x3334, valves.IDENTIFY)]
    await run_until(r.clock, lambda: NEW_EUI in r.snap().valves)
    assert [v.eui for v in r.new_valves].count(NEW_EUI) == 1
    assert r.snap().valves[NEW_EUI].short == 0x3334
    assert r.snap().discovery.valves_found == 3
    assert 0x3334 in r.conn.node_config.avoid_shorts
    # Known EUI now: a later annce only updates the short.
    net.valve_rejoin(newcomer, 0x3335)
    await r.clock.advance(0)
    assert r.snap().valves[NEW_EUI].short == 0x3335
    await r.clock.advance(60)
    reads = [req for to, req in zcl_requests(r, mark) if req == valves.IDENTIFY]
    assert len(reads) == 1
    await stop(r)


async def test_device_annce_known_valve_updates_short_and_ignored_is_skipped() -> None:
    r = make_rig(n_valves=2, behind_router=0, setup=add_acme)
    await discovered(r)
    net = r.inst.network
    first = r.inst.valves[0]
    count = len(r.updates)
    net.valve_rejoin(first, 0x4444)
    await r.clock.advance(0)
    assert r.snap().valves[first.eui].short == 0x4444
    assert len(r.updates) == count + 1
    assert 0x4444 in r.conn.node_config.avoid_shorts
    mark = len(net.received)
    acme = next(v for v in net.valves if v.eui == ACME_EUI)
    net.valve_rejoin(acme, 0x4445)  # ignored device: no identification
    await r.clock.advance(30)
    assert zcl_requests(r, mark) == []
    assert ACME_EUI not in r.snap().valves
    assert [v.eui for v in r.new_valves].count(first.eui) == 1
    await stop(r)


async def test_unknown_annce_retry_after_a_timeout_is_rate_limited() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    net = r.inst.network
    dead = SimValve(r.clock, eui=DEAD_EUI, short=0x3000, rng=random.Random(3), drop_rate=1.0)  # noqa: S311
    mark = len(net.received)
    net.add_valve_later(dead)
    await r.clock.advance(80)  # debounce + one Basic read timing out (2 x 30 s)
    failed_at = r.clock.now()
    net.valve_rejoin(dead, 0x3001)
    net.valve_rejoin(dead, 0x3002)  # flapping: still one retry, at the latest short
    await r.clock.advance(80)
    basic = [to for to, req in zcl_requests(r, mark) if req == valves.IDENTIFY]
    assert basic == [0x3000]  # the retry waits ANNCE_IDENTIFY_RETRY after the failure
    await r.clock.advance_to(failed_at + ANNCE_IDENTIFY_RETRY + 80)
    basic = [to for to, req in zcl_requests(r, mark) if req == valves.IDENTIFY]
    assert basic == [0x3000, 0x3002]
    assert DEAD_EUI not in r.snap().valves
    await stop(r)


async def test_stale_generation_identification_does_not_mutate() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    r.inst.r0.disconnect()
    await ready_again(r, gen.number)
    before = r.bridge.export_cache()
    result = await r.clock.run_task(
        bridge_discovery.identify(r.core, gen, NEW_EUI, r.inst.valves[0].short)
    )
    assert result == "stale"
    assert r.bridge.export_cache() == before
    await stop(r)
