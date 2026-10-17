"""End to end over the simulator: the network and valve rows of the edge-case table.

The row -> test map is in ``test_e2e_sim.py``. Whole library stack on ``VirtualClock``.
"""

from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING

import pytest

from test_bridge import (
    hardware_latency,
    poll,
    ready_again,
    run_times,
    run_until,
    settled,
    stop,
    zcl_requests,
)
from test_e2e_sim import S, all_available, begin, e2e_rig, on_attempt, track_states
from vicare_local_ble import valves
from vicare_local_ble.bridge import (
    DISCOVERY_RETRY_DELAYS,
    MISSES_UNAVAILABLE,
    TOPOLOGY_REFRESH,
    SetpointStatus,
)
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.codec.aps import ZDO_PROFILE_ID
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import ZdoCluster
from vicare_local_ble.zigbee_direct.routing import (
    MTORR_ON_ROUTE_FAILURE_INTERVAL,
    NWK_STATUS_NON_TREE_LINK_FAILURE,
)
from vicare_local_ble.zigbee_direct.types import COORDINATOR, Eui64

if TYPE_CHECKING:
    from test_bridge import BRig
    from vicare_local_ble.bridge import BridgeSnapshot
    from vicare_local_ble.testing.scenario import Installation

NEW_EUI = Eui64.from_str("02:00:00:00:00:01:00:30")
SLOW_EUI = Eui64.from_str("02:00:00:00:00:01:00:31")
ASSIGNED_SHORT = 0x3456
INVALID_SHORT = 0xFFFD


def lqi_requests(r: BRig, start: int = 0) -> int:
    from test_bridge import frames

    return sum(
        1
        for _, aps in frames(r, start)
        if aps.profile_id == ZDO_PROFILE_ID and aps.cluster_id == ZdoCluster.MGMT_LQI_REQ
    )


def status(r: BRig, eui: Eui64) -> SetpointStatus:
    return r.snap().setpoints[eui]


# --- valves silent ---------------------------------------------------------------------------


async def test_valve_silent_unavailable_rewalk() -> None:
    r = e2e_rig()
    await begin(r)
    dead, alive = r.inst.valves
    last = r.snap().states[dead.eui]
    dead.drop_rate = 1.0
    for n in range(1, MISSES_UNAVAILABLE + 1):
        mark = len(r.inst.network.received)
        snap = await poll(r)
        assert snap.misses[dead.eui] == n
        assert snap.available[dead.eui] is (n < MISSES_UNAVAILABLE)
        assert snap.states[dead.eui] == last  # last values kept
    assert snap.available[alive.eui] is True
    await run_until(r.clock, lambda: lqi_requests(r, mark) > 0 and not r.core.walking)
    assert r.conn.current is not None
    assert r.conn.current.number == 1  # one silent valve never rejoins
    dead.drop_rate = 0.0
    snap = await poll(r)
    assert snap.available[dead.eui] is True
    assert snap.misses[dead.eui] == 0
    await stop(r)


async def test_all_valves_silent_rejoin() -> None:
    r = e2e_rig()
    gen1 = await begin(r)
    for valve in r.inst.valves:
        valve.drop_rate = 1.0
    await poll(r)
    assert r.conn.current is gen1
    await poll(r)  # second all-silent poll while READY throughout
    gen2 = await ready_again(r, gen1.number)
    assert r.conn.stats.rejoins == 1
    assert r.conn.stats.last_failure == "rejoin:all_valves_silent"
    for valve in r.inst.valves:
        valve.drop_rate = 0.0
    await run_until(r.clock, lambda: settled(r) and r.core.polls >= 3)
    snap = await poll(r)
    assert all(snap.available.values())
    assert r.conn.current is gen2
    await stop(r)


# --- discovery -------------------------------------------------------------------------------


async def test_no_valves_retry_schedule() -> None:
    r = e2e_rig(n_valves=0)
    await r.clock.run_task(r.conn.start())
    await run_until(r.clock, lambda: len(run_times(r)) >= 5, limit=2 * 86_400)
    delays = [nxt - last for last, nxt, _ in run_times(r)[:5]]
    assert delays == pytest.approx([*DISCOVERY_RETRY_DELAYS, TOPOLOGY_REFRESH, TOPOLOGY_REFRESH])
    snap = await poll(r)
    assert snap.valves == {}
    assert r.conn.stats.rejoins == 0  # an empty valve set never triggers the silent rejoin
    await stop(r)


async def test_partial_discovery_retry_finds_rest() -> None:
    router_short: list[int] = []

    def setup(inst: Installation) -> None:
        short = next(x.short for x in inst.network.routers if x.eui != inst.zdd_eui)
        router_short.append(short)
        inst.network.router_timeout = frozenset({short})  # its Mgmt_Lqi never answers

    r = e2e_rig(n_valves=3, behind_router=1, setup=setup)
    await begin(r)
    hidden = r.inst.valves[-1]
    snap = r.snap()
    assert set(snap.valves) == {v.eui for v in r.inst.valves[:-1]}
    assert snap.discovery.complete is False
    assert snap.discovery.last_run is not None
    assert snap.discovery.next_retry == snap.discovery.last_run + DISCOVERY_RETRY_DELAYS[0]
    r.inst.network.router_timeout = frozenset()  # the router answers again
    await run_until(r.clock, lambda: hidden.eui in r.snap().valves, limit=2 * 3600)
    assert [v.eui for v in r.new_valves][-1] == hidden.eui
    await run_until(r.clock, lambda: not r.core.discovery.running)
    final = r.snap().discovery
    assert final.complete is True
    assert final.last_run is not None
    assert final.next_retry == final.last_run + TOPOLOGY_REFRESH
    assert final.topology is not None
    assert final.topology.parent_of[hidden.eui] == router_short[0]
    await stop(r)


async def test_new_valve_paired_later() -> None:
    r = e2e_rig()
    await begin(r)
    new = SimValve(r.clock, eui=NEW_EUI, short=0x2B2B, rng=random.Random(7))  # noqa: S311
    r.inst.network.add_valve_later(new, parent=COORDINATOR)
    await run_until(r.clock, lambda: NEW_EUI in r.snap().valves)
    assert [v.eui for v in r.new_valves][-1] == NEW_EUI
    assert r.snap().valves[NEW_EUI].short == 0x2B2B
    assert 0x2B2B in r.conn.node_config.avoid_shorts
    await run_until(r.clock, lambda: not r.core.discovery.running)
    snap = await poll(r)
    assert snap.available[NEW_EUI] is True
    assert snap.states[NEW_EUI].updated_at is not None
    await stop(r)


# --- routing and addressing ------------------------------------------------------------------


async def test_network_status_route_error() -> None:
    r = e2e_rig()
    gen = await begin(r)
    valve = r.inst.valves[0]
    stats = gen.node.stats
    mtorrs = stats.mtorr_sent
    network = r.inst.network
    polling = asyncio.ensure_future(r.bridge.poll())
    await r.clock.advance(1.0)  # the reads are in flight (sleepy valves answer in >= 7 s)
    for _ in range(2):  # two route failures within the rate limit: one MTORR
        network._status_later(
            gen.join.own_short, NWK_STATUS_NON_TREE_LINK_FAILURE, about=valve.short
        )
        await r.clock.advance(0)
    snap = await r.clock.run_task(polling)
    assert snap.misses[valve.eui] == 1  # RouteError ends the request: a miss, not a hang
    assert snap.misses[r.inst.valves[1].eui] == 0
    assert stats.network_status == 2
    assert stats.mtorr_sent == mtorrs + 1
    assert r.conn.current is gen
    snap = await poll(r)  # retried on the next cycle
    assert snap.misses[valve.eui] == 0
    await r.clock.advance(MTORR_ON_ROUTE_FAILURE_INTERVAL)
    network._status_later(gen.join.own_short, NWK_STATUS_NON_TREE_LINK_FAILURE, about=valve.short)
    await r.clock.advance(0)
    assert stats.mtorr_sent == mtorrs + 2  # the limit window passed
    await stop(r)


async def test_tc_assigns_other_short_persisted() -> None:
    r = e2e_rig(setup=lambda inst: setattr(inst.network, "assign_short", ASSIGNED_SHORT))
    gen1 = await begin(r)
    assert gen1.join.own_short == ASSIGNED_SHORT
    assert gen1.join.requested_short != ASSIGNED_SHORT
    assert r.snap().own_short == ASSIGNED_SHORT
    assert r.caches
    assert r.caches[-1].own_short == ASSIGNED_SHORT  # persisted
    assert all_available(r)
    # a restart from that cache asks for the adopted short first
    r.inst.network.assign_short = None
    r2 = e2e_rig(cache=r.bridge.export_cache())
    await stop(r)
    gen = await begin(r2)
    assert gen.join.requested_short == ASSIGNED_SHORT
    assert gen.join.own_short == ASSIGNED_SHORT
    await stop(r2)


async def test_invalid_assigned_short_backs_off() -> None:
    r = e2e_rig(setup=lambda inst: setattr(inst.network, "assign_short", INVALID_SHORT))
    states = track_states(r)
    on_attempt(r, {2: lambda: setattr(r.inst.network, "assign_short", None)})
    gen = await begin(r)
    assert states[:4] == [S.CONNECTING, S.JOINING, S.BACKOFF, S.CONNECTING]
    assert r.conn.stats.last_failure == "join"
    assert r.conn.stats.attempts == 2
    assert gen.join.own_short != INVALID_SHORT
    assert all_available(r)
    await stop(r)


async def test_address_conflict_fresh_short() -> None:
    r = e2e_rig()
    gen1 = await begin(r)
    old = gen1.join.own_short
    assert r.caches[-1].own_short == old
    r.inst.network.address_conflict()
    gen2 = await ready_again(r, gen1.number)
    assert r.conn.stats.address_conflicts == 1
    assert gen2.join.own_short != old
    assert gen2.join.requested_short != old
    assert old in r.conn.node_config.avoid_shorts
    assert r.snap().own_short == gen2.join.own_short
    assert r.caches[-1].own_short == gen2.join.own_short
    await run_until(r.clock, lambda: settled(r) and r.core.polls >= 2)
    assert all_available(r)
    await stop(r)


async def test_valve_short_changed_by_annce() -> None:
    r = e2e_rig()
    await begin(r)
    valve = r.inst.valves[0]
    r.inst.network.valve_rejoin(valve, 0x4C4C)
    await r.clock.advance(0)
    assert r.snap().valves[valve.eui].short == 0x4C4C
    mark = len(r.inst.network.received)
    snap = await poll(r)
    assert snap.misses[valve.eui] == 0
    assert {dst for dst, _ in zcl_requests(r, mark)} == {0x4C4C, r.inst.valves[1].short}
    await stop(r)


async def test_valve_short_changed_by_walk() -> None:
    r = e2e_rig()
    await begin(r)
    valve = r.inst.valves[0]
    valve.set_short(0x4D4D)  # silently: the announcement was missed
    for _ in range(MISSES_UNAVAILABLE):
        snap = await poll(r)
    assert snap.available[valve.eui] is False
    await run_until(r.clock, lambda: r.snap().valves[valve.eui].short == 0x4D4D)
    await run_until(r.clock, lambda: not r.core.walking)
    snap = await poll(r)
    assert snap.available[valve.eui] is True
    await stop(r)


async def test_invalid_values_and_limits() -> None:
    def setup(inst: Installation) -> None:
        a, b = inst.valves
        a.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_LOCAL_TEMPERATURE, ZclDataType.INT16, -0x8000)
        a.set_attribute(vt.CL_POWER, 0x0021, ZclDataType.UINT8, 0xFF)
        a.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MIN_LIMIT, ZclDataType.INT16, 3000)
        a.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, ZclDataType.INT16, 800)
        for valve in (b,):
            valve.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MIN_LIMIT, ZclDataType.INT16, 3000)
            valve.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, ZclDataType.INT16, 800)
            valve.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_ABS_MIN, ZclDataType.INT16, 3500)
            valve.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_ABS_MAX, ZclDataType.INT16, 500)

    r = e2e_rig(setup=setup)
    await begin(r)
    for _ in range(valves.SLOW_EVERY_N_POLLS):  # the battery is in the SLOW plan
        snap = await poll(r)
    a, b = r.inst.valves
    state = snap.states[a.eui]
    assert state.local_temperature_c is None  # sentinel: unknown
    assert state.battery_pct is None
    assert state.setpoint_c == 22.0  # the other fields are still read
    assert snap.valves[a.eui].limits.source == "abs"
    assert snap.valves[b.eui].limits == valves.DEFAULT_LIMITS
    assert all(snap.available.values())  # invalid values are still responses
    await stop(r)


# --- setpoints -------------------------------------------------------------------------------


async def test_concurrent_setpoints_newest_wins() -> None:
    r = e2e_rig(n_valves=1, setup=hardware_latency)
    await begin(r)
    eui = r.euis()[0]
    mark = len(r.updates)
    tasks = []
    for celsius in (20.0, 23.0):
        tasks.append(asyncio.ensure_future(r.bridge.set_setpoint(eui, celsius)))
        await r.clock.advance(0)
    await run_until(r.clock, lambda: all(t.done() for t in tasks) and not status(r, eui).pending)
    results = [t.result() for t in tasks]
    assert results[-1].acknowledged_c == 23.0  # the older call returned at its ack, no error
    final = status(r, eui)
    assert (final.version, final.requested_c, final.confirmed_c) == (2, 23.0, 23.0)
    assert r.inst.r0.max_writes_in_flight == 1
    writes = [w for _, w in zcl_requests(r) if isinstance(w, tuple)]
    assert writes == [(vt.CL_THERMOSTAT, 2000), (vt.CL_THERMOSTAT, 2300)]
    # no false revert: once version 2 was requested, the UI never showed an older target
    seen = [snap.setpoints[eui] for _, snap in r.updates[mark:]]
    newest = [sp for sp in seen if sp.version == 2]
    assert newest
    assert all(sp.requested_c == 23.0 for sp in newest)
    assert r.snap().states[eui].setpoint_c == 23.0
    await stop(r)


async def test_confirm_timeout_unconfirmed() -> None:
    def drop_after_ack(rig: BRig, snap: BridgeSnapshot) -> None:
        valve = rig.inst.valves[0]
        if snap.setpoints.get(valve.eui, SetpointStatus()).acknowledged_c is not None:
            valve.drop_rate = 1.0  # the confirming read gets no answer

    r = e2e_rig(n_valves=1, on_update=drop_after_ack)
    await begin(r)
    eui = r.euis()[0]
    before = r.snap().states[eui].setpoint_c
    result = await r.clock.run_task(r.bridge.set_setpoint(eui, 21.5))
    assert result.acknowledged_c == 21.5
    acked_at = r.clock.now()
    await run_until(r.clock, lambda: not status(r, eui).pending)
    assert r.clock.now() - acked_at <= 90.0  # inside the total deadline
    st = status(r, eui)
    assert (st.acknowledged_c, st.confirmed_c, st.confirmed_at) == (21.5, None, None)
    assert r.snap().states[eui].setpoint_c == before  # never reported as confirmed
    assert not r.core.tx[eui].lock.locked()
    await stop(r)


async def test_late_and_duplicate_responses() -> None:
    def setup(inst: Installation) -> None:
        slow = SimValve(
            inst.clock,
            eui=SLOW_EUI,
            short=0x5005,
            rng=random.Random(4),  # noqa: S311
            poll_interval=0.0,
            latency=(35.0, 35.0),  # after the first 30 s attempt: a retransmit is sent
            duplicate_rate=1.0,  # ... and both copies are answered
        )
        inst.network.add_valve(slow, parent=COORDINATOR)

    r = e2e_rig(n_valves=0, setup=setup)
    gen = await begin(r)
    stats = gen.node.stats
    drops = stats.late_drops
    snap = await poll(r)
    assert snap.available[SLOW_EUI] is True
    await r.clock.advance(60)  # the duplicate answer to the retransmit arrives late
    assert stats.late_drops > drops
    assert stats.unmatched == 0
    assert r.snap().misses[SLOW_EUI] == 0
    await stop(r)
