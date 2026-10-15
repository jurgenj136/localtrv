"""ViCareBridge: one EUI per short, and announcement identification retries (review round 2).

P1: valve A moved to a new short without its Device_annce reaching us; valve B announced and
was identified at A's old short. A's mapping must be dropped: no setpoint write or poll read for
A may go to B's short, and B's answers are never A's.

P2: an unknown sender whose identification failed is identified again on its next announcement
(bounded by ``ANNCE_IDENTIFY_RETRY``), not only at the 6 h topology refresh.
"""

from __future__ import annotations

import asyncio
import dataclasses
import random

import pytest

from test_bridge import NEW_EUI, BRig, discovered, make_rig, poll, run_until, stop, zcl_requests
from vicare_local_ble import bridge_poll, valves
from vicare_local_ble.bridge_types import ANNCE_IDENTIFY_DEBOUNCE, MISSES_UNAVAILABLE
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.errors import RouteError
from vicare_local_ble.zigbee_direct.types import Eui64

MOVED_TO = 0x5A5A
ANNCE_RETRY_EUI = Eui64.from_str("02:00:00:00:00:01:00:40")


async def b_takes_a_short(r: BRig) -> tuple[Eui64, int, SimValve]:
    """A moves silently; B announces at A's old short and gets identified there."""
    sim_a = r.inst.valves[0]
    old = r.snap().valves[sim_a.eui].short
    sim_a.set_short(MOVED_TO)  # rejoined elsewhere; its Device_annce never reached us
    sim_b = SimValve(r.clock, eui=NEW_EUI, short=old, rng=random.Random(11))  # noqa: S311
    sim_b.set_attribute(vt.CL_THERMOSTAT, 0x0000, ZclDataType.INT16, 3333)
    r.inst.network.add_valve_later(sim_b)
    await run_until(r.clock, lambda: NEW_EUI in r.snap().valves)
    await r.clock.run_until_idle()
    assert r.snap().valves[NEW_EUI].short == old
    return sim_a.eui, old, sim_b


async def test_setpoint_for_a_valve_whose_short_was_taken_fails_without_a_write() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui_a, old, sim_b = await b_takes_a_short(r)
    mark = len(r.inst.network.received)
    with pytest.raises(RouteError):
        await r.clock.run_task(r.bridge.set_setpoint(eui_a, 25.0))
    assert [req for _, req in zcl_requests(r, mark, dst=old) if isinstance(req, tuple)] == []
    assert sim_b.writes == ()
    status = r.snap().setpoints[eui_a]
    assert (status.pending, status.requested_c, status.acknowledged_c) == (False, None, None)
    assert r.core.eui_for_short(old) == NEW_EUI
    await stop(r)


async def test_poll_does_not_read_another_valves_short() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui_a, old, _ = await b_takes_a_short(r)
    before = r.snap().states[eui_a]
    for _ in range(MISSES_UNAVAILABLE):
        mark = len(r.inst.network.received)
        await poll(r)
        reads = [req for _, req in zcl_requests(r, mark, dst=old)]
        assert reads.count(valves.FAST[0]) == 1  # B's read only, none for A
        assert r.snap().states[eui_a] == before  # B's 33.33 °C never lands on A
    assert r.snap().states[NEW_EUI].local_temperature_c == 33.33
    assert r.snap().misses[eui_a] == MISSES_UNAVAILABLE
    assert r.snap().available[eui_a] is False
    assert r.snap().available[NEW_EUI] is True
    # The re-walk spawned at the third miss finds A at its new short: A is back.
    await run_until(r.clock, lambda: not r.core.walking)
    assert r.snap().valves[eui_a].short == MOVED_TO
    await poll(r)
    assert r.snap().available[eui_a] is True
    await stop(r)


async def test_announced_short_moves_ownership_to_the_announcer() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    sim_a, sim_b = r.inst.valves
    short_a = r.snap().valves[sim_a.eui].short
    sim_a.set_short(MOVED_TO)  # silent move
    r.inst.network.valve_rejoin(sim_b, short_a)  # B (known) announces at A's old short
    await r.clock.advance(0)
    assert r.core.eui_for_short(short_a) == sim_b.eui
    mark = len(r.inst.network.received)
    with pytest.raises(RouteError):
        await r.clock.run_task(r.bridge.set_setpoint(sim_a.eui, 25.0))
    assert [req for _, req in zcl_requests(r, mark) if isinstance(req, tuple)] == []
    r.inst.network.valve_rejoin(sim_a, MOVED_TO + 1)  # A's own annce re-establishes it
    await r.clock.advance(0)
    status = await r.clock.run_task(r.bridge.set_setpoint(sim_a.eui, 25.0))
    assert status.acknowledged_c == 25.0
    assert [to for to, req in zcl_requests(r, mark) if isinstance(req, tuple)] == [MOVED_TO + 1]
    await stop(r)


async def test_cached_duplicate_shorts_are_not_trusted() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    cache = r.bridge.export_cache()
    await stop(r)
    a, b = cache.valves.values()
    dup = dataclasses.replace(
        cache, valves={a.eui: a, b.eui: dataclasses.replace(b, short=a.short)}
    )
    r2 = make_rig(n_valves=2, behind_router=0, cache=dup)
    assert r2.core.unaddressed == {Eui64.from_str(a.eui), Eui64.from_str(b.eui)}
    assert r2.core.eui_for_short(a.short) is None
    await discovered(r2)  # the discovery walk re-learns both
    assert r2.core.unaddressed == set()
    assert all(r2.snap().available.values())
    await stop(r2)


async def test_walk_does_not_steal_a_fresher_announced_short() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    sim_a, sim_b = r.inst.valves
    topology = r.core.topology
    assert topology is not None
    short_a = topology.neighbors[sim_a.eui].nwk_addr
    started = r.clock.now()
    await r.clock.advance(1)
    sim_a.set_short(MOVED_TO)
    r.inst.network.valve_rejoin(sim_b, short_a)  # fresher than the walk below
    await r.clock.advance(0)
    r.core.set_topology(topology, started=started)  # began before B's annce, lists A at it
    assert r.core.eui_for_short(short_a) == sim_b.eui  # the stale walk entry for A lost
    assert sim_a.eui in r.core.unaddressed
    await stop(r)


async def test_failed_annce_identification_retries_on_the_next_annce() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    net = r.inst.network
    sim = SimValve(r.clock, eui=ANNCE_RETRY_EUI, short=0x3000, rng=random.Random(3), drop_rate=1.0)  # noqa: S311
    mark = len(net.received)
    net.add_valve_later(sim)
    await r.clock.advance(ANNCE_IDENTIFY_DEBOUNCE + 70)  # one Basic read timing out
    assert ANNCE_RETRY_EUI not in r.snap().valves
    sim.drop_rate = 0.0  # recovered
    net.valve_rejoin(sim, 0x3001)
    await run_until(r.clock, lambda: ANNCE_RETRY_EUI in r.snap().valves, limit=900)
    assert r.snap().valves[ANNCE_RETRY_EUI].short == 0x3001
    basic = [to for to, req in zcl_requests(r, mark) if req == valves.IDENTIFY]
    assert basic[0] == 0x3000
    assert basic[-1] == 0x3001
    await stop(r)


async def test_answers_from_a_short_that_changed_owner_in_flight_are_not_accepted() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    sim_a, sim_b = r.inst.valves
    short_a = r.snap().valves[sim_a.eui].short
    mark = len(r.inst.network.received)
    task = asyncio.ensure_future(r.bridge.set_setpoint(sim_a.eui, 25.0))
    await run_until(r.clock, lambda: any(isinstance(q, tuple) for _, q in zcl_requests(r, mark)))
    assert not task.done()
    r.core.set_short(sim_b.eui, short_a)  # B learned at A's short while the write is in flight
    await run_until(r.clock, task.done)
    with pytest.raises(RouteError):
        task.result()
    assert r.snap().setpoints[sim_a.eui].acknowledged_c is None
    # Same for a read: the answer is dropped and counts as no response.
    gen = r.conn.current
    assert gen is not None
    r.core.set_short(sim_a.eui, short_a)  # A back at it (B unaddressed now)
    read = asyncio.ensure_future(bridge_poll.read(r.core, gen, sim_a.eui, valves.FAST[0]))
    await r.clock.advance(0)
    r.core.set_short(sim_b.eui, short_a)
    await run_until(r.clock, read.done)
    with pytest.raises(RouteError):
        read.result()
    await stop(r)
