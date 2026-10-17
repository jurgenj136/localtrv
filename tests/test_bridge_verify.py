"""ViCareBridge: walk results are hints, setpoints are verified (review round 5).

Only authoritative evidence (Device_annce, a NWK header source IEEE, an IEEE_addr response)
moves or evicts ownership. A walk listing a known valve elsewhere, or an unaddressed valve, is
verified with IEEE_addr_req before anything is adopted. Every setpoint write is preceded by an
IEEE_addr_req to the valve's short.
"""

from __future__ import annotations

import asyncio
import dataclasses
import random
from typing import TYPE_CHECKING

import pytest

from localtrv import bridge_discovery, valves
from localtrv.bridge_verify import adopt_walk
from localtrv.testing.valve import SimValve
from localtrv.zigbee_direct.codec.zdo import ZdoCluster
from localtrv.zigbee_direct.errors import RouteError
from test_bridge import (
    ACME_EUI,
    NEW_EUI,
    BRig,
    add_acme,
    discovered,
    make_rig,
    poll,
    run_until,
    stop,
    zcl_requests,
    zdo_requests,
)

if TYPE_CHECKING:
    from localtrv.testing.scenario import Installation
    from localtrv.zigbee_direct.types import Eui64

MOVED_TO = 0x5A5A


def writes_to(r: BRig, mark: int, dst: int) -> list[object]:
    return [req for _, req in zcl_requests(r, mark, dst=dst) if isinstance(req, tuple)]


def acme_of(r: BRig) -> SimValve:
    return next(v for v in r.inst.network.valves if v.eui == ACME_EUI)


def stale_walk(r: BRig, eui: Eui64, short: int) -> None:
    """Adopt the last walk with ``eui`` listed at ``short`` (a stale router table)."""
    topology = r.core.topology
    assert topology is not None
    neighbors = dict(topology.neighbors)
    neighbors[eui] = dataclasses.replace(neighbors[eui], nwk_addr=short)
    r.core.set_topology(dataclasses.replace(topology, neighbors=neighbors), started=r.clock.now())


# --- B/F: a stale walk never evicts or redirects -------------------------------------------


async def test_stale_walk_listing_acme_at_a_healthy_valves_short_evicts_nothing() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    await discovered(r)
    sim_a = r.inst.valves[0]
    short_a = r.snap().valves[sim_a.eui].short
    stale_walk(r, ACME_EUI, short_a)
    assert sim_a.eui not in r.core.unaddressed
    mark = len(r.inst.network.received)
    await poll(r)
    assert any(req == valves.FAST[0] for _, req in zcl_requests(r, mark, dst=short_a))
    assert r.snap().available[sim_a.eui] is True
    await stop(r)


async def test_stale_walk_listing_a_at_bs_short_redirects_nothing() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    gen = await discovered(r)
    sim_a, sim_b = r.inst.valves
    short_a = r.snap().valves[sim_a.eui].short
    short_b = r.snap().valves[sim_b.eui].short
    stale_walk(r, sim_a.eui, short_b)
    topology = r.core.topology
    assert topology is not None
    mark = len(r.inst.network.received)
    await r.clock.run_task(adopt_walk(r.core, gen, topology, started=r.clock.now()))
    assert zdo_requests(r, ZdoCluster.IEEE_ADDR_REQ, mark) == [short_b]  # the hint, once
    assert r.snap().valves[sim_a.eui].short == short_a  # B answered: A not moved
    assert sim_b.eui not in r.core.unaddressed
    assert r.core.eui_for_short(short_b) == sim_b.eui
    mark = len(r.inst.network.received)
    status = await r.clock.run_task(r.bridge.set_setpoint(sim_a.eui, 25.0))
    assert status.acknowledged_c == 25.0
    assert writes_to(r, mark, short_b) == []
    assert [to for to, req in zcl_requests(r, mark) if isinstance(req, tuple)] == [short_a]
    assert sim_b.writes == ()
    await stop(r)


async def test_walk_hint_is_adopted_only_after_ieee_confirmation() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    sim_a = r.inst.valves[0]
    sim_a.set_short(MOVED_TO)  # moved silently; the next walk lists it there
    mark = len(r.inst.network.received)
    await r.clock.run_task(bridge_discovery.discovery_run(r.core, gen))
    assert zdo_requests(r, ZdoCluster.IEEE_ADDR_REQ, mark) == [MOVED_TO]
    assert r.snap().valves[sim_a.eui].short == MOVED_TO
    await stop(r)


# --- C: every setpoint write is verified ------------------------------------------------------


async def test_setpoint_is_not_written_to_a_device_that_answers_with_another_ieee() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    await discovered(r)
    sim_a = r.inst.valves[0]
    short_a = r.snap().valves[sim_a.eui].short
    sim_a.set_short(MOVED_TO)
    acme_of(r).set_short(short_a)  # silently: no evidence at all reached the bridge
    mark = len(r.inst.network.received)
    with pytest.raises(RouteError):
        await r.clock.run_task(r.bridge.set_setpoint(sim_a.eui, 25.0))
    assert writes_to(r, mark, short_a) == []
    assert acme_of(r).writes == ()
    assert zdo_requests(r, ZdoCluster.IEEE_ADDR_REQ, mark) == [short_a]
    await stop(r)


# --- E: restored shorts are trusted for reads -------------------------------------------------


async def test_restored_short_is_polled_without_an_ieee_lookup() -> None:
    r = make_rig()
    await discovered(r)
    cache = r.bridge.export_cache()
    behind = r.inst.valves[-1].eui
    await stop(r)

    def setup(inst: Installation) -> None:
        router = next(x.short for x in inst.network.routers if x.eui != inst.zdd_eui)
        inst.network.router_timeout = frozenset({router})  # the walk misses the valve

    r2 = make_rig(cache=cache, setup=setup)
    await discovered(r2)
    assert r2.snap().available[behind] is True
    assert zdo_requests(r2, ZdoCluster.IEEE_ADDR_REQ) == []
    await stop(r2)


# --- G: identification holds an epoch lease ----------------------------------------------------


async def test_evidence_flipping_during_identification_discards_the_result() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    gen = await discovered(r)
    net = r.inst.network
    acme = acme_of(r)
    sim_a = SimValve(r.clock, eui=NEW_EUI, short=0x3000, rng=random.Random(9), drop_rate=1.0)  # noqa: S311
    mark = len(net.received)
    net.add_valve_later(sim_a)
    await run_until(
        r.clock, lambda: any(req == valves.IDENTIFY for _, req in zcl_requests(r, mark))
    )
    await r.clock.advance(1)  # the first Basic attempt is out, unanswered
    sim_a.set_short(0x3100)
    acme.set_short(0x3000)  # Acme now answers at A's old short
    bridge_discovery.on_address(r.core, gen, ACME_EUI, 0x3000, identify=False)
    bridge_discovery.on_address(r.core, gen, NEW_EUI, 0x3000, identify=False)  # flips back
    await run_until(r.clock, lambda: NEW_EUI not in r.core.annce_seen)
    await asyncio.sleep(0)
    assert str(NEW_EUI) not in r.core.ignored
    assert NEW_EUI not in r.snap().valves
    await stop(r)
