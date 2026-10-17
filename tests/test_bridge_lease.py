"""ViCareBridge: request leases on a valve's short (review round 4).

Invariant: no ZCL request meant for valve A is sent to a short unless A verifiably owns it at
that moment (every attempt), and no answer is credited to A unless A owned the short for the
whole request and an explicit NWK source IEEE, if any, is A's.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import random
from typing import TYPE_CHECKING

import pytest

from localtrv import bridge_discovery, bridge_poll, valves
from localtrv.testing import valve_table as vt
from localtrv.testing.valve import SimValve
from localtrv.zigbee_direct.codec.zcl_types import ZclDataType
from localtrv.zigbee_direct.discovery import walk_topology
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
    start,
    stop,
    zcl_requests,
)

if TYPE_CHECKING:
    from localtrv.testing.scenario import Installation

MOVED_TO = 0x5A5A


def writes_to(r: BRig, mark: int, dst: int) -> list[object]:
    return [req for _, req in zcl_requests(r, mark, dst=dst) if isinstance(req, tuple)]


def b_at(r: BRig, short: int, *, temp: int = 3333) -> SimValve:
    sim_b = SimValve(r.clock, eui=NEW_EUI, short=short, rng=random.Random(11))  # noqa: S311
    sim_b.set_attribute(vt.CL_THERMOSTAT, 0x0000, ZclDataType.INT16, temp)
    return sim_b


# --- 1: retransmits re-check ownership --------------------------------------------------------


async def test_write_retransmit_is_not_sent_to_the_replacement_device() -> None:
    armed: list[float] = []

    def drop_after_verification(rig: BRig, _snap: object) -> None:
        # The IEEE_addr answer is recorded just before the write is queued: from then on the
        # valve drops everything, so the first write gets no answer.
        if armed and rig.core.short_seen.get(old, (None, -1.0))[1] > armed[0]:
            rig.inst.valves[0].drop_rate = 1.0

    r = make_rig(n_valves=1, behind_router=0, on_update=drop_after_verification)
    await discovered(r)
    sim_a = r.inst.valves[0]
    old = r.snap().valves[sim_a.eui].short
    armed.append(r.clock.now())
    mark = len(r.inst.network.received)
    task = asyncio.ensure_future(r.bridge.set_setpoint(sim_a.eui, 25.0))
    await run_until(r.clock, lambda: writes_to(r, mark, old) != [])
    sim_a.set_short(MOVED_TO)  # A moves silently; B announces at its old short
    sim_b = b_at(r, old)
    r.inst.network.add_valve_later(sim_b)
    await run_until(r.clock, task.done)
    with pytest.raises(RouteError):
        task.result()
    assert sim_b.writes == ()  # no retransmit reached B
    await stop(r)


# --- 2: a restored short is trusted for reads; a write to it is verified first (round 5) ---


async def test_restart_does_not_trust_an_invalidated_short() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    await discovered(r)
    sim_a = r.inst.valves[0]
    old = r.snap().valves[sim_a.eui].short
    acme = next(v for v in r.inst.network.valves if v.eui == ACME_EUI)
    sim_a.set_short(MOVED_TO)
    r.inst.network.valve_rejoin(acme, old)  # ignored B takes A's short
    await r.clock.advance(0)
    assert sim_a.eui in r.core.unaddressed
    cache = r.bridge.export_cache()
    await stop(r)

    def setup(inst: Installation) -> None:  # the same network after the restart
        add_acme(inst)
        inst.valves[0].set_short(MOVED_TO)
        next(v for v in inst.network.valves if v.eui == ACME_EUI).set_short(old)

    r2 = make_rig(n_valves=1, behind_router=0, cache=cache, setup=setup)
    await start(r2)  # READY; the discovery walk has not finished
    mark = len(r2.inst.network.received)
    with contextlib.suppress(RouteError):  # refused if the short is not verified in time
        await r2.clock.run_task(r2.bridge.set_setpoint(sim_a.eui, 25.0))
    acme2 = next(v for v in r2.inst.network.valves if v.eui == ACME_EUI)
    assert writes_to(r2, mark, old) == []
    assert acme2.writes == ()
    assert {to for to, _ in zcl_requests(r2, mark) if to != old} <= {MOVED_TO}
    await stop(r2)


# --- 3: a walk is a hint only (round 5): stale entries evict nothing ---------------------


async def test_walk_evidence_older_than_an_announcement_is_ignored() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    gen = await discovered(r)
    sim_a = r.inst.valves[0]
    a_short = r.snap().valves[sim_a.eui].short
    acme = next(v for v in r.inst.network.valves if v.eui == ACME_EUI)
    started = r.clock.now()
    walked = await r.clock.run_task(walk_topology(gen.node))
    stale = dict(walked.neighbors)
    stale[ACME_EUI] = dataclasses.replace(stale[ACME_EUI], nwk_addr=a_short)  # stale entry
    r.inst.network.valve_rejoin(sim_a, a_short + 1)
    r.inst.network.valve_rejoin(sim_a, a_short)  # A re-announced after the walk began
    await r.clock.advance(0)
    r.core.set_topology(dataclasses.replace(walked, neighbors=stale), started=started)
    assert sim_a.eui not in r.core.unaddressed
    assert acme.short != a_short
    await stop(r)


# --- 4: a response naming another sender resolves nothing --------------------------------------


async def test_response_with_another_source_ieee_is_not_credited() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    sim_a = r.inst.valves[0]
    old = r.snap().valves[sim_a.eui].short
    before = r.snap().states[sim_a.eui]
    sim_a.set_short(MOVED_TO)
    r.inst.network.add_valve(b_at(r, old))  # B silently at A's short, never announced
    r.inst.network.reply_src_ieee[old] = NEW_EUI  # B's frames name B in the NWK header
    await poll(r)
    assert r.snap().states[sim_a.eui] == before  # B's 33.33 °C never lands on A
    assert sim_a.eui in r.core.unaddressed
    assert r.core.short_seen[old][0] == NEW_EUI
    await stop(r)


# --- 5: ownership over the request's lifetime -------------------------------------------------


async def test_answer_from_a_short_stolen_and_then_left_is_not_credited() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    sim_a = r.inst.valves[0]
    old = r.snap().valves[sim_a.eui].short
    mark = len(r.inst.network.received)
    read = asyncio.ensure_future(bridge_poll.read(r.core, gen, sim_a.eui, valves.FAST[0]))
    await run_until(r.clock, lambda: zcl_requests(r, mark) != [])
    assert not read.done()
    bridge_discovery.on_address(r.core, gen, NEW_EUI, old)  # unknown B claims S
    r.core.set_short(sim_a.eui, MOVED_TO)  # A announced a new short S2
    assert sim_a.eui not in r.core.unaddressed
    await run_until(r.clock, read.done)
    with pytest.raises(RouteError):
        read.result()
    await stop(r)


# --- 6: a stale identification never ignores a real valve -------------------------------------


async def test_stale_identification_does_not_ignore_a_real_valve() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    await discovered(r)
    net = r.inst.network
    acme = next(v for v in net.valves if v.eui == ACME_EUI)
    sim_a = SimValve(r.clock, eui=NEW_EUI, short=0x3000, rng=random.Random(9))  # noqa: S311
    net.add_valve_later(sim_a)
    await r.clock.advance(1)  # debouncing
    sim_a.set_short(0x3100)  # A moves silently
    net.valve_rejoin(acme, 0x3000)  # Acme announces at A's old short
    await r.clock.advance(60)
    assert str(NEW_EUI) not in r.core.ignored
    net.valve_rejoin(sim_a, 0x3101)  # A's correct announcement
    await run_until(r.clock, lambda: NEW_EUI in r.snap().valves, limit=900)
    assert r.snap().valves[NEW_EUI].short == 0x3101
    await stop(r)


async def test_identification_answer_naming_another_sender_is_discarded() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    await discovered(r)
    net = r.inst.network
    acme = next(v for v in net.valves if v.eui == ACME_EUI)
    sim_a = SimValve(r.clock, eui=NEW_EUI, short=0x3000, rng=random.Random(9))  # noqa: S311
    net.add_valve_later(sim_a)
    await r.clock.advance(1)
    sim_a.set_short(0x3100)
    acme.set_short(0x3000)  # silently; its answers name it in the NWK header
    net.reply_src_ieee[0x3000] = ACME_EUI
    await r.clock.advance(120)
    assert str(NEW_EUI) not in r.core.ignored
    assert NEW_EUI not in r.snap().valves
    await stop(r)


async def test_restored_short_missing_from_the_walk_is_verified_by_ieee_lookup() -> None:
    r = make_rig()
    await discovered(r)
    cache = r.bridge.export_cache()
    behind = r.inst.valves[-1].eui
    await stop(r)

    def setup(inst: Installation) -> None:
        router = next(x.short for x in inst.network.routers if x.eui != inst.zdd_eui)
        inst.network.router_timeout = frozenset({router})  # the walk misses the valve behind it

    r2 = make_rig(cache=cache, setup=setup)
    await discovered(r2)
    assert r2.snap().discovery.topology is not None
    assert behind not in r2.core.topology.neighbors  # type: ignore[union-attr]
    assert r2.core.unaddressed == set()  # IEEE_addr_req answered with its own IEEE
    assert r2.snap().available[behind] is True
    await stop(r2)
