"""ViCareBridge: announcements are address evidence on their own (review round 3).

1. A different EUI announcing at a known valve's short takes that short from the valve at once:
   during the identification debounce, after a failed identification, and when the announcer
   is ignored. A frame with an explicit source IEEE counts the same.
2. An identification whose short another EUI was seen at after it started is discarded
   (round 4: not added, not ignored; the valve's own next announcement identifies it).
"""

from __future__ import annotations

import random

import pytest

from localtrv import valves
from localtrv.bridge_types import ANNCE_IDENTIFY_DEBOUNCE
from localtrv.testing.valve import SimValve
from localtrv.zigbee_direct.errors import RouteError
from test_bridge import (
    ACME_EUI,
    NEW_EUI,
    BRig,
    add_acme,
    discovered,
    make_rig,
    run_until,
    stop,
    zcl_requests,
)
from test_bridge_identity import temperature_report

MOVED_TO = 0x5A5A


def writes_to(r: BRig, mark: int, dst: int) -> list[object]:
    return [req for _, req in zcl_requests(r, mark, dst=dst) if isinstance(req, tuple)]


def a_moves_silently(r: BRig) -> tuple[SimValve, int]:
    sim_a = r.inst.valves[0]
    old = r.snap().valves[sim_a.eui].short
    sim_a.set_short(MOVED_TO)  # rejoined elsewhere; its Device_annce never reached us
    return sim_a, old


async def assert_write_refused(r: BRig, sim_a: SimValve, old: int) -> None:
    mark = len(r.inst.network.received)
    with pytest.raises(RouteError):
        await r.clock.run_task(r.bridge.set_setpoint(sim_a.eui, 25.0))
    assert writes_to(r, mark, old) == []
    status = r.snap().setpoints[sim_a.eui]
    assert (status.pending, status.acknowledged_c) == (False, None)
    assert r.core.eui_for_short(old) is None


async def test_unknown_announcer_takes_the_short_during_the_debounce() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    sim_a, old = a_moves_silently(r)
    sim_b = SimValve(r.clock, eui=NEW_EUI, short=old, rng=random.Random(11))  # noqa: S311
    t0 = r.clock.now()
    r.inst.network.add_valve_later(sim_b)
    await r.clock.advance(1)
    assert NEW_EUI not in r.snap().valves  # still debouncing
    await assert_write_refused(r, sim_a, old)
    assert r.clock.now() < t0 + ANNCE_IDENTIFY_DEBOUNCE  # refused inside the debounce
    assert sim_b.writes == ()
    await stop(r)


async def test_announcer_with_failed_identification_still_takes_the_short() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    sim_a, old = a_moves_silently(r)
    sim_b = SimValve(r.clock, eui=NEW_EUI, short=old, rng=random.Random(11), drop_rate=1.0)  # noqa: S311
    r.inst.network.add_valve_later(sim_b)
    await r.clock.advance(ANNCE_IDENTIFY_DEBOUNCE + 70)  # the Basic read timed out
    assert NEW_EUI not in r.snap().valves
    assert NEW_EUI not in r.core.annce_seen  # identification over (failed)
    await assert_write_refused(r, sim_a, old)
    await stop(r)


async def test_ignored_announcer_still_takes_the_short() -> None:
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    await discovered(r)
    assert str(ACME_EUI) in r.core.ignored
    sim_a, old = a_moves_silently(r)
    acme = next(v for v in r.inst.network.valves if v.eui == ACME_EUI)
    r.inst.network.valve_rejoin(acme, old)
    await r.clock.advance(0)
    await assert_write_refused(r, sim_a, old)
    await stop(r)


async def test_frame_with_unknown_or_ignored_ieee_takes_the_short() -> None:
    r = make_rig(n_valves=2, behind_router=0, setup=add_acme)
    gen = await discovered(r)
    sim_a, sim_c = r.inst.valves
    old = r.snap().valves[sim_a.eui].short
    before = r.snap().states[sim_a.eui]
    r.bridge._on_report(gen, temperature_report(old, NEW_EUI, 1234))
    assert sim_a.eui in r.core.unaddressed
    r.bridge._on_report(gen, temperature_report(old, None, 1500))  # by short: nobody's now
    assert r.snap().states[sim_a.eui] == before
    short_c = r.snap().valves[sim_c.eui].short
    r.bridge._on_report(gen, temperature_report(short_c, ACME_EUI, 1234))  # ignored sender
    assert sim_c.eui in r.core.unaddressed
    await stop(r)


async def test_frame_with_known_ieee_at_another_short_moves_the_valve() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    gen = await discovered(r)
    sim_a, sim_b = r.inst.valves
    short_a = r.snap().valves[sim_a.eui].short
    sim_a.set_short(MOVED_TO)
    r.bridge._on_report(gen, temperature_report(short_a, sim_b.eui, 1234))  # B is at short_a
    assert r.snap().valves[sim_b.eui].short == short_a
    assert sim_a.eui in r.core.unaddressed
    assert short_a in r.conn.node_config.avoid_shorts
    await stop(r)


async def test_stale_identification_does_not_take_a_newer_owners_short() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    net = r.inst.network
    sim_b = r.inst.valves[0]
    sim_a = SimValve(r.clock, eui=NEW_EUI, short=0x3000, rng=random.Random(9))  # noqa: S311
    mark = len(net.received)
    net.add_valve_later(sim_a)

    def limits_read_started() -> bool:
        reqs = [req for to, req in zcl_requests(r, mark) if to == 0x3000]
        return valves.IDENTIFY in reqs and any(req != valves.IDENTIFY for req in reqs)

    await run_until(r.clock, limits_read_started)
    assert NEW_EUI not in r.snap().valves
    sim_a.set_short(0x3100)  # A moves silently while being identified
    net.valve_rejoin(sim_b, 0x3000)  # known B announces at A's old short
    await r.clock.advance(0)
    assert r.core.eui_for_short(0x3000) == sim_b.eui
    await run_until(r.clock, lambda: NEW_EUI not in r.core.annce_seen)
    assert NEW_EUI not in r.snap().valves  # the stale result is discarded, not added
    assert str(NEW_EUI) not in r.core.ignored
    assert r.core.eui_for_short(0x3000) == sim_b.eui  # B keeps it
    status = await r.clock.run_task(r.bridge.set_setpoint(sim_b.eui, 22.0))
    assert status.acknowledged_c == 22.0
    net.valve_rejoin(sim_a, 0x3101)  # A's own announcement identifies it
    await run_until(r.clock, lambda: NEW_EUI in r.snap().valves, limit=900)
    assert r.snap().valves[NEW_EUI].short == 0x3101
    assert r.core.eui_for_short(0x3000) == sim_b.eui
    await stop(r)
