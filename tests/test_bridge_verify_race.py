"""IEEE verification races and logging (review round 6).

P1: the IEEE_addr reply resolves, then another device's announcement is processed before the
waiting coroutine resumes. The older reply must not overwrite the newer evidence, and the
setpoint's write lease chains from the verification (no fresh lease after it).
P3: a verification cut short by the ack deadline still logs why at DEBUG.
"""

from __future__ import annotations

import logging
import random

import pytest

from localtrv import bridge_discovery
from localtrv.testing.valve import SimValve
from localtrv.zigbee_direct.errors import RouteError
from test_bridge import NEW_EUI, discovered, make_rig, stop, zcl_requests

MOVED_TO = 0x5A5A


async def test_reply_overtaken_by_an_announcement_does_not_restore_the_old_owner() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    sim_a = r.inst.valves[0]
    short = r.snap().valves[sim_a.eui].short
    sim_b = SimValve(r.clock, eui=NEW_EUI, short=MOVED_TO, rng=random.Random(11))  # noqa: S311
    r.inst.network.add_valve(sim_b)
    r.inst.network.reply_src_ieee[short] = sim_a.eui  # A's reply names A in its NWK header
    fired: list[int] = []

    def on_sender(src: int, ieee: object) -> None:
        # Runs while A's IEEE_addr reply is dispatched, before the verifying coroutine
        # resumes: A leaves, B takes the short and announces it.
        if fired or src != short or ieee != sim_a.eui:
            return
        fired.append(src)
        sim_a.set_short(MOVED_TO + 1)
        sim_b.set_short(short)
        r.inst.network.reply_src_ieee.pop(short)
        bridge_discovery.on_address(r.core, gen, NEW_EUI, short)

    gen.node.on_sender(on_sender)
    mark = len(r.inst.network.received)
    with pytest.raises(RouteError):
        await r.clock.run_task(r.bridge.set_setpoint(sim_a.eui, 25.0))
    assert fired
    assert sim_b.writes == ()  # B never received 25 °C
    assert [q for _, q in zcl_requests(r, mark) if isinstance(q, tuple)] == []
    assert r.snap().setpoints[sim_a.eui].acknowledged_c is None
    assert r.core.eui_for_short(short) is None  # B is not a valve; A no longer owns it
    assert sim_a.eui in r.core.unaddressed
    await stop(r)


async def test_verification_cut_short_by_the_ack_deadline_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, "localtrv.bridge")
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    sim = r.inst.valves[0]
    short = r.snap().valves[sim.eui].short
    sim.drop_rate = 1.0
    with pytest.raises(TimeoutError):
        await r.clock.run_task(r.bridge.set_setpoint(sim.eui, 25.0))
    assert f"valve {sim.eui}: short 0x{short:04X} verification failed (interrupted" in caplog.text
    await stop(r)


async def test_reply_overtaken_by_the_valve_moving_elsewhere_is_not_adopted() -> None:
    # Review round 7: A's reply resolves at S; before the waiter resumes, a newer frame places
    # A at S2 and B silently takes S. Only S2 saw evidence, so a lease on S alone still held.
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    sim_a = r.inst.valves[0]
    short = r.snap().valves[sim_a.eui].short
    sim_b = SimValve(r.clock, eui=NEW_EUI, short=MOVED_TO, rng=random.Random(12))  # noqa: S311
    r.inst.network.add_valve(sim_b)
    fired: list[int] = []

    def on_sender(src: int, ieee: object) -> None:
        if fired or src != short:
            return
        fired.append(src)
        sim_a.set_short(MOVED_TO + 1)
        bridge_discovery.on_address(r.core, gen, sim_a.eui, MOVED_TO + 1)  # newer: A at S2
        sim_b.set_short(short)  # B takes S without announcing

    r.inst.network.reply_src_ieee[short] = sim_a.eui
    gen.node.on_sender(on_sender)
    mark = len(r.inst.network.received)
    with pytest.raises(RouteError):
        await r.clock.run_task(r.bridge.set_setpoint(sim_a.eui, 25.0))
    assert fired
    assert sim_b.writes == ()  # B never received 25 °C
    assert [q for _, q in zcl_requests(r, mark) if isinstance(q, tuple)] == []
    assert r.snap().valves[sim_a.eui].short == MOVED_TO + 1  # the newer evidence stands
    await stop(r)
