"""ViCareBridge (T14) regression tests from the adversarial review (fix round 1).

Each test names the review item it pins.
"""

from __future__ import annotations

import asyncio
import math
from typing import TYPE_CHECKING

import pytest

from test_bridge import (
    BRig,
    discovered,
    make_rig,
    poll,
    ready_again,
    run_until,
    stop,
    zcl_requests,
)
from vicare_local_ble import bridge_poll, valves
from vicare_local_ble.bridge import (
    SETPOINT_ACK_DEADLINE,
    SILENT_REJOIN_BACKOFF,
    BridgeCache,
    SetpointStatus,
    ViCareBridge,
)
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.testing.scenario import default_installation
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.connection import ZdConnection

if TYPE_CHECKING:
    from vicare_local_ble.bridge import BridgeSnapshot
    from vicare_local_ble.testing.scenario import Installation
    from vicare_local_ble.zigbee_direct.types import Eui64


def status(r: BRig, eui: Eui64) -> SetpointStatus:
    return r.snap().setpoints[eui]


async def settle_setpoint(r: BRig, eui: Eui64) -> None:
    await run_until(r.clock, lambda: not status(r, eui).pending)
    await r.clock.advance(0)


# --- 1: cleanup must not depend on a coroutine ``finally`` ---------------------------------------


async def test_two_sets_in_a_row_in_one_task() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]

    async def twice() -> SetpointStatus:
        await r.bridge.set_setpoint(eui, 20.0)
        # The first confirm task has not started yet; preempting it must free the lock.
        return await r.bridge.set_setpoint(eui, 21.0)

    second = await r.clock.run_task(twice())
    assert (second.version, second.acknowledged_c) == (2, 21.0)
    await settle_setpoint(r, eui)
    assert status(r, eui).confirmed_c == 21.0
    assert not r.core.tx[eui].lock.locked()
    assert r.core.tx[eui].confirm is None
    await stop(r)


async def test_confirm_cancelled_before_its_first_step_cleans_up() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]

    async def set_then_cancel() -> None:
        await r.bridge.set_setpoint(eui, 20.0)
        confirm = r.core.tx[eui].confirm
        assert confirm is not None
        confirm.cancel()  # as a teardown would, before the task ever ran

    await r.clock.run_task(set_then_cancel())
    await r.clock.advance(0)
    st = status(r, eui)
    assert (st.acknowledged_c, st.confirmed_c, st.pending) == (20.0, None, False)
    assert not r.core.tx[eui].lock.locked()
    await stop(r)


async def test_walking_flag_resets_after_a_cancelled_walk() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    bridge_poll.spawn_rewalk(r.core, gen)
    assert r.core.walking
    task = next(t for t in asyncio.all_tasks() if t.get_name() == "vicare topology re-walk")
    task.cancel()  # before its first step
    await r.clock.advance(0)
    assert not r.core.walking
    bridge_poll.spawn_rewalk(r.core, gen)  # re-walks are not disabled
    assert r.core.walking
    await run_until(r.clock, lambda: not r.core.walking)
    await stop(r)


# --- 2: a setpoint does not wait behind a whole poll plan ---------------------------------------


@pytest.mark.parametrize("seed", range(10))
async def test_setpoint_during_slow_static_poll_succeeds(seed: int) -> None:
    r = make_rig(n_valves=1, behind_router=0, seed=seed)
    await discovered(r)
    eui = r.euis()[0]
    r.core.polls = valves.SLOW_EVERY_N_POLLS  # this poll is a SLOW one ...
    r.core.static_at.clear()  # ... and STATIC is due
    polling = asyncio.ensure_future(r.bridge.poll())
    await r.clock.advance(1)
    t0 = r.clock.now()
    setting = asyncio.ensure_future(r.bridge.set_setpoint(eui, 23.5))
    await run_until(r.clock, lambda: setting.done() and polling.done())
    assert setting.result().acknowledged_c == 23.5
    assert r.updates[-1][0] - t0 < SETPOINT_ACK_DEADLINE
    snap = polling.result()
    assert snap.misses[eui] == 0  # ended early after a response: not a miss
    assert snap.available[eui] is True
    assert eui not in r.core.static_at  # the cut-short STATIC stays due
    await settle_setpoint(r, eui)
    await stop(r)


# --- 3: confirm only from the confirm response itself -------------------------------------------


async def test_confirm_with_unsupported_status_is_unconfirmed() -> None:
    def hook(rig: BRig, snap: BridgeSnapshot) -> None:
        sim = rig.inst.valves[0]
        if snap.setpoints.get(sim.eui, SetpointStatus()).acknowledged_c is not None:
            sim.remove_attribute(vt.CL_THERMOSTAT, vt.ATTR_SETPOINT)  # 0x86 on the read

    r = make_rig(n_valves=1, behind_router=0, on_update=hook)
    await discovered(r)
    eui = r.euis()[0]
    before = r.snap().states[eui].setpoint_c
    await r.clock.run_task(r.bridge.set_setpoint(eui, 21.0))
    await settle_setpoint(r, eui)
    st = status(r, eui)
    assert (st.acknowledged_c, st.confirmed_c, st.confirmed_at) == (21.0, None, None)
    assert r.snap().states[eui].setpoint_c == before
    await stop(r)


# --- 4: a walk never overwrites a fresher Device_annce short ------------------------------------


async def test_walk_keeps_a_fresher_annce_short() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    sim = r.inst.valves[0]
    old = r.core.topology
    assert old is not None
    started = r.clock.now()
    await r.clock.advance(1)
    r.inst.network.valve_rejoin(sim, 0x4321)
    await r.clock.advance(0)
    assert r.snap().valves[sim.eui].short == 0x4321
    r.core.set_topology(old, started=started)  # a walk that began before the annce
    assert r.core.valves[sim.eui].short == 0x4321
    r.core.set_topology(old, started=r.clock.now() + 1)  # a walk that began after it
    assert r.core.valves[sim.eui].short == old.neighbors[sim.eui].nwk_addr
    await stop(r)


# --- 5: all-silent rejoin backoff ---------------------------------------------------------------


async def silent_polls_until_rejoin(r: BRig, rejoins: int) -> None:
    for _ in range(3):
        await poll(r)
        if r.conn.stats.rejoins == rejoins:
            return
    pytest.fail("no rejoin")


async def wait_initial_poll(r: BRig, after: int) -> None:
    gen = await ready_again(r, after)
    eui = r.euis()[0]
    target = r.core.polls + 1
    await run_until(r.clock, lambda: r.core.polls >= target and not r.core.tx[eui].lock.locked())
    assert r.conn.current is gen


async def test_silent_rejoin_backs_off_until_a_valve_answers() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    sim = r.inst.valves[0]
    sim.drop_rate = 1.0
    await silent_polls_until_rejoin(r, 1)
    await wait_initial_poll(r, gen.number)
    first = r.core.last_silent_rejoin
    assert first is not None
    await poll(r)  # two silent polls again, but within the 1 h gap
    assert r.conn.stats.rejoins == 1
    await r.clock.advance_to(first + SILENT_REJOIN_BACKOFF)
    await poll(r)
    assert r.conn.stats.rejoins == 2
    number = r.conn.stats.generation
    await wait_initial_poll(r, number)
    second = r.core.last_silent_rejoin
    assert second is not None
    await r.clock.advance_to(second + SILENT_REJOIN_BACKOFF)
    await poll(r)
    assert r.conn.stats.rejoins == 2  # the gap doubled to 2 h
    await r.clock.advance_to(second + 2 * SILENT_REJOIN_BACKOFF)
    await poll(r)
    assert r.conn.stats.rejoins == 3
    await wait_initial_poll(r, r.conn.stats.generation)
    sim.drop_rate = 0.0
    await poll(r)  # a valve answered: the backoff resets
    assert r.core.silent_rejoins == 0
    await stop(r)


# --- 6: identification retries unless the device positively mismatches -------------------------


async def test_incomplete_identification_is_retried_not_ignored() -> None:
    def setup(inst: Installation) -> None:
        inst.valves[0].remove_attribute(vt.CL_BASIC, valves.ATTR_MODEL_ID)

    r = make_rig(n_valves=1, behind_router=0, setup=setup)
    await discovered(r)
    eui = r.euis()[0]
    assert str(eui) not in r.bridge.export_cache().ignored
    assert r.snap().discovery.complete is False
    model = (vt.CL_BASIC, valves.ATTR_MODEL_ID, ZclDataType.CHARSTR, "7637434")
    r.inst.valves[0].set_attribute(*model)
    await run_until(r.clock, lambda: eui in r.snap().valves, limit=400)
    await stop(r)


# --- 7: a newer write failing before its ack shows the valve's acked value ----------------------


async def test_older_ack_survives_newer_failure() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    sim = r.inst.valves[0]
    a = asyncio.ensure_future(r.bridge.set_setpoint(eui, 20.0))
    await r.clock.advance(1)  # A's write reached the valve
    sim.queue_default_response(0x02, 0x87)  # the next request (B's write) fails
    b = asyncio.ensure_future(r.bridge.set_setpoint(eui, 23.0))
    await run_until(r.clock, lambda: a.done() and b.done())
    assert a.result().acknowledged_c is None  # A was no longer the latest at its ack
    assert isinstance(b.exception(), Exception)
    st = status(r, eui)
    assert (st.acknowledged_c, st.requested_c, st.pending) == (20.0, None, False)
    assert not r.core.tx[eui].lock.locked()
    await stop(r)


# --- 8: STATIC refresh never downgrades the limits source ---------------------------------------


async def test_static_refresh_keeps_better_limits() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    sim = r.inst.valves[0]
    sim.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MIN_LIMIT, ZclDataType.INT16, 2500)  # inverted
    sim.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, ZclDataType.INT16, 1000)
    sim.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_ABS_MAX, ZclDataType.INT16, 3200)
    r.core.static_at.clear()
    await poll(r)
    limits = r.snap().valves[eui].limits
    assert (limits.min_c, limits.max_c, limits.source) == (8.0, 30.0, "limits")
    assert eui in r.core.static_at
    await stop(r)


# --- 9: the generation is re-read after the lock wait -------------------------------------------


async def test_reconnect_during_lock_wait_uses_the_new_generation() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    eui = r.euis()[0]
    lock = r.core.tx[eui].lock
    assert lock.try_acquire()
    setting = asyncio.ensure_future(r.bridge.set_setpoint(eui, 22.5))
    await r.clock.advance(1)
    r.inst.r0.disconnect()
    await ready_again(r, gen.number)
    lock.release()
    await run_until(r.clock, setting.done)
    assert setting.result().acknowledged_c == 22.5
    await settle_setpoint(r, eui)
    assert status(r, eui).confirmed_c == 22.5
    await stop(r)


# --- 10: a failed on_cache_changed is retried --------------------------------------------------


async def test_failed_cache_callback_is_retried_at_the_next_change() -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    conn = ZdConnection(
        inst.resolver,
        own_eui=inst.zvd_eui,
        network_key=inst.network_key,
        clock=inst.clock,
        connector=inst.connector,
    )
    calls: list[BridgeCache] = []

    def flaky(cache: BridgeCache) -> None:
        calls.append(cache)
        if len(calls) == 1:
            raise OSError("store busy")

    bridge = ViCareBridge(conn, clock=inst.clock, on_cache_changed=flaky)
    bridge.attach()
    gen = await inst.clock.run_task(conn.start())
    await inst.clock.advance(0)
    assert len(calls) >= 2  # the next change retried the failed one
    assert calls[0].own_short == calls[1].own_short == gen.join.own_short
    await inst.clock.run_task(conn.stop())


# --- 11: a re-entrant set from on_update preempts the confirm -----------------------------------


async def test_reentrant_set_from_on_update_preempts_the_confirm() -> None:
    fired: list[asyncio.Task[SetpointStatus]] = []

    def hook(rig: BRig, snap: BridgeSnapshot) -> None:
        eui = rig.inst.valves[0].eui
        st = snap.setpoints.get(eui, SetpointStatus())
        if st.version == 1 and st.acknowledged_c == 20.0 and not fired:
            loop = asyncio.get_running_loop()
            fired.append(loop.create_task(rig.bridge.set_setpoint(eui, 24.0), eager_start=True))

    r = make_rig(n_valves=1, behind_router=0, on_update=hook)
    await discovered(r)
    eui = r.euis()[0]
    await r.clock.run_task(r.bridge.set_setpoint(eui, 20.0))
    await run_until(r.clock, lambda: bool(fired) and fired[0].done())
    await settle_setpoint(r, eui)
    st = status(r, eui)
    assert (st.version, st.confirmed_c) == (2, 24.0)
    assert not r.core.tx[eui].lock.locked()
    writes = [req for _, req in zcl_requests(r) if isinstance(req, tuple)]
    assert writes == [(vt.CL_THERMOSTAT, 2000), (vt.CL_THERMOSTAT, 2400)]
    confirms = [req for _, req in zcl_requests(r) if req == valves.CONFIRM_SETPOINT]
    assert len(confirms) == 1  # A's confirm was preempted before it read anything
    assert not math.isnan(st.confirmed_at or 0.0)
    await stop(r)
