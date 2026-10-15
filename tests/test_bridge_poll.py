"""ViCareBridge (T14): poll cadence, misses, rejoin rule, busy valves, reports, logging."""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import TYPE_CHECKING

import pytest

from test_bridge import (
    LOGGER,
    BRig,
    discovered,
    make_rig,
    poll,
    ready_again,
    run_until,
    stop,
    zcl_requests,
    zdo_requests,
)
from vicare_local_ble import valves
from vicare_local_ble.bridge import MISSES_UNAVAILABLE
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.zigbee_direct.codec.zcl import ZclCommandId, ZclStatus
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import ZdoCluster
from vicare_local_ble.zigbee_direct.connection import ConnectionState

if TYPE_CHECKING:
    from vicare_local_ble.testing.scenario import Installation


def plans(r: BRig, mark: int) -> dict[int, list[valves.ReadRequest]]:
    """Read requests per valve short since ``mark``."""
    out: dict[int, list[valves.ReadRequest]] = {v.short: [] for v in r.inst.valves}
    for to, req in zcl_requests(r, mark):
        assert isinstance(req, valves.ReadRequest)
        out.setdefault(to, []).append(req)
    return out


async def polled(r: BRig) -> dict[int, list[valves.ReadRequest]]:
    mark = len(r.inst.network.received)
    await poll(r)
    return plans(r, mark)


async def test_poll_cadence_fast_slow_static() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    # Discovery read IDENTIFY + limits, then the initial poll (index 0) read FAST + SLOW.
    limits = [req for req in valves.STATIC if req != valves.IDENTIFY]
    expected_initial = [valves.IDENTIFY, *limits, *valves.FAST, *valves.SLOW]
    assert plans(r, 0) == {v.short: expected_initial for v in r.inst.valves}
    for _ in range(1, valves.SLOW_EVERY_N_POLLS):
        assert await polled(r) == {v.short: list(valves.FAST) for v in r.inst.valves}
    assert await polled(r) == {v.short: [*valves.FAST, *valves.SLOW] for v in r.inst.valves}
    # STATIC once a day: not yet due one second early, due after STATIC_REFRESH_S.
    first_static = min(r.core.static_at.values())
    await r.clock.advance_to(first_static + valves.STATIC_REFRESH_S - 1)
    assert await polled(r) == {v.short: list(valves.FAST) for v in r.inst.valves}
    r.inst.valves[0].set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, ZclDataType.INT16, 2800)
    due = max(r.core.static_at.values()) + valves.STATIC_REFRESH_S
    await r.clock.advance_to(max(due, r.clock.now()))
    assert await polled(r) == {v.short: [*valves.FAST, *valves.STATIC] for v in r.inst.valves}
    assert await polled(r) == {v.short: list(valves.FAST) for v in r.inst.valves}
    assert r.snap().valves[r.inst.valves[0].eui].limits.max_c == 28.0  # STATIC refreshed it
    state = r.snap().states[r.inst.valves[0].eui]
    assert (state.local_temperature_c, state.setpoint_c, state.heating_demand) == (19.65, 22.0, 2)
    assert (state.battery_pct, state.lqi, state.rssi, state.window_open_raw) == (63.0, 180, -60, 1)
    await stop(r)


async def test_misses_unavailable_then_rewalk_and_recovery(
    caplog: pytest.LogCaptureFixture,
) -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    dead, alive = r.inst.valves
    dead.drop_rate = 1.0
    for n in range(1, MISSES_UNAVAILABLE):
        mark = len(r.inst.network.received)
        snap = await poll(r)
        assert snap.misses[dead.eui] == n
        assert snap.available[dead.eui] is True
        assert zdo_requests(r, ZdoCluster.MGMT_LQI_REQ, mark) == []
        assert plans(r, mark)[dead.short] == [valves.FAST[0]]  # stops at the first silence
    mark = len(r.inst.network.received)
    snap = await poll(r)
    assert snap.misses[dead.eui] == MISSES_UNAVAILABLE
    assert snap.available[dead.eui] is False
    assert snap.misses[alive.eui] == 0
    assert snap.available[alive.eui] is True
    assert f"valve 0x{dead.short:04X} unavailable" in caplog.text
    await r.clock.advance(30)
    assert zdo_requests(r, ZdoCluster.MGMT_LQI_REQ, mark)  # the re-walk was spawned
    await run_until(r.clock, lambda: not r.core.walking)
    walked = r.snap().discovery.topology
    assert walked is not None
    assert walked.walked_at is not None
    assert walked.walked_at > r.snap().discovery.last_run  # type: ignore[operator]
    # A fourth miss does not spawn another walk.
    mark = len(r.inst.network.received)
    await poll(r)
    await r.clock.advance(30)
    assert zdo_requests(r, ZdoCluster.MGMT_LQI_REQ, mark) == []
    # Any response resets the misses; the recovery is logged once.
    assert "available again" not in caplog.text
    dead.drop_rate = 0.0
    snap = await poll(r)
    assert snap.misses[dead.eui] == 0
    assert snap.available[dead.eui] is True
    assert caplog.text.count(f"valve 0x{dead.short:04X} available again") == 1
    await poll(r)
    assert caplog.text.count("available again") == 1
    await stop(r)


async def test_not_ready_cycle_is_skipped_and_counts_a_miss() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    gen = await discovered(r)
    r.inst.r0.disconnect()
    await run_until(r.clock, lambda: r.conn.state is not ConnectionState.READY)
    count = len(r.updates)
    snap = await r.bridge.poll()  # no awaits needed: nothing is sent
    assert snap.connection_state is not ConnectionState.READY
    assert snap.generation is None
    assert all(m == 1 for m in snap.misses.values())
    assert len(r.updates) == count + 1
    await ready_again(r, gen.number)
    await stop(r)


async def test_all_silent_requests_rejoin_after_two_polls() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    gen = await discovered(r)
    for v in r.inst.valves:
        v.drop_rate = 1.0
    await poll(r)
    assert r.conn.stats.rejoins == 0
    await poll(r)
    assert r.conn.stats.rejoins == 1
    assert r.conn.stats.last_failure == "rejoin:all_valves_silent"
    await ready_again(r, gen.number)
    await stop(r)


async def test_silence_interrupted_by_not_ready_does_not_rejoin() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    r.inst.valves[0].drop_rate = 1.0
    await poll(r)
    r.inst.r0.disconnect()
    await run_until(r.clock, lambda: r.conn.state is not ConnectionState.READY)
    await r.bridge.poll()
    gen2 = await ready_again(r, gen.number)
    # gen 2's initial poll is silent too, but the streak restarted with the generation.
    await run_until(r.clock, lambda: r.core.polls >= 3 and not r.core.tx[r.euis()[0]].lock.locked())
    assert r.core.silent_streak == 1
    assert r.conn.stats.rejoins == 0
    assert r.conn.current is gen2
    await stop(r)


async def test_empty_valve_set_never_rejoins() -> None:
    r = make_rig(n_valves=0, behind_router=0)
    await start_and_settle_empty(r)
    for _ in range(4):
        snap = await poll(r)
    assert snap.valves == {}
    assert r.conn.stats.rejoins == 0
    await stop(r)


async def start_and_settle_empty(r: BRig) -> None:
    await r.clock.run_task(r.conn.start())
    await run_until(r.clock, lambda: r.core.discovery.last_run is not None and r.core.polls >= 1)


async def test_busy_valve_is_skipped() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    busy, free = r.inst.valves
    lock = r.core.tx[busy.eui].lock
    assert lock.try_acquire()
    busy.drop_rate = 1.0  # would be a miss if it were polled
    before = r.snap()
    after = await polled(r)
    assert after[busy.short] == []
    assert after[free.short] == list(valves.FAST)
    snap = r.snap()
    assert snap.misses[busy.eui] == before.misses[busy.eui] == 0
    assert snap.available[busy.eui] is True
    assert r.core.silent_streak == 0
    lock.release()
    await stop(r)


async def test_reports_update_state_and_reset_misses() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    valve = r.inst.valves[0]
    r.core.misses[valve.eui] = 2
    count = len(r.updates)
    valve.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_LOCAL_TEMPERATURE, ZclDataType.INT16, 2105)
    valve.report(vt.CL_THERMOSTAT, (vt.ATTR_LOCAL_TEMPERATURE,))
    await r.clock.advance(0)
    snap = r.snap()
    assert snap.states[valve.eui].local_temperature_c == 21.05
    assert snap.states[valve.eui].updated_at == r.clock.now()
    assert snap.misses[valve.eui] == 0
    assert len(r.updates) == count + 1
    assert r.updates[-1][1].states[valve.eui].local_temperature_c == 21.05
    # The same value again changes nothing: no update.
    valve.report(vt.CL_THERMOSTAT, (vt.ATTR_LOCAL_TEMPERATURE,))
    await r.clock.advance(0)
    assert len(r.updates) == count + 1
    await stop(r)


async def test_read_issues_logged_once_per_valve_and_demand_warning_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, LOGGER)
    r = make_rig(n_valves=2, behind_router=0)
    await discovered(r)
    sentinel, demanding = r.inst.valves
    sentinel.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_LOCAL_TEMPERATURE, ZclDataType.INT16, -0x8000)
    demanding.set_attribute(vt.CL_THERMOSTAT, valves.ATTR_PI_HEATING_DEMAND, ZclDataType.UINT8, 101)
    caplog.clear()
    await poll(r)
    await poll(r)
    snap = r.snap()
    assert snap.states[sentinel.eui].local_temperature_c is None
    assert snap.states[demanding.eui].heating_demand == 101
    rejected = [rec for rec in caplog.records if "rejected (sentinel)" in rec.getMessage()]
    assert len(rejected) == 1
    assert str(sentinel.eui) in rejected[0].getMessage()
    assert rejected[0].levelno == logging.DEBUG
    warnings = [rec for rec in caplog.records if "heating demand above" in rec.getMessage()]
    assert len(warnings) == 1
    assert warnings[0].levelno == logging.WARNING
    assert str(demanding.eui) not in warnings[0].getMessage()  # EUIs only at DEBUG
    for rec in caplog.records:
        if rec.levelno > logging.DEBUG:
            assert all(str(v.eui) not in rec.getMessage() for v in r.inst.valves)
    assert r.inst.network_key.reveal().hex() not in caplog.text
    await stop(r)


async def test_on_update_on_every_change_and_cheap_snapshot() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    assert not inspect.iscoroutinefunction(r.bridge.snapshot)
    a, b = r.snap(), r.snap()
    assert a.valves is b.valves  # cached until the next change
    assert a.states is b.states
    with pytest.raises(TypeError):
        a.states[r.euis()[0]] = a.states[r.euis()[0]]  # type: ignore[index]
    valve = r.inst.valves[0]
    count = len(r.updates)
    valve.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_SETPOINT, ZclDataType.INT16, 1900)
    await poll(r)
    assert len(r.updates) == count + 1
    assert r.updates[-1][1].states[valve.eui].setpoint_c == 19.0
    assert r.snap().states is not a.states
    await poll(r)  # nothing changed: no update
    assert len(r.updates) == count + 1
    await stop(r)


async def test_poll_completing_after_reconnect_does_not_mutate() -> None:
    r = make_rig(n_valves=2, behind_router=0)
    gen = await discovered(r)
    before = r.snap()
    before_polls = r.core.polls
    for v in r.inst.valves:
        v.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_SETPOINT, ZclDataType.INT16, 1500)
    pending = asyncio.ensure_future(r.bridge.poll())
    await r.clock.advance(1)  # the reads are in flight
    r.inst.r0.disconnect()
    await run_until(r.clock, pending.done)
    snap = pending.result()
    assert snap.states == before.states
    assert snap.misses == before.misses
    assert snap.available == before.available
    assert r.core.polls == before_polls + 1
    await ready_again(r, gen.number)
    await stop(r)


async def test_error_status_is_a_response_and_basic_error_is_retried() -> None:
    from test_bridge import ACME_EUI, add_acme

    def setup(inst: Installation) -> None:
        add_acme(inst)
        acme = next(v for v in inst.network.valves if v.eui == ACME_EUI)
        acme.queue_default_response(ZclCommandId.READ_ATTRIBUTES, ZclStatus.UNSUPPORTED_CLUSTER)

    r = make_rig(n_valves=1, behind_router=0, setup=setup)
    await discovered(r)
    # An error status on the Basic read is retryable, not proof of "not a valve".
    assert str(ACME_EUI) not in r.bridge.export_cache().ignored
    assert r.snap().discovery.complete is False
    await run_until(r.clock, lambda: str(ACME_EUI) in r.bridge.export_cache().ignored, 400)
    await run_until(r.clock, lambda: not r.core.discovery.running)
    valve = r.inst.valves[0]
    r.core.misses[valve.eui] = 2
    valve.queue_default_response(ZclCommandId.READ_ATTRIBUTES, ZclStatus.UNSUPPORTED_CLUSTER)
    snap = await poll(r)
    assert snap.misses[valve.eui] == 0
    assert snap.available[valve.eui] is True
    await stop(r)
