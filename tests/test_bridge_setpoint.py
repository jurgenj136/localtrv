"""ViCareBridge (T14): the setpoint transaction (versions, lock, ack, confirm, deadlines)."""

from __future__ import annotations

import asyncio
import math
import random
from typing import TYPE_CHECKING, Any

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
from vicare_local_ble import valves
from vicare_local_ble.bridge import SETPOINT_ACK_DEADLINE, SETPOINT_TOTAL_DEADLINE, SetpointStatus
from vicare_local_ble.bridge_state import TxLock
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.codec.zcl import ZclCommandId, ZclStatus
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.errors import (
    ConnectionLostError,
    RequestTimeoutError,
    ZclStatusError,
)
from vicare_local_ble.zigbee_direct.types import COORDINATOR, Eui64

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from vicare_local_ble.bridge import BridgeSnapshot
    from vicare_local_ble.testing.scenario import Installation

SLOW_EUI = Eui64.from_str("02:00:00:00:00:01:00:30")


def status(r: BRig, eui: Eui64) -> SetpointStatus:
    return r.snap().setpoints[eui]


def writes(r: BRig, mark: int = 0) -> list[tuple[int, ...]]:
    return [req for _, req in zcl_requests(r, mark) if isinstance(req, tuple)]


def confirms(r: BRig, mark: int = 0) -> int:
    return sum(1 for _, req in zcl_requests(r, mark) if req == valves.CONFIRM_SETPOINT)


def drop_after_ack(eui: Eui64, sim: SimValve) -> object:
    """``on_update`` hook: the valve goes silent right at the acknowledgement."""

    def hook(_r: BRig, snap: BridgeSnapshot) -> None:
        if snap.setpoints[eui].acknowledged_c is not None:
            sim.drop_rate = 1.0

    return hook


async def setpoint(r: BRig, eui: Eui64, celsius: float) -> SetpointStatus:
    return await r.clock.run_task(r.bridge.set_setpoint(eui, celsius))


async def test_returns_at_ack_then_background_confirm() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    count = len(r.updates)
    t0 = r.clock.now()
    result = await setpoint(r, eui, 21.5)
    optimistic = r.updates[count][1].setpoints[eui]
    assert (optimistic.requested_c, optimistic.pending, optimistic.version) == (21.5, True, 1)
    assert optimistic.acknowledged_c is None
    assert r.updates[count][0] == t0  # the UI updated before any await
    assert (result.requested_c, result.acknowledged_c, result.confirmed_c) == (21.5, 21.5, None)
    assert result.pending is True
    assert writes(r) == [(vt.CL_THERMOSTAT, 2150)]
    await run_until(r.clock, lambda: not status(r, eui).pending)
    done = status(r, eui)
    assert (done.confirmed_c, done.confirmed_at) == (21.5, r.clock.now())
    assert r.snap().states[eui].setpoint_c == 21.5
    assert not r.core.tx[eui].lock.locked()
    await stop(r)


async def test_concurrent_writes_are_serialised_and_newest_wins() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    a = asyncio.ensure_future(r.bridge.set_setpoint(eui, 20.0))
    await r.clock.advance(0)
    b = asyncio.ensure_future(r.bridge.set_setpoint(eui, 23.0))
    await r.clock.advance(0)
    assert status(r, eui).requested_c == 23.0
    assert status(r, eui).version == 2
    assert writes(r) == [(vt.CL_THERMOSTAT, 2000)]  # B waits for the lock
    await run_until(r.clock, lambda: a.done() and b.done() and not status(r, eui).pending)
    assert writes(r) == [(vt.CL_THERMOSTAT, 2000), (vt.CL_THERMOSTAT, 2300)]
    assert confirms(r) == 1  # A spawned no confirm: B's write followed it
    final = status(r, eui)
    assert (final.requested_c, final.acknowledged_c, final.confirmed_c) == (23.0, 23.0, 23.0)
    assert r.inst.valves[0].get_attribute(vt.CL_THERMOSTAT, vt.ATTR_SETPOINT) == (
        ZclDataType.INT16,
        2300,
    )
    await stop(r)


async def test_newer_version_preempts_the_older_confirm() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    await setpoint(r, eui, 20.0)  # acked; its confirm read is in flight
    first_confirm = r.core.tx[eui].confirm
    assert first_confirm is not None
    await setpoint(r, eui, 24.0)
    assert first_confirm.cancelled()
    await run_until(r.clock, lambda: not status(r, eui).pending)
    final = status(r, eui)
    assert (final.version, final.confirmed_c) == (2, 24.0)
    await stop(r)


async def test_failing_older_write_does_not_revert_newer() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    r.inst.valves[0].queue_default_response(ZclCommandId.WRITE_ATTRIBUTES, ZclStatus.INVALID_VALUE)
    a = asyncio.ensure_future(r.bridge.set_setpoint(eui, 20.0))
    await r.clock.advance(0)
    b = asyncio.ensure_future(r.bridge.set_setpoint(eui, 23.0))
    await run_until(r.clock, a.done)
    with pytest.raises(ZclStatusError):
        a.result()
    mid = status(r, eui)
    assert (mid.requested_c, mid.pending, mid.version) == (23.0, True, 2)
    await run_until(r.clock, lambda: b.done() and not status(r, eui).pending)
    final = status(r, eui)
    assert (final.requested_c, final.acknowledged_c, final.confirmed_c) == (23.0, 23.0, 23.0)
    await stop(r)


async def test_rejected_write_record_raises_and_clears() -> None:
    def inverted(inst: Installation) -> None:
        v = inst.valves[0]
        v.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MIN_LIMIT, ZclDataType.INT16, 2500)
        v.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, ZclDataType.INT16, 1000)

    r = make_rig(n_valves=1, behind_router=0, setup=inverted)
    await discovered(r)
    eui = r.euis()[0]
    assert r.snap().valves[eui].limits.source == "abs"  # inverted limits are never applied
    with pytest.raises(ZclStatusError) as info:
        await setpoint(r, eui, 21.0)
    assert info.value.status == ZclStatus.INVALID_VALUE
    st = status(r, eui)
    assert (st.requested_c, st.pending, st.version) == (None, False, 1)
    await stop(r)


async def test_confirm_timeout_is_acknowledged_unconfirmed() -> None:
    def hook(rig: BRig, snap: BridgeSnapshot) -> None:
        sim = rig.inst.valves[0]
        if snap.setpoints.get(sim.eui, SetpointStatus()).acknowledged_c is not None:
            sim.drop_rate = 1.0

    r = make_rig(n_valves=1, behind_router=0, on_update=hook)
    await discovered(r)
    eui = r.euis()[0]
    before = r.snap().states[eui].setpoint_c
    await setpoint(r, eui, 21.5)
    acked_at = r.clock.now()
    await run_until(r.clock, lambda: not status(r, eui).pending)
    assert r.clock.now() == pytest.approx(acked_at + 60)  # the read's 2 x 30 s attempts
    st = status(r, eui)
    assert (st.acknowledged_c, st.confirmed_c, st.confirmed_at) == (21.5, None, None)
    assert r.snap().states[eui].setpoint_c == before
    assert not r.core.tx[eui].lock.locked()
    await stop(r)


def add_slow_valve(inst: Installation) -> None:
    slow = SimValve(
        inst.clock,
        eui=SLOW_EUI,
        short=0x5005,
        rng=random.Random(4),  # noqa: S311
        latency=(35.0, 35.0),
    )
    inst.network.add_valve(slow, parent=COORDINATOR)


async def test_total_deadline_ninety_seconds() -> None:
    def hook(rig: BRig, snap: BridgeSnapshot) -> None:
        if snap.setpoints.get(SLOW_EUI, SetpointStatus()).acknowledged_c is not None:
            next(v for v in rig.inst.network.valves if v.eui == SLOW_EUI).drop_rate = 1.0

    r = make_rig(n_valves=0, behind_router=0, setup=add_slow_valve, on_update=hook)
    await discovered(r)
    t0 = r.clock.now()
    await setpoint(r, SLOW_EUI, 19.0)
    assert r.clock.now() == pytest.approx(t0 + 35)  # ack after the retransmit
    await run_until(r.clock, lambda: not status(r, SLOW_EUI).pending)
    assert r.clock.now() == pytest.approx(t0 + SETPOINT_TOTAL_DEADLINE)
    assert status(r, SLOW_EUI).confirmed_c is None
    assert status(r, SLOW_EUI).acknowledged_c == 19.0
    await stop(r)


async def test_ack_deadline_sixty_seconds_waiting_for_the_lock() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    lock = r.core.tx[eui].lock
    assert lock.try_acquire()  # e.g. a long poll holds the valve
    t0 = r.clock.now()
    with pytest.raises(TimeoutError) as info:
        await setpoint(r, eui, 21.0)
    assert type(info.value) is TimeoutError
    assert r.clock.now() == pytest.approx(t0 + SETPOINT_ACK_DEADLINE)
    st = status(r, eui)
    assert (st.requested_c, st.pending, st.version) == (None, False, 1)
    assert lock.locked()  # still ours: the failed call did not release it
    lock.release()
    assert writes(r) == []
    await stop(r)


async def test_ack_deadline_request_timeout() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    r.inst.valves[0].drop_rate = 1.0
    t0 = r.clock.now()
    with pytest.raises(TimeoutError) as info:
        await setpoint(r, eui, 21.0)
    assert isinstance(info.value, RequestTimeoutError | TimeoutError)
    assert r.clock.now() <= t0 + SETPOINT_ACK_DEADLINE + 1e-6
    assert not status(r, eui).pending
    assert not r.core.tx[eui].lock.locked()
    await stop(r)


async def test_caller_cancelled_while_waiting_for_the_lock() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    lock = r.core.tx[eui].lock
    assert lock.try_acquire()
    task = asyncio.ensure_future(r.bridge.set_setpoint(eui, 21.0))
    await r.clock.advance(5)
    assert status(r, eui).pending
    task.cancel()
    await r.clock.advance(0)
    assert task.cancelled()
    st = status(r, eui)
    assert (st.requested_c, st.pending) == (None, False)
    lock.release()
    assert not lock.locked()
    await stop(r)


async def test_external_overwrite_seen_on_next_poll_and_report() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    sim = r.inst.valves[0]
    await setpoint(r, eui, 21.5)
    await run_until(r.clock, lambda: not status(r, eui).pending)
    sim.external_setpoint_change(18.0)
    await poll(r)
    assert r.snap().states[eui].setpoint_c == 18.0
    assert status(r, eui).confirmed_c == 21.5  # never rewritten by a poll
    sim.external_setpoint_change(19.5)
    sim.report(vt.CL_THERMOSTAT, (vt.ATTR_SETPOINT,))
    await r.clock.advance(0)
    assert r.snap().states[eui].setpoint_c == 19.5
    await stop(r)


async def test_invalid_input_changes_nothing() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]
    count = len(r.updates)
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError, match="finite"):
            await r.bridge.set_setpoint(eui, bad)
    with pytest.raises(KeyError):
        await r.bridge.set_setpoint(Eui64.from_str("02:00:00:00:00:09:09:09"), 20.0)
    assert len(r.updates) == count
    assert status(r, eui) == SetpointStatus()
    assert writes(r) == []
    await stop(r)


async def test_setpoint_is_clamped_to_the_valve_limits() -> None:
    def limits(inst: Installation) -> None:
        v = inst.valves[0]
        v.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MIN_LIMIT, ZclDataType.INT16, 1000)
        v.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, ZclDataType.INT16, 2500)

    r = make_rig(n_valves=1, behind_router=0, setup=limits)
    await discovered(r)
    eui = r.euis()[0]
    assert (r.snap().valves[eui].limits.min_c, r.snap().valves[eui].limits.max_c) == (10.0, 25.0)
    high = await setpoint(r, eui, 30.0)
    assert high.requested_c == 25.0
    low = await setpoint(r, eui, 3.0)
    assert low.requested_c == 10.0
    await run_until(r.clock, lambda: not status(r, eui).pending)
    assert writes(r) == [(vt.CL_THERMOSTAT, 2500), (vt.CL_THERMOSTAT, 1000)]
    assert status(r, eui).confirmed_c == 10.0
    await stop(r)


async def test_not_ready_raises_connection_lost_without_changes() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    eui = r.euis()[0]
    r.inst.r0.disconnect()
    await r.clock.advance(0)
    assert r.conn.current is None
    with pytest.raises(ConnectionLostError):
        await r.bridge.set_setpoint(eui, 20.0)
    assert status(r, eui) == SetpointStatus()
    await ready_again(r, gen.number)
    await stop(r)


async def test_confirm_after_reconnect_does_not_mutate() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    eui = r.euis()[0]
    before = r.snap().states[eui].setpoint_c
    await setpoint(r, eui, 26.0)
    r.inst.r0.disconnect()  # teardown cancels the in-flight confirm
    await ready_again(r, gen.number)
    st = status(r, eui)
    assert (st.acknowledged_c, st.confirmed_c, st.pending) == (26.0, None, False)
    assert r.snap().states[eui].setpoint_c == before
    assert not r.core.tx[eui].lock.locked()
    await stop(r)


async def test_ack_after_generation_lost_returns_without_confirm() -> None:
    fired: list[bool] = []

    def hook(rig: BRig, snap: BridgeSnapshot) -> None:
        st = snap.setpoints.get(rig.inst.valves[0].eui)
        if st is not None and st.acknowledged_c is not None and not fired:
            fired.append(True)
            rig.inst.r0.disconnect()

    r = make_rig(n_valves=1, behind_router=0, on_update=hook)
    gen = await discovered(r)
    eui = r.euis()[0]
    result = await setpoint(r, eui, 22.5)
    assert result.acknowledged_c == 22.5
    await run_until(r.clock, lambda: not status(r, eui).pending)
    assert status(r, eui).confirmed_c is None
    assert not r.core.tx[eui].lock.locked()
    await ready_again(r, gen.number)
    await stop(r)


async def test_spawn_failing_between_ack_and_confirm_still_returns_the_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    eui = r.euis()[0]

    def lost(_gen: object, coro: Coroutine[Any, Any, object], *, name: str) -> object:
        coro.close()
        raise ConnectionLostError(f"{name}: generation lost")

    monkeypatch.setattr(r.conn, "spawn", lost)
    result = await setpoint(r, eui, 20.5)
    assert (result.acknowledged_c, result.pending, result.confirmed_c) == (20.5, False, None)
    assert not r.core.tx[eui].lock.locked()
    monkeypatch.undo()
    await stop(r)


async def test_tx_lock_hands_over_and_survives_cancelled_waiters() -> None:
    lock = TxLock()
    with pytest.raises(RuntimeError):
        lock.release()
    assert lock.try_acquire()
    assert not lock.try_acquire()
    gone = asyncio.ensure_future(lock.acquire())
    handed = asyncio.ensure_future(lock.acquire())
    nxt = asyncio.ensure_future(lock.acquire())
    await asyncio.sleep(0)
    gone.cancel()  # cancelled while queued: skipped by release
    await asyncio.sleep(0)
    lock.release()  # ownership goes to ``handed`` ...
    handed.cancel()  # ... which is cancelled before it ran: it passes the lock on
    await asyncio.gather(gone, handed, return_exceptions=True)
    await asyncio.sleep(0)
    assert nxt.done()
    assert lock.locked()
    assert not lock.try_acquire()  # no window where the lock looks free
    lock.release()
    assert not lock.locked()
