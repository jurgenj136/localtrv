"""Network Status 0x05/0x06 from a sleepy valve's parent: a failed attempt, not a failed request.

Live (21 h run): 189 of 191 statuses were 0x06 (indirect transaction expiry) 1.6-12 s after the
request; none of those requests was answered later. The node resends under the same TSN / ZDO
seq and raises ``RouteError`` only when the attempt budget is spent.
"""

from __future__ import annotations

import asyncio

import pytest

from test_bridge import poll, stop
from test_e2e_sim import begin, e2e_rig
from test_node import Rig, rig
from test_node_requests import read
from test_node_routing import mtorrs, status_npdu
from test_requests import TSN, VALVE, zcl_envelope
from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.testing.network_aps import is_aps_ack
from vicare_local_ble.testing.network_link import SIM_INDIRECT_EXPIRY_DELAY
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.zcl import ZclFrame
from vicare_local_ble.zigbee_direct.errors import (
    ConnectionLostError,
    RequestTimeoutError,
    RouteError,
)
from vicare_local_ble.zigbee_direct.node import NodeConfig
from vicare_local_ble.zigbee_direct.requests import PendingMap
from vicare_local_ble.zigbee_direct.routing import (
    ATTEMPT_FAILURE_STATUSES,
    NO_INDIRECT_CAPACITY_RETRY_DELAY,
    NWK_STATUS_INDIRECT_TRANSACTION_EXPIRY,
    NWK_STATUS_NO_INDIRECT_CAPACITY,
    ROUTE_FAILURE_STATUSES,
    attempt_retry_delay,
)

LATENCY = 14.0  # the rig's valves answer after exactly this long
EXPIRY = NWK_STATUS_INDIRECT_TRANSACTION_EXPIRY


def zcl_tsns(r: Rig) -> list[int]:
    """TSN of every ZCL request written after the join (MTORRs and APS acks skipped)."""
    out = []
    for raw in r.writes()[4:]:
        frame = NwkFrame.decode(raw)
        if frame.frame_type is not NwkFrameType.DATA or is_aps_ack(frame):
            continue
        out.append(ZclFrame.decode(ApsDataFrame.decode(frame.payload).payload).header.tsn)
    return out


def test_statuses_and_delays() -> None:
    assert {0x05, 0x06} == ATTEMPT_FAILURE_STATUSES
    assert not ATTEMPT_FAILURE_STATUSES & ROUTE_FAILURE_STATUSES  # no MTORR for 0x05/0x06
    assert attempt_retry_delay(EXPIRY) == 0.0
    assert attempt_retry_delay(NWK_STATUS_NO_INDIRECT_CAPACITY) == NO_INDIRECT_CAPACITY_RETRY_DELAY


# --- PendingMap.fail_attempt -----------------------------------------------------------------


async def test_fail_attempt_fails_the_signal_not_the_request() -> None:
    pending = PendingMap(clock=VirtualClock(), late_window=1.0)
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 0  # nothing pending
    entry = pending.register(zcl_envelope())
    other = pending.register(zcl_envelope(src_short=VALVE + 1))
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 0  # no attempt armed
    first = entry.arm_attempt()
    other_signal = other.arm_attempt()
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 1
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 0  # nothing outstanding
    assert not entry.future.done()
    assert not other_signal.done()
    assert isinstance(first.exception(), RouteError)
    second = entry.arm_attempt()
    assert not second.done()
    entry.future.set_result(object())  # type: ignore[arg-type]
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 0  # answered: skipped
    assert not second.done()
    pending.retire(entry.envelope.key)
    assert second.cancelled()
    assert entry.signals == []
    pending.fail_attempt(VALVE + 1, RouteError(VALVE + 1, EXPIRY))
    pending.retire(other.envelope.key)  # marks the failed signal retrieved, no warning
    assert other_signal.done()
    assert pending.is_retired((VALVE, "zcl", TSN))


async def test_fail_attempt_goes_to_the_oldest_outstanding_attempt() -> None:
    pending = PendingMap(clock=VirtualClock(), late_window=1.0)
    entry = pending.register(zcl_envelope())
    timed_out = entry.arm_attempt()  # attempt 1 timed out: still outstanding
    current = entry.arm_attempt()
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 0  # attempt 1's status
    assert timed_out.done()
    assert timed_out.result() is None  # consumed, no error
    assert not current.done()
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 1  # the current one's
    assert isinstance(current.exception(), RouteError)
    third = entry.arm_attempt()
    entry.disarm(third)  # its send raised: no frame, nothing outstanding
    assert third.cancelled()
    assert entry.signals == [timed_out, current]
    assert pending.fail_attempt(VALVE, RouteError(VALVE, EXPIRY)) == 0
    entry.disarm(third)  # idempotent
    pending.retire(entry.envelope.key)
    assert entry.signals == []


# --- node ------------------------------------------------------------------------------------


async def test_expiry_retries_with_the_same_tsn_and_succeeds() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short)
        tsn = r.core.allocators.tsn.peek()
        start = r.clock.now()
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        assert r.clock.now() - start == pytest.approx(SIM_INDIRECT_EXPIRY_DELAY + LATENCY)
        assert zcl_tsns(r) == [tsn, tsn]
        stats = r.node.stats
        assert (stats.indirect_retries, stats.retransmits, stats.timeouts) == (1, 1, 0)
        assert stats.network_status == 1
        assert mtorrs(r) == 2  # 0x06 is not a route failure: no extra MTORR


async def test_expiry_on_every_attempt_raises_route_error() -> None:
    # 2 attempts plus the 1 extra a drop earns (indirect_extra_attempts), all dropped.
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, count=3)
        tsn = r.core.allocators.tsn.peek()
        start = r.clock.now()
        with pytest.raises(RouteError) as exc:
            await r.clock.run_task(read(r))
        assert (exc.value.dst, exc.value.status) == (valve.short, EXPIRY)
        assert r.clock.now() - start == pytest.approx(3 * SIM_INDIRECT_EXPIRY_DELAY)
        stats = r.node.stats
        assert (stats.indirect_retries, stats.retransmits, stats.timeouts) == (2, 2, 0)
        assert len(r.core.pending) == 0
        assert r.core.pending.is_retired((valve.short, "zcl", tsn))


async def test_two_drops_then_an_answer_succeeds_on_the_extra_attempt() -> None:
    # Hardware 2026-10-15: the weak valve's parent dropped both attempts of a poll ~1 in 7.
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, count=2)
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (2, 2)


async def test_no_extra_attempt_after_a_timeout() -> None:
    # A drop, then a timed-out last regular attempt: the extra attempt is for drops only.
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short)
        valve.drop_rate = 1.0
        mark = len(zcl_tsns(r))
        with pytest.raises(RequestTimeoutError):
            await r.clock.run_task(read(r))
        assert len(zcl_tsns(r)) - mark == 2
        assert r.node.stats.timeouts == 1


async def test_extra_attempts_can_be_disabled() -> None:
    async with rig(config=NodeConfig(indirect_extra_attempts=0)) as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, count=2)
        with pytest.raises(RouteError):
            await r.clock.run_task(read(r))
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (1, 1)


def test_negative_extra_attempts_are_rejected() -> None:
    with pytest.raises(ValueError, match="indirect_extra_attempts"):
        NodeConfig(indirect_extra_attempts=-1)


async def test_single_attempt_budget_raises_at_once() -> None:
    async with rig(config=NodeConfig(request_attempts=1, indirect_extra_attempts=0)) as r:
        r.inst.network.drop_indirect(r.inst.valves[0].short)
        with pytest.raises(RouteError):
            await r.clock.run_task(read(r))
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (0, 0)


async def test_expiry_then_timeout_raises_timeout() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short)
        valve.drop_rate = 1.0  # the retry reaches the valve, which never answers
        with pytest.raises(RequestTimeoutError):
            await r.clock.run_task(read(r))
        stats = r.node.stats
        assert (stats.indirect_retries, stats.timeouts) == (1, 1)


async def test_no_indirect_capacity_retries_after_a_delay() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, status=NWK_STATUS_NO_INDIRECT_CAPACITY, delay=0.5)
        start = r.clock.now()
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        elapsed = 0.5 + NO_INDIRECT_CAPACITY_RETRY_DELAY + LATENCY
        assert r.clock.now() - start == pytest.approx(elapsed)
        assert r.node.stats.indirect_retries == 1


async def test_late_answer_to_the_dropped_attempt_still_resolves() -> None:
    # The parent claims expiry, yet the valve got attempt 1: its answer resolves the request
    # during attempt 2 (same key).
    async with rig() as r:
        valve = r.inst.valves[0]
        task = read(r)
        start = r.clock.now()
        await r.clock.advance(1.0)
        r.inject(status_npdu(r, status=EXPIRY, about=valve.short))
        records = await r.clock.run_task(task)
        assert records[0].status == 0
        assert r.clock.now() - start == pytest.approx(LATENCY)
        assert r.node.stats.indirect_retries == 1
        assert len(zcl_tsns(r)) == 2


async def _route_error_after_one_attempt(r: Rig, code: int) -> RouteError:
    valve = r.inst.valves[0]
    task = read(r)
    await r.clock.advance(1.0)
    r.inject(status_npdu(r, status=code, about=valve.short))
    await r.clock.advance(0)
    with pytest.raises(RouteError) as exc:
        await task
    return exc.value


@pytest.mark.parametrize("code", [0x00, 0x01, 0x02, 0x03, 0x0B, 0x0C])
async def test_other_codes_stay_final(code: int) -> None:
    async with rig() as r:
        error = await _route_error_after_one_attempt(r, code)
        assert error.status == code
        assert len(zcl_tsns(r)) == 1  # never resent
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (0, 0)


async def test_expiry_with_nothing_pending_is_harmless() -> None:
    async with rig() as r:
        valve, other = r.inst.valves[0], r.inst.valves[1]
        r.inject(status_npdu(r, status=EXPIRY, about=valve.short))  # nothing pending at all
        await r.clock.advance(0)
        task = read(r)
        await r.clock.advance(1.0)
        r.inject(status_npdu(r, status=EXPIRY, about=other.short))  # pending, other device
        await r.clock.advance(0)
        assert not task.done()
        records = await r.clock.run_task(task)
        assert records[0].status == 0
        stats = r.node.stats
        assert (stats.network_status, stats.indirect_retries, stats.retransmits) == (2, 0, 0)
        r.inject(status_npdu(r, status=EXPIRY, about=valve.short))  # after the request ended
        await r.clock.advance(0)
        assert stats.network_status == 3
        assert r.node.stats.indirect_retries == 0


async def test_cancel_during_the_capacity_delay_retires_the_key() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, status=NWK_STATUS_NO_INDIRECT_CAPACITY, delay=0.5)
        tsn = r.core.allocators.tsn.peek()
        task = read(r)
        await r.clock.advance(1.0)  # status at 0.5, now inside the retry delay
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(r.core.pending) == 0
        assert r.core.pending.is_retired((valve.short, "zcl", tsn))
        assert len(zcl_tsns(r)) == 1
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (0, 0)


# --- end to end ------------------------------------------------------------------------------


async def test_e2e_expiry_retry_is_not_a_miss() -> None:
    r = e2e_rig()
    gen = await begin(r)
    valve = r.inst.valves[0]
    r.inst.network.drop_indirect(valve.short, status=nf.NETWORK_STATUS_INDIRECT_EXPIRY)
    snap = await poll(r)
    assert snap.misses[valve.eui] == 0
    assert snap.available[valve.eui] is True
    assert gen.node.stats.indirect_retries == 1
    await stop(r)


async def test_e2e_expiry_on_every_attempt_is_a_miss() -> None:
    r = e2e_rig()
    gen = await begin(r)
    valve = r.inst.valves[0]
    r.inst.network.drop_indirect(valve.short, count=3)
    snap = await poll(r)
    assert snap.misses[valve.eui] == 1  # RouteError, as before the retry
    assert snap.misses[r.inst.valves[1].eui] == 0
    assert gen.node.stats.indirect_retries == 2
    snap = await poll(r)
    assert snap.misses[valve.eui] == 0
    await stop(r)


# --- attribution and backoff races (review of 2bea1e4) ----------------------------------------


async def test_status_arriving_during_the_send_ends_that_attempt() -> None:
    # The attempt is armed before the write: a status landing while the write completes
    # still ends it (it used to find no signal and wait for the full request timeout).
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.r0.write_latency = 1.0
        r.inst.network.drop_indirect(valve.short, delay=0.5)
        start = r.clock.now()
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        assert r.clock.now() - start < r.node.config.request_timeout
        stats = r.node.stats
        assert (stats.indirect_retries, stats.retransmits, stats.timeouts) == (1, 1, 0)


async def test_delayed_status_of_a_timed_out_attempt_does_not_end_the_next() -> None:
    # Attempt 1 is dropped and times out at 5 s; its 0x06 arrives at 8.8 s, during attempt 2.
    # FIFO attribution consumes it for attempt 1, so attempt 2's answer at 9 s resolves.
    async with rig(config=NodeConfig(request_timeout=5.0), latency=4.0) as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, delay=SIM_INDIRECT_EXPIRY_DELAY)
        start = r.clock.now()
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        assert r.clock.now() - start == pytest.approx(9.0)
        stats = r.node.stats
        assert (stats.indirect_retries, stats.retransmits, stats.timeouts) == (0, 1, 0)
        assert stats.late_drops == 0
        assert stats.network_status == 1


async def test_two_statuses_for_two_attempts_are_attributed_in_order() -> None:
    # One status per dropped frame: the first ends attempt 1 early, the second attempt 2.
    async with rig(config=NodeConfig(request_attempts=3)) as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, count=2, delay=1.0)
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        stats = r.node.stats
        assert (stats.indirect_retries, stats.retransmits, stats.timeouts) == (2, 2, 0)


async def test_node_close_during_the_capacity_delay_fails_at_once() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, status=NWK_STATUS_NO_INDIRECT_CAPACITY, delay=0.5)
        task = read(r)
        await r.clock.advance(1.0)  # status at 0.5, now inside the retry delay
        now = r.clock.now()
        await r.node.close()
        await r.clock.advance(0)
        assert task.done()
        with pytest.raises(ConnectionLostError):
            await task
        assert r.clock.now() == now
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (0, 0)
        assert len(zcl_tsns(r)) == 1


async def test_answer_during_the_capacity_delay_resolves_at_once() -> None:
    # The parent claims no capacity, yet the valve got attempt 1 and answers during the delay.
    async with rig(latency=2.0) as r:
        valve = r.inst.valves[0]
        task = read(r)
        start = r.clock.now()
        await r.clock.advance(1.0)
        r.inject(status_npdu(r, status=NWK_STATUS_NO_INDIRECT_CAPACITY, about=valve.short))
        records = await r.clock.run_task(task)
        assert records[0].status == 0
        assert r.clock.now() - start == pytest.approx(2.0)
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (0, 0)
        assert len(zcl_tsns(r)) == 1


async def test_resend_that_fails_to_send_is_not_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short, status=NWK_STATUS_NO_INDIRECT_CAPACITY, delay=0.5)
        task = read(r)
        await r.clock.advance(1.0)  # status at 0.5, now inside the retry delay
        core = r.node._core

        async def broken(npdu: bytes, check: object = None) -> None:
            raise ConnectionLostError("write failed")

        monkeypatch.setattr(core, "send_secure", broken)
        await r.clock.advance(NO_INDIRECT_CAPACITY_RETRY_DELAY)
        with pytest.raises(ConnectionLostError):
            await task
        assert (r.node.stats.indirect_retries, r.node.stats.retransmits) == (0, 0)
        assert len(zcl_tsns(r)) == 1


async def test_resends_are_logged_with_their_cause(caplog: pytest.LogCaptureFixture) -> None:
    # Hardware 2026-10-15: a drop was followed by an answer with no visible resend line.
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.drop_indirect(valve.short)
        tsn = r.core.allocators.tsn.peek()
        with caplog.at_level("DEBUG", logger="vicare_local_ble.zigbee_direct.node"):
            await r.clock.run_task(read(r))
        assert f"zcl seq {tsn} to 0x{valve.short:04X}: attempt 1 sent (after a drop)" in (
            caplog.text
        )

        valve.drop_rate = 1.0
        caplog.clear()
        with (
            caplog.at_level("DEBUG", logger="vicare_local_ble.zigbee_direct.node"),
            pytest.raises(RequestTimeoutError),
        ):
            await r.clock.run_task(read(r))
        assert "attempt 1 sent (after a timeout)" in caplog.text
        assert "attempt 0 sent" not in caplog.text
