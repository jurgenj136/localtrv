"""ZigbeeDirectNode requests: the per-attempt ``guard`` and ``expect_ieee`` (review round 4)."""

from __future__ import annotations

import pytest

from localtrv.zigbee_direct.codec.nwk import NwkFrame
from localtrv.zigbee_direct.types import Eui64
from test_node import rig
from test_node_requests import read

OTHER = Eui64.from_str("02:00:00:00:00:09:00:01")


class GuardFailedError(Exception):
    pass


async def test_guard_runs_before_every_attempt_and_stops_the_retransmit() -> None:
    async with rig() as r:
        r.inst.valves[0].drop_rate = 1.0
        calls: list[float] = []

        def guard() -> None:  # queued + transmitted once, then fails for the retransmit
            calls.append(r.clock.now())
            if len(calls) > 2:
                raise GuardFailedError

        with pytest.raises(GuardFailedError):
            await r.clock.run_task(read(r, guard=guard))
        attempts = [NwkFrame.decode(w) for w in r.writes()[4:]]
        assert len(attempts) == 1  # the retransmit was never sent
        assert len(calls) == 3
        assert r.core.pending.for_src(r.inst.valves[0].short) == ()


async def test_guard_is_checked_again_when_the_writer_dequeues() -> None:
    async with rig() as r:
        calls: list[float] = []

        def guard() -> None:  # passes when queued, fails at transmission
            calls.append(r.clock.now())
            if len(calls) > 1:
                raise GuardFailedError

        with pytest.raises(GuardFailedError):
            await r.clock.run_task(read(r, guard=guard))
        assert r.writes()[4:] == []  # the frame never reached the GATT write
        assert not r.transport.broken
        assert await r.clock.run_task(read(r))  # the node and transport still work


async def test_guard_failing_first_sends_nothing() -> None:
    async with rig() as r:

        def guard() -> None:
            raise GuardFailedError

        with pytest.raises(GuardFailedError):
            await r.clock.run_task(read(r, guard=guard))
        assert r.writes()[4:] == []


async def test_answer_naming_another_sender_times_out() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inst.network.reply_src_ieee[valve.short] = OTHER
        with pytest.raises(TimeoutError):
            await r.clock.run_task(read(r, expect_ieee=valve.eui))
        assert r.node.stats.unmatched >= 1
        r.inst.network.reply_src_ieee[valve.short] = valve.eui
        records = await r.clock.run_task(read(r, expect_ieee=valve.eui))
        assert records
