"""APS ack send path: ``node_acks.ApsAcker`` (unit) and the node end to end on the simulator."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from fixtures import golden as g
from test_node import rig
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID, ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError
from vicare_local_ble.zigbee_direct.frames import aps_ack_npdu
from vicare_local_ble.zigbee_direct.node_acks import MAX_ACKS_IN_FLIGHT, ApsAcker
from vicare_local_ble.zigbee_direct.node_types import NodeStats
from vicare_local_ble.zigbee_direct.requests import Allocators

if TYPE_CHECKING:
    from collections.abc import Coroutine

    import pytest

h = g.h


def report_aps(counter: int = 0x51) -> ApsDataFrame:
    return ApsDataFrame(
        cluster_id=0x0201,
        profile_id=HA_PROFILE_ID,
        payload=h("18 2F 0A 00 00 29 AD 07"),
        dst_endpoint=1,
        src_endpoint=1,
        counter=counter,
        ack_request=True,
    )


class FakeHost:
    """``AckHost`` whose sends block until ``release`` (or fail with ``error``)."""

    def __init__(self) -> None:
        self.stats = NodeStats()
        self.allocators = Allocators.create()
        self.own_short = g.ZVD_SHORT
        self.sent: list[bytes] = []
        self.release = asyncio.Event()
        self.error: Exception | None = None
        self.closed = False
        self.tasks: set[asyncio.Task[None]] = set()

    async def send_secure(self, npdu: bytes) -> None:
        await self.release.wait()
        if self.error is not None:
            raise self.error
        self.sent.append(npdu)

    def start_task(self, coro: Coroutine[Any, Any, None], *, name: str) -> asyncio.Task[None]:
        if self.closed:
            coro.close()
            raise ConnectionLostError("node is closed")
        task = asyncio.get_running_loop().create_task(coro, name=name)
        self.tasks.add(task)
        return task


async def test_ack_is_built_and_sent_from_a_task() -> None:
    host = FakeHost()
    acker = ApsAcker(host)
    seq = host.allocators.nwk.next() + 1  # the next NWK seq the acker will draw
    acker.ack(g.VALVE_SHORT, report_aps())
    assert acker.in_flight == 1
    assert host.sent == []  # nothing sent synchronously
    host.release.set()
    await asyncio.gather(*host.tasks)
    expected = aps_ack_npdu(
        dst=g.VALVE_SHORT, own_short=g.ZVD_SHORT, nwk_seq=seq & 0xFF, inbound=report_aps()
    )
    assert host.sent == [expected]
    assert (host.stats.aps_acks_sent, host.stats.aps_ack_failures) == (1, 0)
    assert acker.in_flight == 0


async def test_send_failure_is_counted_not_raised() -> None:
    host = FakeHost()
    acker = ApsAcker(host)
    host.error = ConnectionLostError("write failed")
    host.release.set()
    acker.ack(g.VALVE_SHORT, report_aps())
    await asyncio.gather(*host.tasks)
    assert (host.stats.aps_acks_sent, host.stats.aps_ack_failures) == (0, 1)
    assert acker.in_flight == 0


async def test_closed_node_counts_a_failure() -> None:
    host = FakeHost()
    host.closed = True
    acker = ApsAcker(host)
    acker.ack(g.VALVE_SHORT, report_aps())
    assert (host.stats.aps_ack_failures, acker.in_flight) == (1, 0)


async def test_in_flight_acks_are_bounded() -> None:
    host = FakeHost()
    acker = ApsAcker(host)
    for counter in range(MAX_ACKS_IN_FLIGHT + 3):
        acker.ack(g.VALVE_SHORT, report_aps(counter))
    assert acker.in_flight == MAX_ACKS_IN_FLIGHT
    assert host.stats.aps_ack_failures == 3
    host.release.set()
    await asyncio.gather(*host.tasks)
    assert host.stats.aps_acks_sent == MAX_ACKS_IN_FLIGHT
    assert acker.in_flight == 0


async def test_cancelled_before_first_step_releases_its_slot() -> None:
    host = FakeHost()
    acker = ApsAcker(host)
    acker.ack(g.VALVE_SHORT, report_aps())
    (task,) = host.tasks
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert acker.in_flight == 0
    assert (host.stats.aps_acks_sent, host.stats.aps_ack_failures) == (0, 0)


# --- node on the simulator -------------------------------------------------------------------


async def test_node_acks_an_injected_report_through_the_tunnel() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        before = len(r.writes())
        r.inject(r.from_valve(valve.short, report_aps(0x51)))
        await r.clock.advance(0)
        (ack,) = r.writes()[before:]
        frame = NwkFrame.decode(ack)
        assert (frame.dst, frame.src) == (valve.short, r.node.own_short)
        assert frame.payload == h("02 01 0102 0401 01 51")
        assert r.node.stats.aps_acks_sent == 1
        assert r.node.stats.reports == 1


async def test_real_responses_are_acked_and_nothing_is_retransmitted() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        await r.clock.run_task(r.node.zcl_read(valve.short, 1, 0x0201, [0x0000]))
        await r.clock.advance(10.0)  # well past apsAckWaitDuration x retries
        assert r.node.stats.aps_acks_sent == 1
        assert r.inst.network.aps.acks_received == 1
        assert r.inst.network.aps.retransmits == 0
        assert r.node.stats.late_drops == 0


async def test_close_awaits_a_pending_ack_task(monkeypatch: pytest.MonkeyPatch) -> None:
    async with rig() as r:
        started = asyncio.Event()

        async def stuck(_npdu: bytes) -> None:
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(r.core, "send_secure", stuck)
        r.inject(r.from_valve(r.inst.valves[0].short, report_aps()))
        await r.clock.advance(0)
        assert started.is_set()
        assert r.core.task_count >= 1
        await r.node.close()
        assert r.core.task_count == 0
        assert r.node.stats.aps_acks_sent == 0


async def test_ack_after_close_is_counted_as_failure() -> None:
    async with rig() as r:
        await r.node.close()
        r.core.ack_aps(r.inst.valves[0].short, report_aps())
        assert r.node.stats.aps_ack_failures == 1
