"""ZigbeeDirectNode routing: Network Status, address conflicts, RREQ counting, MTORR tasks."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import pytest

from test_node import LOCAL_TEMPERATURE, LOGGER, THERMOSTAT, Rig, rig
from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    NetworkStatus,
    RouteRequest,
    decode_nwk_command,
)
from vicare_local_ble.zigbee_direct.errors import RouteError
from vicare_local_ble.zigbee_direct.node import NodeConfig, RouteReplyMode
from vicare_local_ble.zigbee_direct.requests import PendingMap
from vicare_local_ble.zigbee_direct.routing import (
    MTORR_ON_ROUTE_FAILURE_INTERVAL,
    NWK_STATUS_ADDRESS_CONFLICT,
    NWK_STATUS_MANY_TO_ONE_ROUTE_FAILURE,
    NWK_STATUS_NO_ROUTE_AVAILABLE,
    ROUTE_FAILURE_STATUSES,
    NeighborTable,
    Router,
)
from vicare_local_ble.zigbee_direct.types import BROADCAST_RX_ON, COORDINATOR, Eui64

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce


def boom(*_args: object) -> None:
    raise RuntimeError("listener bug")


def status_npdu(r: Rig, *, status: int, about: int, dst: int | None = None) -> bytes:
    return nf.network_status_npdu(
        dst=r.node.own_short if dst is None else dst,
        src=r.inst.r0.zdd_short,
        seq=0x55,
        status=status,
        about=about,
    )


def mtorrs(r: Rig) -> int:
    count = 0
    for raw in r.writes():
        frame = NwkFrame.decode(raw)
        if frame.frame_type.name == "COMMAND" and isinstance(
            decode_nwk_command(frame.payload), RouteRequest
        ):
            count += 1
    return count


def read(r: Rig, index: int = 0) -> asyncio.Future[object]:
    valve = r.inst.valves[index]
    return asyncio.ensure_future(r.node.zcl_read(valve.short, 1, THERMOSTAT, [LOCAL_TEMPERATURE]))


async def test_network_status_for_pending_dst_raises_route_error_and_one_mtorr() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        task = read(r)
        await r.clock.advance(1.0)
        r.inject(status_npdu(r, status=0x02, about=valve.short))
        await r.clock.advance(0)
        with pytest.raises(RouteError) as exc:
            await task
        assert (exc.value.dst, exc.value.status) == (valve.short, 0x02)
        assert mtorrs(r) == 3  # 2 at join + 1 after the route failure
        assert len(r.core.pending) == 0
        # rate limit: a second 0x02 inside 30 s schedules nothing
        r.inject(status_npdu(r, status=0x02, about=valve.short))
        await r.clock.advance(MTORR_ON_ROUTE_FAILURE_INTERVAL - 2.0)
        r.inject(status_npdu(r, status=0x02, about=valve.short))
        await r.clock.advance(0)
        assert mtorrs(r) == 3
        await r.clock.advance(2.0)
        r.inject(status_npdu(r, status=0x02, about=valve.short))
        await r.clock.advance(0)
        assert mtorrs(r) == 4
        assert r.node.stats.network_status == 4


async def test_other_route_status_fails_without_mtorr() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        task = read(r)
        await r.clock.advance(1.0)
        r.inject(status_npdu(r, status=0x03, about=valve.short))  # not a route failure
        await r.clock.advance(0)
        with pytest.raises(RouteError):
            await task
        assert mtorrs(r) == 2


async def test_network_status_for_others_is_ignored() -> None:
    async with rig() as r:
        valve, other = r.inst.valves[0], r.inst.valves[1]
        task = read(r)
        await r.clock.advance(1.0)
        # broadcast status about our pending dst: never fails requests (dst filter)
        r.inject(status_npdu(r, status=0x02, about=valve.short, dst=BROADCAST_RX_ON))
        # unicast to someone else: dropped by the dispatcher's address filter
        r.inject(status_npdu(r, status=0x02, about=valve.short, dst=other.short))
        # unicast to us about another device: our request is untouched
        r.inject(status_npdu(r, status=0x02, about=other.short))
        await r.clock.advance(0)
        assert not task.done()
        await r.clock.run_task(task)
        assert r.node.stats.network_status == 2


async def test_address_conflict_fires_callback() -> None:
    async with rig() as r:
        calls: list[str] = []
        r.node.on_address_conflict(lambda: calls.append("a"))
        unsubscribe = r.node.on_address_conflict(lambda: calls.append("b"))
        r.node.on_address_conflict(boom)
        unsubscribe()
        unsubscribe()  # idempotent
        r.inst.network.address_conflict()
        await r.clock.advance(0)
        assert calls == ["a"]
        r.inject(status_npdu(r, status=0x0D, about=r.inst.valves[0].short, dst=BROADCAST_RX_ON))
        await r.clock.advance(0)
        assert calls == ["a"]  # a conflict about another short


async def test_network_status_handling_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async with rig() as r:
        monkeypatch.setattr(PendingMap, "fail_dst", boom)
        r.inject(status_npdu(r, status=0x02, about=r.inst.valves[0].short))
        await r.clock.advance(0)
        assert r.node.stats.network_status == 1
        assert r.node.stats.decode_errors == 0


async def test_network_status_before_join_is_ignored() -> None:
    async with rig(join=False) as r:
        npdu = nf.network_status_npdu(
            dst=BROADCAST_RX_ON, src=r.inst.r0.zdd_short, seq=1, status=0x0D, about=0x1234
        )
        r.inject(npdu)
        await r.clock.advance(0)
        assert r.node.stats.network_status == 1
        await r.clock.run_task(r.node.join())


async def test_route_request_is_counted_and_not_answered_when_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    # The RREP responder answers by default; with RREP off only counting/learning remains.
    async with rig(config=NodeConfig(route_reply_mode=RouteReplyMode.OFF)) as r:
        valve = r.inst.valves[0]
        r.inst.network.emit_route_request(valve.short, route_id=7)
        r.inst.network.emit_route_request(valve.short, route_id=8, dst=r.inst.valves[1].short)
        r.inst.network.emit_route_request(valve.short, route_id=9, with_src_ieee=False)
        await r.clock.advance(0)
        assert r.node.stats.rreq_seen == 3
        assert r.node.stats.rrep_sent == 0
        assert r.inst.network.route_replies == ()
        assert r.node.lookup_ieee(valve.short) == valve.eui  # learnt from the NWK src IEEE


async def test_device_annce_listener_and_neighbor_table() -> None:
    async with rig() as r:
        seen: list[tuple[DeviceAnnce, int]] = []
        r.node.on_device_annce(lambda a, src: seen.append((a, src)))
        r.node.on_device_annce(boom)
        valve = r.inst.valves[0]
        r.inst.network.valve_rejoin(valve, 0x0ABC)
        await r.clock.advance(0)
        ((annce, src),) = seen
        assert (annce.nwk_addr, annce.ieee, src) == (0x0ABC, valve.eui, 0x0ABC)
        assert r.node.lookup_ieee(0x0ABC) == valve.eui
        r.node.note_neighbors(r.inst.network.neighbor_table(COORDINATOR))
        assert r.node.lookup_ieee(r.inst.valves[1].short) == r.inst.valves[1].eui


async def test_report_listener_errors_are_swallowed() -> None:
    async with rig() as r:
        events: list[object] = []
        r.node.on_report(boom)
        r.node.on_report(events.append)
        r.inst.valves[0].report(THERMOSTAT, (LOCAL_TEMPERATURE,))
        await r.clock.advance(0)
        assert len(events) == 1


async def test_periodic_mtorr_runs_every_interval() -> None:
    async with rig() as r:
        interval = r.node.config.mtorr_interval
        await r.clock.advance(interval)
        assert r.node.stats.mtorr_sent == 3
        await r.clock.advance(interval)
        assert r.node.stats.mtorr_sent == 4
        r.core.router.start_periodic()  # idempotent while running
        await r.node.send_mtorr()
        assert r.node.stats.mtorr_sent == 5
        r.core.router.stop()
        r.core.router.stop()
        await r.clock.advance(interval)
        assert r.node.stats.mtorr_sent == 5


async def test_periodic_mtorr_survives_send_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    async with rig() as r:
        calls = 0
        original = Router.send_mtorr

        async def flaky(self: Router) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("boom")
            await original(self)

        monkeypatch.setattr(Router, "send_mtorr", flaky)
        interval = r.node.config.mtorr_interval
        await r.clock.advance(2 * interval)
        assert calls == 2
        assert r.node.stats.mtorr_sent == 3


def test_neighbor_table_latest_observation_wins() -> None:
    a, b = Eui64.from_str("02:00:00:00:00:00:00:0A"), Eui64.from_str("02:00:00:00:00:00:00:0B")
    table = NeighborTable()
    table.note(0x1111, a)
    table.note(0x2222, a)  # a moved to a new short
    assert table.ieee_for(0x1111) is None
    assert table.short_for(a) == 0x2222
    table.note(0x2222, b)  # the short was reused by b
    assert table.short_for(a) is None
    assert (table.ieee_for(0x2222), table.short_for(b)) == (b, 0x2222)
    table.note(0xFFFD, a)  # broadcasts are never noted
    assert len(table) == 1


@pytest.mark.parametrize("code", sorted(ROUTE_FAILURE_STATUSES))
async def test_every_route_failure_status_schedules_one_mtorr(code: int) -> None:
    async with rig() as r:
        about = r.inst.valves[0].short
        r.inject(status_npdu(r, status=code, about=about))
        await r.clock.advance(0)
        assert mtorrs(r) == 3


@pytest.mark.parametrize("code", [0x03, 0x0A, NWK_STATUS_ADDRESS_CONFLICT])
async def test_other_statuses_schedule_no_mtorr(code: int) -> None:
    async with rig() as r:
        r.inject(status_npdu(r, status=code, about=r.inst.valves[0].short))
        await r.clock.advance(0)
        assert mtorrs(r) == 2


async def test_route_failure_mtorr_rate_limit_is_shared_across_codes() -> None:
    async with rig() as r:
        about = r.inst.valves[0].short
        r.inject(status_npdu(r, status=NWK_STATUS_NO_ROUTE_AVAILABLE, about=about))
        await r.clock.advance(1.0)
        r.inject(status_npdu(r, status=NWK_STATUS_MANY_TO_ONE_ROUTE_FAILURE, about=about))
        # broadcast route failures never trigger it
        r.inject(status_npdu(r, status=0x00, about=about, dst=BROADCAST_RX_ON))
        await r.clock.advance(MTORR_ON_ROUTE_FAILURE_INTERVAL)
        assert mtorrs(r) == 3
        r.inject(status_npdu(r, status=0x0B, about=about))
        await r.clock.advance(0)
        assert mtorrs(r) == 4


async def test_network_status_after_close_never_raises() -> None:
    async with rig() as r:
        router, own = r.core.router, r.node.own_short
        await r.node.close()
        frame = NwkFrame.decode(status_npdu(r, status=0x02, about=0x0100))
        router.on_network_status(frame, NetworkStatus(0x02, 0x0100))  # start_task refuses
        assert frame.dst == own
