"""ZigbeeDirectNode lifecycle: close(), broken transports, node-owned tasks."""

from __future__ import annotations

import asyncio
import inspect
import random
from typing import TYPE_CHECKING

import pytest

from test_node import LOCAL_TEMPERATURE, THERMOSTAT, rig
from vicare_local_ble.testing import WriteFaultSpec
from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import ActiveEpReq, ActiveEpRsp
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, TransportError
from vicare_local_ble.zigbee_direct.node import NodeConfig, ZigbeeDirectNode
from vicare_local_ble.zigbee_direct.uuids import TUNNEL_NPDU

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from test_node import Rig


async def test_close_fails_pending_and_cancels_tasks() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        tasks = [
            asyncio.ensure_future(r.node.zcl_read(v.short, 1, THERMOSTAT, [LOCAL_TEMPERATURE]))
            for v in r.inst.valves
        ]
        queued = asyncio.ensure_future(
            r.node.zcl_read(valve.short, 1, THERMOSTAT, [LOCAL_TEMPERATURE])
        )
        await r.clock.advance(1.0)
        assert len(r.core.pending) == 3
        assert r.core.task_count == 1  # the periodic MTORR
        await r.node.close()
        assert r.node.closed
        assert r.core.task_count == 0
        for task in [*tasks, queued]:
            with pytest.raises(ConnectionLostError):
                await task
        assert len(r.core.pending) == 0
        await r.node.close()  # idempotent
        await r.clock.advance(r.node.config.mtorr_interval)
        assert r.node.stats.mtorr_sent == 2  # the periodic task is gone
        await r.clock.advance(20.0)  # valve replies after close are ignored
        assert r.node.stats.late_drops == r.node.stats.unmatched == 0


async def test_close_with_custom_exception() -> None:
    async with rig() as r:
        task = asyncio.ensure_future(
            r.node.zcl_read(r.inst.valves[0].short, 1, THERMOSTAT, [LOCAL_TEMPERATURE])
        )
        await r.clock.advance(1.0)
        boom = ConnectionLostError("generation ended")
        await r.node.close(boom)
        with pytest.raises(ConnectionLostError) as exc:
            await task
        assert exc.value is boom


def _api_calls(r: Rig) -> list[Callable[[], Awaitable[object] | object]]:
    valve = r.inst.valves[0].short
    record = AttributeRecord(0x0012, ZclDataType.INT16, 2000)
    return [
        r.node.join,
        lambda: r.node.zcl_read(valve, 1, THERMOSTAT, [0]),
        lambda: r.node.zcl_write(valve, 1, THERMOSTAT, [record]),
        lambda: r.node.zdo_request(valve, ActiveEpReq(0, valve), response=ActiveEpRsp),
        r.node.send_mtorr,
        lambda: r.node.on_report(lambda _e: None),
        lambda: r.node.on_device_annce(lambda _a, _s: None),
        lambda: r.node.on_address_conflict(lambda: None),
        lambda: r.node.note_neighbors(()),
        lambda: r.node.lookup_ieee(valve),
    ]


async def _invoke(call: Callable[[], Awaitable[object] | object]) -> object:
    result = call()
    return await result if inspect.isawaitable(result) else result


@pytest.mark.parametrize("index", range(10))
async def test_every_api_raises_after_close(index: int) -> None:
    async with rig() as r:
        await r.node.close()
        call = _api_calls(r)[index]
        with pytest.raises(ConnectionLostError):
            await _invoke(call)
        stats = r.node.stats  # properties stay readable for diagnostics
        assert stats.mtorr_sent == 2
        assert r.node.own_short == r.inst.network.joined_short


async def test_close_during_join_fails_the_join() -> None:
    async with rig(join=False) as r:
        join = asyncio.ensure_future(r.node.join())
        await r.clock.advance(0.5)
        assert r.core.join_slot.active is not None
        await r.node.close()
        with pytest.raises(ConnectionLostError):
            await join
        assert r.core.join_slot.active is None


async def test_broken_transport_surfaces_as_connection_lost() -> None:
    async with rig() as r:
        r.inst.r0.inject_write_fault(WriteFaultSpec("raise", TUNNEL_NPDU))
        with pytest.raises(ConnectionLostError) as exc:
            await r.clock.run_task(
                r.node.zcl_read(r.inst.valves[0].short, 1, THERMOSTAT, [LOCAL_TEMPERATURE])
            )
        assert isinstance(exc.value.__cause__, TransportError)
        assert r.transport.broken
        assert len(r.core.pending) == 0
        # the periodic MTORR ends on ConnectionLostError instead of retrying forever
        await r.clock.advance(r.node.config.mtorr_interval)
        assert r.core.task_count == 0
        with pytest.raises(ConnectionLostError) as exc:
            await r.node.send_mtorr()
        assert isinstance(exc.value.__cause__, TransportError)


async def test_broken_transport_during_join() -> None:
    async with rig(join=False) as r:
        r.inst.r0.inject_write_fault(WriteFaultSpec("raise", TUNNEL_NPDU))
        with pytest.raises(ConnectionLostError):
            await r.clock.run_task(r.node.join())


async def test_node_tasks_swallow_errors_and_refuse_after_close() -> None:
    async with rig() as r:

        async def fail() -> None:
            raise RuntimeError("boom")

        task = r.core.start_task(fail(), name="test-fail")
        await r.clock.advance(0)
        assert task.done()
        assert isinstance(task.exception(), RuntimeError)  # logged, marked retrieved
        await r.node.close()
        coro = fail()
        with pytest.raises(ConnectionLostError):
            r.core.start_task(coro, name="late")


async def test_frames_after_close_are_ignored() -> None:
    async with rig() as r:
        await r.node.close()
        r.inst.valves[0].report(THERMOSTAT, (LOCAL_TEMPERATURE,))
        await r.clock.advance(0)
        assert r.node.stats.reports == 0


async def test_constructor_needs_an_open_transport() -> None:
    async with rig() as r:
        spare = ZigbeeDirectNode(r.transport, clock=r.clock)  # default config and rng
        assert spare.config == NodeConfig()
        assert spare.join_info is None
        await spare.close()
        await r.transport.close()
        with pytest.raises(ValueError, match="open"):
            ZigbeeDirectNode(r.transport, clock=r.clock, rng=random.Random(0))  # noqa: S311
