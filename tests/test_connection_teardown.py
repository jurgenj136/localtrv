"""ZdConnection: generation teardown order, stale events, spawn ownership, diagnostics."""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import TYPE_CHECKING, Any

import pytest

from localtrv.testing.gatt import WriteFaultSpec
from localtrv.testing.gatt_client import FakeBleakClient
from localtrv.zigbee_direct.debug import NpduRecorder
from localtrv.zigbee_direct.errors import ConnectionLostError, TransportError
from localtrv.zigbee_direct.transport import ZigbeeDirectTransport
from localtrv.zigbee_direct.uuids import TUNNEL_NPDU
from test_connection import S, assert_no_tasks, make_rig, ready_again, run_until, start, stop

if TYPE_CHECKING:
    from collections.abc import Callable

    from bleak.backends.device import BLEDevice
    from bleak_retry_connector import BleakClientWithServiceCache

    from localtrv.zigbee_direct.connection import Generation
    from localtrv.zigbee_direct.transport import FatalHandler, GattClient


def capture_fatal_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[ZigbeeDirectTransport, FatalHandler]]:
    """Record every (transport, fatal handler) the connection installs."""
    seen: list[tuple[ZigbeeDirectTransport, FatalHandler]] = []
    original = ZigbeeDirectTransport.set_fatal_handler

    def record(self: ZigbeeDirectTransport, handler: FatalHandler) -> None:
        seen.append((self, handler))
        original(self, handler)

    monkeypatch.setattr(ZigbeeDirectTransport, "set_fatal_handler", record)
    return seen


async def test_teardown_order(monkeypatch: pytest.MonkeyPatch) -> None:
    r = make_rig()
    events: list[str] = []

    async def worker() -> None:
        try:
            await asyncio.get_running_loop().create_future()
        except asyncio.CancelledError:
            events.append("task cancelled")
            await asyncio.sleep(0)  # the teardown must wait for this
            events.append("task done")
            raise

    def on_ready(gen: Generation) -> None:
        r.conn.spawn(gen, worker(), name="worker")

    r.conn.add_ready_listener(on_ready)
    r.conn.add_state_listener(lambda state: events.append(f"state {state.value}"))
    gen = await start(r)

    node_close = gen.node.close

    async def close_node(exc: BaseException | None = None) -> None:
        assert isinstance(exc, ConnectionLostError)
        events.append("node.close")
        await node_close(exc)

    monkeypatch.setattr(gen.node, "close", close_node)
    transport_close = ZigbeeDirectTransport.close

    async def close_transport(self: ZigbeeDirectTransport) -> None:
        events.append("transport.close")
        await transport_close(self)

    monkeypatch.setattr(ZigbeeDirectTransport, "close", close_transport)
    disconnect = FakeBleakClient.disconnect

    async def disconnect_client(self: FakeBleakClient) -> None:
        events.append("client.disconnect")
        await disconnect(self)

    monkeypatch.setattr(FakeBleakClient, "disconnect", disconnect_client)
    events.clear()
    r.conn.request_rejoin(gen, "test")
    await ready_again(r, gen.number)
    assert events[:7] == [
        "state backoff",  # leaves READY first
        "task cancelled",
        "task done",
        "node.close",
        "transport.close",
        "client.disconnect",
        "state connecting",  # only then the next attempt
    ]
    assert r.conn.stats.last_failure == "rejoin:test"
    assert r.conn.stats.rejoins == 1
    await stop(r)
    assert_no_tasks()


async def test_disconnect_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    r = make_rig()
    gen = await start(r)

    async def hang(self: FakeBleakClient) -> None:
        await asyncio.get_running_loop().create_future()

    monkeypatch.setattr(FakeBleakClient, "disconnect", hang)
    t0 = r.clock.now()
    r.conn.request_rejoin(gen, "test")
    await run_until(r.clock, lambda: len(r.entered(S.CONNECTING)) == 2)
    # 5 s disconnect bound, then a backoff of 2 s +-20 %
    assert 5.0 + 1.6 <= r.entered(S.CONNECTING)[-1] - t0 <= 5.0 + 2.4
    monkeypatch.undo()
    await stop(r)


async def test_stale_disconnect_callback_ignored() -> None:
    r = make_rig()
    callbacks: list[tuple[Callable[[GattClient], None], GattClient]] = []
    inner = r.inst.connector

    async def connector(
        client_class: type[BleakClientWithServiceCache],
        device: BLEDevice,
        name: str,
        disconnected_callback: Callable[[GattClient], None] | None = None,
        **kwargs: Any,
    ) -> GattClient:
        client = await inner(client_class, device, name, disconnected_callback, **kwargs)
        assert disconnected_callback is not None
        callbacks.append((disconnected_callback, client))
        return client

    r.conn._connector = connector
    gen1 = await start(r)
    r.inst.r0.disconnect()
    gen2 = await ready_again(r, gen1.number)
    assert r.conn.stats.disconnects == 1
    old_callback, old_client = callbacks[0]
    old_callback(old_client)  # a late callback for the first client
    await r.clock.advance(60.0)
    assert r.conn.current is gen2
    assert r.conn.state is S.READY
    assert r.conn.stats.disconnects == 1
    await stop(r)


async def test_stale_fatal_and_rejoin_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    handlers = capture_fatal_handlers(monkeypatch)
    r = make_rig()
    gen1 = await start(r)
    r.conn.request_rejoin(gen1, "first")
    r.conn.request_rejoin(gen1, "again")  # the same generation: once
    gen2 = await ready_again(r, gen1.number)
    assert r.conn.stats.rejoins == 1
    _old_transport, old_handler = handlers[0]
    old_handler(TransportError("late", reason="write"))
    r.conn.request_rejoin(gen1, "stale")
    await r.clock.advance(60.0)
    assert r.conn.current is gen2
    assert r.conn.stats.rejoins == 1
    assert r.conn.stats.last_failure == "rejoin:first"
    # a fatal error of the current transport does tear down
    _transport, handler = handlers[-1]
    handler(TransportError("boom", reason="write"))
    gen3 = await ready_again(r, gen2.number)
    assert r.conn.stats.last_failure == "transport:write"
    assert r.conn.stats.last_transport_error == "write"
    assert gen3.number == 3
    await stop(r)
    r.conn.request_rejoin(gen3, "stopped")  # ignored after stop
    assert r.conn.stats.rejoins == 1


async def test_transport_fatal_from_writer_reconnects() -> None:
    r = make_rig()
    gen = await start(r)
    r.inst.r0.inject_write_fault(WriteFaultSpec("raise", TUNNEL_NPDU))
    task = r.conn.spawn(gen, gen.node.send_mtorr(), name="mtorr")
    await ready_again(r, gen.number)
    assert task.done()
    assert r.conn.stats.last_failure == "transport:write"
    assert r.conn.stats.disconnects == 0
    await stop(r)


async def test_spawned_tasks_cancelled_and_awaited() -> None:
    r = make_rig()
    gen = await start(r)
    finished: list[str] = []

    async def forever() -> None:
        try:
            await asyncio.get_running_loop().create_future()
        finally:
            finished.append("forever")

    async def quick() -> int:
        return 42

    task = r.conn.spawn(gen, forever(), name="forever")
    result = r.conn.spawn(gen, quick(), name="quick")
    assert task.get_name() == "forever"
    await r.clock.advance(0)
    assert await result == 42
    r.inst.r0.disconnect()
    await ready_again(r, gen.number)
    assert task.cancelled()
    assert finished == ["forever"]
    await stop(r)
    assert_no_tasks()


async def test_spawn_on_dead_generation_closes_coroutine() -> None:
    r = make_rig()
    gen = await start(r)
    r.inst.r0.disconnect()
    await ready_again(r, gen.number)

    async def work() -> None:  # pragma: no cover - never runs
        return None

    coro = work()
    with pytest.raises(ConnectionLostError):
        r.conn.spawn(gen, coro, name="late")
    assert inspect.getcoroutinestate(coro) == inspect.CORO_CLOSED
    await stop(r)
    coro2 = work()
    with pytest.raises(ConnectionLostError):
        r.conn.spawn(gen, coro2, name="after stop")
    assert inspect.getcoroutinestate(coro2) == inspect.CORO_CLOSED


async def test_spawned_task_failure_logged_and_reraised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    r = make_rig()
    gen = await start(r)

    async def fail() -> None:
        raise ValueError("bridge bug")

    task = r.conn.spawn(gen, fail(), name="poller")
    await r.clock.advance(0)
    warnings = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
    assert any("poller" in rec.getMessage() for rec in warnings)
    with pytest.raises(ValueError, match="bridge bug"):
        await task
    assert r.conn.state is S.READY  # swallowed: no teardown
    await stop(r)


async def test_ready_listener_may_spawn_and_rejoin() -> None:
    r = make_rig()
    rejoined: list[int] = []

    def on_ready(gen: Generation) -> None:
        r.conn.spawn(gen, asyncio.sleep(0), name="probe")
        if gen.number == 1:
            rejoined.append(gen.number)
            r.conn.request_rejoin(gen, "from_listener")

    r.conn.add_ready_listener(on_ready)
    gen = await start(r)  # start resolves with the first READY generation
    assert gen.number == 1
    await ready_again(r, 1)
    assert rejoined == [1]
    await stop(r)
    assert_no_tasks()


async def test_diagnostics_survive_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    handlers = capture_fatal_handlers(monkeypatch)
    recorder = NpduRecorder()
    r = make_rig(recorder=recorder)
    gen1 = await start(r)
    first_records = len(recorder.records())
    assert first_records > 0
    assert r.conn.recorder is recorder
    r.inst.r0.disconnect()
    gen2 = await ready_again(r, gen1.number)
    assert len(recorder.records()) > first_records  # one recorder across generations
    transports = [t for t, _ in handlers]
    assert len(transports) == 2
    assert all(t._recorder is recorder for t in transports)
    await stop(r)
    assert r.conn.last_join == gen2.join
    assert r.conn.transport_stats is transports[-1].stats
    assert r.conn.transport_stats.frames_tx > 0
    snapshot = r.conn.last_node_stats
    assert snapshot is not None
    assert snapshot is not gen2.node.stats  # a final snapshot after teardown
    assert snapshot == gen2.node.stats
    assert snapshot.mtorr_sent >= 1


async def test_stop_during_teardown_finishes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    r = make_rig()
    gen = await start(r)
    disconnected: list[float] = []

    async def slow(self: FakeBleakClient) -> None:
        await r.clock.sleep(3.0)
        disconnected.append(r.clock.now())

    monkeypatch.setattr(FakeBleakClient, "disconnect", slow)
    r.conn.request_rejoin(gen, "test")
    await r.clock.advance(1.0)  # inside the bounded disconnect
    t0 = r.clock.now()
    await stop(r)  # waits for the running teardown instead of cutting it short
    assert disconnected == [pytest.approx(t0 + 2.0)]
    assert r.sequence()[-1] is S.STOPPED
    assert r.conn.stats.attempts == 1  # no further attempt
    assert_no_tasks()
