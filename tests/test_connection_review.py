"""ZdConnection (T13): regressions from the CP4 adversarial review."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import pytest
from bleak.exc import BleakCharacteristicNotFoundError

from test_connection import S, assert_no_tasks, make_rig, ready_again, run_until, start, stop
from test_connection_faults import WRONG_KEY
from test_connection_teardown import capture_fatal_handlers
from vicare_local_ble.testing.gatt_client import FakeBleakClient
from vicare_local_ble.testing.scenario import default_installation
from vicare_local_ble.zigbee_direct.connection import BACKOFF_JITTER, validate_connection
from vicare_local_ble.zigbee_direct.connection_session import run_protected
from vicare_local_ble.zigbee_direct.connection_supervisor import ConnectionCore
from vicare_local_ble.zigbee_direct.errors import HandshakeRejectedError, TransportError
from vicare_local_ble.zigbee_direct.uuids import COMMISSIONING_STATUS

if TYPE_CHECKING:
    from collections.abc import Callable

    from test_connection import Rig
    from vicare_local_ble.zigbee_direct.connection import ConnectionState
    from vicare_local_ble.zigbee_direct.connection_session import Session
    from vicare_local_ble.zigbee_direct.node_types import JoinInfo


async def test_rejection_wins_over_disconnect_during_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1: the ZDD drops the link while the transport cleans up after SE3 0x80."""
    r = make_rig(network_key=WRONG_KEY)

    async def drop_link(self: FakeBleakClient, char: str) -> None:
        r.inst.r0.disconnect()  # the disconnect callback fires first ...
        await r.clock.sleep(0.1)  # ... while the cleanup is still awaiting

    monkeypatch.setattr(FakeBleakClient, "stop_notify", drop_link)
    with pytest.raises(HandshakeRejectedError):
        await start(r)
    assert r.conn.stats.disconnects == 2  # the race really happened, twice
    assert r.conn.stats.auth_failures == 2
    assert r.conn.state is S.AUTH_FAILED
    assert r.inst.r0.connect_count == 2
    await stop(r)
    assert_no_tasks()


async def test_cancelled_stop_does_not_fake_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    """#2: a bounded (cancelled) stop() must not let a second stop() return early."""
    r = make_rig()
    await start(r)
    done: list[float] = []

    async def slow(self: FakeBleakClient) -> None:
        await r.clock.sleep(3.0)
        done.append(r.clock.now())

    monkeypatch.setattr(FakeBleakClient, "disconnect", slow)
    first = asyncio.ensure_future(r.conn.stop())
    await r.clock.advance(1.0)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert done == []  # teardown still running
    await stop(r)
    assert len(done) == 1
    assert r.conn.state is S.STOPPED
    assert_no_tasks()


async def test_stop_from_a_spawned_task() -> None:
    r = make_rig()
    gen = await start(r)
    stopper = r.conn.spawn(gen, r.conn.stop(), name="stopper")
    await stop(r)
    assert stopper.done()
    assert r.conn.state is S.STOPPED
    assert r.inst.r0.client is None
    assert_no_tasks()


async def test_stop_right_after_start_interrupts_first_attempt() -> None:
    """#3: stop() before the supervisor's first step, with a hanging connector."""
    r = make_rig()
    r.inst.connector.hang_next()
    task = asyncio.ensure_future(r.conn.start())
    await asyncio.sleep(0)  # start() ran; the supervisor has not stepped yet
    await stop(r)
    with pytest.raises(Exception, match="stopped"):
        await task
    assert r.conn.state is S.STOPPED
    assert_no_tasks()


async def test_stop_while_connector_hangs_later() -> None:
    r = make_rig()
    gen = await start(r)
    r.inst.connector.hang_next()
    r.conn.request_rejoin(gen, "test")
    await run_until(r.clock, lambda: len(r.entered(S.CONNECTING)) == 2)
    await r.clock.advance(5.0)
    await stop(r)
    assert r.conn.state is S.STOPPED
    assert_no_tasks()


async def test_missing_characteristic_during_join_clears_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#4: the Commissioning Status read (join) hits a stale GATT cache."""
    r = make_rig()
    original = FakeBleakClient.read_gatt_char
    reads: list[int] = []

    async def stale_once(self: FakeBleakClient, char: str) -> bytearray:
        reads.append(1)
        if char == COMMISSIONING_STATUS and len(reads) == 1:
            raise BleakCharacteristicNotFoundError(char)
        return await original(self, char)

    monkeypatch.setattr(FakeBleakClient, "read_gatt_char", stale_once)
    gen = await start(r)
    assert gen.number == 1
    assert r.conn.stats.cache_clears == 1
    assert S.BACKOFF not in r.sequence()
    await stop(r)


async def test_missing_characteristic_from_fatal_handler_clears_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers = capture_fatal_handlers(monkeypatch)
    r = make_rig()
    gen = await start(r)
    _transport, handler = handlers[-1]
    handler(TransportError("gone", reason="missing_characteristic"))
    await ready_again(r, gen.number)
    assert r.conn.stats.cache_clears == 1
    assert r.backoffs() == [pytest.approx(0.0)]  # left READY, then reconnected without a wait
    await stop(r)


async def test_teardown_bounds_tasks_ignoring_cancellation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """#5: a spawned task that ignores cancellation delays teardown by at most 10 s."""
    r = make_rig()
    gen = await start(r)
    release = asyncio.Event()

    async def stubborn() -> None:
        while not release.is_set():
            try:
                await r.clock.sleep(1000.0)
            except asyncio.CancelledError:
                continue

    task = r.conn.spawn(gen, stubborn(), name="stubborn")
    t0 = r.clock.now()
    r.conn.request_rejoin(gen, "test")
    await run_until(r.clock, lambda: len(r.entered(S.CONNECTING)) == 2)
    assert 10.0 + 1.6 <= r.entered(S.CONNECTING)[-1] - t0 <= 10.0 + 2.4
    warnings = [rec.getMessage() for rec in caplog.records if rec.levelno == logging.WARNING]
    assert any("stubborn" in w for w in warnings)
    release.set()
    task.cancel()
    await r.clock.advance(0)
    await stop(r)
    assert_no_tasks()


async def test_unexpected_cycle_error_fails_start_and_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#6: a bug in a cycle never leaves a zombie supervisor."""
    r = make_rig()
    original = ConnectionCore._become_ready
    calls: list[int] = []

    def flaky(self: ConnectionCore, session: Session, join: JoinInfo) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("supervisor bug")
        original(self, session, join)

    monkeypatch.setattr(ConnectionCore, "_become_ready", flaky)
    with pytest.raises(RuntimeError, match="supervisor bug"):
        await start(r)
    gen = await ready_again(r, 0)
    assert r.conn.state is S.READY
    assert r.entered(S.BACKOFF)  # retried after the backoff
    assert gen.number == 1
    await stop(r)
    assert_no_tasks()


def _entered(r: Rig, state: ConnectionState, count: int) -> Callable[[], bool]:
    return lambda: len(r.entered(state)) >= count


async def test_notify_seen_uses_the_unjittered_base() -> None:
    """#9: the 30 s step is shortenable even when jitter makes it shorter than 30 s."""
    below = 0
    for seed in range(8):
        r = make_rig(seed=seed)
        r.inst.connector.fail_next(4)
        task = asyncio.ensure_future(r.conn.start(first_ready_timeout=10_000.0))
        await run_until(r.clock, _entered(r, S.BACKOFF, 4))  # base 30 s
        wait = r.conn.stats.backoff
        assert wait is not None
        assert 30.0 * (1 - BACKOFF_JITTER) <= wait <= 30.0 * (1 + BACKOFF_JITTER)
        below += wait < 30.0
        t0 = r.clock.now()
        await r.clock.advance(1.0)
        r.conn.notify_seen()
        await run_until(r.clock, _entered(r, S.CONNECTING, 5))
        assert r.entered(S.CONNECTING)[-1] - t0 == pytest.approx(3.0)
        await r.clock.run_task(task)
        await stop(r)
    assert below > 0  # at least one jittered wait was under 30 s


async def test_validate_connection_disconnect_survives_repeated_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#11: cancelling validate_connection during its disconnect cannot skip it."""
    inst = default_installation(n_valves=1, behind_router=0)
    started: list[float] = []
    done: list[float] = []

    async def slow(self: FakeBleakClient) -> None:
        started.append(inst.clock.now())
        await inst.clock.sleep(3.0)
        done.append(inst.clock.now())

    monkeypatch.setattr(FakeBleakClient, "disconnect", slow)
    task = asyncio.ensure_future(
        validate_connection(
            inst.resolver,
            own_eui=inst.zvd_eui,
            network_key=inst.network_key,
            clock=inst.clock,
            connector=inst.connector,
        )
    )
    await run_until(inst.clock, lambda: bool(started))
    task.cancel()
    await inst.clock.advance(1.0)
    task.cancel()
    await inst.clock.advance(5.0)
    assert len(done) == 1
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_run_protected_propagates_inner_cancellation() -> None:
    async def cancels_itself() -> None:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await run_protected(cancels_itself())
