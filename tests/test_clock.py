"""Clock protocol: LoopClock smoke tests and VirtualClock determinism."""

from __future__ import annotations

import asyncio
import time

import pytest

from vicare_local_ble.zigbee_direct.clock import Clock, LoopClock, VirtualClock


def test_clocks_satisfy_protocol() -> None:
    clocks: list[Clock] = [LoopClock(), VirtualClock()]
    assert len(clocks) == 2
    assert repr(LoopClock()) == "LoopClock()"
    assert "now=5.0" in repr(VirtualClock(5.0))


# --- LoopClock ---------------------------------------------------------------------------


async def test_loop_clock_now_sleep_and_call_later() -> None:
    clock = LoopClock()
    start = clock.now()
    fired: list[str] = []
    clock.call_later(0, lambda: fired.append("a"))
    handle = clock.call_later(0, lambda: fired.append("cancelled"))
    handle.cancel()
    await clock.sleep(0.001)
    await clock.sleep(-1)
    assert fired == ["a"]
    assert clock.now() >= start


async def test_loop_clock_timeout() -> None:
    clock = LoopClock()
    with pytest.raises(TimeoutError):
        async with clock.timeout(0.001):
            await asyncio.Event().wait()
    async with clock.timeout(None):
        await clock.sleep(0)
    async with clock.timeout(10):
        await clock.sleep(0)


# --- VirtualClock: timers ----------------------------------------------------------------


async def test_call_later_runs_in_time_then_schedule_order() -> None:
    clock = VirtualClock()
    order: list[str] = []
    clock.call_later(5, lambda: order.append("t5-a"))
    clock.call_later(1, lambda: order.append("t1"))
    clock.call_later(5, lambda: order.append("t5-b"))
    clock.call_later(10, lambda: order.append("t10"))
    assert clock.pending_timers == 4
    assert clock.next_deadline() == 1
    await clock.advance(5)
    assert order == ["t1", "t5-a", "t5-b"]
    assert clock.now() == 5
    await clock.advance(5)
    assert order == ["t1", "t5-a", "t5-b", "t10"]
    assert clock.next_deadline() is None


async def test_callback_sees_its_due_time() -> None:
    clock = VirtualClock(100.0)
    seen: list[float] = []
    clock.call_later(3, lambda: seen.append(clock.now()))
    await clock.advance(10)
    assert seen == [103.0]
    assert clock.now() == 110.0


async def test_cancel_call_later() -> None:
    clock = VirtualClock()
    fired: list[int] = []
    handle = clock.call_later(1, lambda: fired.append(1))
    assert not handle.cancelled()
    assert handle.when == 1
    handle.cancel()
    handle.cancel()
    assert handle.cancelled()
    assert "cancelled" in repr(handle)
    assert clock.pending_timers == 0
    await clock.advance(2)
    assert fired == []


async def test_timer_scheduled_by_callback_within_window_fires() -> None:
    clock = VirtualClock()
    order: list[float] = []

    def first() -> None:
        order.append(clock.now())
        clock.call_later(2, lambda: order.append(clock.now()))

    clock.call_later(1, first)
    await clock.advance(3)
    assert order == [1.0, 3.0]


async def test_zero_delay_timer_runs_on_run_until_idle() -> None:
    clock = VirtualClock()
    fired: list[int] = []
    clock.call_later(0, lambda: fired.append(1))
    clock.call_later(-5, lambda: fired.append(2))
    await clock.run_until_idle()
    assert fired == [1, 2]
    assert clock.now() == 0


async def test_advance_rejects_negative() -> None:
    with pytest.raises(ValueError, match="backwards"):
        await VirtualClock().advance(-1)


async def test_callback_exception_propagates() -> None:
    clock = VirtualClock()

    def boom() -> None:
        raise RuntimeError("boom")

    clock.call_later(1, boom)
    with pytest.raises(RuntimeError, match="boom"):
        await clock.advance(1)


# --- VirtualClock: sleep -----------------------------------------------------------------


async def test_long_sleep_is_instant_in_wall_time() -> None:
    clock = VirtualClock()
    task = asyncio.create_task(clock.sleep(900))
    wall = time.monotonic()
    await clock.run_until_idle()
    assert not task.done()
    await clock.advance(899.999)
    assert not task.done()
    await clock.advance(0.001)
    assert task.done()
    assert time.monotonic() - wall < 1.0


async def test_sleep_zero_yields_without_timer() -> None:
    clock = VirtualClock()
    await clock.sleep(0)
    assert clock.pending_timers == 0


async def test_sleep_cancellation_removes_timer() -> None:
    clock = VirtualClock()
    task = asyncio.create_task(clock.sleep(10))
    await clock.run_until_idle()
    assert clock.pending_timers == 1
    task.cancel()
    await clock.run_until_idle()
    assert task.cancelled()
    assert clock.pending_timers == 0
    await clock.advance(20)


async def test_woken_tasks_run_before_next_timer() -> None:
    """A task woken at t=1 schedules work that must interleave with a timer at t=2."""
    clock = VirtualClock()
    log: list[str] = []

    async def sleeper() -> None:
        await clock.sleep(1)
        log.append(f"woke@{clock.now()}")
        await clock.sleep(0.5)
        log.append(f"again@{clock.now()}")

    clock.call_later(2, lambda: log.append("timer@2"))
    task = asyncio.create_task(sleeper())
    await clock.advance(3)
    assert log == ["woke@1.0", "again@1.5", "timer@2"]
    assert task.done()


async def _trace(steps: list[float]) -> list[str]:
    clock = VirtualClock()
    log: list[str] = []

    async def worker(name: str, period: float, count: int) -> None:
        for i in range(count):
            await clock.sleep(period)
            log.append(f"{name}{i}@{clock.now():g}")

    tasks = [
        asyncio.create_task(worker("a", 3, 4)),
        asyncio.create_task(worker("b", 5, 3)),
        asyncio.create_task(worker("c", 7, 2)),
    ]
    clock.call_later(6, lambda: log.append("timer@6"))
    for dt in steps:
        await clock.advance(dt)
    assert all(t.done() for t in tasks)
    return log


async def test_advance_in_steps_equals_one_jump() -> None:
    one_jump = await _trace([20])
    steps = await _trace([0.5] * 40)
    uneven = await _trace([2.9, 0.1, 3, 1, 4.5, 8.5])
    assert one_jump == steps == uneven
    # The t=6 timer was scheduled before a's second sleep, so it fires first.
    assert one_jump[:4] == ["a0@3", "b0@5", "timer@6", "a1@6"]


# --- VirtualClock: timeout ---------------------------------------------------------------


async def test_timeout_raises_timeout_error() -> None:
    clock = VirtualClock()

    async def body() -> None:
        async with clock.timeout(30):
            await asyncio.Event().wait()

    task = asyncio.create_task(body())
    await clock.advance(29.9)
    assert not task.done()
    await clock.advance(0.1)
    assert task.done()
    with pytest.raises(TimeoutError):
        task.result()
    assert clock.pending_timers == 0


async def test_timeout_not_hit_cancels_its_timer() -> None:
    clock = VirtualClock()

    async def body() -> str:
        async with clock.timeout(30):
            await clock.sleep(10)
        return "ok"

    task = asyncio.create_task(body())
    await clock.advance(10)
    assert task.result() == "ok"
    assert clock.pending_timers == 0


async def test_timeout_none_never_fires() -> None:
    clock = VirtualClock()

    async def body() -> str:
        async with clock.timeout(None):
            await clock.sleep(1000)
        return "done"

    assert await clock.run_task(body()) == "done"


def test_timeout_outside_loop_is_rejected() -> None:
    coro = VirtualClock().timeout(1).__aenter__()
    with pytest.raises(RuntimeError):
        coro.send(None)
    coro.close()


async def test_nested_timeouts_inner_fires_first() -> None:
    clock = VirtualClock()
    log: list[str] = []

    async def body() -> None:
        async with clock.timeout(100):
            try:
                async with clock.timeout(5):
                    await clock.sleep(50)
            except TimeoutError:
                log.append(f"inner@{clock.now():g}")
            await clock.sleep(10)
            log.append(f"after@{clock.now():g}")

    await clock.run_task(body())
    assert log == ["inner@5", "after@15"]


async def test_nested_timeouts_outer_fires_first() -> None:
    clock = VirtualClock()
    inner_saw: list[str] = []

    async def body() -> None:
        async with clock.timeout(5):
            try:
                async with clock.timeout(50):
                    await clock.sleep(100)
            except TimeoutError:  # pragma: no cover - must not be the inner timeout
                inner_saw.append("inner")
                raise

    task = asyncio.create_task(body())
    await clock.advance(5)
    with pytest.raises(TimeoutError):
        task.result()
    assert inner_saw == []


async def test_external_cancel_is_not_turned_into_timeout() -> None:
    clock = VirtualClock()

    async def body() -> None:
        async with clock.timeout(10):
            await clock.sleep(100)

    task = asyncio.create_task(body())
    await clock.run_until_idle()
    task.cancel()
    await clock.run_until_idle()
    assert task.cancelled()
    assert clock.pending_timers == 0


async def test_timeout_zero_expires_on_next_drain() -> None:
    clock = VirtualClock()

    async def body() -> None:
        async with clock.timeout(0):
            await asyncio.Event().wait()

    task = asyncio.create_task(body())
    await clock.run_until_idle()
    with pytest.raises(TimeoutError):
        task.result()


# --- VirtualClock: run_task --------------------------------------------------------------


async def test_run_task_jumps_between_timers() -> None:
    clock = VirtualClock()

    async def job() -> float:
        for _ in range(3):
            await clock.sleep(300)
        return clock.now()

    assert await clock.run_task(job()) == 900.0


async def test_run_task_limit() -> None:
    clock = VirtualClock()
    with pytest.raises(TimeoutError, match="virtual seconds"):
        await clock.run_task(clock.sleep(10_000), limit=60)
    assert clock.pending_timers == 0


async def test_run_task_detects_deadlock() -> None:
    clock = VirtualClock()
    with pytest.raises(RuntimeError, match="blocked"):
        await clock.run_task(asyncio.Event().wait())


async def test_run_task_propagates_errors() -> None:
    clock = VirtualClock()

    async def job() -> None:
        await clock.sleep(1)
        raise ValueError("bad")

    with pytest.raises(ValueError, match="bad"):
        await clock.run_task(job())


async def test_run_until_idle_drains_chains_of_tasks() -> None:
    clock = VirtualClock()
    done: list[int] = []

    async def chain(n: int) -> None:
        if n:
            await asyncio.create_task(chain(n - 1))
        done.append(n)

    task = asyncio.create_task(chain(20))
    await clock.run_until_idle()
    assert task.done()
    assert done == list(range(21))
