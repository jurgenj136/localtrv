"""Injected time source: the only path to sleeps, timers and timeouts in the library.

Every timeout, retry, TTL and periodic task in the transport, node, connection, bridge and
simulator goes through a ``Clock``. Library code never calls ``asyncio.sleep``,
``asyncio.timeout``, ``loop.call_later`` or ``loop.time`` directly; tests inject a
``VirtualClock`` so production timeouts (30 s requests, 900 s MTORR, 6 h refreshes) run in
milliseconds of wall time and deterministically.

Threading: a clock is used from one event loop thread only. ``LoopClock`` binds to the loop that
is running when it is first used; ``VirtualClock`` futures are created on the running loop at
call time. Neither is thread-safe.

A zero-delay yield is ``await clock.sleep(0)``: on both clocks it yields to the loop once without
advancing time.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from contextlib import AbstractAsyncContextManager
    from types import TracebackType


class Cancellable(Protocol):
    """Handle returned by ``Clock.call_later``. ``cancel()`` is idempotent."""

    def cancel(self) -> None: ...


class Clock(Protocol):
    """Monotonic time plus sleeping, timers and timeouts.

    * ``now()``: monotonic seconds; only differences are meaningful.
    * ``sleep(seconds)``: suspend the calling task; cancellable. ``seconds <= 0`` yields once.
    * ``call_later(delay, callback)``: run ``callback()`` on the loop thread after ``delay``
      seconds; the return value of the callback is ignored. Exceptions raised by the callback
      are the clock's business (``LoopClock``: the loop exception handler; ``VirtualClock``:
      they propagate out of ``advance``), so callbacks should not raise.
    * ``timeout(delay)``: async context manager that cancels the body after ``delay`` seconds
      and raises ``TimeoutError`` on exit, with ``asyncio.timeout`` semantics (nesting, outer
      cancellation and ``Task.uncancel`` bookkeeping included). ``None`` disables the timeout.
      Must be entered inside a task.
    """

    def now(self) -> float: ...

    async def sleep(self, seconds: float) -> None: ...

    def call_later(self, delay: float, callback: Callable[[], object]) -> Cancellable: ...

    def timeout(self, delay: float | None) -> AbstractAsyncContextManager[None]: ...


class LoopClock:
    """Production clock on the running asyncio loop (``loop.time()``, ``asyncio.timeout``)."""

    __slots__ = ()

    def now(self) -> float:
        return asyncio.get_running_loop().time()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(seconds, 0.0))

    def call_later(self, delay: float, callback: Callable[[], object]) -> Cancellable:
        return asyncio.get_running_loop().call_later(max(delay, 0.0), callback)

    def timeout(self, delay: float | None) -> AbstractAsyncContextManager[None]:
        return _LoopTimeout(delay)

    def __repr__(self) -> str:
        return "LoopClock()"


class _LoopTimeout:
    """Adapter so ``LoopClock.timeout`` is typed ``AbstractAsyncContextManager[None]``."""

    __slots__ = ("_cm", "_delay")

    def __init__(self, delay: float | None) -> None:
        self._delay = delay
        self._cm: asyncio.Timeout | None = None

    async def __aenter__(self) -> None:
        self._cm = asyncio.timeout(self._delay)
        await self._cm.__aenter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._cm is None:  # pragma: no cover - __aexit__ without __aenter__
            return None
        await self._cm.__aexit__(exc_type, exc, tb)
        return None


# --- virtual time --------------------------------------------------------------------------


@dataclass(slots=True, eq=False)
class _Timer:
    when: float
    order: int
    callback: Callable[[], object] | None
    cancelled: bool = field(default=False)

    def cancel(self) -> None:
        self.cancelled = True
        self.callback = None


class VirtualHandle:
    """Cancellable handle of a ``VirtualClock`` timer."""

    __slots__ = ("_timer",)

    def __init__(self, timer: _Timer) -> None:
        self._timer = timer

    @property
    def when(self) -> float:
        """Virtual time at which the callback is due."""
        return self._timer.when

    def cancel(self) -> None:
        self._timer.cancel()

    def cancelled(self) -> bool:
        return self._timer.cancelled

    def __repr__(self) -> str:
        state = "cancelled" if self._timer.cancelled else "active"
        return f"VirtualHandle(when={self._timer.when}, {state})"


class VirtualClock:
    """Deterministic virtual time for tests, on top of the real running loop.

    Time only moves when a test calls ``advance(dt)`` (or ``run_task``). Timers due at the same
    instant run in scheduling order. Between every timer callback the loop is drained
    (``run_until_idle``), so tasks woken by a callback run before the next timer fires; advancing
    in several steps and in one jump therefore produce the same order of events.

    Draining relies on the default asyncio loop's ready queue; on other loops it falls back to a
    fixed number of yields. Real-time loop timers (``loop.call_later``) are not driven by
    ``advance`` - another reason library code must use the clock.
    """

    __slots__ = ("_heap", "_now", "_order")

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)
        self._heap: list[tuple[float, int, _Timer]] = []
        self._order = itertools.count()

    # --- Clock protocol ---

    def now(self) -> float:
        return self._now

    async def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            await asyncio.sleep(0)
            return
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        handle = self.call_later(seconds, lambda: _set_result(future))
        try:
            await future
        finally:
            handle.cancel()

    def call_later(self, delay: float, callback: Callable[[], object]) -> VirtualHandle:
        timer = _Timer(self._now + max(delay, 0.0), next(self._order), callback)
        heapq.heappush(self._heap, (timer.when, timer.order, timer))
        return VirtualHandle(timer)

    def timeout(self, delay: float | None) -> AbstractAsyncContextManager[None]:
        return _VirtualTimeout(self, delay)

    # --- test driving ---

    @property
    def pending_timers(self) -> int:
        """Number of scheduled, not cancelled timers."""
        return sum(1 for _, _, t in self._heap if not t.cancelled)

    def next_deadline(self) -> float | None:
        """Virtual time of the earliest active timer, or ``None``."""
        self._discard_cancelled()
        return self._heap[0][0] if self._heap else None

    async def advance(self, dt: float) -> None:
        """Move time forward by ``dt`` seconds, firing every timer due on the way, in order.

        The loop is drained before the first timer, after every timer and at the end. Time is
        set to each timer's due time while its callback runs, then to ``now + dt``.
        """
        if dt < 0:
            raise ValueError("cannot advance a clock backwards")
        target = self._now + dt
        await self._fire_due(target)
        self._now = target
        await self.run_until_idle()

    async def advance_to(self, when: float) -> None:
        """``advance(when - now())``; ``when`` must not be in the past."""
        await self.advance(when - self._now)

    async def run_until_idle(self, *, max_iterations: int = 100_000) -> None:
        """Drain the loop and fire timers due at the current instant until nothing is runnable.

        Raises ``RuntimeError`` if the loop never settles (a livelock in the code under test).
        """
        for _ in range(max_iterations):
            await _drain_loop(max_iterations)
            if not self._fire_one(self._now):
                return
        raise RuntimeError("VirtualClock.run_until_idle: loop did not settle")  # pragma: no cover

    async def run_task[T](self, awaitable: Awaitable[T], *, limit: float = 86_400.0) -> T:
        """Run ``awaitable`` to completion, jumping from timer to timer.

        Fails with ``TimeoutError`` (after cancelling the task) if more than ``limit`` virtual
        seconds pass, and with ``RuntimeError`` if the task is blocked with no timer left.
        """
        task = asyncio.ensure_future(awaitable)
        deadline = self._now + limit
        try:
            while True:
                await self.run_until_idle()
                if task.done():
                    return task.result()
                when = self.next_deadline()
                if when is None:
                    raise RuntimeError("run_task: task is blocked and no timer is scheduled")
                if when > deadline:
                    raise TimeoutError(f"run_task: not done after {limit} virtual seconds")
                await self.advance_to(when)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    def __repr__(self) -> str:
        return f"VirtualClock(now={self._now}, timers={self.pending_timers})"

    # --- internals ---

    def _discard_cancelled(self) -> None:
        while self._heap and self._heap[0][2].cancelled:
            heapq.heappop(self._heap)

    def _fire_one(self, limit: float) -> bool:
        """Fire the earliest active timer due at or before ``limit``; False if none."""
        self._discard_cancelled()
        if not self._heap or self._heap[0][0] > limit:
            return False
        when, _, timer = heapq.heappop(self._heap)
        callback = timer.callback
        timer.cancel()  # fired: a later cancel() is a no-op
        self._now = max(self._now, when)
        if callback is not None:
            callback()
        return True

    async def _fire_due(self, target: float) -> None:
        await self.run_until_idle()
        while self._fire_one(target):
            await self.run_until_idle()


def _set_result(future: asyncio.Future[None]) -> None:
    if not future.done():
        future.set_result(None)


async def _drain_loop(max_iterations: int) -> None:
    loop = asyncio.get_running_loop()
    ready = getattr(loop, "_ready", None)
    if ready is None:  # pragma: no cover - non-default loop implementation
        for _ in range(64):
            await asyncio.sleep(0)
        return
    for _ in range(max_iterations):
        await asyncio.sleep(0)
        if not ready:
            return
    raise RuntimeError("VirtualClock: loop did not settle")  # pragma: no cover


class _VirtualTimeout:
    """``asyncio.timeout`` semantics on a ``VirtualClock`` (mirrors ``asyncio.Timeout``)."""

    __slots__ = ("_cancelling", "_clock", "_delay", "_expired", "_handle", "_task")

    def __init__(self, clock: VirtualClock, delay: float | None) -> None:
        self._clock = clock
        self._delay = delay
        self._task: asyncio.Task[object] | None = None
        self._handle: VirtualHandle | None = None
        self._expired = False
        self._cancelling = 0

    async def __aenter__(self) -> None:
        task = asyncio.current_task()
        if task is None:  # pragma: no cover - asyncio raises first without a running loop
            raise RuntimeError("Clock.timeout() must be used inside a task")
        self._task = task
        self._cancelling = task.cancelling()
        if self._delay is not None:
            self._handle = self._clock.call_later(self._delay, self._on_timeout)

    def _on_timeout(self) -> None:
        if self._task is None or self._task.done():  # pragma: no cover - defensive
            return
        self._expired = True
        self._handle = None
        self._task.cancel()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None
        if (
            self._expired
            and self._task is not None
            and self._task.uncancel() <= self._cancelling
            and exc_type is asyncio.CancelledError
        ):
            raise TimeoutError from exc
        return None


__all__ = ["Cancellable", "Clock", "LoopClock", "VirtualClock", "VirtualHandle"]
