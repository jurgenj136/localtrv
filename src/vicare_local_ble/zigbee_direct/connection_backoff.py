"""Backoff schedule and the shortenable backoff wait of ``ZdConnection``.

Private helper of ``connection.py``; the constants live there and are passed in. Every delay
goes through the injected ``Clock``.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import random
    from collections.abc import Sequence

    from vicare_local_ble.zigbee_direct.clock import Cancellable, Clock


class Backoff:
    """Position in the backoff schedule; ``next_delay`` returns the jittered wait and steps on.

    The last schedule entry is the cap. ``reset`` returns to the first entry (after a long
    READY period).
    """

    __slots__ = ("_index", "_jitter", "_schedule")

    def __init__(self, schedule: Sequence[float], jitter: float) -> None:
        self._schedule = tuple(schedule)
        self._jitter = jitter
        self._index = 0

    def next_delay(self, rng: random.Random) -> tuple[float, float]:
        """``(base, jittered)`` for the next wait; steps on (up to the cap)."""
        base = self._schedule[min(self._index, len(self._schedule) - 1)]
        self._index = min(self._index + 1, len(self._schedule) - 1)
        return base, base * (1.0 + rng.uniform(-self._jitter, self._jitter))

    def reset(self) -> None:
        self._index = 0


class BackoffWait:
    """One backoff wait at a time; ``shorten`` cuts a long wait's remainder (``notify_seen``).

    A wait whose un-jittered base is at least ``threshold`` seconds is shortened once, to
    ``shortened`` seconds from the moment ``shorten`` is called, unless less remains already.
    """

    __slots__ = (
        "_clock",
        "_deadline",
        "_future",
        "_handle",
        "_shortenable",
        "_shortened",
        "_threshold",
    )

    def __init__(self, clock: Clock, *, threshold: float, shortened: float) -> None:
        self._clock = clock
        self._threshold = threshold
        self._shortened = shortened
        self._future: asyncio.Future[None] | None = None
        self._handle: Cancellable = _Idle()
        self._deadline = 0.0
        self._shortenable = False

    async def wait(self, delay: float, *, base: float) -> None:
        """Sleep ``delay`` seconds on the clock (cancellable; ``shorten`` may end it early if
        ``base``, the un-jittered schedule step, reaches the threshold)."""
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._future = future
        self._deadline = self._clock.now() + delay
        self._shortenable = base >= self._threshold
        self._handle = self._clock.call_later(delay, lambda: _wake(future))
        try:
            await future
        finally:
            self._handle.cancel()
            self._handle = _Idle()
            self._future = None
            self._shortenable = False

    def shorten(self) -> bool:
        """Shorten the running wait (see class docstring); True if it was shortened."""
        future = self._future
        if future is None or not self._shortenable:
            return False  # no wait, or a short one, or already shortened
        now = self._clock.now()
        if self._deadline - now <= self._shortened:
            return False
        self._shortenable = False
        self._handle.cancel()
        self._deadline = now + self._shortened
        self._handle = self._clock.call_later(self._shortened, lambda: _wake(future))
        return True


class _Idle:
    """The timer handle while no wait runs."""

    __slots__ = ()

    def cancel(self) -> None:  # pragma: no cover - placeholder, replaced before any cancel
        return None


def _wake(future: asyncio.Future[None]) -> None:
    if not future.done():
        future.set_result(None)


__all__ = ["Backoff", "BackoffWait"]
