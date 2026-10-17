"""Private state of one ``ZigbeeDirectNode``: the ``DispatchHost`` and ``RoutingHost``.

``NodeCore`` owns the allocators, pending map, join slot, neighbor table, router, dispatcher,
node tasks and listeners of one node generation. ``node.py`` is the public facade; the join
procedure lives in ``node_join.py`` and the request engine in ``node_requests.py``.

APS acks of inbound frames are scheduled by ``node_acks.ApsAcker`` as node tasks.

Lifecycle: built around an open transport (installs ``dispatcher.handle`` as its NPDU handler);
``close`` fails pending futures and the join, cancels and awaits every node task, drops the
listeners and swaps the NPDU handler for a no-op. It never closes the transport.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any

from localtrv.zigbee_direct.dispatch import Dispatcher
from localtrv.zigbee_direct.errors import ConnectionLostError, TransportError
from localtrv.zigbee_direct.node_acks import ApsAcker
from localtrv.zigbee_direct.node_types import NodeStats
from localtrv.zigbee_direct.requests import Allocators, JoinSlot, PendingMap
from localtrv.zigbee_direct.routing import NeighborTable, Router

if TYPE_CHECKING:
    import random
    from collections.abc import Callable, Coroutine

    from localtrv.zigbee_direct.clock import Clock
    from localtrv.zigbee_direct.codec.aps import ApsDataFrame
    from localtrv.zigbee_direct.codec.nwk_commands import CommissioningResponse
    from localtrv.zigbee_direct.codec.tlv import TunnelNpdu
    from localtrv.zigbee_direct.codec.zdo import DeviceAnnce
    from localtrv.zigbee_direct.node_types import JoinInfo, NodeConfig, ReportEvent
    from localtrv.zigbee_direct.transport import ZigbeeDirectTransport
    from localtrv.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("localtrv.zigbee_direct.node")


def _drop_npdu(_npdu: TunnelNpdu) -> None:
    """NPDU handler installed at close: a closed node ignores every frame."""


class NodeCore:
    """Collaborators and shared state of one node (implements ``DispatchHost`` and
    ``RoutingHost``)."""

    def __init__(
        self,
        transport: ZigbeeDirectTransport,
        *,
        clock: Clock,
        config: NodeConfig,
        rng: random.Random,
    ) -> None:
        session = transport.session
        if session is None or transport.closed:
            raise ValueError("the transport must be open")
        self.transport = transport
        self.rng = rng
        self.zdd_eui = session.zdd_eui
        self._own_eui = session.own_eui
        self._clock = clock
        self._config = config
        self._stats = NodeStats()
        self._allocators = Allocators.create()
        self._pending = PendingMap(clock=clock, late_window=config.late_window)
        self._join_slot = JoinSlot()
        self._neighbors = NeighborTable()
        self._current_short: int | None = None
        self.join_info: JoinInfo | None = None
        self.join_started = False
        self.join_future: asyncio.Future[CommissioningResponse] | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._report_listeners: list[Callable[[ReportEvent], None]] = []
        self._annce_listeners: list[Callable[[DeviceAnnce, int], None]] = []
        self._conflict_listeners: list[Callable[[], None]] = []
        self._sender_listeners: list[Callable[[int, Eui64], None]] = []
        self._dst_locks: dict[int, asyncio.Lock] = {}
        self.in_flight = asyncio.Semaphore(config.max_in_flight)
        self._closed = False
        self._closing: asyncio.Future[None] | None = None
        self._router = Router(self)
        self._acker = ApsAcker(self)
        self._dispatcher = Dispatcher(self)
        transport.set_npdu_handler(self._dispatcher.handle)

    # --- DispatchHost / RoutingHost -----------------------------------------------------

    @property
    def clock(self) -> Clock:
        return self._clock

    @property
    def config(self) -> NodeConfig:
        return self._config

    @property
    def stats(self) -> NodeStats:
        return self._stats

    @property
    def allocators(self) -> Allocators:
        return self._allocators

    @property
    def pending(self) -> PendingMap:
        return self._pending

    @property
    def join_slot(self) -> JoinSlot:
        return self._join_slot

    @property
    def router(self) -> Router:
        return self._router

    @property
    def neighbors(self) -> NeighborTable:
        return self._neighbors

    @property
    def current_short(self) -> int | None:
        return self._current_short

    @current_short.setter
    def current_short(self, short: int) -> None:
        self._current_short = short

    @property
    def own_short(self) -> int:
        short = self._current_short
        if short is None:
            raise RuntimeError("own short is unknown before join() accepted a response")
        return short

    @property
    def own_eui(self) -> Eui64:
        return self._own_eui

    @property
    def closed(self) -> bool:
        return self._closed

    async def send_secure(self, npdu: bytes, check: Callable[[], None] | None = None) -> None:
        await self.send(npdu, secure=True, check=check)

    async def send(
        self, npdu: bytes, *, secure: bool, check: Callable[[], None] | None = None
    ) -> None:
        """``transport.send_npdu``; ``ConnectionLostError`` (``TransportError`` chained) if the
        node is closed or the write failed. A raising ``check`` (run at transmission) withdraws
        the frame and its exception propagates."""
        self.check_open()
        try:
            await self.transport.send_npdu(npdu, secure=secure, check=check)
        except TransportError as exc:
            raise ConnectionLostError(f"transport failed ({exc.reason})") from exc

    def start_task(self, coro: Coroutine[Any, Any, None], *, name: str) -> asyncio.Task[None]:
        if self._closed:
            coro.close()
            raise ConnectionLostError("node is closed")
        # The task wraps the coroutine directly: cancelling it before its first step still
        # closes the coroutine (no "never awaited" warning). Failures are logged by the
        # done callback, which also marks them retrieved.
        task = asyncio.get_running_loop().create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.debug("node task %s failed: %s", task.get_name(), type(exc).__name__)

    def ack_aps(self, src_short: int, aps: ApsDataFrame) -> None:
        self._acker.ack(src_short, aps)

    def fire_address_conflict(self) -> None:
        _LOGGER.debug("address conflict for our short")
        for cb in tuple(self._conflict_listeners):
            try:
                cb()
            except Exception:
                _LOGGER.exception("address conflict listener raised")

    def emit_report(self, event: ReportEvent) -> None:
        for cb in tuple(self._report_listeners):
            try:
                cb(event)
            except Exception:
                _LOGGER.exception("report listener raised")

    def emit_sender(self, src_short: int, src_ieee: Eui64) -> None:
        for cb in tuple(self._sender_listeners):
            try:
                cb(src_short, src_ieee)
            except Exception:
                _LOGGER.exception("sender listener raised")

    def emit_device_annce(self, annce: DeviceAnnce, src_short: int) -> None:
        for cb in tuple(self._annce_listeners):
            try:
                cb(annce, src_short)
            except Exception:
                _LOGGER.exception("Device_annce listener raised")

    # --- node facade helpers --------------------------------------------------------------

    def check_open(self) -> None:
        if self._closed:
            raise ConnectionLostError("node is closed")

    def check_ready(self) -> None:
        """Requests need an open, joined node (nothing reaches a device before the join)."""
        self.check_open()
        if self.join_info is None:
            raise RuntimeError("join() has not completed")

    def dst_lock(self, dst: int) -> asyncio.Lock:
        return self._dst_locks.setdefault(dst, asyncio.Lock())

    def on_report(self, cb: Callable[[ReportEvent], None]) -> Callable[[], None]:
        return self._subscribe(self._report_listeners, cb)

    def on_device_annce(self, cb: Callable[[DeviceAnnce, int], None]) -> Callable[[], None]:
        return self._subscribe(self._annce_listeners, cb)

    def on_address_conflict(self, cb: Callable[[], None]) -> Callable[[], None]:
        return self._subscribe(self._conflict_listeners, cb)

    def on_sender(self, cb: Callable[[int, Eui64], None]) -> Callable[[], None]:
        return self._subscribe(self._sender_listeners, cb)

    def _subscribe[T](self, listeners: list[T], cb: T) -> Callable[[], None]:
        self.check_open()
        listeners.append(cb)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                listeners.remove(cb)

        return unsubscribe

    async def close(self, exc: BaseException | None) -> None:
        closing = self._closing
        if closing is not None:
            if asyncio.current_task() in self._tasks:
                return  # a node task must not wait for close(), which awaits it
            await asyncio.shield(closing)
            return
        closing = self._closing = asyncio.get_running_loop().create_future()
        try:
            await self._close(exc)
        finally:
            closing.set_result(None)

    async def _close(self, exc: BaseException | None) -> None:
        self._closed = True
        error = exc if exc is not None else ConnectionLostError("node closed")
        self.transport.set_npdu_handler(_drop_npdu)
        self._pending.fail_all(error)
        join_future = self.join_future
        if join_future is not None and not join_future.done():
            join_future.set_exception(error)
            join_future.exception()  # retrieved even if join() is not awaiting it right now
        self._join_slot.close()
        self._router.stop()
        current = asyncio.current_task()
        tasks = [t for t in self._tasks if t is not current]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._report_listeners.clear()
        self._annce_listeners.clear()
        self._conflict_listeners.clear()
        self._sender_listeners.clear()
        _LOGGER.debug("node closed (%d pending failed)", len(self._pending))

    @property
    def task_count(self) -> int:
        """Live node-owned tasks (diagnostics and tests)."""
        return len(self._tasks)


__all__ = ["NodeCore"]
