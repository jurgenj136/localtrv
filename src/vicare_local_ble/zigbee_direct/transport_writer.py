"""Private writer task of ``transport``: the only code path that writes Tunnel (spec §1.2).

One task per session consumes a FIFO of ``(TunnelNpdu, future)``. It owns the outgoing session
counter: frames reach the GATT layer strictly in counter order and never overlap. Any failure
(write exception, timeout, ``CounterExhaustedError``, or a cancel while a write is in flight)
marks the writer ``broken``; the counter is then in doubt and the session must be replaced.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from bleak.exc import BleakCharacteristicNotFoundError

from vicare_local_ble.zigbee_direct.errors import CounterExhaustedError, TransportError
from vicare_local_ble.zigbee_direct.transport_handshake import gatt_failure
from vicare_local_ble.zigbee_direct.uuids import TUNNEL_NPDU, TUNNEL_SERVICE

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.session import SessionCipher
    from vicare_local_ble.zigbee_direct.transport import GattClient, TransportStats

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.transport")


@dataclass(slots=True)
class _Outgoing:
    npdu: TunnelNpdu
    future: asyncio.Future[None]


def _fail_future(future: asyncio.Future[None], error: TransportError) -> None:
    if not future.done():
        future.set_exception(TransportError(str(error), reason=error.reason))


class TunnelWriter:
    """The transport's writer task. Created and started by ``ZigbeeDirectTransport.open``."""

    __slots__ = (
        "_broken",
        "_cipher",
        "_client",
        "_clock",
        "_current",
        "_max_value",
        "_on_broken",
        "_queue",
        "_recorder",
        "_stats",
        "_task",
        "_timeout",
    )

    def __init__(
        self,
        client: GattClient,
        cipher: SessionCipher,
        *,
        clock: Clock,
        write_timeout: float,
        max_value: int,
        stats: TransportStats,
        recorder: NpduRecorder | None,
        on_broken: Callable[[TransportError], None],
    ) -> None:
        self._client = client
        self._cipher = cipher
        self._clock = clock
        self._timeout = write_timeout
        self._max_value = max_value
        self._stats = stats
        self._recorder = recorder
        self._on_broken = on_broken
        self._queue: asyncio.Queue[_Outgoing] = asyncio.Queue()
        self._current: _Outgoing | None = None
        self._broken = False
        self._task: asyncio.Task[None] | None = None

    @property
    def broken(self) -> bool:
        return self._broken

    @property
    def task(self) -> asyncio.Task[None] | None:
        return self._task

    def start(self) -> None:
        self._task = asyncio.get_running_loop().create_task(
            self._run(), name="zigbee-direct-tunnel-writer"
        )

    def submit(self, npdu: TunnelNpdu) -> asyncio.Future[None]:
        """Queue ``npdu``; the caller awaits the returned future (and may abandon it)."""
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._queue.put_nowait(_Outgoing(npdu, future))
        return future

    async def stop(self) -> None:
        """Cancel and await the task, then fail every queued send with ``closed``."""
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            await asyncio.wait({task})
        self._fail_queued(TransportError("transport closed", reason="closed"))

    # --- the task ---

    async def _run(self) -> None:
        try:
            while True:
                item = await self._queue.get()
                if item.future.done():  # abandoned while queued: no counter spent
                    continue
                self._current = item
                error = await self._write(item)
                self._current = None
                if error is not None:
                    self._break(item, error)
                    return
                self._stats.frames_tx += 1
                if not item.future.done():
                    item.future.set_result(None)
        except asyncio.CancelledError:
            current, self._current = self._current, None
            if current is not None:
                _fail_future(current.future, TransportError("transport closed", reason="closed"))
            raise

    async def _write(self, item: _Outgoing) -> TransportError | None:
        try:
            frame = self._cipher.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, item.npdu.encode())
        except CounterExhaustedError:
            return TransportError("outgoing session counter exhausted", reason="write")
        self._record(item.npdu)
        try:
            async with self._clock.timeout(self._timeout):
                await self._client.write_gatt_char(TUNNEL_NPDU, frame, response=True)
        except asyncio.CancelledError:  # close() mid-flight: the frame may have reached the ZDD
            self._broken = True
            raise
        except Exception as exc:
            if len(frame) > self._max_value and not isinstance(
                exc, BleakCharacteristicNotFoundError
            ):
                return TransportError(
                    f"long write of {len(frame)} B failed (max {self._max_value} B per PDU)",
                    reason="long_write_unsupported",
                )
            return gatt_failure(exc, "tunnel write")
        return None

    def _record(self, npdu: TunnelNpdu) -> None:
        if self._recorder is None:
            return
        try:
            self._recorder.tx(npdu)
        except Exception as exc:  # a recorder failure never affects the session
            _LOGGER.debug("NPDU recorder tx failed: %s", type(exc).__name__)

    def _break(self, item: _Outgoing, error: TransportError) -> None:
        self._broken = True
        _LOGGER.debug("tunnel writer broken: %s", error.reason)
        _fail_future(item.future, error)
        self._fail_queued(TransportError(f"not sent: {error}", reason="closed"))
        self._on_broken(error)

    def _fail_queued(self, error: TransportError) -> None:
        while not self._queue.empty():
            _fail_future(self._queue.get_nowait().future, error)


__all__ = ["TunnelWriter"]
