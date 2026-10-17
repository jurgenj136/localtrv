"""APS acknowledgements of inbound unicast data frames (Zigbee R23 2.2.5.2.3, 2.2.8.4.2).

Devices (the valves, the R0's ZDO) send their responses and reports with the APS ack-request
bit set. Without an ack the sender retransmits the frame up to ``apscMaxFrameRetries`` (3)
times, each a few seconds apart: duplicate responses (``late_drops``), duplicate reports and
wasted valve battery. The dispatcher decides which frames qualify (``Dispatcher._maybe_ack``)
and calls ``ApsAcker.ack`` synchronously from the BLE notify callback; this module only builds
and schedules the frame.

Path: ``ack`` builds the NPDU at once (``frames.aps_ack_npdu``, fresh NWK seq, the inbound APS
counter echoed) and starts one node-owned task (``host.start_task``) that awaits
``host.send_secure``, i.e. the transport writer's FIFO. ``ack`` never awaits and never raises.
At most ``MAX_ACKS_IN_FLIGHT`` ack tasks exist at once; beyond that the ack is skipped and
counted in ``aps_ack_failures`` (the sender then simply retransmits). ``node.close`` cancels
and awaits the ack tasks like every other node task.

Our own requests never set the ack-request bit, so nothing here waits for acks.

Logging: a counter (``aps_acks_sent``) instead of a line per ack; an ack follows almost every
inbound frame and the NPDU recorder already shows each one. Failures log one DEBUG line.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Final, Protocol

from localtrv.zigbee_direct.frames import aps_ack_npdu

if TYPE_CHECKING:
    import asyncio
    from collections.abc import Coroutine

    from localtrv.zigbee_direct.codec.aps import ApsDataFrame
    from localtrv.zigbee_direct.node_types import NodeStats
    from localtrv.zigbee_direct.requests import Allocators

#: Cap on concurrently scheduled ack sends (the writer FIFO serialises them anyway).
MAX_ACKS_IN_FLIGHT: Final = 16

_LOGGER = logging.getLogger("localtrv.zigbee_direct.node")


class AckHost(Protocol):
    """What the acker needs from its node (``NodeCore`` implements it)."""

    @property
    def stats(self) -> NodeStats: ...

    @property
    def allocators(self) -> Allocators: ...

    @property
    def own_short(self) -> int: ...

    async def send_secure(self, npdu: bytes) -> None: ...

    def start_task(self, coro: Coroutine[Any, Any, None], *, name: str) -> asyncio.Task[None]: ...


class ApsAcker:
    """Schedules APS acks for one node."""

    __slots__ = ("_host", "_in_flight")

    def __init__(self, host: AckHost) -> None:
        self._host = host
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        return self._in_flight

    def ack(self, src_short: int, aps: ApsDataFrame) -> None:
        """Schedule the ack of the unicast ``aps`` from ``src_short``. Never raises."""
        host = self._host
        if self._in_flight >= MAX_ACKS_IN_FLIGHT:
            host.stats.aps_ack_failures += 1
            _LOGGER.debug("APS ack to 0x%04X skipped: too many in flight", src_short)
            return
        try:
            npdu = aps_ack_npdu(
                dst=src_short,
                own_short=host.own_short,
                nwk_seq=host.allocators.nwk.next(),
                inbound=aps,
            )
            task = host.start_task(self._send(npdu, src_short), name="aps-ack")
        except Exception as exc:  # closed node, encode error: never raise into ingress
            host.stats.aps_ack_failures += 1
            _LOGGER.debug("APS ack to 0x%04X not sent: %s", src_short, type(exc).__name__)
            return
        # Released by a done callback, so a task cancelled before its first step counts too.
        self._in_flight += 1
        task.add_done_callback(self._release)

    def _release(self, _task: asyncio.Task[None]) -> None:
        self._in_flight -= 1

    async def _send(self, npdu: bytes, src_short: int) -> None:
        host = self._host
        try:
            await host.send_secure(npdu)
        except Exception as exc:
            host.stats.aps_ack_failures += 1
            _LOGGER.debug("APS ack to 0x%04X failed: %s", src_short, type(exc).__name__)
        else:
            host.stats.aps_acks_sent += 1


__all__ = ["MAX_ACKS_IN_FLIGHT", "AckHost", "ApsAcker"]
