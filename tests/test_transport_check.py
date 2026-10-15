"""ZigbeeDirectTransport writer: a frame's ``check`` runs at dequeue (review round 5).

A failing check withdraws that frame only: its sender gets the check's exception, no session
counter is spent, and the writer keeps serving the queue.
"""

from __future__ import annotations

import asyncio

import pytest

from test_transport import opened
from vicare_local_ble.zigbee_direct.clock import VirtualClock


class WithdrawnError(Exception):
    pass


async def test_failed_check_withdraws_one_frame_without_spending_a_counter() -> None:
    clock = VirtualClock()
    r0, peer, transport = await opened(clock, write_latency=0.5)
    allowed = True

    def check() -> None:
        if not allowed:
            raise WithdrawnError

    first = asyncio.create_task(transport.send_npdu(b"\x01"))
    await clock.advance(0.1)  # the first write is in flight; the next two wait in the queue
    second = asyncio.create_task(transport.send_npdu(b"\x02", check=check))
    third = asyncio.create_task(transport.send_npdu(b"\x03"))
    await clock.advance(0)
    allowed = False  # ownership changed while the frame waited
    await clock.run_task(first)
    with pytest.raises(WithdrawnError):
        await second
    await clock.run_task(third)
    assert [n.npdu for n in peer.npdus] == [b"\x01", b"\x03"]
    assert r0.write_counters == (1, 2)
    assert not transport.broken
    assert transport.stats.frames_tx == 2
    await transport.close()


async def test_passing_check_sends_the_frame() -> None:
    clock = VirtualClock()
    _, peer, transport = await opened(clock)
    calls: list[int] = []
    await clock.run_task(transport.send_npdu(b"\x01", check=lambda: calls.append(1)))
    assert [n.npdu for n in peer.npdus] == [b"\x01"]
    assert calls == [1]
    await transport.close()
