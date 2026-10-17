"""ZigbeeDirectTransport: the writer task (ordering, cancellation, failure, close)."""

from __future__ import annotations

import asyncio

import pytest

from test_transport import opened
from vicare_local_ble.testing import WriteFaultSpec
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.crypto import MAX_COUNTER
from vicare_local_ble.zigbee_direct.errors import TransportError
from vicare_local_ble.zigbee_direct.uuids import TUNNEL_NPDU


class FatalSpy:
    def __init__(self) -> None:
        self.errors: list[TransportError] = []

    def __call__(self, error: TransportError) -> None:
        self.errors.append(error)


async def test_fifty_concurrent_senders_keep_counter_order() -> None:
    clock = VirtualClock()
    r0, peer, transport = await opened(clock, write_latency=0.01)
    payloads = [bytes([i]) for i in range(50)]
    sends = [asyncio.create_task(transport.send_npdu(p)) for p in payloads]
    await clock.run_task(asyncio.gather(*sends))
    assert [n.npdu for n in peer.npdus] == payloads
    assert r0.write_counters == tuple(range(1, 51))
    assert r0.max_writes_in_flight == 1
    assert transport.stats.frames_tx == 50
    assert not transport.broken
    await transport.close()


async def test_secure_flag_reaches_the_tunnel() -> None:
    clock = VirtualClock()
    _, peer, transport = await opened(clock)
    await clock.run_task(transport.send_npdu(b"\x01", secure=False))
    await clock.run_task(transport.send_npdu(b"\x02"))
    assert [n.nwk_security for n in peer.npdus] == [False, True]
    await transport.close()


async def test_cancelled_sender_mid_flight_then_second_sender_never_overlap() -> None:
    clock = VirtualClock()
    r0, peer, transport = await opened(clock, write_latency=0.5)
    first = asyncio.create_task(transport.send_npdu(b"\x01"))
    await clock.advance(0.1)  # first write is in flight
    first.cancel()
    second = asyncio.create_task(transport.send_npdu(b"\x02"))
    with pytest.raises(asyncio.CancelledError):
        await first
    await clock.run_task(second)
    assert [n.npdu for n in peer.npdus] == [b"\x01", b"\x02"]  # the writer finished the first
    assert r0.write_counters == (1, 2)
    assert r0.max_writes_in_flight == 1
    assert not transport.broken
    await transport.close()


async def test_sender_cancelled_while_queued_spends_no_counter() -> None:
    clock = VirtualClock()
    r0, peer, transport = await opened(clock, write_latency=0.5)
    sends = [asyncio.create_task(transport.send_npdu(bytes([i]))) for i in range(3)]
    await clock.advance(0.1)  # first in flight, second and third queued
    sends[1].cancel()
    await clock.run_task(asyncio.gather(sends[0], sends[2]))
    assert sends[1].cancelled()
    assert [n.npdu for n in peer.npdus] == [b"\x00", b"\x02"]
    assert r0.write_counters == (1, 2)
    await transport.close()


@pytest.mark.parametrize(("fault", "reason"), [("raise", "write"), ("hang", "timeout")])
async def test_write_failure_breaks_and_fails_queued(fault: str, reason: str) -> None:
    clock = VirtualClock()
    r0, peer, transport = await opened(clock)
    fatal = FatalSpy()
    transport.set_fatal_handler(fatal)
    await clock.run_task(transport.send_npdu(b"\x00"))
    r0.inject_write_fault(WriteFaultSpec(fault, TUNNEL_NPDU))  # type: ignore[arg-type]
    sends = [asyncio.create_task(transport.send_npdu(bytes([i]))) for i in range(1, 4)]
    results = await clock.run_task(asyncio.gather(*sends, return_exceptions=True))
    assert all(isinstance(r, TransportError) for r in results)
    assert [r.reason for r in results if isinstance(r, TransportError)] == [
        reason,
        "closed",
        "closed",
    ]
    if fault == "hang":
        assert clock.now() >= 10.0  # production write timeout
    assert transport.broken
    assert len(fatal.errors) == 1
    assert fatal.errors[0].reason == reason
    assert [n.npdu for n in peer.npdus] == [b"\x00"]
    with pytest.raises(TransportError) as exc:
        await transport.send_npdu(b"\x09")
    assert exc.value.reason == "closed"
    with pytest.raises(TransportError) as exc:
        await transport.read_commissioning_status()
    assert exc.value.reason == "closed"
    await transport.close()
    assert len(fatal.errors) == 1  # close never calls the fatal handler


async def test_disconnect_during_write_breaks() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    fatal = FatalSpy()
    transport.set_fatal_handler(fatal)
    r0.inject_write_fault(WriteFaultSpec("disconnect", TUNNEL_NPDU))
    with pytest.raises(TransportError) as exc:
        await clock.run_task(transport.send_npdu(b"\x01"))
    assert exc.value.reason == "write"
    assert transport.broken
    assert len(fatal.errors) == 1
    await transport.close()  # stop_notify on a dead client is ignored
    assert transport.closed


async def test_counter_exhaustion_breaks() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    fatal = FatalSpy()
    transport.set_fatal_handler(fatal)
    cipher = transport._cipher
    assert cipher is not None
    cipher._outgoing = MAX_COUNTER + 1  # white-box: skip 4 billion frames
    with pytest.raises(TransportError) as exc:
        await clock.run_task(transport.send_npdu(b"\x01"))
    assert exc.value.reason == "write"
    assert transport.broken
    assert len(fatal.errors) == 1
    assert r0.write_counters == ()  # nothing reached the GATT layer
    await transport.close()


async def test_fatal_handler_exception_is_contained() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)

    def explode(_error: TransportError) -> None:
        raise RuntimeError("handler bug")

    transport.set_fatal_handler(explode)
    r0.inject_write_fault(WriteFaultSpec("raise", TUNNEL_NPDU))
    with pytest.raises(TransportError):
        await clock.run_task(transport.send_npdu(b"\x01"))
    assert transport.broken
    await transport.close()


async def test_broken_without_fatal_handler() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    r0.inject_write_fault(WriteFaultSpec("raise", TUNNEL_NPDU))
    with pytest.raises(TransportError):
        await clock.run_task(transport.send_npdu(b"\x01"))
    assert transport.broken
    await transport.close()


async def test_close_awaits_an_idle_writer() -> None:
    clock = VirtualClock()
    _, _, transport = await opened(clock)
    writer = transport._writer
    assert writer is not None
    assert writer.task is not None
    assert not writer.task.done()
    await transport.close()
    assert writer.task.done()
    assert not transport.broken
    with pytest.raises(TransportError) as exc:
        await transport.send_npdu(b"\x01")
    assert exc.value.reason == "closed"


async def test_close_mid_flight_marks_broken_and_fails_senders() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    fatal = FatalSpy()
    transport.set_fatal_handler(fatal)
    r0.inject_write_fault(WriteFaultSpec("hang", TUNNEL_NPDU))
    sends = [asyncio.create_task(transport.send_npdu(bytes([i]))) for i in range(3)]
    await clock.advance(1.0)  # first write hangs, two queued
    writer = transport._writer
    assert writer is not None
    assert writer.task is not None
    await transport.close()
    assert writer.task.done()
    assert transport.broken  # the cancelled write may have reached the ZDD
    results = await asyncio.gather(*sends, return_exceptions=True)
    assert [r.reason for r in results if isinstance(r, TransportError)] == ["closed"] * 3
    assert fatal.errors == []
    assert r0.max_writes_in_flight == 1


async def test_long_write_failure_reason() -> None:
    clock = VirtualClock()
    _, peer, transport = await opened(clock, mtu_size=60, long_write_supported=False)
    fatal = FatalSpy()
    transport.set_fatal_handler(fatal)
    await clock.run_task(transport.send_npdu(bytes(40)))  # 40 + 2 + 2 + 8 = 52 <= 57
    with pytest.raises(TransportError) as exc:
        await clock.run_task(transport.send_npdu(bytes(60)))  # 72 > 57
    assert exc.value.reason == "long_write_unsupported"
    assert fatal.errors[0].reason == "long_write_unsupported"
    assert len(peer.npdus) == 1
    await transport.close()


async def test_long_write_succeeds_when_supported() -> None:
    clock = VirtualClock()
    _, peer, transport = await opened(clock, mtu_size=60, long_write_supported=True)
    await clock.run_task(transport.send_npdu(bytes(60)))
    assert peer.npdus[0].npdu == bytes(60)
    assert not transport.broken
    await transport.close()


async def test_missing_tunnel_characteristic_on_write() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock, mtu_size=60)
    # The services view is fixed per connection; hide Tunnel on this one (white-box).
    client = r0.client
    assert client is not None
    client._services._stale = True
    with pytest.raises(TransportError) as exc:
        await clock.run_task(transport.send_npdu(bytes(60)))  # oversized, still missing_char
    assert exc.value.reason == "missing_characteristic"
    await transport.close()


async def test_send_before_open_is_closed() -> None:
    from test_sim_gatt import make_r0
    from test_transport import make_transport

    clock = VirtualClock()
    transport, _ = make_transport(make_r0(clock))
    with pytest.raises(TransportError) as exc:
        await transport.send_npdu(b"\x01")
    assert exc.value.reason == "closed"
    with pytest.raises(TransportError):
        await transport.read_commissioning_status()


async def test_close_after_the_mid_flight_caller_gave_up() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    r0.inject_write_fault(WriteFaultSpec("hang", TUNNEL_NPDU))
    send = asyncio.create_task(transport.send_npdu(b"\x01"))
    await clock.advance(1.0)
    send.cancel()
    with pytest.raises(asyncio.CancelledError):
        await send
    await transport.close()
    assert transport.broken
