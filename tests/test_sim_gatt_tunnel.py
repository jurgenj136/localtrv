"""Simulated R0, Tunnel (T8): network seam, replays, MTU and oversize, long writes, injection."""

from __future__ import annotations

import pytest

from test_sim_gatt import RecordingPeer, Zvd, counter, make_r0
from vicare_local_ble.testing import FakeGattError, FakeZdd
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
from vicare_local_ble.zigbee_direct.errors import AuthenticationError, ReplayError
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes
from vicare_local_ble.zigbee_direct.uuids import TUNNEL_NPDU, TUNNEL_SERVICE


async def test_tunnel_writes_reach_the_peer() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    await zvd.send(b"\x01\x02")
    await zvd.send(b"\x03", secure=False)
    expected = (TunnelNpdu(b"\x01\x02", True), TunnelNpdu(b"\x03", False))
    assert tuple(peer.npdus) == expected
    assert r0.tunnel_writes == expected
    assert r0.write_counters == (1, 2)


async def test_indications_reach_the_client_from_the_network() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    clock.call_later(1.0, lambda: r0.indicate_npdu(b"\x09\x12", secure=False))
    await clock.advance(1.0)
    assert [zvd.open(f) for f in zvd.tunnel] == [b"\x09\x12"]


async def test_tunnel_write_before_session_gives_0x80() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(TUNNEL_NPDU, bytes(12), response=True)
    assert exc.value.code == 0x80


async def test_indication_without_session_or_subscription_is_dropped() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    r0.indicate_npdu(b"\x01")  # no client at all
    zvd = Zvd(r0, clock)
    r0.indicate_npdu(b"\x01")  # no session
    await zvd.handshake(subscribe_tunnel=False)
    r0.indicate_npdu(b"\x01")  # no Tunnel subscription
    await zvd.client.start_notify(TUNNEL_NPDU, lambda _c, d: zvd.tunnel.append(bytes(d)))
    r0.indicate_npdu(b"\x02")
    await zvd.client.stop_notify(TUNNEL_NPDU)
    r0.indicate_npdu(b"\x03")
    assert [zvd.open(f) for f in zvd.tunnel] == [b"\x02"]


@pytest.mark.parametrize("case", ["replay", "out_of_order", "bad_mic", "short"])
async def test_rejected_writes_silent_drop(case: str) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, replay_behavior="silent_drop")
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    bad = await _bad_frame(zvd, case)
    await zvd.client.write_gatt_char(TUNNEL_NPDU, bad, response=True)  # no error
    expected = [b"\x02"] if case == "out_of_order" else [b"\x01"]
    assert [n.npdu for n in peer.npdus] == expected
    assert len(r0.write_counters) == (1 if case == "short" else 2)  # every frame with a counter


@pytest.mark.parametrize("case", ["replay", "out_of_order", "bad_mic", "short"])
async def test_rejected_writes_gatt_error(case: str) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, replay_behavior="gatt_error")
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    bad = await _bad_frame(zvd, case)
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(TUNNEL_NPDU, bad, response=True)
    assert exc.value.code == 0x80
    assert len(peer.npdus) == 1
    assert zvd.client.is_connected


async def _bad_frame(zvd: Zvd, case: str) -> bytes:
    """Send one good frame and return a frame the R0 must reject."""
    if case == "out_of_order":
        first, second = zvd.seal(b"\x01"), zvd.seal(b"\x02")
        await zvd.client.write_gatt_char(TUNNEL_NPDU, second, response=True)
        return first
    frame = await zvd.send(b"\x01")
    if case == "replay":
        return frame
    if case == "short":
        return b"\x01\x02"
    fresh = zvd.seal(b"\x02")
    return fresh[:-1] + bytes([fresh[-1] ^ 0xFF])


async def test_mtu_size_is_configurable() -> None:
    clock = VirtualClock()
    zvd = Zvd(make_r0(clock, mtu_size=64), clock)
    assert zvd.client.mtu_size == 64


@pytest.mark.parametrize(
    ("behavior", "delivered", "next_counter"),
    [("truncate", 1, 2), ("drop", 0, 2), ("reject", 0, 1)],
)
async def test_oversized_indications(behavior: str, delivered: int, next_counter: int) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, mtu_size=64, oversize_indication=behavior)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.indicate_npdu(bytes(60))  # frame 8 + 4 + 60 = 72 > mtu - 3
    assert r0.oversized_indications == 1
    assert len(zvd.tunnel) == delivered
    if behavior == "truncate":
        assert len(zvd.tunnel[0]) == 61
        with pytest.raises(AuthenticationError):
            zvd.open(zvd.tunnel.pop())
    r0.indicate_npdu(b"\x01")
    assert counter(zvd.tunnel[-1]) == next_counter
    assert zvd.open(zvd.tunnel[-1]) == b"\x01"


async def test_indication_at_the_mtu_limit_is_not_oversized() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, mtu_size=64, oversize_indication="reject")
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.indicate_npdu(bytes(61 - 8 - 4))
    assert r0.oversized_indications == 0
    assert len(zvd.tunnel[0]) == 61


@pytest.mark.parametrize("supported", [True, False])
async def test_long_writes(supported: bool) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, mtu_size=64, long_write_supported=supported)  # SE1 (47 B) fits
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    await zvd.send(bytes(20))  # frame 8 + 4 + 20 = 32 <= mtu - 3: always fine
    frame = zvd.seal(bytes(60))  # frame 72 > 61: needs a long write
    if supported:
        await zvd.client.write_gatt_char(TUNNEL_NPDU, frame, response=True)
        assert len(peer.npdus) == 2
    else:
        with pytest.raises(FakeGattError) as exc:
            await zvd.client.write_gatt_char(TUNNEL_NPDU, frame, response=True)
        assert exc.value.code not in (0x80, None)
        assert len(peer.npdus) == 1
        assert r0.write_counters == (1,)  # the device never saw it


async def test_inject_replayed_indication() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.inject_replayed_indication()  # nothing indicated yet: no-op
    assert zvd.tunnel == []
    r0.indicate_npdu(b"\x01")
    r0.inject_replayed_indication()
    assert zvd.tunnel[0] == zvd.tunnel[1]
    assert zvd.open(zvd.tunnel[0]) == b"\x01"
    with pytest.raises(ReplayError):
        zvd.open(zvd.tunnel[1])


async def test_inject_bad_mic_indication() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.inject_bad_mic_indication()
    r0.indicate_npdu(b"\x01")
    r0.indicate_npdu(b"\x02")
    with pytest.raises(AuthenticationError):
        zvd.open(zvd.tunnel[0])
    assert counter(zvd.tunnel[1]) == counter(zvd.tunnel[0]) + 1  # counter was consumed
    assert zvd.open(zvd.tunnel[1]) == b"\x02"


def test_fake_zdd_seal_and_open_need_a_session() -> None:
    zdd = FakeZdd(eui=Eui64.from_str("02:00:00:00:00:00:00:02"), psk=SecretBytes(bytes(16)))
    assert not zdd.established
    with pytest.raises(RuntimeError):
        zdd.seal(TUNNEL_SERVICE, TUNNEL_NPDU, b"x")
    with pytest.raises(RuntimeError):
        zdd.open_frame(TUNNEL_SERVICE, TUNNEL_NPDU, bytes(12))
