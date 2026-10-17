"""Simulated R0, connection-level faults: write faults, cancellation, disconnect, stale
services, reboot, Status variants, the GATT surface and ``fake_connector``."""

from __future__ import annotations

import asyncio

import pytest
from bleak.exc import BleakCharacteristicNotFoundError, BleakError
from bleak_retry_connector import BleakClientWithServiceCache

from localtrv.testing import FakeGattError, WriteFaultSpec, fake_connector
from localtrv.zigbee_direct.clock import VirtualClock
from localtrv.zigbee_direct.uuids import (
    COMMISSIONING_FORM_NETWORK,
    COMMISSIONING_STATUS,
    TUNNEL_NPDU,
)
from test_sim_gatt import AUTH, OTHER, RecordingPeer, Zvd, make_r0

# --- write faults ------------------------------------------------------------------------------


async def test_write_fault_raise_after_n_writes() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.inject_write_fault(WriteFaultSpec("raise", TUNNEL_NPDU.upper(), after_writes=1, code=0x81))
    await zvd.send(b"\x01")
    with pytest.raises(FakeGattError) as exc:
        await zvd.send(b"\x02")
    assert exc.value.code == 0x81
    await zvd.send(b"\x03")  # consumed: later writes succeed
    assert [n.npdu for n in peer.npdus] == [b"\x01", b"\x03"]
    assert r0.write_counters == (1, 3)  # the failed write never reached the device


async def test_write_fault_only_hits_its_characteristic() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    r0.inject_write_fault(WriteFaultSpec("raise", TUNNEL_NPDU))
    zvd = Zvd(r0, clock)
    await zvd.handshake()  # Authenticate writes are unaffected
    with pytest.raises(FakeGattError):
        await zvd.send(b"\x01")


async def test_write_fault_hang_until_cancelled_then_next_sender() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.inject_write_fault(WriteFaultSpec("hang", TUNNEL_NPDU))
    hung = asyncio.create_task(zvd.send(b"\x01"))
    await clock.advance(3600.0)
    assert not hung.done()
    hung.cancel()
    with pytest.raises(asyncio.CancelledError):
        await hung
    await zvd.send(b"\x02")
    assert [n.npdu for n in peer.npdus] == [b"\x02"]
    assert r0.max_writes_in_flight == 1


async def test_write_fault_hang_ends_with_disconnect() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.inject_write_fault(WriteFaultSpec("hang", TUNNEL_NPDU))
    hung = asyncio.create_task(zvd.send(b"\x01"))
    await clock.advance(1.0)
    r0.disconnect()
    with pytest.raises(FakeGattError) as exc:
        await hung
    assert exc.value.code != 0x80


async def test_write_fault_disconnect() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.inject_write_fault(WriteFaultSpec("disconnect", TUNNEL_NPDU))
    with pytest.raises(FakeGattError):
        await zvd.send(b"\x01")
    assert zvd.disconnects == [zvd.client]
    assert peer.resets == 1
    assert peer.npdus == []


async def test_cancel_mid_flight_spends_the_counter_and_never_overlaps() -> None:
    """Race hook: a sender cancelled during ``write_latency`` then an immediate second sender."""
    clock = VirtualClock()
    r0 = make_r0(clock, write_latency=0.5)
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    first = asyncio.create_task(zvd.send(b"\x01"))
    await clock.advance(0.1)
    first.cancel()
    second = asyncio.create_task(zvd.send(b"\x02"))
    with pytest.raises(asyncio.CancelledError):
        await first
    await clock.run_task(second)
    assert [n.npdu for n in peer.npdus] == [b"\x01", b"\x02"]  # the cancelled one arrived
    assert r0.write_counters == (1, 2)
    assert r0.max_writes_in_flight == 1


async def test_overlapping_writes_are_recorded() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, write_latency=0.5)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    sends = [asyncio.create_task(zvd.send(bytes([i]))) for i in range(2)]
    await clock.advance(0.5)
    await asyncio.gather(*sends)
    assert r0.max_writes_in_flight == 2


# --- disconnect, reboot, stale services --------------------------------------------------------


async def test_disconnect_injection() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.disconnect()
    r0.disconnect()  # idempotent
    assert zvd.disconnects == [zvd.client]
    assert not zvd.client.is_connected
    assert r0.client is None
    assert not r0.session_established
    assert peer.resets == 1
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.read_gatt_char(COMMISSIONING_STATUS)
    assert exc.value.code != 0x80
    for op in (
        zvd.client.start_notify(TUNNEL_NPDU, lambda _c, _d: None),
        zvd.client.stop_notify(TUNNEL_NPDU),
        zvd.client.write_gatt_char(TUNNEL_NPDU, b"x", response=True),
    ):
        with pytest.raises(FakeGattError):
            await op
    await zvd.client.disconnect()  # still fine
    assert await zvd.client.clear_cache()
    again = Zvd(r0, clock)
    await again.handshake()
    assert r0.connect_count == 2
    assert r0.client is again.client


async def test_client_disconnect_fires_callback_once() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.client.disconnect()
    await zvd.client.disconnect()
    assert zvd.disconnects == [zvd.client]


async def test_second_connect_while_connected_fails() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    Zvd(r0, clock)
    with pytest.raises(FakeGattError):
        r0.connect(r0.ble_device(), None)


async def test_r0_reboot() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    r0.r0_reboot()  # not connected: still resets the peer
    assert peer.resets == 1
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.r0_reboot()
    assert peer.resets == 2
    assert zvd.disconnects == [zvd.client]
    assert not r0.session_established


async def test_stale_services_until_clear_cache() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, stale_services=True)
    zvd = Zvd(r0, clock)
    assert zvd.client.services.get_characteristic(TUNNEL_NPDU) is None
    assert zvd.client.services.get_characteristic(AUTH) is not None
    await zvd.handshake(subscribe_tunnel=False)
    for op in (
        zvd.client.start_notify(TUNNEL_NPDU, lambda _c, _d: None),
        zvd.client.write_gatt_char(TUNNEL_NPDU, b"x", response=True),
        zvd.client.read_gatt_char(TUNNEL_NPDU),
    ):
        with pytest.raises(BleakCharacteristicNotFoundError):
            await op
    assert await zvd.client.clear_cache() is True
    assert zvd.client.services.get_characteristic(TUNNEL_NPDU) is None  # next connection only
    await zvd.client.disconnect()
    fresh = Zvd(r0, clock)
    assert fresh.client.services.get_characteristic(TUNNEL_NPDU) is not None
    await fresh.handshake()


# --- Commissioning Status variants ------------------------------------------------------------


async def test_status_omit_short() -> None:
    clock = VirtualClock()
    zvd = Zvd(make_r0(clock, status_omit_short=True), clock)
    await zvd.handshake()
    status = await zvd.read_status()
    assert status.nwk_address is None
    assert status.network_key is not None


async def test_status_ieee_override() -> None:
    clock = VirtualClock()
    zvd = Zvd(make_r0(clock, status_ieee_override=OTHER), clock)
    await zvd.handshake()
    status = await zvd.read_status()
    assert status.ieee_address == OTHER
    assert zvd.cipher.peer_eui != OTHER  # SE2 still carries the real ZDD EUI


# --- GATT surface ------------------------------------------------------------------------------


async def test_gatt_surface_errors() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    with pytest.raises(ValueError, match="response=True"):
        await zvd.client.write_gatt_char(TUNNEL_NPDU, b"x")
    with pytest.raises(BleakCharacteristicNotFoundError):
        await zvd.client.read_gatt_char("00000000-0000-0000-0000-000000000000")
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(COMMISSIONING_FORM_NETWORK, b"x", response=True)
    assert exc.value.code == 0x03
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.read_gatt_char(TUNNEL_NPDU)
    assert exc.value.code == 0x02
    await zvd.client.disconnect()
    fresh = Zvd(r0, clock)
    with pytest.raises(FakeGattError) as exc:  # SE3 without SE1 on a fresh connection
        await fresh.client.write_gatt_char(AUTH, b"\x03\x04\x0f" + bytes(16), response=True)
    assert exc.value.code == 0x80
    assert zvd.client.address == r0.address
    assert zvd.client.device.address == r0.address
    assert "connected=False" in repr(zvd.client)


async def test_disconnect_during_latency_fails_the_read() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    r0.write_latency = 1.0
    read = asyncio.create_task(zvd.client.read_gatt_char(COMMISSIONING_STATUS))
    await clock.advance(0.5)
    r0.disconnect()
    await clock.advance(0.5)
    with pytest.raises(FakeGattError):
        await read


def test_ble_device_per_source() -> None:
    r0 = make_r0(VirtualClock())
    a, b = r0.ble_device(), r0.ble_device(source="proxy-1")
    assert a is not b
    assert a.address == b.address == r0.address
    assert a.details == {"source": "hci0"}
    assert b.details == {"source": "proxy-1"}


# --- fake_connector ----------------------------------------------------------------------------


async def test_fake_connector_connects_after_latency() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    connector = fake_connector(r0, connect_latency=0.5)
    device = r0.ble_device()
    gone: list[object] = []
    client = await clock.run_task(connector(BleakClientWithServiceCache, device, "R0", gone.append))
    assert clock.now() == pytest.approx(0.5)
    assert client is r0.client
    assert connector.devices == (device,)
    await client.disconnect()
    assert gone == [client]


async def test_fake_connector_fail_and_hang() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    connector = fake_connector(r0)
    device = r0.ble_device()
    custom = TimeoutError("custom")
    connector.fail_next()
    connector.fail_next(exc=custom)
    with pytest.raises(BleakError):
        await clock.run_task(connector(BleakClientWithServiceCache, device, "R0"))
    with pytest.raises(TimeoutError, match="custom"):
        await clock.run_task(connector(BleakClientWithServiceCache, device, "R0"))
    connector.hang_next()
    hung = asyncio.create_task(connector(BleakClientWithServiceCache, device, "R0"))
    await clock.advance(3600.0)
    assert not hung.done()
    hung.cancel()
    with pytest.raises(asyncio.CancelledError):
        await hung
    assert await clock.run_task(connector(BleakClientWithServiceCache, device, "R0"))
    assert len(connector.devices) == 4
    assert r0.connect_count == 1
