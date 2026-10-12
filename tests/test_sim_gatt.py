"""Simulated R0, GATT level (T8): handshake, Status reads, counter models, indication timing.

Shared helpers live here too (``test_sim_gatt_*.py`` import them). The client side is the
phase-1 ``HandshakeInitiator`` + ``SessionCipher`` driving ``FakeBleakClient`` directly; the
transport (T10) is not involved. Everything runs on ``VirtualClock`` with production-size
timeouts. Keys and EUIs are dummies.
"""

from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING, Any

import pytest

from vicare_local_ble.testing import FakeGattError, SimulatedR0, ZddCounterModel
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.commissioning import CommissioningStatus
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu, parse_tunnel_tlvs
from vicare_local_ble.zigbee_direct.crypto import SecretType, derive_basic_authorization_key
from vicare_local_ble.zigbee_direct.errors import HandshakeError
from vicare_local_ble.zigbee_direct.session import (
    CounterModel,
    Established,
    HandshakeInitiator,
    SendSe3,
    SessionCipher,
)
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes
from vicare_local_ble.zigbee_direct.uuids import (
    COMMISSIONING_IDENTIFY,
    COMMISSIONING_SERVICE,
    COMMISSIONING_STATUS,
    SECURITY_AUTHENTICATE_C25519,
    TUNNEL_NPDU,
    TUNNEL_SERVICE,
)

if TYPE_CHECKING:
    from vicare_local_ble.testing.network import TunnelHost
    from vicare_local_ble.zigbee_direct.transport import GattClient


AUTH = SECURITY_AUTHENTICATE_C25519
ZVD = Eui64.from_str("02:00:00:00:00:00:00:01")
ZDD = Eui64.from_str("02:00:00:00:00:00:00:02")
EPID = Eui64.from_str("02:00:00:00:00:00:00:0A")
TC = Eui64.from_str("02:00:00:00:00:00:00:0B")
OTHER = Eui64.from_str("02:00:00:00:00:00:00:0C")
NETWORK_KEY = SecretBytes(bytes(range(0x10, 0x20)))
LINK_KEY = SecretBytes(bytes(range(0x20, 0x30)))
ADMIN_KEY = SecretBytes(bytes(range(0x30, 0x40)))
ZVD_PRIV = SecretBytes(bytes(range(0x40, 0x60)))
BAK = derive_basic_authorization_key(ZVD, NETWORK_KEY)
ZDD_SHORT = 0x1234
PAN_ID = 0xABCD
HANDSHAKE_TIMEOUT = 10.0  # production value


def make_r0(clock: VirtualClock, *, seed: int = 7, **knobs: Any) -> SimulatedR0:
    return SimulatedR0(
        clock,
        eui=ZDD,
        network_key=NETWORK_KEY,
        zdd_short=ZDD_SHORT,
        pan_id=PAN_ID,
        extended_pan_id=EPID,
        trust_center_eui=TC,
        link_key=LINK_KEY,
        admin_key=ADMIN_KEY,
        rng=random.Random(seed),  # noqa: S311 - deterministic simulator
        **knobs,
    )


class RecordingPeer:
    """``TunnelPeer`` stub; ``echo`` answers every NPDU synchronously via ``indicate_npdu``."""

    def __init__(self, r0: SimulatedR0, *, echo: bool = False) -> None:
        self.r0 = r0
        self.echo = echo
        self.npdus: list[TunnelNpdu] = []
        self.resets = 0
        r0.attach_network(self)

    def on_zvd_npdu(self, npdu: TunnelNpdu) -> None:
        self.npdus.append(npdu)
        if self.echo:
            self.r0.indicate_npdu(b"\xec" + npdu.npdu)

    def on_session_reset(self) -> None:
        self.resets += 1


class Zvd:
    """The client side: phase-1 initiator + cipher over one ``FakeBleakClient``."""

    def __init__(self, r0: SimulatedR0, clock: VirtualClock) -> None:
        self.r0 = r0
        self.clock = clock
        self.disconnects: list[GattClient] = []
        self.client = r0.connect(r0.ble_device(), self.disconnects.append)
        self.auth: list[bytes] = []
        self.auth_event = asyncio.Event()
        self.tunnel: list[bytes] = []
        self._cipher: SessionCipher | None = None
        self.initiator = HandshakeInitiator(
            own_eui=ZVD,
            psk=BAK,
            secret_type=SecretType.BASIC_AUTHORIZATION_KEY,
            private_key=ZVD_PRIV,
        )

    @property
    def cipher(self) -> SessionCipher:
        assert self._cipher is not None
        return self._cipher

    def _on_auth(self, _char: object, data: bytearray) -> None:
        self.auth.append(bytes(data))
        self.auth_event.set()

    def _on_tunnel(self, _char: object, data: bytearray) -> None:
        self.tunnel.append(bytes(data))

    async def next_auth(self) -> bytes:
        """Wait (production timeout) for the next Authenticate indication."""
        async with self.clock.timeout(HANDSHAKE_TIMEOUT):
            while not self.auth:
                self.auth_event.clear()
                await self.auth_event.wait()
        return self.auth.pop(0)

    async def write(self, char: str, data: bytes) -> None:
        """Write on the virtual clock (``write_latency`` elapses in virtual time)."""
        await self.clock.run_task(self.client.write_gatt_char(char, data, response=True))

    async def write_se1(self) -> None:
        await self.client.start_notify(AUTH, self._on_auth)
        await self.client.write_gatt_char(AUTH, self.initiator.start(), response=True)

    async def se3(self) -> bytes:
        step = self.initiator.feed(await self.clock.run_task(self.next_auth()))
        assert isinstance(step, SendSe3)
        return step.payload

    async def handshake(self, *, subscribe_tunnel: bool = True) -> SessionCipher:
        await self.client.start_notify(AUTH, self._on_auth)
        await self.write(AUTH, self.initiator.start())
        await self.write(AUTH, await self.se3())
        step = self.initiator.feed(await self.clock.run_task(self.next_auth()))
        assert isinstance(step, Established)
        self._cipher = step.cipher
        if subscribe_tunnel:
            await self.client.start_notify(TUNNEL_NPDU, self._on_tunnel)
        return step.cipher

    def seal(self, npdu: bytes, *, secure: bool = True) -> bytes:
        return self.cipher.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, TunnelNpdu(npdu, secure).encode())

    async def send(self, npdu: bytes, *, secure: bool = True) -> bytes:
        frame = self.seal(npdu, secure=secure)
        await self.client.write_gatt_char(TUNNEL_NPDU, frame, response=True)
        return frame

    def open(self, frame: bytes) -> bytes:
        (item,) = parse_tunnel_tlvs(self.cipher.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, frame))
        assert isinstance(item, TunnelNpdu)
        return item.npdu

    async def read_status(self) -> CommissioningStatus:
        raw = await self.client.read_gatt_char(COMMISSIONING_STATUS)
        plain = self.cipher.decrypt(COMMISSIONING_SERVICE, COMMISSIONING_STATUS, bytes(raw))
        return CommissioningStatus.decode(plain)


def counter(frame: bytes) -> int:
    return int.from_bytes(frame[:4], "little")


def _r0_is_tunnel_host(r0: SimulatedR0) -> TunnelHost:
    return r0  # mypy: SimulatedR0 satisfies network.TunnelHost


# --- handshake and Status --------------------------------------------------------------------


async def test_handshake_then_status_read() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.write_se1()
    assert zvd.auth == []  # SE2 comes after handshake_latency, not inside the write
    await clock.advance(0.05)
    assert len(zvd.auth) == 1
    await zvd.client.write_gatt_char(AUTH, await zvd.se3(), response=True)
    step = zvd.initiator.feed(await clock.run_task(zvd.next_auth()))
    assert isinstance(step, Established)
    assert step.peer_eui == ZDD
    zvd._cipher = step.cipher
    assert r0.session_established
    status = await zvd.read_status()
    assert status.nwk_address == ZDD_SHORT
    assert status.pan_id == PAN_ID
    assert status.ieee_address == ZDD
    assert status.extended_pan_id == EPID
    assert status.trust_center_address == TC
    assert status.network_key == NETWORK_KEY
    assert status.link_key == LINK_KEY
    assert status.admin_key == ADMIN_KEY
    assert clock.now() < 1.0


async def test_status_value_never_in_reprs() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    await zvd.read_status()
    for text in (repr(r0), repr(zvd.client), repr(r0.client)):
        for key in (NETWORK_KEY, LINK_KEY, ADMIN_KEY):
            assert key.reveal().hex() not in text


async def test_se3_bad_tag_gives_0x80() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.write_se1()
    await zvd.se3()
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(AUTH, b"\x03\x04\x0f" + bytes(16), response=True)
    assert exc.value.code == 0x80
    assert not r0.session_established
    assert zvd.client.is_connected


async def test_wrong_network_key_gives_0x80_on_se3() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    zvd.initiator = HandshakeInitiator(
        own_eui=ZVD,
        psk=derive_basic_authorization_key(ZVD, LINK_KEY),  # wrong key
        secret_type=SecretType.BASIC_AUTHORIZATION_KEY,
        private_key=ZVD_PRIV,
    )
    await zvd.write_se1()
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(AUTH, await zvd.se3(), response=True)
    assert exc.value.code == 0x80


@pytest.mark.parametrize("char", [COMMISSIONING_STATUS, COMMISSIONING_IDENTIFY])
async def test_read_before_session_gives_0x80(char: str) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.read_gatt_char(char)
    assert exc.value.code == 0x80
    await zvd.write_se1()  # SE1 alone does not open the session
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.read_gatt_char(char)
    assert exc.value.code == 0x80


async def test_identify_readable_after_session() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    raw = await zvd.client.read_gatt_char(COMMISSIONING_IDENTIFY)
    assert zvd.cipher.decrypt(COMMISSIONING_SERVICE, COMMISSIONING_IDENTIFY, bytes(raw))


@pytest.mark.parametrize("code", [0x0E, 0x81, 0x01])
async def test_se3_gatt_error_is_not_0x80(code: int) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, se3_fault="gatt_error", se3_error_code=code)
    zvd = Zvd(r0, clock)
    await zvd.write_se1()
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(AUTH, await zvd.se3(), response=True)
    assert exc.value.code == code
    assert exc.value.code != 0x80
    assert zvd.client.is_connected


async def test_se3_disconnect_is_not_0x80() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, se3_fault="disconnect")
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.write_se1()
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(AUTH, await zvd.se3(), response=True)
    assert exc.value.code != 0x80
    assert not zvd.client.is_connected
    assert zvd.disconnects == [zvd.client]
    assert peer.resets == 1
    assert r0.client is None


async def test_se2_silence_times_out() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, handshake_fault="se2_silence")
    zvd = Zvd(r0, clock)
    await zvd.write_se1()
    with pytest.raises(TimeoutError):
        await clock.run_task(zvd.next_auth())
    assert clock.now() == pytest.approx(HANDSHAKE_TIMEOUT)


async def test_se4_silence_times_out() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, handshake_fault="se4_silence")
    zvd = Zvd(r0, clock)
    await zvd.write_se1()
    await zvd.client.write_gatt_char(AUTH, await zvd.se3(), response=True)
    with pytest.raises(TimeoutError):
        await clock.run_task(zvd.next_auth())
    assert r0.session_established  # the device accepted SE3; only SE4 got lost


async def test_malformed_se2_is_a_protocol_error() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, handshake_fault="malformed_se2")
    zvd = Zvd(r0, clock)
    await zvd.write_se1()
    with pytest.raises(HandshakeError, match="truncated"):
        await zvd.se3()


async def test_same_seed_same_handshake_bytes() -> None:
    se2s = []
    for _ in range(2):
        clock = VirtualClock()
        zvd = Zvd(make_r0(clock, seed=3), clock)
        await zvd.write_se1()
        se2s.append(await clock.run_task(zvd.next_auth()))
    assert se2s[0] == se2s[1]


async def test_new_se1_ends_the_session() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    with pytest.raises(FakeGattError) as exc:
        await zvd.client.write_gatt_char(AUTH, b"\x01\x00\x01\x01\x03", response=True)
    assert exc.value.code == 0x80
    assert not r0.session_established
    assert peer.resets == 1


# --- counter models ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "expected", "status_ctr", "tunnel_ctrs"),
    [
        (ZddCounterModel.SHARED, CounterModel.SHARED, 1, [2, 3]),
        (ZddCounterModel.PER_CHARACTERISTIC, CounterModel.PER_CHARACTERISTIC, 1, [1, 2]),
    ],
)
async def test_counter_models(
    model: ZddCounterModel, expected: CounterModel, status_ctr: int, tunnel_ctrs: list[int]
) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, counter_model=model)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    raw = bytes(await zvd.client.read_gatt_char(COMMISSIONING_STATUS))
    assert counter(raw) == status_ctr
    zvd.cipher.decrypt(COMMISSIONING_SERVICE, COMMISSIONING_STATUS, raw)
    r0.indicate_npdu(b"\x01")
    r0.indicate_npdu(b"\x02")
    assert [counter(f) for f in zvd.tunnel] == tunnel_ctrs
    assert [zvd.open(f) for f in zvd.tunnel] == [b"\x01", b"\x02"]
    assert zvd.cipher.counter_model() is expected


# --- indication timing (race hooks for T10) ----------------------------------------------------


async def test_handshake_response_before_write_returns() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, indicate_before_write_returns=True, write_latency=0.2)
    zvd = Zvd(r0, clock)
    write = asyncio.create_task(zvd.write_se1())
    await clock.run_until_idle()
    assert len(zvd.auth) == 1  # SE2 already delivered ...
    assert not write.done()  # ... while the SE1 write is still in flight
    await clock.advance(0.2)
    assert write.done()
    await write


async def test_tunnel_response_before_write_returns() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, indicate_before_write_returns=True, write_latency=0.2)
    RecordingPeer(r0, echo=True)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    send = asyncio.create_task(zvd.send(b"\x42"))
    await clock.run_until_idle()
    assert [zvd.open(f) for f in zvd.tunnel] == [b"\xec\x42"]
    assert not send.done()
    await clock.advance(0.2)
    await send


@pytest.mark.parametrize("latency", [0.0, 0.2])
async def test_tunnel_response_after_write_returns_by_default(latency: float) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, write_latency=latency)
    RecordingPeer(r0, echo=True)
    zvd = Zvd(r0, clock)
    await zvd.handshake()
    send = asyncio.create_task(zvd.send(b"\x42"))
    seen_at_return: list[int] = []
    send.add_done_callback(lambda _t: seen_at_return.append(len(zvd.tunnel)))
    await clock.advance(latency)
    await send
    assert seen_at_return == [0]
    assert [zvd.open(f) for f in zvd.tunnel] == [b"\xec\x42"]
