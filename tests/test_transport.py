"""ZigbeeDirectTransport (T10): handshake, strict auth classification, MTU, missing characteristic.

Shared helpers live here (``test_transport_*.py`` import them). Everything runs against the
simulated R0 on ``VirtualClock`` with production timeouts (10 s); keys and EUIs are dummies.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import pytest
from bleak.exc import (
    BleakCharacteristicNotFoundError,
    BleakDBusError,
    BleakError,
    BleakGATTProtocolError,
)

from test_sim_gatt import AUTH, LINK_KEY, NETWORK_KEY, ZDD, ZVD, RecordingPeer, make_r0
from vicare_local_ble.testing import FakeGattError, SimulatedR0
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.crypto import derive_basic_authorization_key
from vicare_local_ble.zigbee_direct.errors import (
    HandshakeRejectedError,
    TransportError,
)
from vicare_local_ble.zigbee_direct.transport import (
    MIN_RECOMMENDED_MTU,
    SessionInfo,
    ZigbeeDirectTransport,
    _att_error_code,
)
from vicare_local_ble.zigbee_direct.uuids import TUNNEL_NPDU

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.testing import FakeBleakClient
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.transport import GattServices, NotifyCallback
    from vicare_local_ble.zigbee_direct.types import SecretBytes

BAK = derive_basic_authorization_key(ZVD, NETWORK_KEY)
LOGGER = "vicare_local_ble.zigbee_direct.transport"


class SpyClient:
    """``GattClient`` wrapper around ``FakeBleakClient``: records calls, injects faults.

    ``fail[op]`` raises that exception on the next ``op`` call (consumed). ``tamper`` rewrites
    Authenticate indications before they reach the transport.
    """

    def __init__(self, inner: FakeBleakClient) -> None:
        self.inner = inner
        self.calls: list[tuple[str, str]] = []
        self.fail: dict[str, BaseException] = {}
        self.tamper: Callable[[bytes], bytes] | None = None

    @property
    def is_connected(self) -> bool:
        return self.inner.is_connected

    @property
    def mtu_size(self) -> int:
        return self.inner.mtu_size

    @property
    def services(self) -> GattServices:
        return self.inner.services

    def _check(self, op: str, char: str) -> None:
        self.calls.append((op, char))
        exc = self.fail.pop(op, None)
        if exc is not None:
            raise exc

    async def start_notify(self, char_specifier: str, callback: NotifyCallback) -> None:
        self._check("start_notify", char_specifier)

        def wrapped(char: Any, data: bytearray) -> None:
            if self.tamper is not None and char_specifier == AUTH:
                data = bytearray(self.tamper(bytes(data)))
            callback(char, data)

        await self.inner.start_notify(char_specifier, wrapped)

    async def stop_notify(self, char_specifier: str) -> None:
        self._check("stop_notify", char_specifier)
        await self.inner.stop_notify(char_specifier)

    async def write_gatt_char(
        self, char_specifier: str, data: bytes, response: bool | None = None
    ) -> None:
        op = f"write:{data[:1].hex()}" if char_specifier == AUTH else "write"
        self._check(op, char_specifier)
        await self.inner.write_gatt_char(char_specifier, data, response=response)

    async def read_gatt_char(self, char_specifier: str) -> bytearray:
        self._check("read", char_specifier)
        return await self.inner.read_gatt_char(char_specifier)

    async def disconnect(self) -> None:
        await self.inner.disconnect()

    async def clear_cache(self) -> bool:
        return await self.inner.clear_cache()


def make_transport(
    r0: SimulatedR0,
    *,
    psk: SecretBytes = BAK,
    recorder: NpduRecorder | None = None,
    spy: bool = False,
) -> tuple[ZigbeeDirectTransport, SpyClient | FakeBleakClient]:
    inner = r0.connect(r0.ble_device(), None)
    client: SpyClient | FakeBleakClient = SpyClient(inner) if spy else inner
    transport = ZigbeeDirectTransport(
        client, own_eui=ZVD, psk=psk, clock=r0.clock, recorder=recorder
    )
    return transport, client


async def opened(
    clock: VirtualClock, **knobs: Any
) -> tuple[SimulatedR0, RecordingPeer, ZigbeeDirectTransport]:
    r0 = make_r0(clock, **knobs)
    peer = RecordingPeer(r0)
    transport, _ = make_transport(r0)
    await clock.run_task(transport.open())
    return r0, peer, transport


async def open_error(transport: ZigbeeDirectTransport, clock: VirtualClock) -> BaseException:
    with pytest.raises((TransportError, HandshakeRejectedError)) as exc:
        await clock.run_task(transport.open())
    assert transport.closed
    assert transport.session is None
    return exc.value


# --- handshake ------------------------------------------------------------------------------------


async def test_handshake_happy_path(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, _ = make_transport(r0)
    assert transport.session is None
    assert not transport.mtu_low
    info = await clock.run_task(transport.open())
    assert info == SessionInfo(own_eui=ZVD, zdd_eui=ZDD, mtu=247)
    assert transport.session == info
    assert r0.session_established
    assert not transport.broken
    assert not transport.closed
    assert not transport.mtu_low
    assert clock.now() < 1.0
    messages = [r.getMessage() for r in caplog.records if r.name == LOGGER]
    assert "handshake OK" in messages
    assert "connected, mtu=247" in messages
    assert "ZigbeeDirectTransport(" in repr(transport)
    await transport.close()
    assert transport.closed


async def test_handshake_with_indications_inside_the_write() -> None:
    clock = VirtualClock()
    _, _, transport = await opened(clock, indicate_before_write_returns=True)
    assert transport.session is not None
    await transport.close()


async def test_tunnel_subscribed_only_after_se4() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, client = make_transport(r0, spy=True)
    assert isinstance(client, SpyClient)
    await clock.run_task(transport.open())
    ops = [op for op, _ in client.calls]
    assert ops == ["start_notify", "write:01", "write:03", "start_notify"]
    assert client.calls[0] == ("start_notify", AUTH)
    assert client.calls[-1] == ("start_notify", TUNNEL_NPDU)
    await transport.close()
    assert ("stop_notify", TUNNEL_NPDU) in client.calls
    assert ("stop_notify", AUTH) in client.calls


async def test_open_only_once() -> None:
    clock = VirtualClock()
    _, _, transport = await opened(clock)
    with pytest.raises(TransportError) as exc:
        await transport.open()
    assert exc.value.reason == "closed"
    await transport.close()
    await transport.close()  # idempotent
    with pytest.raises(TransportError):
        await transport.open()


# --- auth classification ----------------------------------------------------------------------


async def test_wrong_key_0x80_on_se3_is_rejected() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, _ = make_transport(r0, psk=derive_basic_authorization_key(ZVD, LINK_KEY))
    exc = await open_error(transport, clock)
    assert isinstance(exc, HandshakeRejectedError)


async def test_se3_gatt_error_0x80_is_rejected() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, se3_fault="gatt_error", se3_error_code=0x80)
    transport, _ = make_transport(r0)
    assert isinstance(await open_error(transport, clock), HandshakeRejectedError)


@pytest.mark.parametrize("code", [0x0E, 0x81, 0x05])
async def test_se3_other_gatt_error_is_retryable(code: int) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, se3_fault="gatt_error", se3_error_code=code)
    transport, _ = make_transport(r0)
    exc = await open_error(transport, clock)
    assert type(exc) is TransportError
    assert exc.reason == "write"


async def test_disconnect_during_se3_is_retryable() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, se3_fault="disconnect")
    transport, _ = make_transport(r0)
    exc = await open_error(transport, clock)
    assert type(exc) is TransportError
    assert exc.reason == "write"


async def test_se4_tag_mismatch_is_rejected() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, client = make_transport(r0, spy=True)
    assert isinstance(client, SpyClient)
    client.tamper = lambda m: m[:-1] + bytes([m[-1] ^ 1]) if m[:1] == b"\x04" else m
    assert isinstance(await open_error(transport, clock), HandshakeRejectedError)


@pytest.mark.parametrize("se4", [b"\x05\x04\x0f" + bytes(16), b"\x04", b"\x04\x04\x0f\x00"])
async def test_malformed_se4_is_protocol(se4: bytes) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, client = make_transport(r0, spy=True)
    assert isinstance(client, SpyClient)
    client.tamper = lambda m: se4 if m[:1] == b"\x04" else m
    exc = await open_error(transport, clock)
    assert type(exc) is TransportError
    assert exc.reason == "protocol"


async def test_malformed_se2_is_protocol() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, handshake_fault="malformed_se2")
    transport, _ = make_transport(r0)
    exc = await open_error(transport, clock)
    assert type(exc) is TransportError
    assert exc.reason == "protocol"


@pytest.mark.parametrize("fault", ["se2_silence", "se4_silence"])
async def test_handshake_silence_is_timeout(fault: str) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, handshake_fault=fault)
    transport, client = make_transport(r0)
    exc = await open_error(transport, clock)
    assert type(exc) is TransportError
    assert exc.reason == "timeout"
    assert 10.0 <= clock.now() < 10.5  # production handshake timeout, in virtual time
    assert not isinstance(client, SpyClient)
    assert not client._subscribed(AUTH)  # notifications stopped on failure


@pytest.mark.parametrize(
    ("op", "exc", "reason"),
    [
        ("write:01", FakeGattError("SE1 refused", code=0x80), "write"),  # 0x80 on SE1 != auth
        ("write:01", BleakCharacteristicNotFoundError(AUTH), "missing_characteristic"),
        ("start_notify", BleakCharacteristicNotFoundError(AUTH), "missing_characteristic"),
        ("start_notify", BleakError("backend down"), "write"),
        ("write:03", BleakCharacteristicNotFoundError(AUTH), "missing_characteristic"),
        ("write:03", BleakGATTProtocolError(0x80), "rejected"),
    ],
)
async def test_gatt_call_failures_are_classified(op: str, exc: Exception, reason: str) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, client = make_transport(r0, spy=True)
    assert isinstance(client, SpyClient)
    client.fail[op] = exc
    error = await open_error(transport, clock)
    if reason == "rejected":
        assert isinstance(error, HandshakeRejectedError)
    else:
        assert type(error) is TransportError
        assert error.reason == reason


async def test_stale_services_is_missing_characteristic() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, stale_services=True)
    transport, _ = make_transport(r0)
    exc = await open_error(transport, clock)
    assert isinstance(exc, TransportError)
    assert exc.reason == "missing_characteristic"


async def test_cancelled_open_leaves_the_transport_closed() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock, handshake_fault="se2_silence")
    transport, client = make_transport(r0, spy=True)
    assert isinstance(client, SpyClient)
    client.fail["stop_notify"] = BleakError("gone")  # cleanup errors are ignored
    task = asyncio.create_task(transport.open())
    await clock.advance(1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert transport.closed
    with pytest.raises(TransportError) as exc:
        await transport.send_npdu(b"\x01")
    assert exc.value.reason == "closed"


# --- MTU ---------------------------------------------------------------------------------------


async def test_small_mtu_sets_flag_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    clock = VirtualClock()
    _, _, transport = await opened(clock, mtu_size=MIN_RECOMMENDED_MTU - 1)
    assert transport.mtu_low
    assert transport.session is not None
    assert transport.session.mtu_low
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert f"mtu={MIN_RECOMMENDED_MTU - 1}" in warnings[0].getMessage()
    await transport.close()


async def test_recommended_mtu_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    clock = VirtualClock()
    _, _, transport = await opened(clock, mtu_size=MIN_RECOMMENDED_MTU)
    assert not transport.mtu_low
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    await transport.close()


# --- _att_error_code -------------------------------------------------------------------------


class _EspGattError:
    def __init__(self, error: int) -> None:
        self.error = error


class _EspApiError(Exception):
    def __init__(self, error: int) -> None:
        super().__init__("Bluetooth GATT Error")
        self.error = _EspGattError(error)


def _chained(outer: BaseException, cause: BaseException) -> BaseException:
    outer.__cause__ = cause
    return outer


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (FakeGattError("x", code=0x80), 0x80),
        (FakeGattError("x", code=0x0E), 0x0E),
        (BleakGATTProtocolError(0x80), 0x80),
        (BleakDBusError("org.bluez.Error.Failed", ["Operation failed with ATT error: 0x80"]), 0x80),
        (BleakError("Could not write value: Protocol Error 0x80: Unknown"), 0x80),
        (BleakError('Error Domain=CBATTErrorDomain Code=128 "Unknown ATT error."'), 0x80),
        (BleakError("Bluetooth GATT Error address=AA handle=12 error=133 description=x"), 133),
        (_chained(BleakError("wrapped"), _EspApiError(0x80)), 0x80),
        (_chained(BleakError("wrapped"), BleakGATTProtocolError(0x81)), 0x81),
        (BleakError("Not connected"), None),
        (TimeoutError(), None),
        (BleakError("ATT error: 0x1ff"), None),
        (BleakError("CBATTErrorDomain Code=999"), None),
    ],
)
def test_att_error_code(exc: BaseException, code: int | None) -> None:
    assert _att_error_code(exc) == code


def test_att_error_code_ignores_non_int_code_attributes() -> None:
    class WeirdError(Exception):
        code = True
        error = "text"

    exc = WeirdError("no code here")
    assert _att_error_code(exc) is None
    looping = Exception("a")
    looping.__context__ = looping
    assert _att_error_code(looping) is None
