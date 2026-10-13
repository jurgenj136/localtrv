"""Simulated ubisys R0 at the GATT level: ``SimulatedR0``, ``FakeBleakClient``, ``fake_connector``.

Implemented by T8 on the frozen T2 interface. ``FakeBleakClient``/``FakeConnector`` live in
``gatt_client.py`` and the GATT table/Status value in ``gatt_services.py``; both are
re-exported here. Everything runs on a shared ``VirtualClock``: every
delay is a ``clock.call_later``; indications are delivered by calling the client's notify
callback from a clock callback (or synchronously inside ``write_gatt_char`` when
``indicate_before_write_returns``), never from another thread.

Layers
    ``SimulatedR0`` is the device: GATT services, the handshake (``FakeZdd``), session crypto
    under a ``ZddCounterModel``, the Commissioning Status value, and fault injection. One R0
    serves at most one connected ``FakeBleakClient`` at a time (like the real R0).
    ``FakeBleakClient`` is the per-connection client object handed to the library; it forwards
    to the R0 and satisfies ``zigbee_direct.transport.GattClient``.
    ``fake_connector(r0)`` returns a ``Connector`` that "connects" by asking the R0 for a new
    client.

Seam to the network simulator (T9)
    The R0 decrypts every Tunnel write and hands the plaintext ``TunnelNpdu`` to its attached
    ``TunnelPeer`` (``SimNetwork``); the network answers by calling ``r0.indicate_npdu(...)``,
    which encrypts and indicates it (applying MTU and oversize behaviour). The R0 calls
    ``peer.on_session_reset()`` when the session ends (disconnect, reboot), so the network
    forgets join/gating state.

GATT behaviours (spec §1.7 "Required behaviours: GATT") and their knobs
    * SE3 with a bad tag -> ``FakeGattError(0x80)`` (always, via ``FakeZdd``).
    * Read of Commissioning Status or Identify before the session -> ``FakeGattError(0x80)``.
    * SE3 write failing with a non-0x80 error or a disconnect -> ``se3_fault``.
    * ZDD counter model -> ``counter_model``.
    * Out-of-order or replayed writes -> ``replay_behavior``.
    * Write faults raise / hang / disconnect -> ``inject_write_fault`` (cancel mid-flight is the
      test cancelling a caller while a write hangs or ``write_latency`` is running). A Tunnel
      frame is processed when the write arrives, before ``write_latency``: a write cancelled
      during the latency has reached the device (its counter is spent). ``max_writes_in_flight``
      records overlapping writes for the writer race tests.
    * ``mtu_size``; oversized indications -> ``oversize_indication``.
    * Long writes on/off -> ``long_write_supported``.
    * Disconnect injection -> ``disconnect()``.
    * Stale services until ``clear_cache()`` -> ``stale_services``: while set, the client's
      ``services`` lookup returns ``None`` for the Tunnel characteristic and ``start_notify`` /
      ``write_gatt_char`` / ``read_gatt_char`` on Tunnel raise
      ``bleak.exc.BleakCharacteristicNotFoundError(char)`` (the real bleak class), which the
      transport maps to ``TransportError(reason="missing_characteristic")``.
      ``FakeBleakClient.clear_cache()`` clears ``stale_services`` on the R0 and returns True.
    * Handshake faults -> ``handshake_fault``: ``se2_silence`` / ``se4_silence`` (the
      indication never comes), ``malformed_se2`` (SE2 with a truncated point TLV).
    * Commissioning Status variants -> ``status_omit_short`` (TLV 0x06 missing) and
      ``status_ieee_override`` (TLV 0x08 differs from the SE2 EUI); ``status_layout``
      ``"r0_live"`` sends the live R0 layout (4-byte TLV 0x05, no key TLVs), default ``"spec"``.
    * Tunnel indication faults -> ``inject_replayed_indication()`` (re-sends the last
      indication frame verbatim: ``ReplayError`` on the client) and
      ``inject_bad_mic_indication()`` (next indication with a corrupted MIC).
    * Response indication before ``write_gatt_char`` returns -> ``indicate_before_write_returns``:
      SE2/SE4 and any Tunnel indication the peer produces synchronously while a write is
      processed are delivered inside ``write_gatt_char``. Otherwise SE2/SE4 follow after
      ``handshake_latency`` and synchronous peer replies right after the write returns.
    * Event ``r0_reboot()``.

Decisions the frozen interface left open
    * The handshake PSK is always the BAK; a new SE1 starts a fresh ``FakeZdd`` (ephemeral key
      from ``rng``) and ends any previous session.
    * Replayed, out-of-order, bad-MIC or undecodable Tunnel writes share ``replay_behavior``;
      ``"gatt_error"`` answers ``FakeGattError(0x80)``.
    * Oversize ``"drop"`` seals the frame (counter spent) and loses it; ``"reject"`` refuses it
      before sealing (no counter spent). Both count ``oversized_indications``.
    * Long writes refused with ATT 0x06; writes to non-writable characteristics 0x03; reads of
      non-readable ones 0x02; operations on a disconnected client 0x0E.
"""

from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING, Final, NoReturn

from bleak.backends.device import BLEDevice

from vicare_local_ble.testing.errors import GATT_ERROR_REJECTED, GATT_ERROR_UNLIKELY, FakeGattError
from vicare_local_ble.testing.gatt_client import FakeBleakClient, FakeConnector, fake_connector
from vicare_local_ble.testing.gatt_faults import (
    HandshakeFault,
    OversizeBehavior,
    ReplayBehavior,
    Se3Fault,
    TunnelPeer,
    WriteFault,
    WriteFaultQueue,
    WriteFaultSpec,
)
from vicare_local_ble.testing.gatt_services import (
    GATT_ERROR_READ_NOT_PERMITTED,
    GATT_ERROR_REQUEST_NOT_SUPPORTED,
    GATT_ERROR_WRITE_NOT_PERMITTED,
    SESSION_READABLE,
    StatusLayout,
    se1_eui,
    status_value,
)
from vicare_local_ble.testing.zdd import FakeZdd, ZddCounterModel
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu, parse_tunnel_tlvs
from vicare_local_ble.zigbee_direct.crypto import (
    COUNTER_SIZE,
    MIC_LENGTH,
    derive_basic_authorization_key,
    session_frame_counter,
)
from vicare_local_ble.zigbee_direct.errors import AuthenticationError, DecodeError, ReplayError
from vicare_local_ble.zigbee_direct.session import OPCODE_SE3
from vicare_local_ble.zigbee_direct.transport import ATT_HEADER_LEN
from vicare_local_ble.zigbee_direct.types import SecretBytes
from vicare_local_ble.zigbee_direct.uuids import (
    COMMISSIONING_STATUS,
    SECURITY_AUTHENTICATE_C25519,
    TUNNEL_NPDU,
    TUNNEL_SERVICE,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.testing.gatt_services import FakeCharacteristic
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.transport import GattClient
    from vicare_local_ble.zigbee_direct.types import Eui64

_PRIVATE_KEY_SIZE: Final = 32
#: Bytes cut from SE2 for ``malformed_se2`` (the point TLV then claims more than it carries).
_SE2_TRUNCATION: Final = 8
_SESSION_OVERHEAD: Final = COUNTER_SIZE + MIC_LENGTH


class SimulatedR0:
    """A scripted ubisys R0 (ZDD). See module docstring for behaviours and knobs.

    Identity and Commissioning Status contents are constructor arguments; keys are dummy
    ``SecretBytes`` chosen by the test (the diagnostics secret test uses distinct values for
    ``network_key``, ``link_key`` and ``admin_key``). The PSK for each handshake is the BAK
    derived from ``network_key`` and the EUI the client sends in SE1, as on the real device.
    Knob attributes may be changed between steps.
    """

    def __init__(
        self,
        clock: VirtualClock,
        *,
        eui: Eui64,
        network_key: SecretBytes,
        zdd_short: int,
        pan_id: int,
        extended_pan_id: Eui64,
        trust_center_eui: Eui64,
        link_key: SecretBytes | None = None,
        admin_key: SecretBytes | None = None,
        address: str = "AA:BB:CC:DD:EE:01",
        name: str = "ubisys R0",
        rng: random.Random | None = None,
        mtu_size: int = 247,
        counter_model: ZddCounterModel = ZddCounterModel.SHARED,
        replay_behavior: ReplayBehavior = "silent_drop",
        oversize_indication: OversizeBehavior = "drop",
        long_write_supported: bool = True,
        se3_fault: Se3Fault = "none",
        se3_error_code: int = GATT_ERROR_UNLIKELY,
        stale_services: bool = False,
        indicate_before_write_returns: bool = False,
        write_latency: float = 0.0,
        handshake_latency: float = 0.05,
        handshake_fault: HandshakeFault = "none",
        status_omit_short: bool = False,
        status_ieee_override: Eui64 | None = None,
        status_layout: StatusLayout = "spec",
    ) -> None:
        self._clock = clock
        self._eui = eui
        self._network_key = network_key
        self._link_key = link_key
        self._admin_key = admin_key
        self._pan_id = pan_id
        self._extended_pan_id = extended_pan_id
        self._trust_center_eui = trust_center_eui
        self._rng = rng if rng is not None else random.Random(0)  # noqa: S311 - simulator
        self.zdd_short = zdd_short
        self.address = address
        self.name = name
        # knobs
        self.mtu_size = mtu_size
        self.counter_model = counter_model
        self.replay_behavior: ReplayBehavior = replay_behavior
        self.oversize_indication: OversizeBehavior = oversize_indication
        self.long_write_supported = long_write_supported
        self.se3_fault: Se3Fault = se3_fault
        self.se3_error_code = se3_error_code
        self.stale_services = stale_services
        self.indicate_before_write_returns = indicate_before_write_returns
        self.write_latency = write_latency
        self.handshake_latency = handshake_latency
        self.handshake_fault: HandshakeFault = handshake_fault
        self.status_omit_short = status_omit_short
        self.status_ieee_override = status_ieee_override
        self.status_layout: StatusLayout = status_layout
        # state
        self._peer: TunnelPeer | None = None
        self._client: FakeBleakClient | None = None
        self._zdd: FakeZdd | None = None
        self._connect_count = 0
        self._tunnel_writes: list[TunnelNpdu] = []
        self._write_counters: list[int] = []
        self._faults = WriteFaultQueue()
        self._hangs: set[asyncio.Future[None]] = set()
        self._last_indication: bytes | None = None
        self._corrupt_next = False
        self._dispatching = False
        self._deferred: list[tuple[bytes, bool]] = []
        self._writes_in_flight = 0
        self._max_writes_in_flight = 0
        self._oversized = 0

    def __repr__(self) -> str:
        return f"SimulatedR0(eui={self._eui}, connected={self.client is not None})"

    # --- wiring ---

    def attach_network(self, peer: TunnelPeer) -> None:
        self._peer = peer

    def ble_device(self, *, source: str = "hci0") -> BLEDevice:
        """A ``BLEDevice`` for this R0 as seen through adapter/proxy ``source`` (distinct
        objects per source, same address), for resolver and proxy-switch tests."""
        return BLEDevice(self.address, self.name, {"source": source})

    def connect(
        self, device: BLEDevice, disconnected_callback: Callable[[GattClient], None] | None
    ) -> FakeBleakClient:
        """A new connected client; ``FakeGattError`` if another client is connected.
        ``disconnected_callback(client)`` is called once when that client disconnects."""
        if self.client is not None:
            raise FakeGattError("R0 already has a connected client", code=GATT_ERROR_UNLIKELY)
        client = FakeBleakClient(self, device=device, disconnected_callback=disconnected_callback)
        self._client = client
        self._zdd = None
        self._connect_count += 1
        return client

    def indicate_npdu(self, npdu: bytes, *, secure: bool = True) -> None:
        """Encrypt ``npdu`` in a tunnel TLV and indicate it to the subscribed client.

        Dropped silently without a session or Tunnel subscription. Values above
        ``mtu_size - 3`` follow ``oversize_indication``.
        """
        if self._dispatching and not self.indicate_before_write_returns:
            self._deferred.append((npdu, secure))
            return
        self._send_tunnel(npdu, secure)

    # --- fault injection and events ---

    def inject_write_fault(self, spec: WriteFaultSpec) -> None:
        self._faults.add(spec)

    def inject_replayed_indication(self) -> None:
        """Re-indicate the last Tunnel indication frame verbatim (same counter)."""
        client = self._tunnel_client()
        if client is not None and self._last_indication is not None:
            client._deliver(TUNNEL_NPDU, self._last_indication)

    def inject_bad_mic_indication(self) -> None:
        """Corrupt the MIC of the next Tunnel indication (the counter is still consumed)."""
        self._corrupt_next = True

    def disconnect(self) -> None:
        """Drop the current connection from the device side (disconnect callback fires)."""
        if self._client is not None:
            self._drop(self._client)

    def r0_reboot(self) -> None:
        """Disconnect, forget the session, and reset the tunnel peer (``on_session_reset``)."""
        client = self.client
        if client is not None:
            self._drop(client)
            return
        self._zdd = None
        if self._peer is not None:
            self._peer.on_session_reset()

    # --- observation ---

    @property
    def clock(self) -> VirtualClock:
        return self._clock

    @property
    def eui(self) -> Eui64:
        return self._eui

    @property
    def client(self) -> FakeBleakClient | None:
        client = self._client
        return client if client is not None and client.is_connected else None

    @property
    def session_established(self) -> bool:
        return self._zdd is not None and self._zdd.established

    @property
    def tunnel_writes(self) -> tuple[TunnelNpdu, ...]:
        """Every decrypted, accepted Tunnel write of the current session, in order."""
        return tuple(self._tunnel_writes)

    @property
    def write_counters(self) -> tuple[int, ...]:
        """Session counters of every Tunnel write received (accepted or not), in order."""
        return tuple(self._write_counters)

    @property
    def connect_count(self) -> int:
        return self._connect_count

    @property
    def max_writes_in_flight(self) -> int:
        """Most GATT writes ever in progress at once (1 if writes never overlapped)."""
        return self._max_writes_in_flight

    @property
    def oversized_indications(self) -> int:
        """Tunnel indications above ``mtu_size - 3`` (truncated, dropped or rejected)."""
        return self._oversized

    # --- GATT operations (called by FakeBleakClient) ---

    async def _gatt_write(
        self, client: FakeBleakClient, char: FakeCharacteristic, data: bytes
    ) -> None:
        self._writes_in_flight += 1
        self._max_writes_in_flight = max(self._max_writes_in_flight, self._writes_in_flight)
        try:
            fault = self._faults.take(char.uuid)
            if fault is not None:
                await self._apply_fault(client, fault)
            if len(data) > self.mtu_size - ATT_HEADER_LEN and not self.long_write_supported:
                raise FakeGattError(
                    "long write not supported", code=GATT_ERROR_REQUEST_NOT_SUPPORTED
                )
            self._dispatching = True
            try:
                if char.uuid == SECURITY_AUTHENTICATE_C25519:
                    self._on_authenticate(client, data)
                elif char.uuid == TUNNEL_NPDU:
                    self._on_tunnel_write(data)
                else:
                    raise FakeGattError("write not permitted", code=GATT_ERROR_WRITE_NOT_PERMITTED)
            finally:
                self._dispatching = False
            await self._latency(client)
        finally:
            self._writes_in_flight -= 1
            if self._deferred:
                self._clock.call_later(0, self._flush_deferred)

    async def _gatt_read(self, client: FakeBleakClient, char: FakeCharacteristic) -> bytes:
        if char.uuid not in SESSION_READABLE:
            raise FakeGattError("read not permitted", code=GATT_ERROR_READ_NOT_PERMITTED)
        zdd = self._zdd
        if zdd is None or not zdd.established:
            raise FakeGattError("read before session", code=GATT_ERROR_REJECTED)
        plaintext = self._status_plaintext() if char.uuid == COMMISSIONING_STATUS else b"\x00"
        value = zdd.seal(char.service_uuid, char.uuid, plaintext)
        await self._latency(client)
        return value

    def _drop(self, client: FakeBleakClient) -> None:
        """End ``client``'s connection: fail hanging writes, reset the peer, fire the callback."""
        if not client.is_connected:
            return
        if client is self._client:
            self._zdd = None
            self._deferred.clear()
        for hang in self._hangs:
            if not hang.done():
                hang.set_exception(FakeGattError("disconnected", code=GATT_ERROR_UNLIKELY))
        if self._peer is not None:
            self._peer.on_session_reset()
        client._on_disconnected()

    # --- internals ---

    async def _latency(self, client: FakeBleakClient) -> None:
        if self.write_latency > 0:
            await self._clock.sleep(self.write_latency)
        if not client.is_connected:
            raise FakeGattError("disconnected during operation", code=GATT_ERROR_UNLIKELY)

    async def _apply_fault(self, client: FakeBleakClient, spec: WriteFaultSpec) -> NoReturn:
        if spec.kind == "disconnect":
            self._drop(client)
            raise FakeGattError("disconnected during write", code=GATT_ERROR_UNLIKELY)
        if spec.kind == "hang":
            hang: asyncio.Future[None] = asyncio.get_running_loop().create_future()
            self._hangs.add(hang)
            try:
                await hang
            finally:
                self._hangs.discard(hang)
        raise FakeGattError("injected write fault", code=spec.code)

    def _on_authenticate(self, client: FakeBleakClient, data: bytes) -> None:
        if data[:1] == bytes([OPCODE_SE3]):
            self._on_se3(client, data)
            return
        if self.session_established and self._peer is not None:
            self._peer.on_session_reset()
        self._zdd = None
        eui = se1_eui(data)
        if eui is None:
            raise FakeGattError("SE1 rejected: malformed", code=GATT_ERROR_REJECTED)
        zdd = FakeZdd(
            eui=self._eui,
            psk=derive_basic_authorization_key(eui, self._network_key),
            private_key=SecretBytes(self._rng.randbytes(_PRIVATE_KEY_SIZE)),
            counter_model=self.counter_model,
        )
        se2 = zdd.handle_se1(data)
        self._zdd = zdd
        if self.handshake_fault == "se2_silence":
            return
        if self.handshake_fault == "malformed_se2":
            se2 = se2[:-_SE2_TRUNCATION]
        self._respond(client, se2)

    def _on_se3(self, client: FakeBleakClient, data: bytes) -> None:
        if self.se3_fault == "gatt_error":
            raise FakeGattError("SE3 write failed", code=self.se3_error_code)
        if self.se3_fault == "disconnect":
            self._drop(client)
            raise FakeGattError("disconnected during SE3 write", code=GATT_ERROR_UNLIKELY)
        if self._zdd is None:
            raise FakeGattError("SE3 before SE1", code=GATT_ERROR_REJECTED)
        se4 = self._zdd.handle_se3(data)  # FakeGattError(0x80) on a bad tag
        self._tunnel_writes.clear()
        self._write_counters.clear()
        self._last_indication = None
        if self.handshake_fault != "se4_silence":
            self._respond(client, se4)

    def _respond(self, client: FakeBleakClient, message: bytes) -> None:
        if self.indicate_before_write_returns:
            client._deliver(SECURITY_AUTHENTICATE_C25519, message)
        else:
            self._clock.call_later(
                self.handshake_latency,
                lambda: client._deliver(SECURITY_AUTHENTICATE_C25519, message),
            )

    def _on_tunnel_write(self, data: bytes) -> None:
        zdd = self._zdd
        if zdd is None or not zdd.established:
            raise FakeGattError("tunnel write before session", code=GATT_ERROR_REJECTED)
        try:
            self._write_counters.append(session_frame_counter(data))
            items = parse_tunnel_tlvs(zdd.open_frame(TUNNEL_SERVICE, TUNNEL_NPDU, data))
        except (ReplayError, AuthenticationError, DecodeError) as exc:
            if self.replay_behavior == "gatt_error":
                reason = type(exc).__name__
                raise FakeGattError(f"tunnel frame rejected ({reason})") from None
            return
        for item in items:
            if isinstance(item, TunnelNpdu):
                self._tunnel_writes.append(item)
                if self._peer is not None:
                    self._peer.on_zvd_npdu(item)

    def _tunnel_client(self) -> FakeBleakClient | None:
        client = self.client
        if client is None or not self.session_established or not client._subscribed(TUNNEL_NPDU):
            return None
        return client

    def _send_tunnel(self, npdu: bytes, secure: bool) -> None:
        client, zdd = self._tunnel_client(), self._zdd
        if client is None or zdd is None:
            return
        plaintext = TunnelNpdu(npdu, secure).encode()
        limit = self.mtu_size - ATT_HEADER_LEN
        oversized = _SESSION_OVERHEAD + len(plaintext) > limit
        if oversized:
            self._oversized += 1
            if self.oversize_indication == "reject":
                return
        frame = zdd.seal(TUNNEL_SERVICE, TUNNEL_NPDU, plaintext)
        if self._corrupt_next:
            self._corrupt_next = False
            frame = frame[:-1] + bytes([frame[-1] ^ 0xFF])
        if oversized:
            if self.oversize_indication == "drop":
                return
            frame = frame[:limit]
        self._last_indication = frame
        client._deliver(TUNNEL_NPDU, frame)

    def _flush_deferred(self) -> None:
        deferred, self._deferred = self._deferred, []
        for npdu, secure in deferred:
            self._send_tunnel(npdu, secure)

    def _status_plaintext(self) -> bytes:
        """The Commissioning Status TLVs; holds the network key, never logged."""
        return status_value(
            extended_pan_id=self._extended_pan_id,
            pan_id=self._pan_id,
            network_key=self._network_key,
            link_key=self._link_key,
            admin_key=self._admin_key,
            zdd_short=None if self.status_omit_short else self.zdd_short,
            ieee=self.status_ieee_override or self._eui,
            trust_center_eui=self._trust_center_eui,
            layout=self.status_layout,
        )


__all__ = [
    "GATT_ERROR_REJECTED",
    "GATT_ERROR_UNLIKELY",
    "FakeBleakClient",
    "FakeConnector",
    "FakeGattError",
    "HandshakeFault",
    "OversizeBehavior",
    "ReplayBehavior",
    "Se3Fault",
    "SimulatedR0",
    "TunnelPeer",
    "WriteFault",
    "WriteFaultSpec",
    "fake_connector",
]
