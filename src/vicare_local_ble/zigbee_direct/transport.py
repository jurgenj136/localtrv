"""GATT transport for Zigbee Direct: handshake, status read, writer task, ingress (spec §1.2).

Implemented by phase-2 task T10; this module is the frozen interface (T2).

Ownership and threading
    One ``ZigbeeDirectTransport`` per BLE connection attempt, created by ``ZdConnection`` (T13)
    around a client that is already connected. The transport never scans, connects or
    disconnects: the connection owns the client. All methods run on the loop thread. Queues,
    futures and the writer task are created lazily in ``open()`` (the object can be built
    outside a running loop). Every delay goes through the injected ``Clock``.

Handshake (``open``)
    1. ``start_notify(Authenticate)``; SE2/SE4 indications go to a queue.
    2. Write SE1 (write-with-response). Wait ``handshake_timeout`` for SE2.
    3. Write SE3. Wait ``handshake_timeout`` for SE4.
    4. ``start_notify(Tunnel)`` only now (PN §1 step 7), start the writer task.
    Classification is strict: ``HandshakeRejectedError`` only for an ATT error code exactly 0x80
    on the SE3 write (``_att_error_code``) or an SE4 tag mismatch (``HandshakeError`` from the
    initiator while in AWAIT_SE4 because of the tag). Every other failure raises
    ``TransportError``: ``reason="timeout"`` for SE2/SE4 timeouts, ``"protocol"`` for a malformed
    SE2/SE4, ``"write"`` for GATT/backend errors and disconnects (including non-0x80 SE3 errors),
    ``"missing_characteristic"`` when any GATT call (``start_notify``, writes, the status read)
    raises ``bleak.exc.BleakCharacteristicNotFoundError`` (exists in bleak 3.0.2; the simulator's
    ``FakeBleakClient`` raises the same class in stale-services mode).

Writer task (``send_npdu``)
    The only code path that writes Tunnel. It owns the ``SessionCipher`` outgoing counter and
    consumes an ``asyncio.Queue`` of ``(plaintext, future)``: skip items whose future is already
    cancelled (no counter spent), encrypt (burns the counter), ``write_gatt_char(TUNNEL, frame,
    response=True)`` inside ``clock.timeout(write_timeout)``, resolve the future. A cancelled
    caller abandons its future; the writer still finishes that write. Any write exception,
    timeout or ``CounterExhaustedError`` marks the transport ``broken``, fails every queued
    future with ``TransportError``, calls the fatal handler once and ends the writer. A write of
    a frame larger than ``mtu - 3`` that fails raises ``reason="long_write_unsupported"``.

Ingress
    The Tunnel notify callback is synchronous on the loop: ``decrypt`` then
    ``parse_tunnel_tlvs``; for each ``TunnelNpdu``: ``recorder.rx(npdu)`` then the NPDU handler.
    ``ReplayError`` counts ``replay_drops`` (DEBUG), ``AuthenticationError`` counts
    ``mic_failures`` (three in a row log one WARNING naming the MTU), TLV errors count
    ``tlv_errors``. None of these is fatal, and the handler never sees those frames. Handler
    exceptions are caught and logged (they must not kill the BLE callback). Recorder calls
    (``rx``/``tx``) are guarded the same way: a recorder failure is logged at DEBUG (no
    payload) and never affects the session. ``redact_npdu`` itself never raises either.

Logging (logger ``vicare_local_ble.zigbee_direct.transport``)
    INFO: connected, ``mtu=``, handshake OK, ``counter_model=`` logged exactly once per session:
    when ``SessionCipher.counter_model()`` first leaves UNKNOWN (checked after each accepted
    frame), or at ``close()`` if it never did (then ``counter_model=unknown``). WARNING: MIC
    streaks, low MTU. NEVER logged or recorded: handshake messages, the PSK/BAK, the session
    key, the Commissioning Status value (raw, decrypted or decoded).

Size note: keep this module under ~500 lines when implemented. T10 may split private helpers
into sibling modules, e.g. ``_transport_handshake.py`` (SE1-SE4 driving and classification,
``_att_error_code``) and ``_transport_writer.py`` (writer task); the public names stay here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol

from vicare_local_ble.zigbee_direct.session import CounterModel

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.commissioning import CommissioningStatus
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.errors import TransportError
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

#: About 116 B plaintext NPDU + 4 B tunnel TLV + 8 B session overhead + 3 B ATT header.
MIN_RECOMMENDED_MTU: Final = 131
#: ATT write/indication header; the largest single-PDU value is ``mtu - ATT_HEADER_LEN``.
ATT_HEADER_LEN: Final = 3
#: Consecutive MIC failures that trigger the MTU WARNING.
MIC_WARNING_STREAK: Final = 3

#: Bleak passes a ``BleakGATTCharacteristic`` first; the transport ignores it.
type NotifyCallback = Callable[[Any, bytearray], None]
type NpduHandler = Callable[[TunnelNpdu], None]
type FatalHandler = Callable[[TransportError], None]


class GattServices(Protocol):
    """The part of ``BleakGATTServiceCollection`` the library uses."""

    def get_characteristic(self, specifier: str) -> object | None: ...


class GattClient(Protocol):
    """The connected-client surface the library needs.

    ``BleakClient``/``BleakClientWithServiceCache`` satisfy it structurally, and so does
    ``vicare_local_ble.testing.FakeBleakClient``. Writes are always called with
    ``response=True``.
    """

    @property
    def is_connected(self) -> bool: ...

    @property
    def mtu_size(self) -> int: ...

    @property
    def services(self) -> GattServices: ...

    async def start_notify(self, char_specifier: str, callback: NotifyCallback) -> None: ...

    async def stop_notify(self, char_specifier: str) -> None: ...

    async def write_gatt_char(
        self, char_specifier: str, data: bytes, response: bool | None = None
    ) -> None: ...

    async def read_gatt_char(self, char_specifier: str) -> bytearray: ...

    async def disconnect(self) -> None: ...

    async def clear_cache(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class SessionInfo:
    """Result of a successful ``open()``. ``mtu`` is ``client.mtu_size`` at open time."""

    own_eui: Eui64
    zdd_eui: Eui64
    mtu: int

    @property
    def mtu_low(self) -> bool:
        """True if ``mtu`` is below ``MIN_RECOMMENDED_MTU`` (repair issue ``mtu_too_small``)."""
        return self.mtu < MIN_RECOMMENDED_MTU


@dataclass(slots=True)
class TransportStats:
    """Counters for diagnostics; mutated only by the transport on the loop thread."""

    replay_drops: int = 0
    mic_failures: int = 0
    tlv_errors: int = 0
    frames_rx: int = 0
    frames_tx: int = 0
    counter_model: CounterModel = CounterModel.UNKNOWN


def _att_error_code(exc: BaseException) -> int | None:
    """ATT error code carried by a GATT exception, or ``None`` if it cannot be determined.

    Reads typed attributes first (``FakeGattError.code``; bleak 3's
    ``bleak.exc.BleakGATTProtocolError.code``; bleak-esphome code attributes when present),
    then matches backend message patterns. Never guesses: an
    unknown shape returns ``None`` (which classifies as a retryable ``TransportError``).
    """
    raise NotImplementedError("T10")


class ZigbeeDirectTransport:
    """Encrypted Zigbee Direct GATT tunnel over a connected client (see module docstring).

    ``psk`` is the pre-shared secret for the handshake (the BAK, derived once by the
    connection). It is held only as ``SecretBytes`` and dropped after the handshake.
    ``recorder`` receives every Tunnel NPDU (rx and tx) and nothing else.
    """

    def __init__(
        self,
        client: GattClient,
        *,
        own_eui: Eui64,
        psk: SecretBytes,
        clock: Clock,
        handshake_timeout: float = 10.0,
        write_timeout: float = 10.0,
        recorder: NpduRecorder | None = None,
    ) -> None:
        raise NotImplementedError("T10")

    async def open(self) -> SessionInfo:
        """Run SE1..SE4, subscribe Tunnel, start the writer task; call once.

        Reads and logs ``client.mtu_size`` (WARNING and ``mtu_low`` below
        ``MIN_RECOMMENDED_MTU``). Raises ``HandshakeRejectedError`` (wrong key) or
        ``TransportError`` (everything else, see module docstring). On failure the transport is
        closed (no writer, notifications stopped where possible). Cancellation of the caller
        propagates and leaves the transport closed.
        """
        raise NotImplementedError("T10")

    async def read_commissioning_status(self) -> CommissioningStatus:
        """Read, decrypt (AAD of the Commissioning Status characteristic) and decode the status.

        Valid only after ``open()``. Uses ``clock.timeout(write_timeout)``. Raises
        ``TransportError`` (``"write"``, ``"timeout"``, ``"closed"``) or ``DecodeError``. The
        value is never recorded or logged: it holds the network key.
        """
        raise NotImplementedError("T10")

    async def send_npdu(self, npdu: bytes, *, secure: bool = True) -> None:
        """Queue one NPDU for the writer and wait until its GATT write completed.

        ``secure`` is the tunnel flag (NWK security requested); only the Commissioning Request
        uses ``secure=False``. Raises ``TransportError(reason="closed")`` if the transport is
        not open or already broken, and the writer's ``TransportError`` if this write failed.
        Cancelling the caller does not cancel the write once it has been dequeued.
        ``recorder.tx`` is called just before the write.
        """
        raise NotImplementedError("T10")

    def set_npdu_handler(self, handler: NpduHandler) -> None:
        """Install the single ingress handler (the node's dispatcher); replaces any previous one.

        Called synchronously on the loop for every decrypted NPDU, in arrival order.
        """
        raise NotImplementedError("T10")

    def set_fatal_handler(self, handler: FatalHandler) -> None:
        """Install the handler called once when the transport becomes ``broken``.

        Installed by ``ZdConnection`` (T13). Called synchronously from the writer task; it must
        not await and must not call ``close()`` inline (schedule teardown instead).
        """
        raise NotImplementedError("T10")

    @property
    def session(self) -> SessionInfo | None:
        """``SessionInfo`` after a successful ``open()``, else ``None``."""
        raise NotImplementedError("T10")

    @property
    def mtu_low(self) -> bool:
        """True if the MTU read at ``open()`` is below ``MIN_RECOMMENDED_MTU``."""
        raise NotImplementedError("T10")

    @property
    def broken(self) -> bool:
        """True once a write failed or the counter is in doubt; the session must be replaced."""
        raise NotImplementedError("T10")

    @property
    def closed(self) -> bool:
        """True after ``close()`` or a failed ``open()``."""
        raise NotImplementedError("T10")

    @property
    def stats(self) -> TransportStats:
        raise NotImplementedError("T10")

    async def close(self) -> None:
        """Idempotent. Cancel and await the writer, fail queued sends, ``stop_notify`` (errors
        ignored). A write cancelled mid-flight marks the transport ``broken``. Does not call
        the fatal handler and does not disconnect the client."""
        raise NotImplementedError("T10")


__all__ = [
    "ATT_HEADER_LEN",
    "MIC_WARNING_STREAK",
    "MIN_RECOMMENDED_MTU",
    "FatalHandler",
    "GattClient",
    "GattServices",
    "NotifyCallback",
    "NpduHandler",
    "SessionInfo",
    "TransportStats",
    "ZigbeeDirectTransport",
]
