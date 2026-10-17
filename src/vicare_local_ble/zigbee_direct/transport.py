"""GATT transport for Zigbee Direct: handshake, status read, writer task, ingress.

Ownership and threading
    One ``ZigbeeDirectTransport`` per BLE connection attempt, created by ``ZdConnection``
    around a client that is already connected. The transport never scans, connects or
    disconnects: the connection owns the client. All methods run on the loop thread. Queues,
    futures and the writer task are created lazily in ``open()`` (the object can be built
    outside a running loop). Every delay goes through the injected ``Clock``.

Handshake (``open``)
    1. ``start_notify(Authenticate)``; SE2/SE4 indications go to a queue.
    2. Write SE1 (write-with-response). Wait ``handshake_timeout`` for SE2.
    3. Write SE3. Wait ``handshake_timeout`` for SE4.
    4. ``start_notify(Tunnel)`` only now, start the writer task.
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

Size note: this module stays under ~500 lines. Private helpers live in sibling modules:
``transport_handshake.py`` (SE1-SE4 driving and classification, ``_att_error_code``) and
``transport_writer.py`` (writer task); the public names stay here.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol

from vicare_local_ble.zigbee_direct.codec.commissioning import CommissioningStatus
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu, parse_tunnel_tlvs
from vicare_local_ble.zigbee_direct.errors import (
    AuthenticationError,
    DecodeError,
    EncodeError,
    HandshakeRejectedError,
    ReplayError,
    TransportError,
)
from vicare_local_ble.zigbee_direct.session import CounterModel
from vicare_local_ble.zigbee_direct.transport_handshake import (
    att_error_code,
    guarded,
    run_handshake,
)
from vicare_local_ble.zigbee_direct.transport_writer import TunnelWriter
from vicare_local_ble.zigbee_direct.uuids import (
    COMMISSIONING_SERVICE,
    COMMISSIONING_STATUS,
    SECURITY_AUTHENTICATE_C25519,
    TUNNEL_NPDU,
    TUNNEL_SERVICE,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.session import SessionCipher
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

#: About 116 B plaintext NPDU + 4 B tunnel TLV + 8 B session overhead + 3 B ATT header.
MIN_RECOMMENDED_MTU: Final = 131
#: ATT write/indication header; the largest single-PDU value is ``mtu - ATT_HEADER_LEN``.
ATT_HEADER_LEN: Final = 3
#: Consecutive MIC failures that trigger the MTU WARNING.
MIC_WARNING_STREAK: Final = 3

_LOGGER = logging.getLogger(__name__)
_AUTH: Final = SECURITY_AUTHENTICATE_C25519

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
    return att_error_code(exc)


class ZigbeeDirectTransport:
    """Encrypted Zigbee Direct GATT tunnel over a connected client (see module docstring).

    ``psk`` is the pre-shared secret for the handshake (the BAK, derived once by the
    connection). It is held only as ``SecretBytes`` and dropped after the handshake.
    ``recorder`` receives every Tunnel NPDU (rx and tx) and nothing else.
    """

    __slots__ = (
        "_auth_subscribed",
        "_cipher",
        "_client",
        "_clock",
        "_closed",
        "_fatal_handler",
        "_handler",
        "_handshake_timeout",
        "_mic_streak",
        "_model_logged",
        "_opened",
        "_own_eui",
        "_psk",
        "_recorder",
        "_rejection",
        "_session",
        "_stats",
        "_tunnel_subscribed",
        "_write_timeout",
        "_writer",
    )

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
        self._client = client
        self._own_eui = own_eui
        self._psk: SecretBytes | None = psk
        self._clock = clock
        self._handshake_timeout = handshake_timeout
        self._write_timeout = write_timeout
        self._recorder = recorder
        self._stats = TransportStats()
        self._session: SessionInfo | None = None
        self._cipher: SessionCipher | None = None
        self._writer: TunnelWriter | None = None
        self._handler: NpduHandler | None = None
        self._fatal_handler: FatalHandler | None = None
        self._opened = False
        self._closed = False
        self._auth_subscribed = False
        self._tunnel_subscribed = False
        self._mic_streak = 0
        self._model_logged = False
        self._rejection: HandshakeRejectedError | None = None

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open" if self._session else "new"
        return f"ZigbeeDirectTransport(own_eui={self._own_eui}, {state}, broken={self.broken})"

    async def open(self) -> SessionInfo:
        """Run SE1..SE4, subscribe Tunnel, start the writer task; call once.

        Reads and logs ``client.mtu_size`` (WARNING and ``mtu_low`` below
        ``MIN_RECOMMENDED_MTU``). Raises ``HandshakeRejectedError`` (wrong key) or
        ``TransportError`` (everything else, see module docstring). On failure the transport is
        closed (no writer, notifications stopped where possible). Cancellation of the caller
        propagates and leaves the transport closed.
        """
        if self._opened or self._closed:
            raise TransportError("open() may be called once", reason="closed")
        self._opened = True
        try:
            return await self._open()
        except BaseException as exc:
            _LOGGER.debug("open failed: %s", type(exc).__name__)
            if isinstance(exc, HandshakeRejectedError):
                self._rejection = exc  # recorded before the cleanup awaits (it may be cancelled)
            await self._shutdown()
            raise
        finally:
            self._psk = None  # the BAK is only needed for the handshake

    async def _open(self) -> SessionInfo:
        client, clock, timeout = self._client, self._clock, self._handshake_timeout
        indications: asyncio.Queue[bytes] = asyncio.Queue()

        def on_auth(_char: Any, data: bytearray) -> None:
            indications.put_nowait(bytes(data))

        await guarded(clock, timeout, "Authenticate subscribe", client.start_notify(_AUTH, on_auth))
        self._auth_subscribed = True
        psk = self._psk
        if psk is None:  # pragma: no cover - open() runs once
            raise TransportError("pre-shared key already dropped", reason="closed")
        established = await run_handshake(
            client,
            own_eui=self._own_eui,
            psk=psk,
            clock=clock,
            timeout=timeout,
            indications=indications,
        )
        self._psk = None
        self._cipher = established.cipher
        _LOGGER.info("handshake OK")
        await guarded(
            clock, timeout, "Tunnel subscribe", client.start_notify(TUNNEL_NPDU, self._on_tunnel)
        )
        self._tunnel_subscribed = True
        mtu = int(client.mtu_size)
        session = SessionInfo(own_eui=self._own_eui, zdd_eui=established.peer_eui, mtu=mtu)
        _LOGGER.info("connected, mtu=%d", mtu)
        if session.mtu_low:
            _LOGGER.warning(
                "mtu=%d is below the recommended %d: large indications may be lost",
                mtu,
                MIN_RECOMMENDED_MTU,
            )
        writer = TunnelWriter(
            client,
            established.cipher,
            clock=clock,
            write_timeout=self._write_timeout,
            max_value=mtu - ATT_HEADER_LEN,
            stats=self._stats,
            recorder=self._recorder,
            on_broken=self._on_writer_broken,
        )
        self._writer = writer
        writer.start()
        self._session = session
        return session

    async def read_commissioning_status(self) -> CommissioningStatus:
        """Read, decrypt (AAD of the Commissioning Status characteristic) and decode the status.

        Valid only after ``open()``. Uses ``clock.timeout(write_timeout)``. Raises
        ``TransportError`` (``"write"``, ``"timeout"``, ``"closed"``) or ``DecodeError``. The
        value is never recorded or logged: it holds the network key.
        """
        cipher = self._usable_cipher()
        raw = await guarded(
            self._clock,
            self._write_timeout,
            "Commissioning Status read",
            self._client.read_gatt_char(COMMISSIONING_STATUS),
        )
        try:
            plaintext = cipher.decrypt(COMMISSIONING_SERVICE, COMMISSIONING_STATUS, bytes(raw))
        except (ReplayError, AuthenticationError) as exc:
            raise TransportError(
                f"Commissioning Status rejected: {type(exc).__name__}", reason="protocol"
            ) from None
        self._check_counter_model()
        return CommissioningStatus.decode(plaintext)

    async def send_npdu(
        self, npdu: bytes, *, secure: bool = True, check: Callable[[], None] | None = None
    ) -> None:
        """Queue one NPDU for the writer and wait until its GATT write completed.

        ``check`` runs when the writer dequeues the frame, right before encryption; if it
        raises, the frame is not sent and that exception is raised here (the transport and
        its counters are unaffected).

        ``secure`` is the tunnel flag (NWK security requested); only the Commissioning Request
        uses ``secure=False``. Raises ``TransportError(reason="closed")`` if the transport is
        not open or already broken, and the writer's ``TransportError`` if this write failed.
        Cancelling the caller does not cancel the write once it has been dequeued.
        ``recorder.tx`` is called just before the write.
        """
        writer = self._writer
        if writer is None or self._closed or writer.broken:
            raise TransportError("transport is not open", reason="closed")
        await writer.submit(TunnelNpdu(bytes(npdu), secure), check)

    def set_npdu_handler(self, handler: NpduHandler) -> None:
        """Install the single ingress handler (the node's dispatcher); replaces any previous one.

        Called synchronously on the loop for every decrypted NPDU, in arrival order.
        """
        self._handler = handler

    def set_fatal_handler(self, handler: FatalHandler) -> None:
        """Install the handler called once when the transport becomes ``broken``.

        Installed by ``ZdConnection``. Called synchronously from the writer task; it must
        not await and must not call ``close()`` inline (schedule teardown instead).
        """
        self._fatal_handler = handler

    @property
    def session(self) -> SessionInfo | None:
        """``SessionInfo`` after a successful ``open()``, else ``None``."""
        return self._session

    @property
    def mtu_low(self) -> bool:
        """True if the MTU read at ``open()`` is below ``MIN_RECOMMENDED_MTU``."""
        return self._session is not None and self._session.mtu_low

    @property
    def broken(self) -> bool:
        """True once a write failed or the counter is in doubt; the session must be replaced."""
        return self._writer is not None and self._writer.broken

    @property
    def rejection(self) -> HandshakeRejectedError | None:
        """The ``HandshakeRejectedError`` of a failed ``open()``, set before its cleanup runs
        (so it is known even if the cleanup is cancelled, e.g. by a disconnect)."""
        return self._rejection

    @property
    def closed(self) -> bool:
        """True after ``close()`` or a failed ``open()``."""
        return self._closed

    @property
    def stats(self) -> TransportStats:
        return self._stats

    async def close(self) -> None:
        """Idempotent. Cancel and await the writer, fail queued sends, ``stop_notify`` (errors
        ignored). A write cancelled mid-flight marks the transport ``broken``. Does not call
        the fatal handler and does not disconnect the client."""
        if self._closed:
            return
        await self._shutdown()

    # --- internals ---

    async def _shutdown(self) -> None:
        self._closed = True
        self._psk = None
        if self._writer is not None:
            await self._writer.stop()
        for subscribed, char in (
            (self._tunnel_subscribed, TUNNEL_NPDU),
            (self._auth_subscribed, _AUTH),
        ):
            if subscribed:
                await self._stop_notify(char)
        self._tunnel_subscribed = self._auth_subscribed = False
        if self._cipher is not None and not self._model_logged:
            self._model_logged = True
            _LOGGER.info("counter_model=%s", self._stats.counter_model.value)

    async def _stop_notify(self, char: str) -> None:
        try:
            async with self._clock.timeout(self._write_timeout):
                await self._client.stop_notify(char)
        except Exception as exc:  # the client may already be gone
            _LOGGER.debug("stop_notify failed: %s", type(exc).__name__)

    def _usable_cipher(self) -> SessionCipher:
        if self._cipher is None or self._closed or self.broken:
            raise TransportError("transport is not open", reason="closed")
        return self._cipher

    def _on_writer_broken(self, error: TransportError) -> None:
        handler = self._fatal_handler
        if handler is None:
            return
        try:
            handler(error)
        except Exception:
            _LOGGER.exception("fatal handler raised")

    def _check_counter_model(self) -> None:
        if self._cipher is None:  # pragma: no cover - only called with a session
            return
        model = self._cipher.counter_model()
        self._stats.counter_model = model
        if model is not CounterModel.UNKNOWN and not self._model_logged:
            self._model_logged = True
            _LOGGER.info("counter_model=%s", model.value)

    def _on_tunnel(self, _char: Any, data: bytearray) -> None:
        cipher = self._cipher
        if cipher is None or self._closed:
            return
        try:
            plaintext = cipher.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, bytes(data))
        except ReplayError:
            self._stats.replay_drops += 1
            _LOGGER.debug("dropped a replayed Tunnel indication")
            return
        except AuthenticationError:
            self._on_mic_failure()
            return
        except DecodeError:
            self._stats.tlv_errors += 1
            _LOGGER.debug("dropped a Tunnel indication shorter than a session frame")
            return
        self._mic_streak = 0
        self._stats.frames_rx += 1
        self._check_counter_model()
        try:
            items = parse_tunnel_tlvs(plaintext)
        except DecodeError, EncodeError:
            self._stats.tlv_errors += 1
            _LOGGER.debug("dropped a Tunnel indication with malformed TLVs")
            return
        for item in items:
            if isinstance(item, TunnelNpdu):
                self._deliver(item)
            else:
                _LOGGER.debug("ignored Tunnel TLV 0x%02X", item.tag)

    def _on_mic_failure(self) -> None:
        self._stats.mic_failures += 1
        self._mic_streak += 1
        if self._mic_streak == MIC_WARNING_STREAK:
            mtu = self._session.mtu if self._session is not None else 0
            _LOGGER.warning(
                "%d Tunnel indications in a row failed the MIC (mtu=%d): oversized indications "
                "may be truncated",
                MIC_WARNING_STREAK,
                mtu,
            )

    def _deliver(self, npdu: TunnelNpdu) -> None:
        if self._recorder is not None:
            try:
                self._recorder.rx(npdu)
            except Exception as exc:
                _LOGGER.debug("NPDU recorder rx failed: %s", type(exc).__name__)
        handler = self._handler
        if handler is None:
            return
        try:
            handler(npdu)
        except Exception:
            _LOGGER.exception("NPDU handler raised")


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
