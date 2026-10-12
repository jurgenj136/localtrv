"""Sans-IO Zigbee Direct session: SPEKE handshake initiator (SE1-SE4) and session cipher.

No asyncio, no I/O. The caller moves bytes between this module and the
Security Service Authenticate characteristic (SE1/SE3 writes, SE2/SE4
indications) and afterwards uses ``SessionCipher`` for every characteristic
value (Zigbee R23 Annex J, Zigbee Direct 1.0; research handover section 3.2-3.3).

Handshake message layout (research tools/zvd_client.py:53-83, 175-262)::

    SE1 = 0x01 | TLV(0x00, method || secret_type) | TLV(0x02, own_EUI || own_Q)
    SE2 = 0x02 | TLV(0x02, peer_EUI || peer_Q) [| TLV(0x00, method || secret_type)]
    SE3 = 0x03 | TLV(0x04, KC_2_U tag)
    SE4 = 0x04 | TLV(0x04, KC_2_V tag)

Every handshake TLV is ``tag(1) | len-1 (1) | value(len)``. Unknown TLVs are
ignored; duplicate known TLVs and malformed TLVs are rejected. Whether SE2
echoes the method TLV is not observed in research; it is validated if present.

``CounterModel`` and the incoming-counter tracker live in ``counters.py`` (re-exported here).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Final

from vicare_local_ble.zigbee_direct.counters import CounterModel, IncomingCounters
from vicare_local_ble.zigbee_direct.crypto import (
    LABEL_KC_2_U,
    LABEL_KC_2_V,
    MAX_COUNTER,
    POINT_SIZE,
    TAG_SIZE,
    UUID_SIZE,
    KeyNegotiationMethod,
    SecretType,
    confirmation_tag,
    decrypt_session_frame,
    encrypt_session_frame,
    generate_private_key,
    session_frame_counter,
    speke_base_point,
    speke_derive_link_key,
    speke_public_point,
    speke_session_secret,
    speke_shared_point,
    tags_equal,
)
from vicare_local_ble.zigbee_direct.errors import (
    CounterExhaustedError,
    HandshakeError,
    ReplayError,
)
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes
from vicare_local_ble.zigbee_direct.uuids import uuid_bytes

if TYPE_CHECKING:
    from collections.abc import Callable

_LOGGER = logging.getLogger(__name__)

OPCODE_SE1: Final = 0x01
OPCODE_SE2: Final = 0x02
OPCODE_SE3: Final = 0x03
OPCODE_SE4: Final = 0x04

TLV_SELECTED_METHOD: Final = 0x00
TLV_C25519_POINT: Final = 0x02
TLV_MAC_TAG: Final = 0x04

_EUI_SIZE: Final = 8
_POINT_TLV_SIZE: Final = _EUI_SIZE + POINT_SIZE
_METHOD_TLV_SIZE: Final = 2
_KEY_SIZE: Final = 16


# --- handshake TLVs ----------------------------------------------------------------------


def encode_handshake_tlv(tag: int, value: bytes) -> bytes:
    """``tag | len-1 | value``; value must be 1..256 bytes."""
    if not 0 <= tag <= 0xFF:
        raise ValueError(f"TLV tag out of range: {tag!r}")
    if not 1 <= len(value) <= 256:
        raise ValueError(f"handshake TLV value must be 1..256 bytes, got {len(value)}")
    return bytes([tag, len(value) - 1]) + value


def parse_handshake_message(data: bytes, *, opcode: int, known: dict[int, int]) -> dict[int, bytes]:
    """Validate ``opcode | TLVs`` and return the known TLVs by tag.

    ``known`` maps tag -> exact value length. Raises ``HandshakeError`` on a
    wrong/missing opcode, truncated TLV, duplicate known tag or wrong length.
    Unknown tags are skipped. Presence of required tags is the caller's check.
    """
    if not data:
        raise HandshakeError("empty handshake message")
    if data[0] != opcode:
        raise HandshakeError(f"expected opcode 0x{opcode:02x}, got 0x{data[0]:02x}")
    found: dict[int, bytes] = {}
    idx = 1
    while idx < len(data):
        if idx + 2 > len(data):
            raise HandshakeError("truncated TLV header")
        tag, length = data[idx], data[idx + 1] + 1
        end = idx + 2 + length
        if end > len(data):
            raise HandshakeError(f"truncated TLV 0x{tag:02x}")
        value = data[idx + 2 : end]
        idx = end
        if tag not in known:
            continue
        if tag in found:
            raise HandshakeError(f"duplicate TLV 0x{tag:02x}")
        if length != known[tag]:
            raise HandshakeError(f"TLV 0x{tag:02x} has length {length}, expected {known[tag]}")
        found[tag] = value
    return found


def _uuid(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        if len(value) != UUID_SIZE:
            raise ValueError(f"UUID bytes must be {UUID_SIZE} long")
        return value
    return uuid_bytes(value)


# --- session cipher ------------------------------------------------------------------------


class SessionCipher:
    """Encrypts/decrypts GATT values of an established session.

    Outgoing: one counter for the whole session (``outgoing_counter`` is the next counter to
    send, starts at 1, never reused, never rolled back: a failed write burns it). We only write
    to Authenticate (before the session) and Tunnel, so our CCM nonces are never reused.

    Incoming: the last accepted counter is tracked per characteristic UUID and must be strictly
    greater on that characteristic. Whether the ZDD uses one counter for all characteristics or
    one per characteristic is NOT proven (PN §5.9); both are accepted, and ``counter_model()``
    reports what was observed. Residual risk: the CCM nonce has no characteristic in it, so a
    per-characteristic ZDD reuses nonces across characteristics under one key (leaking the XOR of
    those plaintexts and weakening authenticity for them). That is a ZDD flaw we cannot fix
    client-side. The replay check runs before the MIC and the counter advances only after the
    MIC passes. After counter 0xFFFFFFFF has been used, ``encrypt`` raises
    ``CounterExhaustedError``; reconnect with a new handshake.
    """

    __slots__ = ("_incoming", "_key", "_outgoing", "_own_eui", "_peer_eui")

    def __init__(
        self,
        *,
        session_key: SecretBytes,
        own_eui: Eui64,
        peer_eui: Eui64,
        _initial_outgoing_counter: int = 1,
    ) -> None:
        if not isinstance(session_key, SecretBytes) or len(session_key) != _KEY_SIZE:
            raise ValueError(f"session key must be SecretBytes of {_KEY_SIZE} bytes")
        if not 1 <= _initial_outgoing_counter <= MAX_COUNTER + 1:
            raise ValueError("initial outgoing counter out of range")
        self._key = session_key
        self._own_eui = own_eui
        self._peer_eui = peer_eui
        self._outgoing = _initial_outgoing_counter
        self._incoming = IncomingCounters()

    @property
    def own_eui(self) -> Eui64:
        return self._own_eui

    @property
    def peer_eui(self) -> Eui64:
        return self._peer_eui

    @property
    def outgoing_counter(self) -> int:
        """Counter the next ``encrypt`` call will use."""
        return self._outgoing

    @property
    def incoming_counter(self) -> int:
        """Highest peer counter accepted on any characteristic (0 before any frame)."""
        return self._incoming.highest

    def encrypt(self, service_uuid: str | bytes, char_uuid: str | bytes, plaintext: bytes) -> bytes:
        """Seal ``plaintext`` as ``counter_LE(4) || ciphertext || MIC(4)``."""
        counter = self._outgoing
        if counter > MAX_COUNTER:
            raise CounterExhaustedError("outgoing frame counter exhausted; start a new session")
        svc, chr_ = _uuid(service_uuid), _uuid(char_uuid)
        self._outgoing = counter + 1  # burn before sealing: never reuse a counter
        return encrypt_session_frame(self._key, self._own_eui, counter, svc, chr_, plaintext)

    def decrypt(self, service_uuid: str | bytes, char_uuid: str | bytes, frame: bytes) -> bytes:
        """Verify and open a peer frame.

        Raises ``DecodeError`` (too short), ``ReplayError`` (counter not
        strictly increasing per characteristic; checked before the MIC) or ``AuthenticationError``.
        """
        svc, chr_ = _uuid(service_uuid), _uuid(char_uuid)
        counter = session_frame_counter(frame)
        if self._incoming.is_replay(chr_, counter):
            raise ReplayError(
                f"frame counter {counter} <= last accepted {self._incoming.last(chr_)} "
                "on this characteristic"
            )
        plaintext = decrypt_session_frame(self._key, self._peer_eui, svc, chr_, frame)
        self._incoming.accept(chr_, counter)
        return plaintext

    def counter_model(self) -> CounterModel:
        """Detected ZDD counter model from the counters accepted so far (spec §1.1).

        Never rejects a session. ``PER_CHARACTERISTIC`` is sticky and wins over ``SHARED``;
        ``UNKNOWN`` until both Status and Tunnel have been seen. Pure and cheap; the transport
        calls it after each accepted frame and logs the first non-UNKNOWN result at INFO.
        """
        return self._incoming.model()

    def __repr__(self) -> str:
        return (
            f"SessionCipher(own_eui={self._own_eui}, peer_eui={self._peer_eui}, "
            f"outgoing_counter={self._outgoing}, incoming_counter={self.incoming_counter})"
        )


# --- handshake initiator ---------------------------------------------------------------------


class HandshakeState(Enum):
    IDLE = "idle"
    AWAIT_SE2 = "await_se2"
    AWAIT_SE4 = "await_se4"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SendSe3:
    """Write ``payload`` (SE3) to the Authenticate characteristic."""

    payload: bytes


@dataclass(frozen=True, slots=True)
class Established:
    """Handshake complete; use ``cipher`` for all further characteristic values."""

    cipher: SessionCipher
    peer_eui: Eui64


type HandshakeStep = SendSe3 | Established


class HandshakeInitiator:
    """ZVD (initiator) side of the SPEKE session establishment.

    ``psk`` is the already-derived 16-byte pre-shared secret matching
    ``secret_type`` (see ``crypto.derive_basic_authorization_key``,
    ``install_code_to_link_key``, ``WELL_KNOWN_PSK``). A fresh ephemeral key is
    generated at ``start()`` unless ``private_key`` is injected (tests). Any
    validation failure moves to the terminal FAILED state and raises
    ``HandshakeError``; so does misuse (wrong call order).
    """

    __slots__ = (
        "_base_point",
        "_own_eui",
        "_own_q",
        "_peer_eui",
        "_peer_q",
        "_private_key",
        "_psk",
        "_secret_type",
        "_session_key",
        "_state",
    )

    def __init__(
        self,
        *,
        own_eui: Eui64,
        psk: SecretBytes,
        secret_type: SecretType,
        private_key: SecretBytes | None = None,
    ) -> None:
        if not isinstance(psk, SecretBytes) or len(psk) != _KEY_SIZE:
            raise ValueError(f"psk must be SecretBytes of {_KEY_SIZE} bytes")
        if private_key is not None and (
            not isinstance(private_key, SecretBytes) or len(private_key) != POINT_SIZE
        ):
            raise ValueError(f"private key must be SecretBytes of {POINT_SIZE} bytes")
        self._own_eui = own_eui
        self._psk = psk
        self._secret_type = SecretType(secret_type)
        self._private_key = private_key
        self._state = HandshakeState.IDLE
        self._base_point: SecretBytes | None = None
        self._own_q = b""
        self._peer_eui: Eui64 | None = None
        self._peer_q = b""
        self._session_key: SecretBytes | None = None

    @property
    def state(self) -> HandshakeState:
        return self._state

    def __repr__(self) -> str:
        return f"HandshakeInitiator(own_eui={self._own_eui}, state={self._state.name})"

    def start(self) -> bytes:
        """Return SE1 and move to AWAIT_SE2."""
        if self._state is not HandshakeState.IDLE:
            raise HandshakeError(f"start() called in state {self._state.name}")
        if self._private_key is None:
            self._private_key = generate_private_key()
        self._base_point = speke_base_point(self._psk)
        self._own_q = speke_public_point(self._private_key, self._base_point)
        se1 = (
            bytes([OPCODE_SE1])
            + encode_handshake_tlv(TLV_SELECTED_METHOD, self._method_value())
            + encode_handshake_tlv(TLV_C25519_POINT, self._own_eui.wire + self._own_q)
        )
        self._transition(HandshakeState.AWAIT_SE2)
        return se1

    def feed(self, indication: bytes) -> HandshakeStep:
        """Process SE2 (-> ``SendSe3``) or SE4 (-> ``Established``)."""
        state = self._state
        if state is HandshakeState.AWAIT_SE2:
            return self._guarded(self._on_se2, indication)
        if state is HandshakeState.AWAIT_SE4:
            return self._guarded(self._on_se4, indication)
        raise HandshakeError(f"feed() called in state {state.name}")

    # --- internals ---

    def _method_value(self) -> bytes:
        return bytes([KeyNegotiationMethod.CURVE25519_AESMMO128, self._secret_type])

    def _transition(self, new: HandshakeState) -> None:
        _LOGGER.debug("handshake %s -> %s", self._state.name, new.name)
        self._state = new

    def _guarded[T](self, handler: Callable[[bytes], T], data: bytes) -> T:
        try:
            return handler(data)
        except HandshakeError:
            self._fail()
            raise
        except Exception as exc:  # never leave a half-validated handshake usable
            self._fail()
            raise HandshakeError(f"handshake failed: {type(exc).__name__}") from exc

    def _fail(self) -> None:
        self._transition(HandshakeState.FAILED)
        self._session_key = None
        self._private_key = None

    def _on_se2(self, data: bytes) -> SendSe3:
        tlvs = parse_handshake_message(
            data,
            opcode=OPCODE_SE2,
            known={TLV_C25519_POINT: _POINT_TLV_SIZE, TLV_SELECTED_METHOD: _METHOD_TLV_SIZE},
        )
        point = tlvs.get(TLV_C25519_POINT)
        if point is None:
            raise HandshakeError("SE2 lacks the Curve25519 point TLV")
        method = tlvs.get(TLV_SELECTED_METHOD)
        if method is not None and method != self._method_value():
            raise HandshakeError("SE2 method/secret type does not match SE1")
        peer_eui = Eui64.from_wire(point[:_EUI_SIZE])
        peer_q = point[_EUI_SIZE:]
        if peer_eui == self._own_eui:
            raise HandshakeError("SE2 peer EUI equals our own EUI (reflection)")
        if tags_equal(peer_q, self._own_q):
            raise HandshakeError("SE2 peer point equals our own point (reflection)")
        if self._private_key is None or self._base_point is None:
            raise HandshakeError("internal state lost")  # pragma: no cover
        xk = speke_shared_point(self._private_key, peer_q)  # rejects low-order points
        secret = speke_session_secret(
            xk, self._own_eui, self._own_q, peer_eui, peer_q, self._base_point
        )
        self._session_key = speke_derive_link_key(secret)
        self._peer_eui, self._peer_q = peer_eui, peer_q
        tag = self._tag(LABEL_KC_2_U)
        self._transition(HandshakeState.AWAIT_SE4)
        return SendSe3(bytes([OPCODE_SE3]) + encode_handshake_tlv(TLV_MAC_TAG, tag))

    def _on_se4(self, data: bytes) -> Established:
        tlvs = parse_handshake_message(data, opcode=OPCODE_SE4, known={TLV_MAC_TAG: TAG_SIZE})
        tag = tlvs.get(TLV_MAC_TAG)
        if tag is None:
            raise HandshakeError("SE4 lacks the MAC tag TLV")
        if not tags_equal(tag, self._tag(LABEL_KC_2_V)):
            raise HandshakeError("SE4 confirmation tag mismatch (wrong PSK or peer)")
        if self._session_key is None or self._peer_eui is None:
            raise HandshakeError("internal state lost")  # pragma: no cover
        cipher = SessionCipher(
            session_key=self._session_key, own_eui=self._own_eui, peer_eui=self._peer_eui
        )
        self._private_key = None
        self._transition(HandshakeState.DONE)
        return Established(cipher=cipher, peer_eui=self._peer_eui)

    def _tag(self, label: bytes) -> bytes:
        if self._session_key is None or self._peer_eui is None:
            raise HandshakeError("internal state lost")  # pragma: no cover
        return confirmation_tag(
            self._session_key,
            label,
            responder_eui=self._peer_eui,
            responder_q=self._peer_q,
            initiator_eui=self._own_eui,
            initiator_q=self._own_q,
        )


__all__ = [
    "OPCODE_SE1",
    "OPCODE_SE2",
    "OPCODE_SE3",
    "OPCODE_SE4",
    "TLV_C25519_POINT",
    "TLV_MAC_TAG",
    "TLV_SELECTED_METHOD",
    "CounterModel",
    "Established",
    "HandshakeInitiator",
    "HandshakeState",
    "HandshakeStep",
    "SendSe3",
    "SessionCipher",
    "encode_handshake_tlv",
    "parse_handshake_message",
]
