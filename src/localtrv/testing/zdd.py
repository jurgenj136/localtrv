"""``FakeZdd``: the ZDD (responder) side of SE1-SE4 plus its session crypto.

Moved unchanged in behaviour from the former ``localtrv.testing`` module.
``FakeZdd`` emulates the responder (Zigbee Direct Device) side of the SPEKE session
establishment and then the session-frame crypto, so integrations can
be tested without hardware. It uses the same crypto primitives as the
initiator but with the roles spelled out explicitly, so a responder/initiator
mix-up in the library fails the tests instead of cancelling itself out.

It also has ZDD counter models (``ZddCounterModel``): the per-characteristic model gives every
characteristic its own outgoing counter (starting at 1) under the one session key, to exercise
the client's per-characteristic incoming tracking and counter-model detection.
"""

from __future__ import annotations

from enum import Enum, StrEnum
from typing import Final

from localtrv.testing.errors import GATT_ERROR_REJECTED, FakeGattError
from localtrv.zigbee_direct.crypto import (
    LABEL_KC_2_U,
    LABEL_KC_2_V,
    POINT_SIZE,
    TAG_SIZE,
    KeyNegotiationMethod,
    SecretType,
    confirmation_tag,
    generate_private_key,
    speke_base_point,
    speke_derive_link_key,
    speke_public_point,
    speke_session_secret,
    speke_shared_point,
    tags_equal,
)
from localtrv.zigbee_direct.errors import HandshakeError
from localtrv.zigbee_direct.session import (
    OPCODE_SE1,
    OPCODE_SE2,
    OPCODE_SE3,
    OPCODE_SE4,
    TLV_C25519_POINT,
    TLV_MAC_TAG,
    TLV_SELECTED_METHOD,
    SessionCipher,
    encode_handshake_tlv,
    parse_handshake_message,
)
from localtrv.zigbee_direct.types import Eui64, SecretBytes

_EUI_SIZE: Final = 8


class ZddCounterModel(StrEnum):
    """How the simulated ZDD numbers its outgoing session frames (docs/protocol.md §4).

    * ``SHARED``: one outgoing counter across Status reads and Tunnel indications.
    * ``PER_CHARACTERISTIC``: one outgoing counter per characteristic, each starting at 1.
    """

    SHARED = "shared"
    PER_CHARACTERISTIC = "per_characteristic"


class _State(Enum):
    AWAIT_SE1 = "await_se1"
    AWAIT_SE3 = "await_se3"
    DONE = "done"
    FAILED = "failed"


class FakeZdd:
    """Responder side of SE1-SE4 plus its own ``SessionCipher`` (own EUI = ZDD).

    ``handle_se1`` returns SE2; ``handle_se3`` returns SE4 or raises
    ``FakeGattError(code=0x80)`` on a bad tag, like the live ZDD. Any malformed
    or out-of-order message also raises ``FakeGattError`` and is terminal.
    """

    def __init__(
        self,
        *,
        eui: Eui64,
        psk: SecretBytes,
        private_key: SecretBytes | None = None,
        counter_model: ZddCounterModel = ZddCounterModel.SHARED,
    ) -> None:
        self._counter_model = counter_model
        self._eui = eui
        self._psk = psk
        self._private_key = private_key
        self._state = _State.AWAIT_SE1
        self._base_point: SecretBytes | None = None
        self._own_q = b""
        self._peer_eui: Eui64 | None = None
        self._peer_q = b""
        self._session_key: SecretBytes | None = None
        self._secret_type: SecretType | None = None
        self._cipher: SessionCipher | None = None
        self._per_char: dict[str, SessionCipher] = {}

    @property
    def eui(self) -> Eui64:
        return self._eui

    @property
    def secret_type(self) -> SecretType | None:
        """Secret type requested in SE1 (``None`` before SE1)."""
        return self._secret_type

    @property
    def cipher(self) -> SessionCipher:
        """The ZDD's session cipher; only available after a successful SE3."""
        if self._cipher is None:
            raise RuntimeError("FakeZdd session not established")
        return self._cipher

    @property
    def counter_model(self) -> ZddCounterModel:
        return self._counter_model

    @property
    def established(self) -> bool:
        """True once SE3 was accepted (the session cipher exists)."""
        return self._cipher is not None

    def seal(self, service_uuid: str, char_uuid: str, plaintext: bytes) -> bytes:
        """Encrypt a ZDD-to-ZVD value (indication or read response) under ``counter_model``.

        ``SHARED`` uses ``cipher``; ``PER_CHARACTERISTIC`` uses one outgoing counter per
        ``char_uuid`` (each starting at 1, same session key). ``RuntimeError`` before the
        session exists.
        """
        cipher = self.cipher
        if self._counter_model is ZddCounterModel.SHARED:
            return cipher.encrypt(service_uuid, char_uuid, plaintext)
        key = char_uuid.lower()
        sender = self._per_char.get(key)
        if sender is None:
            if self._session_key is None or self._peer_eui is None:  # pragma: no cover
                raise RuntimeError("FakeZdd internal state lost")
            sender = SessionCipher(
                session_key=self._session_key, own_eui=self._eui, peer_eui=self._peer_eui
            )
            self._per_char[key] = sender
        return sender.encrypt(service_uuid, char_uuid, plaintext)

    def open_frame(self, service_uuid: str, char_uuid: str, frame: bytes) -> bytes:
        """Decrypt and replay-check a ZVD-to-ZDD write (the ZVD always uses one counter).

        Raises ``DecodeError``/``ReplayError``/``AuthenticationError`` like
        ``SessionCipher.decrypt``; the GATT layer maps them to its configured replay
        behaviour. ``RuntimeError`` before the session exists.
        """
        return self.cipher.decrypt(service_uuid, char_uuid, frame)

    def __repr__(self) -> str:
        return f"FakeZdd(eui={self._eui}, state={self._state.name})"

    def handle_se1(self, se1: bytes) -> bytes:
        """Process SE1 and return SE2 (``0x02 | TLV(0x02, ZDD_EUI || ZDD_Q)``)."""
        self._expect(_State.AWAIT_SE1)
        try:
            tlvs = parse_handshake_message(
                se1,
                opcode=OPCODE_SE1,
                known={TLV_SELECTED_METHOD: 2, TLV_C25519_POINT: _EUI_SIZE + POINT_SIZE},
            )
            method, point = tlvs.get(TLV_SELECTED_METHOD), tlvs.get(TLV_C25519_POINT)
            if method is None or point is None:
                raise HandshakeError("SE1 lacks a required TLV")
            if method[0] != KeyNegotiationMethod.CURVE25519_AESMMO128:
                raise HandshakeError("unsupported key negotiation method")
            secret_type = SecretType(method[1])
            if self._private_key is None:
                self._private_key = generate_private_key()
            self._base_point = speke_base_point(self._psk)
            self._own_q = speke_public_point(self._private_key, self._base_point)
            self._peer_eui = Eui64.from_wire(point[:_EUI_SIZE])
            self._peer_q = point[_EUI_SIZE:]
            xk = speke_shared_point(self._private_key, self._peer_q)
            secret = speke_session_secret(
                xk,
                initiator_eui=self._peer_eui,
                initiator_q=self._peer_q,
                responder_eui=self._eui,
                responder_q=self._own_q,
                base_point=self._base_point,
            )
        except (HandshakeError, ValueError) as exc:
            self._state = _State.FAILED
            raise FakeGattError(f"SE1 rejected: {exc}") from exc
        self._secret_type = secret_type
        self._session_key = speke_derive_link_key(secret)
        self._state = _State.AWAIT_SE3
        return bytes([OPCODE_SE2]) + encode_handshake_tlv(
            TLV_C25519_POINT, self._eui.wire + self._own_q
        )

    def handle_se3(self, se3: bytes) -> bytes:
        """Verify the initiator's KC_2_U tag and return SE4 (KC_2_V tag)."""
        self._expect(_State.AWAIT_SE3)
        try:
            tlvs = parse_handshake_message(se3, opcode=OPCODE_SE3, known={TLV_MAC_TAG: TAG_SIZE})
        except HandshakeError as exc:
            self._state = _State.FAILED
            raise FakeGattError(f"SE3 rejected: {exc}") from exc
        tag = tlvs.get(TLV_MAC_TAG)
        if tag is None or not tags_equal(tag, self._tag(LABEL_KC_2_U)):
            self._state = _State.FAILED
            raise FakeGattError("SE3 confirmation tag rejected")
        se4 = bytes([OPCODE_SE4]) + encode_handshake_tlv(TLV_MAC_TAG, self._tag(LABEL_KC_2_V))
        if self._session_key is None or self._peer_eui is None:  # pragma: no cover
            raise RuntimeError("FakeZdd internal state lost")
        self._cipher = SessionCipher(
            session_key=self._session_key, own_eui=self._eui, peer_eui=self._peer_eui
        )
        self._state = _State.DONE
        return se4

    def _expect(self, state: _State) -> None:
        if self._state is not state:
            current = self._state
            self._state = _State.FAILED
            raise FakeGattError(f"unexpected message in state {current.name}")

    def _tag(self, label: bytes) -> bytes:
        if self._session_key is None or self._peer_eui is None:  # pragma: no cover
            raise RuntimeError("FakeZdd internal state lost")
        return confirmation_tag(
            self._session_key,
            label,
            responder_eui=self._eui,
            responder_q=self._own_q,
            initiator_eui=self._peer_eui,
            initiator_q=self._peer_q,
        )


__all__ = ["GATT_ERROR_REJECTED", "FakeGattError", "FakeZdd", "ZddCounterModel"]
