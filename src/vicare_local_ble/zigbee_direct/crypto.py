"""Zigbee Direct Security Service cryptography (Zigbee R23 Annex J, Zigbee Direct 1.0).

Key derivation (BAK, install code, well-known PSK), SPEKE over Curve25519 with
AES-MMO-128, the SE3/SE4 confirmation tag and AES-CCM session frames.

Stateless and pure: no I/O, no logging, no frame counters (``session.py`` owns
counter state and replay checks). EUI-64 values are ``Eui64``; key material is
``SecretBytes``; public points, tags, nonces and frames are plain ``bytes``.
"""

from __future__ import annotations

import hmac
import os
from enum import IntEnum
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from vicare_local_ble.zigbee_direct.errors import AuthenticationError, DecodeError, HandshakeError
from vicare_local_ble.zigbee_direct.mmo import (
    BLOCK_SIZE,
    hmac_aes_mmo,
    install_code_crc16,
    mmo_hash,
)
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

KEY_SIZE: Final = 16
POINT_SIZE: Final = 32
TAG_SIZE: Final = 16
COUNTER_SIZE: Final = 4
MIC_LENGTH: Final = 4
SECURITY_LEVEL: Final = 0x05  # ENC-MIC-32
MAX_COUNTER: Final = 0xFFFFFFFF
UUID_SIZE: Final = 16

#: Anonymous well-known PSK (``apscWellKnownPSK``, R23 Annex C.7.1).
WELL_KNOWN_PSK: Final = SecretBytes(b"ZigBeeAlliance18")

#: SE3 (initiator -> responder) and SE4 (responder -> initiator) confirmation labels.
LABEL_KC_2_U: Final = b"KC_2_U"
LABEL_KC_2_V: Final = b"KC_2_V"

_INSTALL_CODE_LENGTHS: Final = frozenset({6, 8, 12, 16})
_BAK_KDF_INPUT: Final = b"\x03"
_LINK_KEY_KDF_INPUT: Final = b"\x01"


class SecretType(IntEnum):
    """Pre-shared secret type of the Security Service (docs/protocol.md §3)."""

    SYMMETRIC_AUTH_TOKEN = 0x00
    INSTALL_CODE_LINK_KEY = 0x01
    VARIABLE_LENGTH_PASSCODE = 0x02
    BASIC_AUTHORIZATION_KEY = 0x03
    ADMIN_AUTHORIZATION_KEY = 0x04
    ANONYMOUS_WELL_KNOWN = 0x05


class KeyNegotiationMethod(IntEnum):
    """Key negotiation method of the Security Service (docs/protocol.md §3)."""

    CURVE25519_AESMMO128 = 0x01


# --- pre-shared secret derivation -----------------------------------------------------


def install_code_to_link_key(install_code: bytes, *, includes_crc: bool = False) -> SecretBytes:
    """Derive the pre-configured link key ``MMO(install_code || CRC16_LE)`` (R23 10.1).

    ``install_code`` is 6, 8, 12 or 16 bytes. With ``includes_crc=True`` it carries
    its 2-byte little-endian CRC (as printed on devices), which is verified.
    """
    code = install_code
    if includes_crc:
        if len(code) - 2 not in _INSTALL_CODE_LENGTHS:
            raise ValueError(f"install code with CRC must be 8/10/14/18 bytes, got {len(code)}")
        code, given = code[:-2], code[-2:]
        if install_code_crc16(code).to_bytes(2, "little") != given:
            raise ValueError("install code CRC mismatch")
    elif len(code) not in _INSTALL_CODE_LENGTHS:
        raise ValueError(f"install code must be 6/8/12/16 bytes, got {len(code)}")
    return SecretBytes(mmo_hash(code + install_code_crc16(code).to_bytes(2, "little")))


def derive_basic_authorization_key(zvd_eui: Eui64, network_key: SecretBytes) -> SecretBytes:
    """Basic Authorization Key ``HMAC-AES-MMO(MMO(zvd_eui_wire || network_key), 0x03)``.

    ``zvd_eui`` enters in little-endian wire order (docs/protocol.md §3;
    Silicon Labs ``sl_zigbee_direct_calculate_basic_key``).
    """
    if len(network_key) != KEY_SIZE:
        raise ValueError(f"network key must be {KEY_SIZE} bytes")
    inner = mmo_hash(zvd_eui.wire + network_key.reveal())
    return SecretBytes(hmac_aes_mmo(inner, _BAK_KDF_INPUT))


# --- SPEKE (R23 Annex J) -----------------------------------------------------------------


def speke_base_point(psk: SecretBytes) -> SecretBytes:
    """Generator ``G = MMO(PSK) || MMO(PSK)`` (Annex J, Table J-1).

    Secret: knowing ``G`` is enough to run the handshake as either party.
    """
    digest = mmo_hash(psk.reveal())
    return SecretBytes(digest + digest)


def clamp_scalar(scalar: bytes) -> bytes:
    """RFC 7748 ``decodeScalar25519`` clamping of a 32-byte scalar."""
    if len(scalar) != POINT_SIZE:
        raise ValueError(f"X25519 scalar must be {POINT_SIZE} bytes")
    out = bytearray(scalar)
    out[0] &= 248
    out[31] &= 127
    out[31] |= 64
    return bytes(out)


def generate_private_key() -> SecretBytes:
    """Fresh random 32-byte ephemeral scalar (clamped on use)."""
    return SecretBytes(os.urandom(POINT_SIZE))


def x25519(scalar: SecretBytes, point: bytes | SecretBytes) -> bytes:
    """``X25519(clamp(scalar), point)``.

    Raises ``HandshakeError`` for an all-zero result (low-order / small-subgroup
    point, RFC 7748 6.1) and ``ValueError`` for wrong input lengths.
    """
    raw_point = point.reveal() if isinstance(point, SecretBytes) else point
    if len(raw_point) != POINT_SIZE:
        raise ValueError(f"X25519 point must be {POINT_SIZE} bytes")
    priv = X25519PrivateKey.from_private_bytes(clamp_scalar(scalar.reveal()))
    try:
        out = priv.exchange(X25519PublicKey.from_public_bytes(raw_point))
    except ValueError as exc:  # cryptography rejects all-zero output itself
        raise HandshakeError("X25519 produced an all-zero result (low-order point)") from exc
    if not any(out):
        raise HandshakeError("X25519 produced an all-zero result (low-order point)")
    return out


def speke_public_point(private_key: SecretBytes, base_point: SecretBytes) -> bytes:
    """Our public point ``Q = X25519(private_key, G)``."""
    return x25519(private_key, base_point)


def speke_shared_point(private_key: SecretBytes, peer_q: bytes) -> SecretBytes:
    """Shared point ``xk = X25519(private_key, Q_peer)``."""
    return SecretBytes(x25519(private_key, peer_q))


def eui64_compare(a: Eui64, b: Eui64) -> int:
    """Compare two EUI-64 as 64-bit integers; returns -1, 0 or 1.

    The last wire byte is most significant (R23 Annex J.1.3 step 5).
    """
    x, y = a.as_int(), b.as_int()
    return (x > y) - (x < y)


def speke_session_secret(
    xk: SecretBytes,
    initiator_eui: Eui64,
    initiator_q: bytes,
    responder_eui: Eui64,
    responder_q: bytes,
    base_point: SecretBytes,
) -> SecretBytes:
    """``s = MMO(xk || I || G)``; ``I`` is the (EUI, Q) pairs, numerically smaller EUI first.

    Ties put the responder first, as the research prototype did (docs/protocol.md §3).
    """
    if eui64_compare(responder_eui, initiator_eui) <= 0:
        session_id = responder_eui.wire + responder_q + initiator_eui.wire + initiator_q
    else:
        session_id = initiator_eui.wire + initiator_q + responder_eui.wire + responder_q
    return SecretBytes(mmo_hash(xk.reveal() + session_id + base_point.reveal()))


def speke_derive_link_key(session_secret: SecretBytes) -> SecretBytes:
    """Session key ``DK = HMAC-AES-MMO(s, 0x01)`` (Annex J KDF)."""
    return SecretBytes(hmac_aes_mmo(session_secret.reveal(), _LINK_KEY_KDF_INPUT))


def confirmation_tag(
    session_key: SecretBytes,
    label: bytes,
    responder_eui: Eui64,
    responder_q: bytes,
    initiator_eui: Eui64,
    initiator_q: bytes,
) -> bytes:
    """SE3/SE4 MAC tag in the Silicon Labs responder-first order.

    ``HMAC-AES-MMO(key, label || responder_EUI || responder_Q || initiator_EUI || initiator_Q)``
    with ``label`` ``KC_2_U`` (SE3) or ``KC_2_V`` (SE4). This is the only order the
    ZDD accepted on hardware; the other orders the research prototype tried are dropped.
    """
    if label not in (LABEL_KC_2_U, LABEL_KC_2_V):
        raise ValueError("label must be KC_2_U or KC_2_V")
    if len(responder_q) != POINT_SIZE or len(initiator_q) != POINT_SIZE:
        raise ValueError(f"points must be {POINT_SIZE} bytes")
    body = label + responder_eui.wire + responder_q + initiator_eui.wire + initiator_q
    return hmac_aes_mmo(session_key.reveal(), body)


def tags_equal(a: bytes, b: bytes) -> bool:
    """Constant-time tag comparison."""
    return hmac.compare_digest(a, b)


# --- session frames (AES-CCM*, ENC-MIC-32) --------------------------------------------------


def ccm_nonce(sender_eui: Eui64, counter: int) -> bytes:
    """13-byte nonce ``sender_EUI_wire(8) || counter_LE(4) || 0x05``."""
    if not 0 <= counter <= MAX_COUNTER:
        raise ValueError("frame counter out of range 0..0xFFFFFFFF")
    return sender_eui.wire + counter.to_bytes(COUNTER_SIZE, "little") + bytes([SECURITY_LEVEL])


def ccm_aad(service_uuid: bytes, char_uuid: bytes) -> bytes:
    """AAD ``service_uuid(16) || 0x00 || char_uuid(16) || 0x00`` (canonical UUID bytes)."""
    if len(service_uuid) != UUID_SIZE or len(char_uuid) != UUID_SIZE:
        raise ValueError(f"UUIDs must be {UUID_SIZE} canonical bytes (see uuids.uuid_bytes)")
    return service_uuid + b"\x00" + char_uuid + b"\x00"


def _ccm(session_key: SecretBytes) -> AESCCM:
    if len(session_key) != KEY_SIZE:
        raise ValueError(f"session key must be {KEY_SIZE} bytes")
    return AESCCM(session_key.reveal(), tag_length=MIC_LENGTH)


def encrypt_session_frame(
    session_key: SecretBytes,
    sender_eui: Eui64,
    counter: int,
    service_uuid: bytes,
    char_uuid: bytes,
    plaintext: bytes,
) -> bytes:
    """Encrypt one GATT value: ``counter_LE(4) || ciphertext || MIC(4)``."""
    nonce = ccm_nonce(sender_eui, counter)
    sealed = _ccm(session_key).encrypt(nonce, plaintext, ccm_aad(service_uuid, char_uuid))
    return counter.to_bytes(COUNTER_SIZE, "little") + sealed


def session_frame_counter(frame: bytes) -> int:
    """Read the frame counter (for replay checks before decrypting); length-checked."""
    if len(frame) < COUNTER_SIZE + MIC_LENGTH:
        raise DecodeError(f"session frame too short: {len(frame)} bytes")
    return int.from_bytes(frame[:COUNTER_SIZE], "little")


def decrypt_session_frame(
    session_key: SecretBytes,
    sender_eui: Eui64,
    service_uuid: bytes,
    char_uuid: bytes,
    frame: bytes,
) -> bytes:
    """Verify and decrypt a session frame from ``sender_eui``.

    Raises ``DecodeError`` if shorter than counter + MIC and
    ``AuthenticationError`` on MIC failure.
    """
    counter = session_frame_counter(frame)
    nonce = ccm_nonce(sender_eui, counter)
    aad = ccm_aad(service_uuid, char_uuid)
    try:
        return _ccm(session_key).decrypt(nonce, frame[COUNTER_SIZE:], aad)
    except InvalidTag as exc:
        raise AuthenticationError("session frame MIC check failed") from exc


__all__ = [
    "BLOCK_SIZE",
    "COUNTER_SIZE",
    "KEY_SIZE",
    "LABEL_KC_2_U",
    "LABEL_KC_2_V",
    "MAX_COUNTER",
    "MIC_LENGTH",
    "POINT_SIZE",
    "SECURITY_LEVEL",
    "TAG_SIZE",
    "UUID_SIZE",
    "WELL_KNOWN_PSK",
    "KeyNegotiationMethod",
    "SecretType",
    "ccm_aad",
    "ccm_nonce",
    "clamp_scalar",
    "confirmation_tag",
    "decrypt_session_frame",
    "derive_basic_authorization_key",
    "encrypt_session_frame",
    "eui64_compare",
    "generate_private_key",
    "hmac_aes_mmo",
    "install_code_crc16",
    "install_code_to_link_key",
    "mmo_hash",
    "session_frame_counter",
    "speke_base_point",
    "speke_derive_link_key",
    "speke_public_point",
    "speke_session_secret",
    "speke_shared_point",
    "tags_equal",
    "x25519",
]
