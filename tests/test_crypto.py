"""Zigbee Direct crypto tests: R23 Annex C.7.1 SPEKE vectors, key derivation, CCM frames.

CCM known answers are computed inside the tests from the spec formulas with
``cryptography``'s ``AESCCM`` directly, not via the library helpers.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from vicare_direct.zigbee_direct import crypto as zc
from vicare_direct.zigbee_direct.errors import AuthenticationError, DecodeError, HandshakeError
from vicare_direct.zigbee_direct.mmo import hmac_aes_mmo, mmo_hash
from vicare_direct.zigbee_direct.types import Eui64, SecretBytes
from vicare_direct.zigbee_direct.uuids import COMMISSIONING_STATUS, TUNNEL_NPDU, uuid_bytes


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


# --- R23 Annex C.7.1 test vector #1 (PSK = apscWellKnownPSK) -------------------------------
G_1 = unhex(
    "90 2B 44 85 C8 4E C4 A0 59 44 AB 34 42 92 68 78 "  # secret-scan: allow
    "90 2B 44 85 C8 4E C4 A0 59 44 AB 34 42 92 68 78"  # secret-scan: allow
)
ALICE_PRIV = SecretBytes(b"AliceAliceAliceAliceAliceAliceAl")
BOB_PRIV = SecretBytes(b"BobBobBobBobBobBobBobBobBobBobBo")
ALICE_EUI = Eui64.from_wire(unhex("AA 00 A0 A0 0A 0A A0 A0"))
BOB_EUI = Eui64.from_wire(unhex("BB 00 B0 B0 0B 0B B0 B0"))
ALICE_Q = unhex(
    "BA BB C4 D7 85 6A BF 56 1B B4 37 8F D9 FD 24 92 "  # secret-scan: allow
    "C1 EA 16 02 1B 90 D6 1F CE 3A 96 5B 04 1C A2 59"  # secret-scan: allow
)
BOB_Q = unhex(
    "47 7D C0 5F F5 42 AC 83 AD DF 2B 87 87 11 92 DC "  # secret-scan: allow
    "6C 59 6A C5 40 C8 D3 5A FB 7E C7 25 9A 71 5B 6C"  # secret-scan: allow
)
XK = unhex(
    "FB 9C 3C 7A 2E 49 03 CD D2 36 DA 82 CD 0B 71 81 "  # secret-scan: allow
    "B1 61 7D 99 67 4C 4E A8 A3 F5 D4 60 31 DD A7 09"  # secret-scan: allow
)
S_1 = unhex("AE 46 6B 75 30 9D 5C 2D 71 5F 7E 44 31 DF 04 7A")  # secret-scan: allow
LINK_KEY_1 = unhex("25 47 F3 AF 96 39 1E 1E BF F2 A3 B7 6D 6A 29 29")  # secret-scan: allow

# Dummy identities for CCM tests (not real devices).
ZVD = Eui64.from_wire(bytes(range(1, 9)))
ZDD = Eui64.from_wire(bytes(range(0x11, 0x19)))
KEY = SecretBytes(bytes(range(16)))
SVC = uuid_bytes(0xFFF7)
CHR = uuid_bytes(COMMISSIONING_STATUS)


# --- C.7.1 -----------------------------------------------------------------------------------


def test_well_known_psk() -> None:
    assert zc.WELL_KNOWN_PSK.reveal() == b"ZigBeeAlliance18"


def test_base_point_vector() -> None:
    assert zc.speke_base_point(zc.WELL_KNOWN_PSK).reveal() == G_1


def test_public_points_vector() -> None:
    g = SecretBytes(G_1)
    assert zc.speke_public_point(ALICE_PRIV, g) == ALICE_Q
    assert zc.speke_public_point(BOB_PRIV, g) == BOB_Q


def test_shared_point_vector() -> None:
    assert zc.speke_shared_point(ALICE_PRIV, BOB_Q).reveal() == XK
    assert zc.speke_shared_point(BOB_PRIV, ALICE_Q).reveal() == XK


def test_session_secret_vector() -> None:
    s = zc.speke_session_secret(
        SecretBytes(XK), ALICE_EUI, ALICE_Q, BOB_EUI, BOB_Q, SecretBytes(G_1)
    )
    assert s.reveal() == S_1


def test_session_secret_independent_of_role() -> None:
    # Ordering is by numeric EUI, so swapping roles yields the same secret.
    s = zc.speke_session_secret(
        SecretBytes(XK), BOB_EUI, BOB_Q, ALICE_EUI, ALICE_Q, SecretBytes(G_1)
    )
    assert s.reveal() == S_1


def test_link_key_vector() -> None:
    assert zc.speke_derive_link_key(SecretBytes(S_1)).reveal() == LINK_KEY_1


def test_eui64_compare_numeric() -> None:
    assert zc.eui64_compare(ALICE_EUI, BOB_EUI) == -1
    assert zc.eui64_compare(BOB_EUI, ALICE_EUI) == 1
    assert zc.eui64_compare(ALICE_EUI, ALICE_EUI) == 0
    # Last wire byte is most significant, not the first.
    lo = Eui64.from_wire(bytes([0xFF, 0, 0, 0, 0, 0, 0, 0x01]))
    hi = Eui64.from_wire(bytes([0x00, 0, 0, 0, 0, 0, 0, 0x02]))
    assert zc.eui64_compare(lo, hi) == -1


def test_session_secret_tie_puts_responder_first() -> None:
    xk, g = SecretBytes(bytes(32)), SecretBytes(bytes(32))
    q_i, q_r = bytes([1]) * 32, bytes([2]) * 32
    s = zc.speke_session_secret(xk, ALICE_EUI, q_i, ALICE_EUI, q_r, g)
    expected = mmo_hash(bytes(32) + ALICE_EUI.wire + q_r + ALICE_EUI.wire + q_i + bytes(32))
    assert s.reveal() == expected


# --- X25519 ----------------------------------------------------------------------------------


@pytest.mark.parametrize("point", [bytes(32), b"\x01" + bytes(31)])
def test_x25519_rejects_low_order_points(point: bytes) -> None:
    with pytest.raises(HandshakeError):
        zc.x25519(ALICE_PRIV, point)


def test_x25519_rejects_bad_lengths() -> None:
    with pytest.raises(ValueError, match="point"):
        zc.x25519(ALICE_PRIV, bytes(31))
    with pytest.raises(ValueError, match="scalar"):
        zc.x25519(SecretBytes(bytes(31)), BOB_Q)


def test_clamp_scalar() -> None:
    out = zc.clamp_scalar(b"\xff" * 32)
    assert out[0] == 0xF8
    assert out[31] == 0x7F
    assert zc.clamp_scalar(bytes(32))[31] == 0x40


def test_generate_private_key_is_secret_and_fresh() -> None:
    a, b = zc.generate_private_key(), zc.generate_private_key()
    assert isinstance(a, SecretBytes)
    assert len(a) == 32
    assert a != b


# --- confirmation tag ------------------------------------------------------------------------


def test_confirmation_tag_known_answer_responder_first() -> None:
    key = SecretBytes(LINK_KEY_1)
    # Initiator = Alice, responder = Bob: SiLabs order is responder pair first.
    for label in (b"KC_2_U", b"KC_2_V"):
        expected = hmac_aes_mmo(LINK_KEY_1, label + BOB_EUI.wire + BOB_Q + ALICE_EUI.wire + ALICE_Q)
        tag = zc.confirmation_tag(key, label, BOB_EUI, BOB_Q, ALICE_EUI, ALICE_Q)
        assert tag == expected
        assert len(tag) == zc.TAG_SIZE


def test_confirmation_tag_labels_differ() -> None:
    key = SecretBytes(LINK_KEY_1)
    u = zc.confirmation_tag(key, zc.LABEL_KC_2_U, BOB_EUI, BOB_Q, ALICE_EUI, ALICE_Q)
    v = zc.confirmation_tag(key, zc.LABEL_KC_2_V, BOB_EUI, BOB_Q, ALICE_EUI, ALICE_Q)
    assert u != v
    assert zc.tags_equal(u, u)
    assert not zc.tags_equal(u, v)


def test_confirmation_tag_rejects_bad_inputs() -> None:
    key = SecretBytes(LINK_KEY_1)
    with pytest.raises(ValueError, match="label"):
        zc.confirmation_tag(key, b"KC_1_U", BOB_EUI, BOB_Q, ALICE_EUI, ALICE_Q)
    with pytest.raises(ValueError, match="points"):
        zc.confirmation_tag(key, zc.LABEL_KC_2_U, BOB_EUI, BOB_Q[:31], ALICE_EUI, ALICE_Q)


# --- pre-shared secrets ----------------------------------------------------------------------

IC = unhex("83FED3407A939723A5C639B26916D505")  # secret-scan: allow
IC_LINK_KEY = unhex("66B6900981E1EE3CA4206B6B861C02BB")  # secret-scan: allow


def test_install_code_link_key_vector() -> None:
    assert zc.install_code_to_link_key(IC).reveal() == IC_LINK_KEY
    with_crc = IC + unhex("C3B5")
    assert zc.install_code_to_link_key(with_crc, includes_crc=True).reveal() == IC_LINK_KEY


@pytest.mark.parametrize("length", [6, 8, 12, 16])
def test_install_code_lengths(length: int) -> None:
    code = bytes(range(length))
    key = zc.install_code_to_link_key(code)
    crc = zc.install_code_crc16(code).to_bytes(2, "little")
    assert key.reveal() == mmo_hash(code + crc)
    assert zc.install_code_to_link_key(code + crc, includes_crc=True) == key


@pytest.mark.parametrize("length", [0, 5, 7, 10, 17])
def test_install_code_bad_length(length: int) -> None:
    with pytest.raises(ValueError, match="install code"):
        zc.install_code_to_link_key(bytes(length))


def test_install_code_bad_crc() -> None:
    with pytest.raises(ValueError, match="CRC mismatch"):
        zc.install_code_to_link_key(IC + b"\x00\x00", includes_crc=True)
    with pytest.raises(ValueError, match="with CRC"):
        zc.install_code_to_link_key(IC, includes_crc=True)


def test_basic_authorization_key_definition() -> None:
    nwk_key = SecretBytes(bytes(range(0x20, 0x30)))
    bak = zc.derive_basic_authorization_key(ZVD, nwk_key)
    expected = hmac_aes_mmo(mmo_hash(ZVD.wire + nwk_key.reveal()), b"\x03")
    assert isinstance(bak, SecretBytes)
    assert bak.reveal() == expected
    assert zc.derive_basic_authorization_key(ZDD, nwk_key) != bak


def test_basic_authorization_key_rejects_bad_key() -> None:
    with pytest.raises(ValueError, match="network key"):
        zc.derive_basic_authorization_key(ZVD, SecretBytes(bytes(15)))


def test_enums() -> None:
    assert int(zc.SecretType.BASIC_AUTHORIZATION_KEY) == 0x03
    assert int(zc.SecretType.ANONYMOUS_WELL_KNOWN) == 0x05
    assert int(zc.KeyNegotiationMethod.CURVE25519_AESMMO128) == 0x01


# --- session frames --------------------------------------------------------------------------


def _independent_frame(sender: Eui64, counter: int, plaintext: bytes) -> bytes:
    nonce = sender.wire + counter.to_bytes(4, "little") + b"\x05"
    aad = SVC + b"\x00" + CHR + b"\x00"
    ct = AESCCM(KEY.reveal(), tag_length=4).encrypt(nonce, plaintext, aad)
    return counter.to_bytes(4, "little") + ct


def test_nonce_and_aad_layout() -> None:
    assert zc.ccm_nonce(ZVD, 0x01020304) == ZVD.wire + b"\x04\x03\x02\x01\x05"
    assert zc.ccm_aad(SVC, CHR) == SVC + b"\x00" + CHR + b"\x00"


def test_encrypt_known_answer() -> None:
    plaintext = b"\x05\x00\x0a\x01\x02\x03"
    frame = zc.encrypt_session_frame(KEY, ZVD, 7, SVC, CHR, plaintext)
    assert frame == _independent_frame(ZVD, 7, plaintext)
    assert len(frame) == 4 + len(plaintext) + 4
    assert zc.session_frame_counter(frame) == 7


def test_decrypt_known_answer() -> None:
    frame = _independent_frame(ZDD, 42, b"hello")
    assert zc.decrypt_session_frame(KEY, ZDD, SVC, CHR, frame) == b"hello"


def test_empty_plaintext_roundtrip() -> None:
    frame = zc.encrypt_session_frame(KEY, ZVD, 1, SVC, CHR, b"")
    assert len(frame) == 8
    assert zc.decrypt_session_frame(KEY, ZVD, SVC, CHR, frame) == b""


@pytest.mark.parametrize(
    "tamper",
    ["mic", "ciphertext", "counter", "eui", "service", "char", "key"],
)
def test_decrypt_rejects_tampering(tamper: str) -> None:
    frame = bytearray(_independent_frame(ZDD, 9, b"payload"))
    sender, svc, chr_, key = ZDD, SVC, CHR, KEY
    if tamper == "mic":
        frame[-1] ^= 0x01
    elif tamper == "ciphertext":
        frame[5] ^= 0x01
    elif tamper == "counter":
        frame[0] ^= 0x01
    elif tamper == "eui":
        sender = ZVD
    elif tamper == "service":
        svc = uuid_bytes(TUNNEL_NPDU)
    elif tamper == "char":
        chr_ = uuid_bytes(TUNNEL_NPDU)
    else:
        key = SecretBytes(bytes(16))
    with pytest.raises(AuthenticationError):
        zc.decrypt_session_frame(key, sender, svc, chr_, bytes(frame))


@pytest.mark.parametrize("length", [0, 3, 7])
def test_decrypt_rejects_truncated(length: int) -> None:
    with pytest.raises(DecodeError, match="too short"):
        zc.decrypt_session_frame(KEY, ZDD, SVC, CHR, bytes(length))


def test_counter_range() -> None:
    zc.encrypt_session_frame(KEY, ZVD, zc.MAX_COUNTER, SVC, CHR, b"x")
    with pytest.raises(ValueError, match="counter"):
        zc.ccm_nonce(ZVD, zc.MAX_COUNTER + 1)
    with pytest.raises(ValueError, match="counter"):
        zc.ccm_nonce(ZVD, -1)


def test_bad_uuid_and_key_lengths() -> None:
    with pytest.raises(ValueError, match="UUID"):
        zc.ccm_aad(SVC[:2], CHR)
    with pytest.raises(ValueError, match="session key"):
        zc.encrypt_session_frame(SecretBytes(bytes(8)), ZVD, 1, SVC, CHR, b"x")
