"""Sans-IO handshake initiator and session cipher tests.

Known answers use the R23 Annex C.7.1 vector #1 (public spec values) and are
recomputed from primitives inside the tests, independent of the library's
message builders and ``confirmation_tag``.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from vicare_local_ble.testing import FakeGattError, FakeZdd
from vicare_local_ble.zigbee_direct import crypto as zc
from vicare_local_ble.zigbee_direct.errors import (
    AuthenticationError,
    CounterExhaustedError,
    DecodeError,
    HandshakeError,
    ReplayError,
)
from vicare_local_ble.zigbee_direct.mmo import hmac_aes_mmo
from vicare_local_ble.zigbee_direct.session import (
    Established,
    HandshakeInitiator,
    HandshakeState,
    SendSe3,
    SessionCipher,
    encode_handshake_tlv,
)
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes
from vicare_local_ble.zigbee_direct.uuids import (
    COMMISSIONING_SERVICE,
    COMMISSIONING_STATUS,
    TUNNEL_NPDU,
    TUNNEL_SERVICE,
    uuid_bytes,
)


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


# R23 Annex C.7.1 vector #1 (Alice = initiator/ZVD, Bob = responder/ZDD).
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
LINK_KEY_1 = unhex("25 47 F3 AF 96 39 1E 1E BF F2 A3 B7 6D 6A 29 29")  # secret-scan: allow

PSK = zc.WELL_KNOWN_PSK
SECRET_TYPE = zc.SecretType.ANONYMOUS_WELL_KNOWN

# Dummy identities (not real devices).
ZVD = Eui64.from_wire(bytes(range(1, 9)))
ZDD = Eui64.from_wire(bytes(range(0x11, 0x19)))
KEY = SecretBytes(bytes(range(16)))


def alice() -> HandshakeInitiator:
    return HandshakeInitiator(
        own_eui=ALICE_EUI, psk=PSK, secret_type=SECRET_TYPE, private_key=ALICE_PRIV
    )


def bob() -> FakeZdd:
    return FakeZdd(eui=BOB_EUI, psk=PSK, private_key=BOB_PRIV)


def se2_bytes(*tlvs: tuple[int, bytes], opcode: int = 0x02) -> bytes:
    return bytes([opcode]) + b"".join(bytes([t, len(v) - 1]) + v for t, v in tlvs)


GOOD_POINT = (0x02, BOB_EUI.wire + BOB_Q)


def expected_tag(label: bytes) -> bytes:
    """Responder-first confirmation tag built from primitives (docs/protocol.md §3)."""
    return hmac_aes_mmo(LINK_KEY_1, label + BOB_EUI.wire + BOB_Q + ALICE_EUI.wire + ALICE_Q)


# --- known answers ----------------------------------------------------------------------------


def test_se1_known_answer() -> None:
    se1 = alice().start()
    assert se1 == unhex("01 00 01 01 05 02 27") + ALICE_EUI.wire + ALICE_Q


def test_se3_known_answer_and_full_c71_handshake() -> None:
    init = alice()
    zdd = bob()
    se2 = zdd.handle_se1(init.start())
    assert se2 == unhex("02 02 27") + BOB_EUI.wire + BOB_Q
    step = init.feed(se2)
    assert isinstance(step, SendSe3)
    assert step.payload == unhex("03 04 0F") + expected_tag(b"KC_2_U")
    se4 = zdd.handle_se3(step.payload)
    assert se4 == unhex("04 04 0F") + expected_tag(b"KC_2_V")
    done = init.feed(se4)
    assert isinstance(done, Established)
    assert done.peer_eui == BOB_EUI
    assert init.state is HandshakeState.DONE
    # The negotiated key is the spec link key: encrypt with it directly via AESCCM.
    frame = done.cipher.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"hi")
    nonce = ALICE_EUI.wire + (1).to_bytes(4, "little") + b"\x05"
    aad = uuid_bytes(TUNNEL_SERVICE) + b"\x00" + uuid_bytes(TUNNEL_NPDU) + b"\x00"
    assert frame == b"\x01\x00\x00\x00" + AESCCM(LINK_KEY_1, tag_length=4).encrypt(
        nonce, b"hi", aad
    )


# --- end-to-end with random keys -------------------------------------------------------------


def handshake(
    zvd_psk: SecretBytes = KEY, zdd_psk: SecretBytes = KEY
) -> tuple[SessionCipher, SessionCipher]:
    init = HandshakeInitiator(
        own_eui=ZVD, psk=zvd_psk, secret_type=zc.SecretType.BASIC_AUTHORIZATION_KEY
    )
    zdd = FakeZdd(eui=ZDD, psk=zdd_psk)
    step = init.feed(zdd.handle_se1(init.start()))
    assert isinstance(step, SendSe3)
    done = init.feed(zdd.handle_se3(step.payload))
    assert isinstance(done, Established)
    assert zdd.secret_type is zc.SecretType.BASIC_AUTHORIZATION_KEY
    return done.cipher, zdd.cipher


def test_bidirectional_frames_share_one_counter_pair() -> None:
    zvd, zdd = handshake()
    assert zvd.own_eui == ZVD
    assert zvd.peer_eui == ZDD
    assert zdd.own_eui == ZDD
    assert zdd.peer_eui == ZVD
    f1 = zvd.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"npdu-1")
    f2 = zvd.encrypt(COMMISSIONING_SERVICE, COMMISSIONING_STATUS, b"status")
    assert zdd.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, f1) == b"npdu-1"
    assert zdd.decrypt(COMMISSIONING_SERVICE, COMMISSIONING_STATUS, f2) == b"status"
    assert (zvd.outgoing_counter, zdd.incoming_counter) == (3, 2)
    back = zdd.encrypt(uuid_bytes(TUNNEL_SERVICE), uuid_bytes(TUNNEL_NPDU), b"reply")
    assert zvd.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, back) == b"reply"
    assert zvd.incoming_counter == 1


def test_fresh_ephemeral_key_per_handshake() -> None:
    a = HandshakeInitiator(own_eui=ZVD, psk=KEY, secret_type=SECRET_TYPE)
    b = HandshakeInitiator(own_eui=ZVD, psk=KEY, secret_type=SECRET_TYPE)
    assert a.start()[7 + 8 :] != b.start()[7 + 8 :]


def test_wrong_psk_rejected_by_zdd_with_gatt_0x80() -> None:
    init = HandshakeInitiator(own_eui=ZVD, psk=KEY, secret_type=SECRET_TYPE)
    zdd = FakeZdd(eui=ZDD, psk=SecretBytes(bytes(16)))
    step = init.feed(zdd.handle_se1(init.start()))
    assert isinstance(step, SendSe3)
    with pytest.raises(FakeGattError) as exc:
        zdd.handle_se3(step.payload)
    assert exc.value.code == 0x80
    with pytest.raises(RuntimeError):
        _ = zdd.cipher


def test_tampered_se4_fails_and_is_terminal() -> None:
    init, zdd = alice(), bob()
    step = init.feed(zdd.handle_se1(init.start()))
    assert isinstance(step, SendSe3)
    se4 = bytearray(zdd.handle_se3(step.payload))
    se4[-1] ^= 0x01
    with pytest.raises(HandshakeError, match="tag mismatch"):
        init.feed(bytes(se4))
    assert init.state is HandshakeState.FAILED
    with pytest.raises(HandshakeError):
        init.feed(bytes(se4))


@pytest.mark.parametrize(
    "se4",
    [
        unhex("03 04 0F") + bytes(16),  # wrong opcode
        unhex("04"),  # missing tag TLV
        unhex("04 04 0E") + bytes(15),  # wrong length
        unhex("04 04 0F") + bytes(10),  # truncated
    ],
)
def test_malformed_se4(se4: bytes) -> None:
    init, zdd = alice(), bob()
    init.feed(zdd.handle_se1(init.start()))
    with pytest.raises(HandshakeError):
        init.feed(se4)
    assert init.state is HandshakeState.FAILED


# --- SE2 validation ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("se2", "match"),
    [
        (b"", "empty"),
        (se2_bytes(GOOD_POINT, opcode=0x04), "opcode"),
        (se2_bytes(), "lacks"),
        (se2_bytes((0x07, b"\x01")), "lacks"),
        (se2_bytes((0x02, BOB_EUI.wire + BOB_Q[:-1])), "length"),
        (se2_bytes(GOOD_POINT, GOOD_POINT), "duplicate"),
        (se2_bytes(GOOD_POINT)[:-1], "truncated"),
        (se2_bytes(GOOD_POINT) + b"\x07", "truncated"),
        (se2_bytes(GOOD_POINT, (0x00, b"\x01\x03")), "method"),
        (se2_bytes((0x02, ALICE_EUI.wire + BOB_Q)), "reflection"),
        (se2_bytes((0x02, BOB_EUI.wire + ALICE_Q)), "reflection"),
        (se2_bytes((0x02, BOB_EUI.wire + bytes(32))), "low-order"),
    ],
)
def test_malformed_se2(se2: bytes, match: str) -> None:
    init = alice()
    init.start()
    with pytest.raises(HandshakeError, match=match):
        init.feed(se2)
    assert init.state is HandshakeState.FAILED


def test_se2_accepts_method_echo_and_ignores_unknown_tlvs() -> None:
    init = alice()
    init.start()
    se2 = se2_bytes((0x09, b"\xaa\xbb"), (0x00, b"\x01\x05"), GOOD_POINT)
    step = init.feed(se2)
    assert isinstance(step, SendSe3)
    assert step.payload == unhex("03 04 0F") + expected_tag(b"KC_2_U")


# --- state misuse ------------------------------------------------------------------------------


def test_feed_before_start() -> None:
    with pytest.raises(HandshakeError, match="IDLE"):
        alice().feed(se2_bytes(GOOD_POINT))


def test_start_twice() -> None:
    init = alice()
    init.start()
    with pytest.raises(HandshakeError, match="AWAIT_SE2"):
        init.start()


def test_feed_after_done() -> None:
    init, zdd = alice(), bob()
    step = init.feed(zdd.handle_se1(init.start()))
    assert isinstance(step, SendSe3)
    init.feed(zdd.handle_se3(step.payload))
    with pytest.raises(HandshakeError, match="DONE"):
        init.feed(b"\x04")


def test_se4_fed_while_awaiting_se2() -> None:
    init = alice()
    init.start()
    with pytest.raises(HandshakeError, match="opcode"):
        init.feed(unhex("04 04 0F") + bytes(16))


def test_constructor_validation_and_repr() -> None:
    with pytest.raises(ValueError, match="psk"):
        HandshakeInitiator(own_eui=ZVD, psk=SecretBytes(b"short"), secret_type=SECRET_TYPE)
    with pytest.raises(ValueError, match="private key"):
        HandshakeInitiator(
            own_eui=ZVD, psk=KEY, secret_type=SECRET_TYPE, private_key=SecretBytes(b"x")
        )
    init = HandshakeInitiator(own_eui=ZVD, psk=KEY, secret_type=SECRET_TYPE, private_key=ALICE_PRIV)
    assert "Alice" not in repr(init)
    assert KEY.reveal().hex() not in repr(init)


def test_handshake_tlv_bounds() -> None:
    with pytest.raises(ValueError, match=r"1\.\.256"):
        encode_handshake_tlv(0x04, b"")
    with pytest.raises(ValueError, match="tag"):
        encode_handshake_tlv(0x100, b"\x00")
    assert encode_handshake_tlv(0x04, bytes(256))[:2] == b"\x04\xff"


# --- session cipher ---------------------------------------------------------------------------


def pair(counter: int = 1) -> tuple[SessionCipher, SessionCipher]:
    a = SessionCipher(session_key=KEY, own_eui=ZVD, peer_eui=ZDD, _initial_outgoing_counter=counter)
    b = SessionCipher(session_key=KEY, own_eui=ZDD, peer_eui=ZVD)
    return a, b


def test_replay_rejected() -> None:
    a, b = pair()
    f = a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"x")
    b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, f)
    with pytest.raises(ReplayError):
        b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, f)


def test_out_of_order_rejected() -> None:
    a, b = pair()
    f1 = a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"1")
    f2 = a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"2")
    assert b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, f2) == b"2"
    with pytest.raises(ReplayError):
        b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, f1)


def test_replay_checked_before_mic() -> None:
    a, b = pair()
    b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"1"))
    forged = (1).to_bytes(4, "little") + bytes(8)  # garbage MIC, stale counter
    with pytest.raises(ReplayError):
        b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, forged)


def test_mic_failure_does_not_advance_counter() -> None:
    a, b = pair()
    good = a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"payload")
    bad = good[:-1] + bytes([good[-1] ^ 0xFF])
    with pytest.raises(AuthenticationError):
        b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, bad)
    assert b.incoming_counter == 0
    assert b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, good) == b"payload"
    assert b.incoming_counter == 1


def test_wrong_characteristic_uuid_fails_mic() -> None:
    a, b = pair()
    f = a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"x")
    with pytest.raises(AuthenticationError):
        b.decrypt(COMMISSIONING_SERVICE, COMMISSIONING_STATUS, f)
    assert b.incoming_counter == 0


def test_wrong_peer_eui_fails_mic() -> None:
    a, _ = pair()
    other = SessionCipher(session_key=KEY, own_eui=ZDD, peer_eui=ZDD)
    with pytest.raises(AuthenticationError):
        other.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"x"))


def test_short_frame_is_decode_error() -> None:
    _, b = pair()
    with pytest.raises(DecodeError):
        b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, bytes(7))


def test_counter_exhaustion() -> None:
    a, b = pair(counter=zc.MAX_COUNTER)
    last = a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"last")
    assert last[:4] == b"\xff\xff\xff\xff"
    assert b.decrypt(TUNNEL_SERVICE, TUNNEL_NPDU, last) == b"last"
    with pytest.raises(CounterExhaustedError):
        a.encrypt(TUNNEL_SERVICE, TUNNEL_NPDU, b"overflow")
    assert a.outgoing_counter == zc.MAX_COUNTER + 1


def test_cipher_validation_and_repr() -> None:
    with pytest.raises(ValueError, match="session key"):
        SessionCipher(session_key=SecretBytes(b"k"), own_eui=ZVD, peer_eui=ZDD)
    with pytest.raises(ValueError, match="counter"):
        SessionCipher(session_key=KEY, own_eui=ZVD, peer_eui=ZDD, _initial_outgoing_counter=0)
    a, _ = pair()
    with pytest.raises(ValueError, match="UUID"):
        a.encrypt(b"short", TUNNEL_NPDU, b"x")
    assert a.outgoing_counter == 1  # failed encrypt does not burn a counter before validation
    text = repr(a)
    assert KEY.reveal().hex() not in text
    assert str(ZVD) in text


def test_counters_are_read_only() -> None:
    a, _ = pair()
    with pytest.raises(AttributeError):
        a.outgoing_counter = 5  # type: ignore[misc]
    with pytest.raises(AttributeError):
        a.incoming_counter = 5  # type: ignore[misc]


def test_unexpected_error_wrapped_and_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    from vicare_local_ble.zigbee_direct import session as session_mod

    def boom(*_args: object) -> SecretBytes:
        raise ValueError("boom")

    monkeypatch.setattr(session_mod, "speke_shared_point", boom)
    init = alice()
    init.start()
    with pytest.raises(HandshakeError, match="ValueError") as exc:
        init.feed(se2_bytes(GOOD_POINT))
    assert isinstance(exc.value.__cause__, ValueError)
    assert init.state is HandshakeState.FAILED
