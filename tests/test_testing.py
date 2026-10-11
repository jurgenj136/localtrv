"""FakeZdd responder tests (role correctness, rejection behaviour)."""

from __future__ import annotations

import pytest

from vicare_local_ble.testing import GATT_ERROR_REJECTED, FakeGattError, FakeZdd
from vicare_local_ble.zigbee_direct import crypto as zc
from vicare_local_ble.zigbee_direct.mmo import hmac_aes_mmo
from vicare_local_ble.zigbee_direct.session import HandshakeInitiator, SendSe3
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

ZVD = Eui64.from_wire(bytes(range(1, 9)))
ZDD = Eui64.from_wire(bytes(range(0x11, 0x19)))
KEY = SecretBytes(bytes(range(16)))
ZVD_PRIV = SecretBytes(bytes(range(32)))
ZDD_PRIV = SecretBytes(bytes(range(32, 64)))
SECRET_TYPE = zc.SecretType.BASIC_AUTHORIZATION_KEY


def se1() -> bytes:
    return HandshakeInitiator(
        own_eui=ZVD, psk=KEY, secret_type=SECRET_TYPE, private_key=ZVD_PRIV
    ).start()


def test_se2_carries_zdd_eui_and_point() -> None:
    zdd = FakeZdd(eui=ZDD, psk=KEY, private_key=ZDD_PRIV)
    se2 = zdd.handle_se1(se1())
    g = zc.speke_base_point(KEY)
    assert se2 == b"\x02\x02\x27" + ZDD.wire + zc.speke_public_point(ZDD_PRIV, g)
    assert zdd.secret_type is SECRET_TYPE
    assert zdd.eui == ZDD


def test_se4_tag_is_responder_first_kc_2_v() -> None:
    """A role mix-up (initiator-first order) in FakeZdd would fail this test."""
    zdd = FakeZdd(eui=ZDD, psk=KEY, private_key=ZDD_PRIV)
    init = HandshakeInitiator(own_eui=ZVD, psk=KEY, secret_type=SECRET_TYPE, private_key=ZVD_PRIV)
    step = init.feed(zdd.handle_se1(init.start()))
    assert isinstance(step, SendSe3)
    se4 = zdd.handle_se3(step.payload)
    g = zc.speke_base_point(KEY)
    zvd_q = zc.speke_public_point(ZVD_PRIV, g)
    zdd_q = zc.speke_public_point(ZDD_PRIV, g)
    xk = zc.speke_shared_point(ZDD_PRIV, zvd_q)
    key = zc.speke_derive_link_key(zc.speke_session_secret(xk, ZVD, zvd_q, ZDD, zdd_q, g))
    expected = hmac_aes_mmo(key.reveal(), b"KC_2_V" + ZDD.wire + zdd_q + ZVD.wire + zvd_q)
    assert se4 == b"\x04\x04\x0f" + expected
    assert zdd.cipher.own_eui == ZDD
    assert zdd.cipher.peer_eui == ZVD


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"\x03\x00\x01\x01\x03",  # wrong opcode
        b"\x01\x00\x01\x01\x03",  # missing point TLV
        b"\x01\x00\x01\x02\x03\x02\x27" + bytes(40),  # unsupported method
        b"\x01\x00\x01\x01\x7f\x02\x27" + bytes(40),  # unknown secret type
        b"\x01\x00\x01\x01\x03\x02\x27" + bytes(40),  # low-order (all-zero) point
    ],
)
def test_bad_se1_rejected(bad: bytes) -> None:
    zdd = FakeZdd(eui=ZDD, psk=KEY)
    with pytest.raises(FakeGattError) as exc:
        zdd.handle_se1(bad)
    assert exc.value.code == GATT_ERROR_REJECTED
    with pytest.raises(FakeGattError, match="FAILED"):
        zdd.handle_se1(se1())


@pytest.mark.parametrize(
    "bad_se3",
    [
        b"\x03",  # missing tag
        b"\x04\x04\x0f" + bytes(16),  # wrong opcode
        b"\x03\x04\x0f" + bytes(16),  # wrong tag
        b"\x03\x04\x0f" + bytes(3),  # truncated
    ],
)
def test_bad_se3_rejected(bad_se3: bytes) -> None:
    zdd = FakeZdd(eui=ZDD, psk=KEY)
    zdd.handle_se1(se1())
    with pytest.raises(FakeGattError) as exc:
        zdd.handle_se3(bad_se3)
    assert exc.value.code == 0x80
    with pytest.raises(RuntimeError, match="not established"):
        _ = zdd.cipher


def test_out_of_order_messages() -> None:
    zdd = FakeZdd(eui=ZDD, psk=KEY)
    with pytest.raises(FakeGattError, match="AWAIT_SE1"):
        zdd.handle_se3(b"\x03\x04\x0f" + bytes(16))


def test_gatt_error_custom_code_and_repr() -> None:
    err = FakeGattError("nope", code=0x0E)
    assert err.code == 0x0E
    assert "0x0e" in str(err)
    zdd = FakeZdd(eui=ZDD, psk=KEY, private_key=ZDD_PRIV)
    assert KEY.reveal().hex() not in repr(zdd)
    assert str(ZDD) in repr(zdd)
