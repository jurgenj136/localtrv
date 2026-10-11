"""Tests for generic Zigbee TLVs and the tunnel NPDU TLV."""

from __future__ import annotations

import pytest

from vicare_local_ble.zigbee_direct.codec.tlv import (
    MAX_NPDU_LEN,
    Tlv,
    TunnelNpdu,
    decode_tlvs,
    encode_tlvs,
    parse_tunnel_tlvs,
)
from vicare_local_ble.zigbee_direct.errors import EncodeError, TlvDecodeError


def test_tlv_length_is_value_len_minus_one() -> None:
    assert Tlv(0x41, b"\xaa\xbb").encode() == bytes.fromhex("4101aabb")
    assert Tlv(0x07, b"\x01").encode() == bytes.fromhex("070001")


def test_tlv_max_value_256_bytes() -> None:
    tlv = Tlv(0x10, bytes(256))
    encoded = tlv.encode()
    assert encoded[:2] == b"\x10\xff"
    assert Tlv.decode(encoded) == tlv


@pytest.mark.parametrize("value", [b"", bytes(257)])
def test_tlv_rejects_bad_value_length(value: bytes) -> None:
    with pytest.raises(EncodeError):
        Tlv(0x01, value)


def test_tlv_rejects_bad_tag() -> None:
    with pytest.raises(EncodeError):
        Tlv(0x100, b"\x00")


def test_tlv_list_round_trip() -> None:
    tlvs = (Tlv(0x01, b"\x34\x12"), Tlv(0x06, b"\x5a\x5a"), Tlv(0xFE, b"\x00"))
    data = encode_tlvs(tlvs)
    assert data == bytes.fromhex("0101341206015a5afe0000")
    assert decode_tlvs(data) == tlvs
    assert decode_tlvs(b"") == ()


@pytest.mark.parametrize("data", ["01", "0101aa", "0100aa02"])
def test_decode_tlvs_truncated(data: str) -> None:
    with pytest.raises(TlvDecodeError):
        decode_tlvs(bytes.fromhex(data))


def test_single_tlv_decode_rejects_trailing() -> None:
    with pytest.raises(TlvDecodeError, match="trailing"):
        Tlv.decode(bytes.fromhex("0100aaff"))


def test_tunnel_npdu_encode_byte_exact() -> None:
    npdu = bytes.fromhex("0918")
    assert TunnelNpdu(npdu, nwk_security=False).encode() == bytes.fromhex("000300020918")
    assert TunnelNpdu(npdu, nwk_security=True).encode() == bytes.fromhex("000301020918")


def test_tunnel_npdu_round_trip_max_len() -> None:
    npdu = bytes(range(MAX_NPDU_LEN))
    frame = TunnelNpdu(npdu, nwk_security=True)
    encoded = frame.encode()
    assert encoded[:4] == bytes((0x00, 0xFF, 0x01, 254))
    assert TunnelNpdu.decode(encoded) == frame


def test_tunnel_npdu_too_long() -> None:
    with pytest.raises(EncodeError):
        TunnelNpdu(bytes(MAX_NPDU_LEN + 1), nwk_security=False)


def test_tunnel_npdu_ignores_reserved_flag_bits() -> None:
    assert TunnelNpdu.decode(bytes.fromhex("0002fe01aa")) == TunnelNpdu(b"\xaa", False)


@pytest.mark.parametrize(
    "data",
    [
        "000302030918",  # npdu_len 3 but only 2 bytes
        "0003000109aa",  # npdu_len 1 but 2 bytes follow
        "000000",  # value shorter than flags + npdu_len
    ],
)
def test_tunnel_npdu_length_mismatch(data: str) -> None:
    with pytest.raises(TlvDecodeError):
        TunnelNpdu.decode(bytes.fromhex(data))


def test_tunnel_npdu_from_wrong_tag() -> None:
    with pytest.raises(TlvDecodeError, match="not a tunnel"):
        TunnelNpdu.from_tlv(Tlv(0x05, b"\x00\x00"))


def test_parse_tunnel_tlvs_keeps_unknown_tags() -> None:
    first = TunnelNpdu(bytes.fromhex("4802"), nwk_security=True)
    second = TunnelNpdu(bytes.fromhex("0918"), nwk_security=False)
    unknown = Tlv(0x7F, b"\x01\x02")
    data = first.encode() + unknown.encode() + second.encode()
    assert parse_tunnel_tlvs(data) == (first, unknown, second)


def test_parse_tunnel_tlvs_truncated() -> None:
    data = TunnelNpdu(b"\x01\x02", nwk_security=False).encode()
    with pytest.raises(TlvDecodeError):
        parse_tunnel_tlvs(data[:-1])
    with pytest.raises(TlvDecodeError):
        parse_tunnel_tlvs(data + b"\x00")
