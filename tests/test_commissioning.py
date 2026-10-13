"""Tests for the Commissioning Status characteristic decoder."""

from __future__ import annotations

import pytest

from vicare_local_ble.zigbee_direct.codec.commissioning import (
    ChannelMask,
    CommissioningStatus,
    DeviceType,
    JoinedStatus,
    JoiningMethod,
)
from vicare_local_ble.zigbee_direct.codec.tlv import Tlv
from vicare_local_ble.zigbee_direct.errors import CommissioningDecodeError
from vicare_local_ble.zigbee_direct.types import Eui64

EXT_PAN = Eui64.from_str("DD:DD:DD:DD:DD:DD:DD:01")
ZDD_EUI = Eui64.from_str("02:00:00:00:00:00:00:02")
TC_EUI = Eui64.from_str("02:00:00:00:00:00:00:00")
DUMMY_KEY = bytes(range(16))


def _tlv(tag: int, value: bytes) -> bytes:
    return Tlv(tag, value).encode()


def _sample() -> bytes:
    channel_word = (0 << 27) | (1 << 15)
    return b"".join(
        (
            _tlv(0x00, EXT_PAN.wire),
            _tlv(0x01, b"\xcd\xab"),
            _tlv(0x02, b"\x01" + channel_word.to_bytes(4, "little")),
            _tlv(0x05, b"\x01"),
            _tlv(0x06, b"\x5a\x5a"),
            _tlv(0x07, b"\x01"),
            _tlv(0x08, ZDD_EUI.wire),
            _tlv(0x09, TC_EUI.wire),
            _tlv(0x0A, bytes((0x02 | 0x10,))),
            _tlv(0x0B, b"\x03"),
            _tlv(0x0C, b"\x00"),
            _tlv(0x0E, b"\x00\x00"),
            _tlv(0x7E, b"\xaa\xbb"),
        )
    )


def test_decode_typical_status() -> None:
    status = CommissioningStatus.decode(_sample())
    assert status.extended_pan_id == EXT_PAN
    assert status.pan_id == 0xABCD
    assert status.device_type == DeviceType.ROUTER
    assert status.nwk_address == 0x5A5A
    assert status.joining_method == JoiningMethod.NWK_REJOIN
    assert status.ieee_address == ZDD_EUI
    assert status.trust_center_address == TC_EUI
    assert status.joined_status == JoinedStatus.JOINED
    assert status.permit_join_open is False
    assert status.centralized is True
    assert status.nwk_update_id == 3
    assert status.active_key_seq == 0
    assert status.status_code == (0, 0)
    assert status.channel_masks == (ChannelMask(page=0, mask=1 << 15),)
    assert status.channel_masks[0].channels == (15,)
    assert status.unknown == (Tlv(0x7E, b"\xaa\xbb"),)
    assert status.network_key is None
    assert status.link_key is None


def test_empty_status() -> None:
    status = CommissioningStatus.decode(b"")
    assert status == CommissioningStatus()
    assert status.joined_status is None
    assert status.permit_join_open is None
    assert status.centralized is None
    assert status.channel_masks is None


def test_keys_are_redacted() -> None:
    data = (
        _tlv(0x03, DUMMY_KEY)
        + _tlv(0x04, b"\x01" + DUMMY_KEY)
        + _tlv(0x0D, DUMMY_KEY)
        + _tlv(0x0A, b"\x0a")
    )
    status = CommissioningStatus.decode(data)
    assert status.network_key is not None
    assert status.network_key.reveal() == DUMMY_KEY
    assert status.link_key is not None
    assert status.link_key.reveal() == DUMMY_KEY
    assert status.link_key_flags == 0x01
    assert status.admin_key is not None
    assert status.permit_join_open is True
    assert status.joined_status == JoinedStatus.JOINED
    assert DUMMY_KEY.hex() not in repr(status)
    assert "<redacted>" in repr(status)


def test_channel_tlv_malformed_raises_lazily() -> None:
    status = CommissioningStatus.decode(_tlv(0x02, b"\x02\x00\x80\x00\x00"))
    assert status.network_channel_raw == b"\x02\x00\x80\x00\x00"
    with pytest.raises(CommissioningDecodeError, match="channel"):
        _ = status.channel_masks


def test_channel_page_bits() -> None:
    word = (2 << 27) | 0x3
    status = CommissioningStatus.decode(_tlv(0x02, b"\x01" + word.to_bytes(4, "little")))
    assert status.channel_masks == (ChannelMask(page=2, mask=0x3),)


@pytest.mark.parametrize(
    ("data", "match"),
    [
        (_tlv(0x06, b"\x5a"), "NWK_ADDRESS"),
        (_tlv(0x08, b"\x01" * 7), "IEEE_ADDRESS"),
        (_tlv(0x01, b"\x01\x02") + _tlv(0x01, b"\x01\x02"), "duplicate PAN_ID"),
        (b"\x06\x01\x5a", "truncated NWK_ADDRESS"),
    ],
)
def test_malformed(data: bytes, match: str) -> None:
    with pytest.raises(CommissioningDecodeError, match=match):
        CommissioningStatus.decode(data)
