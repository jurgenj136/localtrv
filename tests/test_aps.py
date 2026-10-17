"""Tests for the APS data frame codec (R23 2.2.5, docs/protocol.md §9)."""

from __future__ import annotations

import pytest

from localtrv.zigbee_direct.codec.aps import (
    HA_PROFILE_ID,
    ApsDataFrame,
    ApsDeliveryMode,
    ApsFrameControl,
    ApsFrameType,
)
from localtrv.zigbee_direct.errors import ApsDecodeError, EncodeError, UnsupportedFrameError

ZCL_READ = bytes.fromhex("0005000000080012 00".replace(" ", ""))


def test_unicast_zcl_layout_matches_captured_layout() -> None:
    frame = ApsDataFrame(
        cluster_id=0x0201,
        profile_id=HA_PROFILE_ID,
        payload=ZCL_READ,
        dst_endpoint=1,
        src_endpoint=1,
        counter=0x80,
    )
    wire = frame.encode()
    # FC ‖ dst_ep ‖ cluster LE ‖ profile LE ‖ src_ep ‖ counter ‖ ZCL
    assert wire == bytes.fromhex("00 01 0102 0401 01 80".replace(" ", "")) + ZCL_READ
    assert ApsDataFrame.decode(wire) == frame


def test_broadcast_zdo_device_annce_header() -> None:
    frame = ApsDataFrame(
        cluster_id=0x0013,
        profile_id=0,
        payload=b"\x01",
        delivery_mode=ApsDeliveryMode.BROADCAST,
        counter=7,
    )
    wire = frame.encode()
    assert wire == bytes.fromhex("08 00 1300 0000 00 07 01".replace(" ", ""))
    assert ApsDataFrame.decode(wire) == frame


def test_group_delivery_has_group_address_not_endpoint() -> None:
    frame = ApsDataFrame(
        cluster_id=0x0006,
        profile_id=HA_PROFILE_ID,
        payload=b"\x01\x02\x01",
        delivery_mode=ApsDeliveryMode.GROUP,
        dst_endpoint=None,
        group_address=0x1234,
        src_endpoint=1,
        counter=3,
        ack_request=False,
    )
    wire = frame.encode()
    assert wire[:3] == bytes([0x0C, 0x34, 0x12])
    decoded = ApsDataFrame.decode(wire)
    assert decoded == frame
    assert decoded.dst_endpoint is None


def test_ack_request_bit_roundtrip() -> None:
    frame = ApsDataFrame(cluster_id=0x0201, profile_id=HA_PROFILE_ID, payload=b"", ack_request=True)
    wire = frame.encode()
    assert wire[0] == 0x40
    assert ApsDataFrame.decode(wire).ack_request is True


def test_frame_control_fields() -> None:
    fc = ApsFrameControl.from_byte(0xFE)
    assert fc.frame_type is ApsFrameType.ACK
    assert fc.delivery_mode == 3
    assert fc.ack_format
    assert fc.security
    assert fc.ack_request
    assert fc.extended_header


@pytest.mark.parametrize("fc", [0x01, 0x02, 0x03])
def test_non_data_frames_unsupported(fc: int) -> None:
    with pytest.raises(UnsupportedFrameError):
        ApsDataFrame.decode(bytes([fc]) + bytes(10))


def test_reserved_delivery_mode_rejected() -> None:
    with pytest.raises(ApsDecodeError, match="reserved"):
        ApsDataFrame.decode(bytes([0x04]) + bytes(10))


def test_secured_frame_never_plaintext() -> None:
    with pytest.raises(UnsupportedFrameError, match="secured"):
        ApsDataFrame.decode(bytes([0x20]) + bytes(20))


def test_extended_header_unsupported() -> None:
    with pytest.raises(UnsupportedFrameError, match="extended"):
        ApsDataFrame.decode(bytes([0x80]) + bytes(20))


@pytest.mark.parametrize("length", [0, 1, 2, 4, 6, 7])
def test_truncated_header(length: int) -> None:
    wire = bytes.fromhex("0001010204010180")
    with pytest.raises(ApsDecodeError, match="truncated"):
        ApsDataFrame.decode(wire[:length])


def test_header_only_frame_has_empty_payload() -> None:
    decoded = ApsDataFrame.decode(bytes.fromhex("0001010204010180"))
    assert decoded.payload == b""


@pytest.mark.parametrize(
    "kwargs",
    [
        {"delivery_mode": ApsDeliveryMode.GROUP},
        {"delivery_mode": ApsDeliveryMode.GROUP, "dst_endpoint": None},
        {"group_address": 0x10},
        {"dst_endpoint": None},
        {"dst_endpoint": 256},
        {"counter": -1},
        {"cluster_id": 0x10000},
        {"delivery_mode": 1},
    ],
)
def test_invalid_construction(kwargs: dict[str, object]) -> None:
    base: dict[str, object] = {"cluster_id": 0, "profile_id": 0, "payload": b""}
    base.update(kwargs)
    with pytest.raises(EncodeError):
        ApsDataFrame(**base)  # type: ignore[arg-type]


def test_payload_must_be_bytes() -> None:
    with pytest.raises(EncodeError):
        ApsDataFrame(cluster_id=0, profile_id=0, payload=bytearray(b"x"))  # type: ignore[arg-type]
