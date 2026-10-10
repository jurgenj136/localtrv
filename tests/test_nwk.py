"""Tests for the NWK frame codec (R23 3.3.1)."""

from __future__ import annotations

import pytest

from vicare_direct.zigbee_direct.codec.nwk import (
    DISCOVER_ROUTE_ENABLE,
    NwkFrame,
    NwkFrameControl,
    NwkFrameType,
    SourceRoute,
)
from vicare_direct.zigbee_direct.errors import EncodeError, NwkDecodeError
from vicare_direct.zigbee_direct.types import Eui64

EUI_A = Eui64.from_str("02:00:00:00:00:00:00:01")
EUI_B = Eui64.from_str("02:00:00:00:00:00:00:02")


def test_unicast_data_frame_byte_exact() -> None:
    frame = NwkFrame(
        frame_type=NwkFrameType.DATA,
        dst=0x5A5A,
        src=0x1234,
        radius=30,
        seq=0x07,
        payload=b"\xaa\xbb",
        discover_route=DISCOVER_ROUTE_ENABLE,
        security=True,
    )
    encoded = frame.encode()
    assert encoded == bytes.fromhex("48025a5a34121e07aabb")
    assert NwkFrame.decode(encoded) == frame


def test_command_frame_with_both_ieee_byte_exact() -> None:
    frame = NwkFrame(
        frame_type=NwkFrameType.COMMAND,
        dst=0x5A5A,
        src=0x1234,
        radius=1,
        seq=0x01,
        payload=b"\x0e",
        dst_ieee=EUI_B,
        src_ieee=EUI_A,
    )
    encoded = frame.encode()
    assert encoded[:2] == bytes.fromhex("0918")
    assert encoded[8:16] == bytes.fromhex("0200000000000002")[::-1]
    assert encoded[16:24] == bytes.fromhex("0200000000000001")[::-1]
    assert encoded[24:] == b"\x0e"
    decoded = NwkFrame.decode(encoded)
    assert decoded == frame
    assert decoded.dst_ieee == EUI_B
    assert decoded.src_ieee == EUI_A


def test_source_route_subframe_shifts_payload_by_four() -> None:
    """A 1-relay source route adds 4 header bytes (count, index, relay short).

    Documents the HYPOTHESIS behind the research offset scan: inbound frames
    whose payload seemed to start "4 bytes late" may carry this subframe.
    """
    plain = NwkFrame(NwkFrameType.DATA, dst=0x1234, src=0x5A5A, radius=29, seq=9, payload=b"\x40")
    routed = NwkFrame(
        NwkFrameType.DATA,
        dst=0x1234,
        src=0x5A5A,
        radius=29,
        seq=9,
        payload=b"\x40",
        source_route=SourceRoute(relay_index=0, relays=(0x4B4B,)),
    )
    encoded = routed.encode()
    assert encoded[:2] == bytes.fromhex("0804")
    assert encoded[8:12] == bytes.fromhex("01004b4b")
    assert len(encoded) - len(plain.encode()) == 4
    assert encoded.index(b"\x40") == 12
    decoded = NwkFrame.decode(encoded)
    assert decoded.source_route == SourceRoute(0, (0x4B4B,))
    assert decoded.payload == b"\x40"


def test_all_optional_fields_order() -> None:
    frame = NwkFrame(
        NwkFrameType.DATA,
        dst=0xFFFD,
        src=0x1234,
        radius=5,
        seq=0xFF,
        payload=b"\x01\x02",
        dst_ieee=EUI_B,
        src_ieee=EUI_A,
        multicast_control=0x2A,
        source_route=SourceRoute(1, (0x1111, 0x2222)),
        end_device_initiator=True,
    )
    encoded = frame.encode()
    assert encoded[1] == 0x01 | 0x04 | 0x08 | 0x10 | 0x20
    assert encoded[24] == 0x2A
    assert encoded[25:31] == bytes.fromhex("020111112222")
    assert encoded[31:] == b"\x01\x02"
    assert NwkFrame.decode(encoded) == frame


def test_frame_control_round_trip() -> None:
    fc = NwkFrameControl(NwkFrameType.INTER_PAN, discover_route=3, security=True)
    assert fc.encode() == bytes.fromhex("cb02")
    assert NwkFrameControl.decode(fc.encode()) == fc


def test_frame_control_reserved_type() -> None:
    with pytest.raises(NwkDecodeError, match="reserved"):
        NwkFrameControl.decode(b"\x0a\x00")


def test_frame_control_wrong_length() -> None:
    with pytest.raises(NwkDecodeError):
        NwkFrameControl.decode(b"\x08")


def test_security_bit_does_not_imply_aux_header() -> None:
    data = bytes.fromhex("0802341200001e0100112233")
    frame = NwkFrame.decode(data)
    assert frame.security is True
    assert frame.payload == bytes.fromhex("00112233")


@pytest.mark.parametrize(
    "data",
    [
        "4802341200001e",  # shorter than the fixed header
        "0808341200001e010100000000",  # dst IEEE truncated
        "0801341200001e01",  # multicast control missing
        "0804341200001e0101",  # source route header truncated
        "0804341200001e010200aaaabb",  # relay list truncated
    ],
)
def test_truncated_frames(data: str) -> None:
    with pytest.raises(NwkDecodeError):
        NwkFrame.decode(bytes.fromhex(data))


def test_empty_payload_allowed() -> None:
    data = bytes.fromhex("4800341200001e01")
    assert NwkFrame.decode(data).payload == b""


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dst": 0x10000},
        {"src": -1},
        {"radius": 256},
        {"seq": 256},
        {"discover_route": 4},
        {"protocol_version": 16},
        {"multicast_control": 0x100},
    ],
)
def test_encode_validation(kwargs: dict[str, int]) -> None:
    base: dict[str, int] = {"dst": 0, "src": 0, "radius": 1, "seq": 0}
    base.update(kwargs)
    with pytest.raises(EncodeError):
        NwkFrame(frame_type=NwkFrameType.DATA, payload=b"", **base)  # type: ignore[arg-type]


def test_source_route_validation() -> None:
    with pytest.raises(EncodeError):
        SourceRoute(0, (0x10000,))
    with pytest.raises(EncodeError):
        SourceRoute(256, ())
