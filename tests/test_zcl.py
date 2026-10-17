"""Tests for the ZCL codec and data type table (docs/protocol.md §9)."""

from __future__ import annotations

import math

import pytest

from vicare_local_ble.zigbee_direct.codec._cursor import Cursor
from vicare_local_ble.zigbee_direct.codec.zcl import (
    AttributeRecord,
    DefaultResponse,
    ReadAttributes,
    ReadAttributesResponse,
    ReadAttributeStatus,
    ReportAttributes,
    WriteAttributes,
    WriteAttributesResponse,
    WriteAttributeStatus,
    ZclCommandId,
    ZclDirection,
    ZclFrame,
    ZclFrameType,
    ZclHeader,
    ZclStatus,
    decode_global_command,
)
from vicare_local_ble.zigbee_direct.codec.zcl_types import (
    ZclDataType,
    ZclValue,
    decode_value,
    encode_value,
    read_value,
)
from vicare_local_ble.zigbee_direct.errors import EncodeError, UnsupportedFrameError, ZclDecodeError
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

T = ZclDataType


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


# --------------------------------------------------------------------------- section 7 vectors


def test_read_attributes_matches_captured_layout() -> None:
    frame = ZclFrame.build(0x80, ReadAttributes((0x0000, 0x0008, 0x0012)))
    assert frame.encode() == h("00 80 00 0000 0800 1200")
    decoded = ZclFrame.decode(frame.encode())
    assert decoded == frame
    assert decoded.global_command() == ReadAttributes((0x0000, 0x0008, 0x0012))


def test_write_setpoint_matches_captured_layout() -> None:
    record = AttributeRecord(0x0012, T.INT16, 2150)  # 21.50 degC
    frame = ZclFrame.build(0x81, WriteAttributes((record,)))
    assert frame.encode() == h("00 81 02 1200 29 6608")
    assert ZclFrame.decode(frame.encode()).global_command() == WriteAttributes((record,))


def test_read_attributes_response_decode() -> None:
    wire = h("18 80 01 0000 00 29 3408 0800 00 20 2A 1200 86")
    frame = ZclFrame.decode(wire)
    assert frame.header.direction is ZclDirection.SERVER_TO_CLIENT
    assert frame.header.disable_default_response is True
    rsp = frame.global_command()
    assert rsp == ReadAttributesResponse(
        (
            ReadAttributeStatus(0x0000, 0, T.INT16, 2100),
            ReadAttributeStatus(0x0008, 0, T.UINT8, 42),
            ReadAttributeStatus(0x0012, ZclStatus.UNSUPPORTED_ATTRIBUTE),
        )
    )
    assert isinstance(rsp, ReadAttributesResponse)
    assert rsp.encode() == wire[3:]


def test_negative_int16_temperature() -> None:
    rsp = ReadAttributesResponse.decode(h("0000 00 29 0CFE"))
    assert rsp.records[0].value == -500


# --------------------------------------------------------------------------- header


def test_header_manufacturer_specific_roundtrip() -> None:
    header = ZclHeader(
        tsn=5,
        command_id=0x42,
        frame_type=ZclFrameType.CLUSTER_SPECIFIC,
        manufacturer_code=0x10F2,
        direction=ZclDirection.SERVER_TO_CLIENT,
        disable_default_response=True,
    )
    wire = header.encode()
    assert wire == h("1D F210 05 42")
    frame = ZclFrame.decode(wire + b"\xaa")
    assert frame.header == header
    assert frame.payload == b"\xaa"
    with pytest.raises(UnsupportedFrameError, match="cluster-specific"):
        frame.global_command()


def test_manufacturer_specific_global_command_decodes() -> None:
    """MS bit on a global command scopes the attributes, not the command id (ZCL 2.4.1.1.2)."""
    frame = ZclFrame.decode(h("1c 34 12 80 04 00"))
    assert frame.header.manufacturer_code == 0x1234
    assert frame.header.frame_type is ZclFrameType.GLOBAL
    assert frame.global_command() == WriteAttributesResponse((WriteAttributeStatus(0),))
    read = ZclFrame(ZclHeader(1, 0x00, manufacturer_code=0x1234), h("0000"))
    assert read.global_command() == ReadAttributes((0x0000,))


def test_manufacturer_specific_unknown_global_still_unsupported() -> None:
    frame = ZclFrame(ZclHeader(1, 0x0D, manufacturer_code=0x1234), b"")
    with pytest.raises(UnsupportedFrameError):
        frame.global_command()


@pytest.mark.parametrize("wire", ["", "00", "00 01", "04 F2 10 05", "02 01 00", "03 01 00"])
def test_header_truncated_or_reserved(wire: str) -> None:
    with pytest.raises(ZclDecodeError):
        ZclFrame.decode(h(wire))


def test_unknown_global_command() -> None:
    with pytest.raises(UnsupportedFrameError):
        decode_global_command(0x0D, b"")


# --------------------------------------------------------------------------- commands


def test_read_attributes_bad_length() -> None:
    for wire in ("", "00", "000012"):
        with pytest.raises(ZclDecodeError):
            ReadAttributes.decode(h(wire))
    with pytest.raises(EncodeError):
        ReadAttributes(()).encode()


@pytest.mark.parametrize(
    "wire",
    [
        "",  # empty
        "0000",  # truncated record header
        "0000 00",  # missing type
        "0000 00 29 34",  # truncated value
        "0000 00 FE 00",  # unknown data type
        "0000 00 42 05 6162",  # truncated string
    ],
)
def test_read_attributes_response_strict(wire: str) -> None:
    with pytest.raises(ZclDecodeError):
        ReadAttributesResponse.decode(h(wire))


def test_read_record_encode_needs_type() -> None:
    with pytest.raises(EncodeError):
        ReadAttributeStatus(0, 0).encode()
    with pytest.raises(EncodeError):
        ReadAttributesResponse(()).encode()


def test_write_attributes_response_forms() -> None:
    ok = WriteAttributesResponse.decode(h("00"))
    assert ok.success
    assert ok.records == (WriteAttributeStatus(0),)
    assert ok.encode() == h("00")
    failed = WriteAttributesResponse.decode(h("87 1200 88 0000"))
    assert not failed.success
    assert failed.records == (WriteAttributeStatus(0x87, 0x0012), WriteAttributeStatus(0x88, 0))
    assert failed.encode() == h("87 1200 88 0000")


@pytest.mark.parametrize("wire", ["", "87", "87 12", "87 1200 88"])
def test_write_attributes_response_invalid(wire: str) -> None:
    with pytest.raises(ZclDecodeError):
        WriteAttributesResponse.decode(h(wire))


def test_write_attributes_response_encode_guards() -> None:
    with pytest.raises(EncodeError):
        WriteAttributesResponse(()).encode()
    with pytest.raises(EncodeError):
        WriteAttributesResponse((WriteAttributeStatus(0x87),)).encode()


@pytest.mark.parametrize(
    "wire", ["001200", "00 1200 87 1300", "87 1200 00 1300", "00 1200 00 1300"]
)
def test_write_attributes_response_rejects_success_records_in_list(wire: str) -> None:
    """Successful attributes are omitted from a failure list; all-success is exactly ``00``."""
    with pytest.raises(ZclDecodeError, match="SUCCESS"):
        WriteAttributesResponse.decode(h(wire))


@pytest.mark.parametrize(
    "records",
    [
        (WriteAttributeStatus(0, 0x0012),),
        (WriteAttributeStatus(0x87, 0x0012), WriteAttributeStatus(0, 0x0013)),
        (WriteAttributeStatus(0), WriteAttributeStatus(0x87, 0x0012)),
    ],
)
def test_write_attributes_response_encode_rejects_success_records_in_list(
    records: tuple[WriteAttributeStatus, ...],
) -> None:
    with pytest.raises(EncodeError):
        WriteAttributesResponse(records).encode()


def test_write_and_report_require_records() -> None:
    with pytest.raises(ZclDecodeError):
        WriteAttributes.decode(b"")
    with pytest.raises(ZclDecodeError):
        ReportAttributes.decode(b"")
    with pytest.raises(EncodeError):
        WriteAttributes(()).encode()
    with pytest.raises(EncodeError):
        ReportAttributes(()).encode()


def test_report_attributes() -> None:
    wire = h("0000 29 3408 0800 20 64")
    report = ReportAttributes.decode(wire)
    assert report.records == (
        AttributeRecord(0x0000, T.INT16, 2100),
        AttributeRecord(0x0008, T.UINT8, 100),
    )
    assert report.encode() == wire
    with pytest.raises(ZclDecodeError):
        ReportAttributes.decode(wire[:-1])


def test_default_response() -> None:
    frame = ZclFrame.build(9, DefaultResponse(0x02, ZclStatus.READ_ONLY))
    assert frame.encode() == h("00 09 0B 02 88")
    assert frame.header.command_id == ZclCommandId.DEFAULT_RESPONSE
    assert ZclFrame.decode(frame.encode()).global_command() == DefaultResponse(2, 0x88)
    for wire in ("02", "02 88 00"):
        with pytest.raises(ZclDecodeError):
            DefaultResponse.decode(h(wire))


# --------------------------------------------------------------------------- type table

EUI = Eui64.from_str("02:00:00:00:00:00:00:0C")
KEY = SecretBytes(bytes(range(16)))

ROUNDTRIP: list[tuple[ZclDataType, ZclValue, str]] = [
    (T.NO_DATA, None, ""),
    (T.DATA8, 0xAB, "AB"),
    (T.DATA16, 0x0102, "0201"),
    (T.DATA24, 0x010203, "030201"),
    (T.DATA32, 1, "01000000"),
    (T.DATA40, 1, "0100000000"),
    (T.DATA48, 1, "010000000000"),
    (T.DATA56, 1, "01000000000000"),
    (T.MAP24, 1, "010000"),
    (T.MAP32, 1, "01000000"),
    (T.MAP40, 1, "0100000000"),
    (T.MAP48, 1, "010000000000"),
    (T.MAP56, 1, "01000000000000"),
    (T.DATA64, 1, "0100000000000000"),
    (T.BOOL, True, "01"),
    (T.BOOL, False, "00"),
    (T.BOOL, None, "FF"),
    (T.MAP8, 0x81, "81"),
    (T.MAP16, 0x8001, "0180"),
    (T.MAP64, 2**64 - 1, "FFFFFFFFFFFFFFFF"),
    (T.UINT8, 200, "C8"),
    (T.UINT16, 0xBEEF, "EFBE"),
    (T.UINT24, 0xFFFFFF, "FFFFFF"),
    (T.UINT32, 0x01020304, "04030201"),
    (T.UINT40, 1 << 32, "0000000001"),
    (T.UINT48, 1 << 40, "000000000001"),
    (T.UINT56, 1 << 48, "00000000000001"),
    (T.UINT64, 2**63, "0000000000000080"),
    (T.INT8, -1, "FF"),
    (T.INT16, -32768, "0080"),
    (T.INT24, -2, "FEFFFF"),
    (T.INT32, -(2**31), "00000080"),
    (T.INT40, -1, "FFFFFFFFFF"),
    (T.INT48, 5, "050000000000"),
    (T.INT56, -1, "FFFFFFFFFFFFFF"),
    (T.INT64, -(2**63), "0000000000000080"),
    (T.ENUM8, 3, "03"),
    (T.ENUM16, 0x0102, "0201"),
    (T.SEMI, 1.5, "003E"),
    (T.SINGLE, 1.5, "0000C03F"),
    (T.DOUBLE, -2.0, "00000000000000C0"),
    (T.OCTSTR, b"\x01\x02", "02 0102"),
    (T.OCTSTR, b"", "00"),
    (T.OCTSTR, None, "FF"),
    (T.CHARSTR, "ab", "02 6162"),
    (T.CHARSTR, None, "FF"),
    (T.LONG_OCTSTR, b"\xaa", "0100 AA"),
    (T.LONG_OCTSTR, None, "FFFF"),
    (T.LONG_CHARSTR, "x", "0100 78"),
    (T.LONG_CHARSTR, None, "FFFF"),
    (T.UTC, 0x2A000000, "0000002A"),
    (T.CLUSTER_ID, 0x0201, "0102"),
    (T.ATTRIBUTE_ID, 0x0012, "1200"),
    (T.EUI64, EUI, "0C00000000000002"),
    (T.KEY128, KEY, "000102030405060708090A0B0C0D0E0F"),  # secret-scan: allow
]


@pytest.mark.parametrize(("dtype", "value", "wire"), ROUNDTRIP)
def test_type_roundtrip(dtype: ZclDataType, value: ZclValue, wire: str) -> None:
    raw = h(wire)
    assert encode_value(dtype, value) == raw
    assert decode_value(dtype, raw) == value
    # truncation of every non-empty value raises
    if raw:
        with pytest.raises(ZclDecodeError):
            decode_value(dtype, raw[:-1])


def test_all_listed_types_covered() -> None:
    assert {d for d, _, _ in ROUNDTRIP} == set(ZclDataType)


def test_key128_decodes_to_secret() -> None:
    value = decode_value(T.KEY128, bytes(16))
    assert isinstance(value, SecretBytes)
    assert "redacted" in repr(value)


def test_float_nan_and_semi_special() -> None:
    nan = decode_value(T.SEMI, h("007E"))
    assert isinstance(nan, float)
    assert math.isnan(nan)
    assert decode_value(T.SINGLE, h("0000807F")) == math.inf


@pytest.mark.parametrize("code", [0x01, 0x11, 0x32, 0x48, 0xE0, 0xFF])
def test_unknown_type_raises(code: int) -> None:
    with pytest.raises(ZclDecodeError, match="unsupported"):
        decode_value(code, b"\x00")
    with pytest.raises(EncodeError):
        encode_value(code, 0)


def test_invalid_bool_and_utf8() -> None:
    with pytest.raises(ZclDecodeError, match="bool"):
        decode_value(T.BOOL, b"\x02")
    with pytest.raises(ZclDecodeError, match="UTF-8"):
        decode_value(T.CHARSTR, h("01 FF"))


def test_trailing_bytes_rejected() -> None:
    with pytest.raises(ZclDecodeError, match="trailing"):
        decode_value(T.UINT8, b"\x01\x02")


def test_read_value_advances_cursor() -> None:
    cur = Cursor(h("0102 03"), ZclDecodeError, "t")
    assert read_value(cur, T.UINT16) == 0x0201
    assert cur.pos == 2


@pytest.mark.parametrize(
    ("dtype", "value"),
    [
        (T.UINT8, 256),
        (T.UINT8, -1),
        (T.INT16, 32768),
        (T.INT8, True),
        (T.UINT16, 1.0),
        (T.BOOL, 1),
        (T.SEMI, 1e9),
        (T.SINGLE, "1"),
        (T.SINGLE, False),
        (T.NO_DATA, 0),
        (T.OCTSTR, "text"),
        (T.CHARSTR, b"bytes"),
        (T.OCTSTR, bytes(255)),
        (T.LONG_OCTSTR, bytes(0xFFFF)),
        (T.EUI64, b"12345678"),
        (T.KEY128, bytes(16)),
        (T.KEY128, SecretBytes(bytes(15))),
    ],
)
def test_encode_value_rejects(dtype: ZclDataType, value: ZclValue) -> None:
    with pytest.raises(EncodeError):
        encode_value(dtype, value)


def test_header_encode_range_checks() -> None:
    with pytest.raises(EncodeError):
        ZclHeader(tsn=256, command_id=0).encode()
    with pytest.raises(EncodeError):
        ZclHeader(tsn=0, command_id=0, manufacturer_code=0x10000).encode()
