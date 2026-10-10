"""ZCL data types (ZCL rev 8, section 2.6.2) and typed value encode/decode.

Replaces the research size table (tools/zvd_tunnel.py:245-246), which knew 9
types and returned the raw tail for anything else; unknown types now raise
:class:`ZclDecodeError`.

Value mapping:

- integers, bitmaps, enums, ``dataN``, UTC, cluster/attribute ids -> ``int``
  (integer "invalid" sentinels such as int16 0x8000 are kept as raw ints;
  their meaning is attribute-specific)
- bool -> ``bool``; 0xFF (invalid) -> ``None``
- semi/single/double -> ``float`` (via :mod:`struct`)
- octet/char strings -> ``bytes``/``str``; length 0xFF / 0xFFFF (invalid) -> ``None``
- EUI-64 -> :class:`Eui64`; 128-bit security key -> :class:`SecretBytes`
- no data -> ``None``
"""

from __future__ import annotations

import struct
from enum import IntEnum

from vicare_direct.zigbee_direct.codec._cursor import Cursor
from vicare_direct.zigbee_direct.errors import EncodeError, ZclDecodeError
from vicare_direct.zigbee_direct.types import Eui64, SecretBytes

type ZclValue = int | float | bool | bytes | str | Eui64 | SecretBytes | None


class ZclDataType(IntEnum):
    NO_DATA = 0x00
    DATA8 = 0x08
    DATA16 = 0x09
    DATA24 = 0x0A
    DATA32 = 0x0B
    DATA40 = 0x0C
    DATA48 = 0x0D
    DATA56 = 0x0E
    DATA64 = 0x0F
    BOOL = 0x10
    MAP8 = 0x18
    MAP16 = 0x19
    MAP24 = 0x1A
    MAP32 = 0x1B
    MAP40 = 0x1C
    MAP48 = 0x1D
    MAP56 = 0x1E
    MAP64 = 0x1F
    UINT8 = 0x20
    UINT16 = 0x21
    UINT24 = 0x22
    UINT32 = 0x23
    UINT40 = 0x24
    UINT48 = 0x25
    UINT56 = 0x26
    UINT64 = 0x27
    INT8 = 0x28
    INT16 = 0x29
    INT24 = 0x2A
    INT32 = 0x2B
    INT40 = 0x2C
    INT48 = 0x2D
    INT56 = 0x2E
    INT64 = 0x2F
    ENUM8 = 0x30
    ENUM16 = 0x31
    SEMI = 0x38
    SINGLE = 0x39
    DOUBLE = 0x3A
    OCTSTR = 0x41
    CHARSTR = 0x42
    LONG_OCTSTR = 0x43
    LONG_CHARSTR = 0x44
    UTC = 0xE2
    CLUSTER_ID = 0xE8
    ATTRIBUTE_ID = 0xE9
    EUI64 = 0xF0
    KEY128 = 0xF1


_FLOAT_FORMATS = {ZclDataType.SEMI: "<e", ZclDataType.SINGLE: "<f", ZclDataType.DOUBLE: "<d"}
_FIXED_UNSIGNED = {
    ZclDataType.ENUM8: 1,
    ZclDataType.ENUM16: 2,
    ZclDataType.UTC: 4,
    ZclDataType.CLUSTER_ID: 2,
    ZclDataType.ATTRIBUTE_ID: 2,
}
_STRINGS = {  # type -> (length-prefix width, is text)
    ZclDataType.OCTSTR: (1, False),
    ZclDataType.CHARSTR: (1, True),
    ZclDataType.LONG_OCTSTR: (2, False),
    ZclDataType.LONG_CHARSTR: (2, True),
}
_BOOL_INVALID = 0xFF


def parse_data_type(code: int) -> ZclDataType:
    """Map a wire type code to :class:`ZclDataType`; unknown codes raise ZclDecodeError."""
    try:
        return ZclDataType(code)
    except ValueError:
        raise ZclDecodeError(f"unsupported ZCL data type 0x{code:02X}") from None


def _int_layout(dt: ZclDataType) -> tuple[int, bool] | None:
    """(width, signed) for plain integer-like types, else None."""
    if ZclDataType.DATA8 <= dt <= ZclDataType.DATA64:
        return dt - ZclDataType.DATA8 + 1, False
    if ZclDataType.MAP8 <= dt <= ZclDataType.MAP64:
        return dt - ZclDataType.MAP8 + 1, False
    if ZclDataType.UINT8 <= dt <= ZclDataType.UINT64:
        return dt - ZclDataType.UINT8 + 1, False
    if ZclDataType.INT8 <= dt <= ZclDataType.INT64:
        return dt - ZclDataType.INT8 + 1, True
    width = _FIXED_UNSIGNED.get(dt)
    return None if width is None else (width, False)


def read_value(cur: Cursor, data_type: int) -> ZclValue:
    """Read one value of ``data_type`` from ``cur`` (bounds-checked)."""
    dt = parse_data_type(data_type)
    layout = _int_layout(dt)
    if layout is not None:
        width, signed = layout
        return int.from_bytes(cur.take(width, dt.name), "little", signed=signed)
    if dt is ZclDataType.NO_DATA:
        return None
    if dt is ZclDataType.BOOL:
        flag = cur.u8("bool")
        if flag == _BOOL_INVALID:
            return None
        if flag > 1:
            raise cur.fail(f"invalid bool value 0x{flag:02X}")
        return bool(flag)
    if dt in _FLOAT_FORMATS:
        fmt = _FLOAT_FORMATS[dt]
        return float(struct.unpack(fmt, cur.take(struct.calcsize(fmt), dt.name))[0])
    if dt in _STRINGS:
        prefix, text = _STRINGS[dt]
        length = int.from_bytes(cur.take(prefix, f"{dt.name} length"), "little")
        if length == (1 << (8 * prefix)) - 1:
            return None
        raw = cur.take(length, dt.name)
        if not text:
            return raw
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise cur.fail(f"{dt.name} is not valid UTF-8") from exc
    if dt is ZclDataType.EUI64:
        return cur.eui()
    # KEY128 is the only remaining member.
    return SecretBytes(cur.take(16, "key128"))


def decode_value(data_type: int, data: bytes) -> ZclValue:
    """Decode exactly one value; trailing bytes raise ZclDecodeError."""
    cur = Cursor(data, ZclDecodeError, "ZCL value")
    value = read_value(cur, data_type)
    cur.expect_end()
    return value


def _require[T](value: object, kind: type[T], dt: ZclDataType) -> T:
    if isinstance(value, bool) and kind is not bool:
        raise EncodeError(f"{dt.name} does not accept bool")
    if not isinstance(value, kind):
        raise EncodeError(f"{dt.name} needs {kind}, got {type(value).__name__}")
    return value


def encode_value(data_type: int, value: ZclValue) -> bytes:
    """Encode ``value`` as ``data_type`` (little-endian); raise EncodeError on mismatch/range."""
    try:
        dt = ZclDataType(data_type)
    except ValueError:
        raise EncodeError(f"unsupported ZCL data type 0x{data_type:02X}") from None
    layout = _int_layout(dt)
    if layout is not None:
        width, signed = layout
        number = _require(value, int, dt)
        try:
            return number.to_bytes(width, "little", signed=signed)
        except OverflowError:
            raise EncodeError(f"{number} does not fit {dt.name}") from None
    if dt is ZclDataType.NO_DATA:
        if value is not None:
            raise EncodeError("NO_DATA takes None")
        return b""
    if dt is ZclDataType.BOOL:
        if value is None:
            return bytes([_BOOL_INVALID])
        return bytes([int(_require(value, bool, dt))])
    if dt in _FLOAT_FORMATS:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise EncodeError(f"{dt.name} needs a number, got {type(value).__name__}")
        number_f = value
        try:
            return struct.pack(_FLOAT_FORMATS[dt], number_f)
        except (OverflowError, struct.error):
            raise EncodeError(f"{number_f} does not fit {dt.name}") from None
    if dt in _STRINGS:
        prefix, text = _STRINGS[dt]
        invalid = (1 << (8 * prefix)) - 1
        if value is None:
            return invalid.to_bytes(prefix, "little")
        raw = _require(value, str, dt).encode() if text else _require(value, bytes, dt)
        if len(raw) >= invalid:
            raise EncodeError(f"{dt.name} too long: {len(raw)} bytes")
        return len(raw).to_bytes(prefix, "little") + raw
    if dt is ZclDataType.EUI64:
        return bytes(_require(value, Eui64, dt))
    key = _require(value, SecretBytes, dt)
    if len(key) != 16:
        raise EncodeError("KEY128 needs 16 bytes")
    return key.reveal()
