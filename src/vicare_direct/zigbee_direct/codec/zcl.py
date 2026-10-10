"""ZCL frame codec (ZCL rev 8 section 2.4): header plus profile-wide commands.

Ports research tools/zvd_tunnel.py:239-317 with fixes: full frame control
(frame type, manufacturer specific + code, direction, disable default
response), the full type table (``zcl_types.py``), strict record parsing (a
truncated record or unknown type raises instead of being swallowed) and the
Report Attributes / Default Response commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import ClassVar, Self

from vicare_direct.zigbee_direct.codec._cursor import Cursor, check_uint
from vicare_direct.zigbee_direct.codec.zcl_types import (
    ZclDataType,
    ZclValue,
    encode_value,
    parse_data_type,
    read_value,
)
from vicare_direct.zigbee_direct.errors import EncodeError, UnsupportedFrameError, ZclDecodeError

_FT_MASK = 0x03
_MANUFACTURER_SPECIFIC = 0x04
_DIRECTION = 0x08
_DISABLE_DEFAULT_RESPONSE = 0x10


class ZclFrameType(IntEnum):
    GLOBAL = 0
    CLUSTER_SPECIFIC = 1


class ZclDirection(IntEnum):
    CLIENT_TO_SERVER = 0
    SERVER_TO_CLIENT = 1


class ZclCommandId(IntEnum):
    """Profile-wide (global) command ids handled here."""

    READ_ATTRIBUTES = 0x00
    READ_ATTRIBUTES_RESPONSE = 0x01
    WRITE_ATTRIBUTES = 0x02
    WRITE_ATTRIBUTES_RESPONSE = 0x04
    REPORT_ATTRIBUTES = 0x0A
    DEFAULT_RESPONSE = 0x0B


class ZclStatus(IntEnum):
    """Common ZCL status codes (ZCL rev 8 Table 2-12). Decoded statuses stay ints."""

    SUCCESS = 0x00
    FAILURE = 0x01
    NOT_AUTHORIZED = 0x7E
    MALFORMED_COMMAND = 0x80
    UNSUP_COMMAND = 0x81
    INVALID_FIELD = 0x85
    UNSUPPORTED_ATTRIBUTE = 0x86
    INVALID_VALUE = 0x87
    READ_ONLY = 0x88
    INSUFFICIENT_SPACE = 0x89
    NOT_FOUND = 0x8B
    UNREPORTABLE_ATTRIBUTE = 0x8C
    INVALID_DATA_TYPE = 0x8D
    INVALID_SELECTOR = 0x8E
    TIMEOUT = 0x94
    ABORT = 0x95
    INVALID_IMAGE = 0x96
    WAIT_FOR_DATA = 0x97
    NO_IMAGE_AVAILABLE = 0x98
    REQUIRE_MORE_IMAGE = 0x99
    NOTIFICATION_PENDING = 0x9A
    UNSUPPORTED_CLUSTER = 0xC3


def _cursor(data: bytes, name: str) -> Cursor:
    return Cursor(data, ZclDecodeError, name)


# --------------------------------------------------------------------------- header


@dataclass(frozen=True, slots=True)
class ZclHeader:
    """ZCL header: FC ‖ [manufacturer code] ‖ tsn ‖ command id."""

    tsn: int
    command_id: int
    frame_type: ZclFrameType = ZclFrameType.GLOBAL
    manufacturer_code: int | None = None
    direction: ZclDirection = ZclDirection.CLIENT_TO_SERVER
    disable_default_response: bool = False

    def encode(self) -> bytes:
        fc = check_uint(self.frame_type, 2, "frame_type")
        if self.direction:
            fc |= _DIRECTION
        if self.disable_default_response:
            fc |= _DISABLE_DEFAULT_RESPONSE
        out = bytearray()
        if self.manufacturer_code is not None:
            fc |= _MANUFACTURER_SPECIFIC
            out += check_uint(self.manufacturer_code, 16, "manufacturer_code").to_bytes(2, "little")
        out += bytes([check_uint(self.tsn, 8, "tsn"), check_uint(self.command_id, 8, "command")])
        return bytes([fc]) + bytes(out)

    @classmethod
    def read(cls, cur: Cursor) -> Self:
        fc = cur.u8("frame control")
        if fc & _FT_MASK > ZclFrameType.CLUSTER_SPECIFIC:
            raise cur.fail(f"reserved frame type {fc & _FT_MASK}")
        manufacturer = cur.u16("manufacturer code") if fc & _MANUFACTURER_SPECIFIC else None
        tsn, command_id = cur.u8("tsn"), cur.u8("command id")
        return cls(
            tsn=tsn,
            command_id=command_id,
            frame_type=ZclFrameType(fc & _FT_MASK),
            manufacturer_code=manufacturer,
            direction=ZclDirection(bool(fc & _DIRECTION)),
            disable_default_response=bool(fc & _DISABLE_DEFAULT_RESPONSE),
        )


# --------------------------------------------------------------------------- records


@dataclass(frozen=True, slots=True)
class AttributeRecord:
    """attr id ‖ type ‖ value: used by Write Attributes and Report Attributes."""

    attribute_id: int
    data_type: ZclDataType
    value: ZclValue

    def encode(self) -> bytes:
        attr = check_uint(self.attribute_id, 16, "attribute_id").to_bytes(2, "little")
        return attr + bytes([self.data_type]) + encode_value(self.data_type, self.value)

    @classmethod
    def read(cls, cur: Cursor) -> Self:
        attribute_id = cur.u16("attribute id")
        data_type = parse_data_type(cur.u8("data type"))
        return cls(attribute_id, data_type, read_value(cur, data_type))


def _read_records(data: bytes, name: str) -> tuple[AttributeRecord, ...]:
    cur = _cursor(data, name)
    if not cur.remaining():
        raise cur.fail("no attribute records")
    records: list[AttributeRecord] = []
    while cur.remaining():
        records.append(AttributeRecord.read(cur))
    return tuple(records)


def _require_records(records: tuple[object, ...], name: str) -> None:
    if not records:
        raise EncodeError(f"{name} needs at least one record")


# --------------------------------------------------------------------------- commands


@dataclass(frozen=True, slots=True)
class ReadAttributes:
    """Read Attributes (0x00): attribute ids, 2 bytes LE each."""

    COMMAND_ID: ClassVar[ZclCommandId] = ZclCommandId.READ_ATTRIBUTES

    attribute_ids: tuple[int, ...]

    def encode(self) -> bytes:
        _require_records(self.attribute_ids, "ReadAttributes")
        return b"".join(
            check_uint(a, 16, "attribute_id").to_bytes(2, "little") for a in self.attribute_ids
        )

    @classmethod
    def decode(cls, data: bytes) -> Self:
        if not data or len(data) % 2:
            raise ZclDecodeError(f"ReadAttributes: bad payload length {len(data)}")
        return cls(tuple(int.from_bytes(data[i : i + 2], "little") for i in range(0, len(data), 2)))


@dataclass(frozen=True, slots=True)
class ReadAttributeStatus:
    """Read response record: id ‖ status ‖ [type ‖ value] (type/value only on success)."""

    attribute_id: int
    status: int
    data_type: ZclDataType | None = None
    value: ZclValue = None

    def encode(self) -> bytes:
        head = check_uint(self.attribute_id, 16, "attribute_id").to_bytes(2, "little")
        head += bytes([check_uint(self.status, 8, "status")])
        if self.status != ZclStatus.SUCCESS:
            return head
        if self.data_type is None:
            raise EncodeError("successful read record needs data_type")
        return head + bytes([self.data_type]) + encode_value(self.data_type, self.value)


@dataclass(frozen=True, slots=True)
class ReadAttributesResponse:
    """Read Attributes Response (0x01): one or more :class:`ReadAttributeStatus`."""

    COMMAND_ID: ClassVar[ZclCommandId] = ZclCommandId.READ_ATTRIBUTES_RESPONSE

    records: tuple[ReadAttributeStatus, ...]

    def encode(self) -> bytes:
        _require_records(self.records, "ReadAttributesResponse")
        return b"".join(r.encode() for r in self.records)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "ReadAttributesResponse")
        if not cur.remaining():
            raise cur.fail("no attribute records")
        records: list[ReadAttributeStatus] = []
        while cur.remaining():
            attribute_id, status = cur.u16("attribute id"), cur.u8("status")
            if status != ZclStatus.SUCCESS:
                records.append(ReadAttributeStatus(attribute_id, status))
                continue
            data_type = parse_data_type(cur.u8("data type"))
            value = read_value(cur, data_type)
            records.append(ReadAttributeStatus(attribute_id, status, data_type, value))
        return cls(tuple(records))


@dataclass(frozen=True, slots=True)
class WriteAttributes:
    """Write Attributes (0x02): one or more :class:`AttributeRecord`."""

    COMMAND_ID: ClassVar[ZclCommandId] = ZclCommandId.WRITE_ATTRIBUTES

    records: tuple[AttributeRecord, ...]

    def encode(self) -> bytes:
        _require_records(self.records, "WriteAttributes")
        return b"".join(r.encode() for r in self.records)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        return cls(_read_records(data, "WriteAttributes"))


@dataclass(frozen=True, slots=True)
class WriteAttributeStatus:
    """Write response record; ``attribute_id`` is None for the all-success short form."""

    status: int
    attribute_id: int | None = None


@dataclass(frozen=True, slots=True)
class WriteAttributesResponse:
    """Write Attributes Response (0x04), BUILD_SPEC A8.

    Empty payload -> error; a single 0x00 -> all success; otherwise a list of
    ``status ‖ attr id`` (3 bytes each) for the failed attributes only. A
    SUCCESS record inside such a list is illegal (ZCL rev 8 2.5.5.1.2:
    successful attributes are omitted) and rejected on encode and decode.
    """

    COMMAND_ID: ClassVar[ZclCommandId] = ZclCommandId.WRITE_ATTRIBUTES_RESPONSE

    records: tuple[WriteAttributeStatus, ...]

    @property
    def success(self) -> bool:
        return all(r.status == ZclStatus.SUCCESS for r in self.records)

    def encode(self) -> bytes:
        if self.records == (WriteAttributeStatus(ZclStatus.SUCCESS),):
            return b"\x00"
        _require_records(self.records, "WriteAttributesResponse")
        out = bytearray()
        for r in self.records:
            if r.attribute_id is None:
                raise EncodeError("only the single all-success record may omit attribute_id")
            if r.status == ZclStatus.SUCCESS:
                raise EncodeError("SUCCESS records are only valid as the lone all-success form")
            out.append(check_uint(r.status, 8, "status"))
            out += check_uint(r.attribute_id, 16, "attribute_id").to_bytes(2, "little")
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        if not data:
            raise ZclDecodeError("WriteAttributesResponse: empty payload")
        if len(data) == 1:
            if data[0] != ZclStatus.SUCCESS:
                raise ZclDecodeError("WriteAttributesResponse: lone status must be SUCCESS")
            return cls((WriteAttributeStatus(ZclStatus.SUCCESS),))
        if len(data) % 3:
            raise ZclDecodeError(f"WriteAttributesResponse: bad payload length {len(data)}")
        records = tuple(
            WriteAttributeStatus(data[i], int.from_bytes(data[i + 1 : i + 3], "little"))
            for i in range(0, len(data), 3)
        )
        if any(r.status == ZclStatus.SUCCESS for r in records):
            raise ZclDecodeError("WriteAttributesResponse: SUCCESS record in a failure list")
        return cls(records)


@dataclass(frozen=True, slots=True)
class ReportAttributes:
    """Report Attributes (0x0A): one or more :class:`AttributeRecord`."""

    COMMAND_ID: ClassVar[ZclCommandId] = ZclCommandId.REPORT_ATTRIBUTES

    records: tuple[AttributeRecord, ...]

    def encode(self) -> bytes:
        _require_records(self.records, "ReportAttributes")
        return b"".join(r.encode() for r in self.records)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        return cls(_read_records(data, "ReportAttributes"))


@dataclass(frozen=True, slots=True)
class DefaultResponse:
    """Default Response (0x0B): command id ‖ status (exactly 2 bytes)."""

    COMMAND_ID: ClassVar[ZclCommandId] = ZclCommandId.DEFAULT_RESPONSE

    command_id: int
    status: int

    def encode(self) -> bytes:
        return bytes(
            [check_uint(self.command_id, 8, "command_id"), check_uint(self.status, 8, "status")]
        )

    @classmethod
    def decode(cls, data: bytes) -> Self:
        if len(data) != 2:
            raise ZclDecodeError(f"DefaultResponse: need 2 bytes, got {len(data)}")
        return cls(data[0], data[1])


type ZclGlobalCommand = (
    ReadAttributes
    | ReadAttributesResponse
    | WriteAttributes
    | WriteAttributesResponse
    | ReportAttributes
    | DefaultResponse
)

_GLOBAL_COMMANDS: MappingProxyType[int, type[ZclGlobalCommand]] = MappingProxyType(
    {
        c.COMMAND_ID: c
        for c in (
            ReadAttributes,
            ReadAttributesResponse,
            WriteAttributes,
            WriteAttributesResponse,
            ReportAttributes,
            DefaultResponse,
        )
    }
)


def decode_global_command(command_id: int, payload: bytes) -> ZclGlobalCommand:
    """Decode a profile-wide command payload; unknown ids raise UnsupportedFrameError."""
    cls = _GLOBAL_COMMANDS.get(command_id)
    if cls is None:
        raise UnsupportedFrameError(f"ZCL global command 0x{command_id:02X} not supported")
    return cls.decode(payload)


# --------------------------------------------------------------------------- frame


@dataclass(frozen=True, slots=True)
class ZclFrame:
    """A full ZCL frame: header plus raw command payload."""

    header: ZclHeader
    payload: bytes = b""

    @classmethod
    def build(
        cls,
        tsn: int,
        command: ZclGlobalCommand,
        *,
        direction: ZclDirection = ZclDirection.CLIENT_TO_SERVER,
        manufacturer_code: int | None = None,
        disable_default_response: bool = False,
    ) -> Self:
        """Wrap a profile-wide command in a GLOBAL frame."""
        header = ZclHeader(
            tsn=tsn,
            command_id=command.COMMAND_ID,
            direction=direction,
            manufacturer_code=manufacturer_code,
            disable_default_response=disable_default_response,
        )
        return cls(header, command.encode())

    def encode(self) -> bytes:
        return self.header.encode() + self.payload

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "ZCL frame")
        header = ZclHeader.read(cur)
        return cls(header, cur.rest())

    def global_command(self) -> ZclGlobalCommand:
        """Decode the payload as a standard profile-wide command.

        Cluster-specific frames raise UnsupportedFrameError. A manufacturer-specific
        global frame keeps the standard command layout (the MS bit scopes the
        attribute ids to ``header.manufacturer_code``, ZCL rev 8 2.4.1.1.2), so it
        decodes normally; callers must match on the header's manufacturer code.
        """
        if self.header.frame_type is not ZclFrameType.GLOBAL:
            raise UnsupportedFrameError("cluster-specific ZCL command")
        return decode_global_command(self.header.command_id, self.payload)
