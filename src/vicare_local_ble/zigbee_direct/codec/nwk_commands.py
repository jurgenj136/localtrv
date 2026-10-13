"""NWK command payloads (R23 3.4) used by a Zigbee Direct Virtual Device.

Every ``encode()`` returns the full NWK payload including the command id
octet; ``decode()`` expects it too. Trailing bytes after the fixed fields of
Route Request / Route Reply / Network Status are kept raw in ``tlvs`` (R23
allows TLVs there); Commissioning Request / Response TLVs are decoded strictly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_mesh import LinkStatus, RouteRecord
from vicare_local_ble.zigbee_direct.codec.tlv import Tlv, decode_tlvs, encode_tlvs
from vicare_local_ble.zigbee_direct.errors import (
    EncodeError,
    NwkDecodeError,
    TlvDecodeError,
    UnsupportedFrameError,
)
from vicare_local_ble.zigbee_direct.types import BROADCAST_ROUTERS, Eui64


class NwkCommandId(IntEnum):
    ROUTE_REQUEST = 0x01
    ROUTE_REPLY = 0x02
    NETWORK_STATUS = 0x03
    LEAVE = 0x04
    ROUTE_RECORD = 0x05
    REJOIN_REQUEST = 0x06
    REJOIN_RESPONSE = 0x07
    LINK_STATUS = 0x08
    NETWORK_REPORT = 0x09
    NETWORK_UPDATE = 0x0A
    END_DEVICE_TIMEOUT_REQUEST = 0x0B
    END_DEVICE_TIMEOUT_RESPONSE = 0x0C
    LINK_POWER_DELTA = 0x0D
    COMMISSIONING_REQUEST = 0x0E
    COMMISSIONING_RESPONSE = 0x0F


class ManyToOne(IntEnum):
    """Route Request options bits 3-4 (R23 3.4.1.3.1); 3 is reserved."""

    NONE = 0
    WITH_ROUTE_RECORD_TABLE = 1
    WITHOUT_ROUTE_RECORD_TABLE = 2


class AssociationType(IntEnum):
    """Commissioning Request association type (values as research tools/zvd_tunnel.py:28-30)."""

    INITIAL_JOIN = 0x00
    REJOIN = 0x01
    SECURE_LINK = 0x02


class UnsupportedNwkCommandError(UnsupportedFrameError):
    """Well-formed NWK command whose id this library does not decode."""

    def __init__(self, command_id: int) -> None:
        super().__init__(f"unsupported NWK command 0x{command_id:02X}")
        self.command_id = command_id


_RREQ_MANY_TO_ONE_SHIFT = 3
_RREQ_DST_IEEE = 0x20
_RREQ_MULTICAST = 0x40
_RREP_ORIG_IEEE = 0x10
_RREP_RESP_IEEE = 0x20
_RREP_MULTICAST = 0x40

# Global TLV tags (R23 Annex I) and the ZD 1.0 Device Capability Extension.
TLV_SUPPORTED_KEY_NEGOTIATION = 0x41
TLV_FRAGMENTATION_PARAMETERS = 0x47
TLV_JOINER_ENCAPSULATION = 0x48
TLV_DEVICE_CAPABILITY_EXTENSION = 0x4C

DEFAULT_ZVD_CAPABILITY = 0x8E


def _check(name: str, value: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise EncodeError(f"{name} out of range 0..0x{maximum:X}: {value!r}")


def _expect(data: bytes, cmd: NwkCommandId, min_len: int) -> None:
    if not data or data[0] != cmd:
        raise NwkDecodeError(f"not a {cmd.name} command")
    if len(data) < min_len:
        raise NwkDecodeError(f"{cmd.name} too short: {len(data)} < {min_len}")


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _strict_tlvs(data: bytes, what: str) -> tuple[Tlv, ...]:
    try:
        return decode_tlvs(data)
    except TlvDecodeError as exc:
        raise NwkDecodeError(f"{what}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class RouteRequest:
    """``01 ‖ options ‖ route_id ‖ dst(2) ‖ path_cost ‖ [dst IEEE(8)] ‖ tlvs``.

    Options bits 3-4 many-to-one, bit 5 dst IEEE present (derived), bit 6
    multicast; other option bits are dropped on decode.
    """

    route_id: int
    dst: int
    path_cost: int = 0
    many_to_one: ManyToOne = ManyToOne.NONE
    dst_ieee: Eui64 | None = None
    multicast: bool = False
    tlvs: bytes = b""

    def __post_init__(self) -> None:
        _check("route_id", self.route_id, 0xFF)
        _check("dst", self.dst, 0xFFFF)
        _check("path_cost", self.path_cost, 0xFF)

    @property
    def options(self) -> int:
        return (
            (int(self.many_to_one) << _RREQ_MANY_TO_ONE_SHIFT)
            | (_RREQ_DST_IEEE if self.dst_ieee is not None else 0)
            | (_RREQ_MULTICAST if self.multicast else 0)
        )

    def encode(self) -> bytes:
        out = bytearray((NwkCommandId.ROUTE_REQUEST, self.options, self.route_id))
        out += self.dst.to_bytes(2, "little")
        out.append(self.path_cost)
        if self.dst_ieee is not None:
            out += self.dst_ieee.wire
        return bytes(out) + self.tlvs

    @classmethod
    def decode(cls, data: bytes) -> Self:
        _expect(data, NwkCommandId.ROUTE_REQUEST, 6)
        options = data[1]
        try:
            many_to_one = ManyToOne((options >> _RREQ_MANY_TO_ONE_SHIFT) & 0x03)
        except ValueError:
            raise NwkDecodeError("reserved many-to-one value 3 in route request") from None
        offset = 6
        dst_ieee = None
        if options & _RREQ_DST_IEEE:
            if len(data) < offset + 8:
                raise NwkDecodeError("route request truncated in dst IEEE")
            dst_ieee = Eui64(bytes(data[offset : offset + 8]))
            offset += 8
        return cls(
            route_id=data[2],
            dst=_u16(data, 3),
            path_cost=data[5],
            many_to_one=many_to_one,
            dst_ieee=dst_ieee,
            multicast=bool(options & _RREQ_MULTICAST),
            tlvs=bytes(data[offset:]),
        )


def many_to_one_route_request(
    route_id: int,
    *,
    many_to_one: ManyToOne = ManyToOne.WITH_ROUTE_RECORD_TABLE,
    path_cost: int = 0,
) -> RouteRequest:
    """Many-to-one Route Request to 0xFFFC; default encodes ``01 08 id FC FF 00``.

    As research tools/zvd_tunnel.py ``build_manytoone_route_request`` (Telink reference).
    """
    return RouteRequest(
        route_id=route_id, dst=BROADCAST_ROUTERS, path_cost=path_cost, many_to_one=many_to_one
    )


def many_to_one_route_request_npdu(
    *, route_id: int, src_short: int, src_ieee: Eui64, seq: int, radius: int = 30
) -> bytes:
    """Full NWK frame: command, dst 0xFFFC, src IEEE present, security bit set (handover §5).

    Radius 30 and the security bit follow research tools/zvd_client.py:968-972.
    """
    return NwkFrame(
        frame_type=NwkFrameType.COMMAND,
        dst=BROADCAST_ROUTERS,
        src=src_short,
        radius=radius,
        seq=seq,
        payload=many_to_one_route_request(route_id).encode(),
        security=True,
        src_ieee=src_ieee,
    ).encode()


@dataclass(frozen=True, slots=True)
class RouteReply:
    """Route Reply (R23 3.4.2).

    ``02 ‖ options ‖ route_id ‖ originator(2) ‖ responder(2) ‖ path_cost ‖
    [originator IEEE(8)] ‖ [responder IEEE(8)] ‖ tlvs``.

    Options are DERIVED (R23 3.4.2.3.1): bit 4 originator IEEE present, bit 5
    responder IEEE present, bit 6 multicast. With both EUIs this yields 0x30,
    which is spec-correct but unverified live: the research client sent 0x20
    with both EUIs appended (research tools/zvd_tunnel.py ``build_route_reply``)
    and that worked against the installation.

    ``options_override`` replaces the options byte on ``encode`` only (live mode: 0x20) and
    every present EUI is still appended. ``decode`` stays spec-derived and never sets it.
    """

    route_id: int
    originator: int
    responder: int
    path_cost: int = 0
    originator_ieee: Eui64 | None = None
    responder_ieee: Eui64 | None = None
    multicast: bool = False
    tlvs: bytes = b""
    options_override: int | None = None

    def __post_init__(self) -> None:
        _check("route_id", self.route_id, 0xFF)
        _check("originator", self.originator, 0xFFFF)
        _check("responder", self.responder, 0xFFFF)
        _check("path_cost", self.path_cost, 0xFF)
        if self.options_override is not None:
            _check("options_override", self.options_override, 0xFF)

    @property
    def options(self) -> int:
        return (
            (_RREP_ORIG_IEEE if self.originator_ieee is not None else 0)
            | (_RREP_RESP_IEEE if self.responder_ieee is not None else 0)
            | (_RREP_MULTICAST if self.multicast else 0)
        )

    def encode(self) -> bytes:
        options = self.options if self.options_override is None else self.options_override
        out = bytearray((NwkCommandId.ROUTE_REPLY, options, self.route_id))
        out += self.originator.to_bytes(2, "little")
        out += self.responder.to_bytes(2, "little")
        out.append(self.path_cost)
        if self.originator_ieee is not None:
            out += self.originator_ieee.wire
        if self.responder_ieee is not None:
            out += self.responder_ieee.wire
        return bytes(out) + self.tlvs

    @classmethod
    def decode(cls, data: bytes) -> Self:
        _expect(data, NwkCommandId.ROUTE_REPLY, 8)
        options = data[1]
        offset = 8
        ieees: list[Eui64 | None] = []
        for bit, what in ((_RREP_ORIG_IEEE, "originator"), (_RREP_RESP_IEEE, "responder")):
            if options & bit:
                if len(data) < offset + 8:
                    raise NwkDecodeError(f"route reply truncated in {what} IEEE")
                ieees.append(Eui64(bytes(data[offset : offset + 8])))
                offset += 8
            else:
                ieees.append(None)
        return cls(
            route_id=data[2],
            originator=_u16(data, 3),
            responder=_u16(data, 5),
            path_cost=data[7],
            originator_ieee=ieees[0],
            responder_ieee=ieees[1],
            multicast=bool(options & _RREP_MULTICAST),
            tlvs=bytes(data[offset:]),
        )


@dataclass(frozen=True, slots=True)
class NetworkStatus:
    """``03 ‖ status code ‖ destination(2) ‖ tlvs`` (R23 3.4.3)."""

    status: int
    destination: int
    tlvs: bytes = b""

    def __post_init__(self) -> None:
        _check("status", self.status, 0xFF)
        _check("destination", self.destination, 0xFFFF)

    def encode(self) -> bytes:
        return (
            bytes((NwkCommandId.NETWORK_STATUS, self.status))
            + self.destination.to_bytes(2, "little")
            + self.tlvs
        )

    @classmethod
    def decode(cls, data: bytes) -> Self:
        _expect(data, NwkCommandId.NETWORK_STATUS, 4)
        return cls(status=data[1], destination=_u16(data, 2), tlvs=bytes(data[4:]))


@dataclass(frozen=True, slots=True)
class CommissioningRequest:
    """``0E ‖ association type ‖ capability ‖ TLVs`` (R23 3.4.14)."""

    association_type: int
    capability: int
    tlvs: tuple[Tlv, ...] = ()

    def __post_init__(self) -> None:
        _check("association_type", self.association_type, 0xFF)
        _check("capability", self.capability, 0xFF)

    def encode(self) -> bytes:
        head = bytes((NwkCommandId.COMMISSIONING_REQUEST, self.association_type, self.capability))
        return head + encode_tlvs(self.tlvs)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        _expect(data, NwkCommandId.COMMISSIONING_REQUEST, 3)
        return cls(data[1], data[2], _strict_tlvs(bytes(data[3:]), "commissioning request"))


def zvd_commissioning_tlvs(*, zvd_eui: Eui64, placeholder_short: int) -> tuple[Tlv, ...]:
    """Joiner Encapsulation TLV (0x48) wrapping the TLVs of handover §5.

    Inner TLVs (values as research tools/zvd_tunnel.py ``build_commissioning_request``,
    after the Telink zbdirectTestTool reference):
    Supported Key Negotiation Methods ``01 00 ‖ EUI``, Fragmentation Parameters
    ``short ‖ 01 ‖ CF 00``, Device Capability Extension ``01 00``.
    """
    _check("placeholder_short", placeholder_short, 0xFFFF)
    inner = (
        Tlv(TLV_SUPPORTED_KEY_NEGOTIATION, b"\x01\x00" + zvd_eui.wire),
        Tlv(
            TLV_FRAGMENTATION_PARAMETERS,
            placeholder_short.to_bytes(2, "little") + b"\x01\xcf\x00",
        ),
        Tlv(TLV_DEVICE_CAPABILITY_EXTENSION, b"\x01\x00"),
    )
    return (Tlv(TLV_JOINER_ENCAPSULATION, encode_tlvs(inner)),)


def commissioning_request_npdu(
    *,
    zvd_eui: Eui64,
    zdd_eui: Eui64,
    zdd_short: int,
    placeholder_short: int,
    seq: int,
    association_type: AssociationType = AssociationType.INITIAL_JOIN,
    capability: int = DEFAULT_ZVD_CAPABILITY,
    discover_route: int = 0,
) -> bytes:
    """Full NWK Commissioning Request frame (handover §5).

    Command frame, no security, radius 1 (R23 3.4.14.2), dst = ZDD short + IEEE,
    src = placeholder short + ZVD IEEE (FC byte1 0x18; the SiLabs ZDD requires
    both IEEEs). ``discover_route=0`` gives FC byte0 0x09 as research; 1 gives 0x49.
    The ZDD short comes from the Commissioning Status characteristic and the
    placeholder short is caller-chosen; the TC-assigned short is in the response.
    """
    payload = CommissioningRequest(
        association_type=association_type,
        capability=capability,
        tlvs=zvd_commissioning_tlvs(zvd_eui=zvd_eui, placeholder_short=placeholder_short),
    ).encode()
    return NwkFrame(
        frame_type=NwkFrameType.COMMAND,
        dst=zdd_short,
        src=placeholder_short,
        radius=1,
        seq=seq,
        payload=payload,
        discover_route=discover_route,
        dst_ieee=zdd_eui,
        src_ieee=zvd_eui,
    ).encode()


@dataclass(frozen=True, slots=True)
class CommissioningResponse:
    """``0F ‖ short(2 LE) ‖ status ‖ TLVs`` (R23 3.4.15); status 0x00 = success."""

    short: int
    status: int
    tlvs: tuple[Tlv, ...] = ()

    def __post_init__(self) -> None:
        _check("short", self.short, 0xFFFF)
        _check("status", self.status, 0xFF)

    @property
    def success(self) -> bool:
        return self.status == 0x00

    def encode(self) -> bytes:
        return (
            bytes((NwkCommandId.COMMISSIONING_RESPONSE,))
            + self.short.to_bytes(2, "little")
            + bytes((self.status,))
            + encode_tlvs(self.tlvs)
        )

    @classmethod
    def decode(cls, data: bytes) -> Self:
        _expect(data, NwkCommandId.COMMISSIONING_RESPONSE, 4)
        return cls(_u16(data, 1), data[3], _strict_tlvs(bytes(data[4:]), "commissioning response"))


type NwkCommand = (
    RouteRequest
    | RouteReply
    | NetworkStatus
    | RouteRecord
    | LinkStatus
    | CommissioningRequest
    | CommissioningResponse
)


def decode_nwk_command(payload: bytes) -> NwkCommand:
    """Decode a NWK command payload; unknown ids raise ``UnsupportedNwkCommandError``."""
    if not payload:
        raise NwkDecodeError("empty NWK command payload")
    match payload[0]:
        case NwkCommandId.ROUTE_REQUEST:
            return RouteRequest.decode(payload)
        case NwkCommandId.ROUTE_REPLY:
            return RouteReply.decode(payload)
        case NwkCommandId.NETWORK_STATUS:
            return NetworkStatus.decode(payload)
        case NwkCommandId.ROUTE_RECORD:
            return RouteRecord.decode(payload)
        case NwkCommandId.LINK_STATUS:
            return LinkStatus.decode(payload)
        case NwkCommandId.COMMISSIONING_REQUEST:
            return CommissioningRequest.decode(payload)
        case NwkCommandId.COMMISSIONING_RESPONSE:
            return CommissioningResponse.decode(payload)
        case other:
            raise UnsupportedNwkCommandError(other)
