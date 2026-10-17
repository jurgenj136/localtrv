"""ZDO codec (Zigbee R23 section 2.4): device/service discovery and Device_annce.

A ZDO frame is ``seq ‖ payload`` carried in an APS data frame on endpoint 0,
profile 0x0000, with the cluster id identifying the command. Every class here
encodes/decodes that ``seq ‖ payload`` part only.

Decoding is strict for every status: each response has an exact,
status-dependent layout (R23 2.4.4.2.x) and any missing, inconsistent or
trailing byte raises ZdoDecodeError:

* NWK_addr_rsp / IEEE_addr_rsp (2.4.4.2.1-2): ``status ‖ IEEE ‖ NWK`` on success
  and failure alike (single-device form; the device fills in the address
  fields it was asked about);
* Active_EP_rsp / Match_Desc_rsp (2.4.4.2.6-7): ``status ‖ NWKAddrOfInterest ‖
  count ‖ list``; on failure the count is 0 and the list absent;
* Simple_Desc_rsp (2.4.4.2.5): ``status ‖ NWKAddrOfInterest ‖ length ‖ desc``;
  on failure the length is 0 and the descriptor absent.

There is no short "status only" compatibility mode. Mgmt_Lqi lives in
``zdo_mgmt.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar, Self

from localtrv.zigbee_direct.codec._cursor import Cursor, check_uint
from localtrv.zigbee_direct.errors import EncodeError, UnsupportedFrameError, ZdoDecodeError
from localtrv.zigbee_direct.types import Eui64, validate_short


class ZdoCluster(IntEnum):
    """ZDO cluster ids (requests; responses have bit 15 set)."""

    NWK_ADDR_REQ = 0x0000
    IEEE_ADDR_REQ = 0x0001
    SIMPLE_DESC_REQ = 0x0004
    ACTIVE_EP_REQ = 0x0005
    MATCH_DESC_REQ = 0x0006
    DEVICE_ANNCE = 0x0013
    MGMT_LQI_REQ = 0x0031
    NWK_ADDR_RSP = 0x8000
    IEEE_ADDR_RSP = 0x8001
    SIMPLE_DESC_RSP = 0x8004
    ACTIVE_EP_RSP = 0x8005
    MATCH_DESC_RSP = 0x8006
    MGMT_LQI_RSP = 0x8031


class ZdoStatus(IntEnum):
    """Common ZDP status codes (R23 Table 2-137). Decoded statuses stay plain ints."""

    SUCCESS = 0x00
    INV_REQUESTTYPE = 0x80
    DEVICE_NOT_FOUND = 0x81
    INVALID_EP = 0x82
    NOT_ACTIVE = 0x83
    NOT_SUPPORTED = 0x84
    TIMEOUT = 0x85
    NO_MATCH = 0x86
    NO_ENTRY = 0x88
    NO_DESCRIPTOR = 0x89
    INSUFFICIENT_SPACE = 0x8A
    NOT_PERMITTED = 0x8B
    TABLE_FULL = 0x8C
    NOT_AUTHORIZED = 0x8D


class AddrRequestType(IntEnum):
    SINGLE_DEVICE = 0x00
    EXTENDED = 0x01


def _cursor(data: bytes, name: str) -> Cursor:
    return Cursor(data, ZdoDecodeError, name)


def _short(value: int, name: str) -> int:
    try:
        return validate_short(value)
    except ValueError as exc:
        raise EncodeError(f"{name}: {exc}") from exc


def _u8_list(values: tuple[int, ...], name: str) -> bytes:
    if len(values) > 0xFF:
        raise EncodeError(f"too many {name}: {len(values)}")
    return bytes([len(values), *(check_uint(v, 8, name) for v in values)])


def _u16_list(values: tuple[int, ...], name: str) -> bytes:
    if len(values) > 0xFF:
        raise EncodeError(f"too many {name}: {len(values)}")
    out = bytearray([len(values)])
    for v in values:
        out += check_uint(v, 16, name).to_bytes(2, "little")
    return bytes(out)


def _read_u16_list(cur: Cursor, name: str) -> tuple[int, ...]:
    count = cur.u8(f"{name} count")
    return tuple(cur.u16(name) for _ in range(count))


# --------------------------------------------------------------------------- annce


@dataclass(frozen=True, slots=True)
class DeviceAnnce:
    """Device_annce (0x0013): seq ‖ NWK addr ‖ IEEE ‖ capability (R23 2.4.3.1.11)."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.DEVICE_ANNCE

    seq: int
    nwk_addr: int
    ieee: Eui64
    capability: int

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.capability, 8, "capability")
        return (
            bytes([self.seq])
            + _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")
            + bytes(self.ieee)
            + bytes([self.capability])
        )

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "Device_annce")
        out = cls(cur.u8("seq"), cur.u16("nwk addr"), cur.eui("IEEE"), cur.u8("capability"))
        cur.expect_end()
        return out


# --------------------------------------------------------------------------- address


@dataclass(frozen=True, slots=True)
class NwkAddrReq:
    """NWK_addr_req (0x0000): seq ‖ IEEE ‖ request type ‖ start index."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.NWK_ADDR_REQ

    seq: int
    ieee: Eui64
    request_type: int = AddrRequestType.SINGLE_DEVICE
    start_index: int = 0

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.request_type, 8, "request_type")
        check_uint(self.start_index, 8, "start_index")
        return bytes([self.seq]) + bytes(self.ieee) + bytes([self.request_type, self.start_index])

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "NWK_addr_req")
        out = cls(cur.u8("seq"), cur.eui("IEEE"), cur.u8("request type"), cur.u8("start index"))
        cur.expect_end()
        return out


@dataclass(frozen=True, slots=True)
class IeeeAddrReq:
    """IEEE_addr_req (0x0001): seq ‖ NWK addr of interest ‖ request type ‖ start index."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.IEEE_ADDR_REQ

    seq: int
    nwk_addr: int
    request_type: int = AddrRequestType.SINGLE_DEVICE
    start_index: int = 0

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.request_type, 8, "request_type")
        check_uint(self.start_index, 8, "start_index")
        addr = _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")
        return bytes([self.seq]) + addr + bytes([self.request_type, self.start_index])

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "IEEE_addr_req")
        out = cls(cur.u8("seq"), cur.u16("nwk addr"), cur.u8("request type"), cur.u8("start index"))
        cur.expect_end()
        return out


@dataclass(frozen=True, slots=True)
class _AddrRsp:
    """Shared body of NWK_addr_rsp / IEEE_addr_rsp, single-device form only.

    seq ‖ status ‖ IEEE ‖ NWK addr: exactly 12 bytes for every status. On
    success, trailing bytes are the extended form (associated device list) and
    raise UnsupportedFrameError; on failure they are malformed (ZdoDecodeError).
    """

    NAME: ClassVar[str] = "addr_rsp"

    seq: int
    status: int
    ieee: Eui64
    nwk_addr: int

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.status, 8, "status")
        addr = _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")
        return bytes([self.seq, self.status]) + bytes(self.ieee) + addr

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, cls.NAME)
        seq, status = cur.u8("seq"), cur.u8("status")
        ieee, nwk = cur.eui("IEEE"), cur.u16("nwk addr")
        if cur.remaining() and status == ZdoStatus.SUCCESS:
            raise UnsupportedFrameError(f"{cls.NAME}: extended (associated list) form")
        cur.expect_end()
        return cls(seq, status, ieee, nwk)


@dataclass(frozen=True, slots=True)
class NwkAddrRsp(_AddrRsp):
    """NWK_addr_rsp (0x8000), single-device form."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.NWK_ADDR_RSP
    NAME: ClassVar[str] = "NWK_addr_rsp"


@dataclass(frozen=True, slots=True)
class IeeeAddrRsp(_AddrRsp):
    """IEEE_addr_rsp (0x8001), single-device form."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.IEEE_ADDR_RSP
    NAME: ClassVar[str] = "IEEE_addr_rsp"


# --------------------------------------------------------------------------- endpoints


@dataclass(frozen=True, slots=True)
class ActiveEpReq:
    """Active_EP_req (0x0005): seq ‖ NWK addr of interest."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.ACTIVE_EP_REQ

    seq: int
    nwk_addr: int

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        return bytes([self.seq]) + _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "Active_EP_req")
        out = cls(cur.u8("seq"), cur.u16("nwk addr"))
        cur.expect_end()
        return out


@dataclass(frozen=True, slots=True)
class _EndpointListRsp:
    """seq ‖ status ‖ NWK addr ‖ count ‖ endpoints (Active_EP_rsp / Match_Desc_rsp).

    On failure the count must be 0 (R23 2.4.4.2.6.1, 2.4.4.2.7.1).
    """

    NAME: ClassVar[str] = "endpoint_rsp"

    seq: int
    status: int
    nwk_addr: int
    endpoints: tuple[int, ...] = ()

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.status, 8, "status")
        if self.status != ZdoStatus.SUCCESS and self.endpoints:
            raise EncodeError(f"{self.NAME}: a failure response carries no endpoints")
        out = bytes([self.seq, self.status])
        out += _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")
        return out + _u8_list(self.endpoints, "endpoints")

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, cls.NAME)
        seq, status, nwk = cur.u8("seq"), cur.u8("status"), cur.u16("nwk addr")
        count = cur.u8("endpoint count")
        if status != ZdoStatus.SUCCESS and count:
            raise cur.fail(f"failure status 0x{status:02X} with endpoint count {count}")
        endpoints = tuple(cur.take(count, "endpoint list"))
        cur.expect_end()
        return cls(seq, status, nwk, endpoints)


@dataclass(frozen=True, slots=True)
class ActiveEpRsp(_EndpointListRsp):
    """Active_EP_rsp (0x8005)."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.ACTIVE_EP_RSP
    NAME: ClassVar[str] = "Active_EP_rsp"


@dataclass(frozen=True, slots=True)
class MatchDescRsp(_EndpointListRsp):
    """Match_Desc_rsp (0x8006)."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.MATCH_DESC_RSP
    NAME: ClassVar[str] = "Match_Desc_rsp"


@dataclass(frozen=True, slots=True)
class MatchDescReq:
    """Match_Desc_req (0x0006): seq ‖ NWK addr ‖ profile ‖ in clusters ‖ out clusters."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.MATCH_DESC_REQ

    seq: int
    nwk_addr: int
    profile_id: int
    in_clusters: tuple[int, ...] = ()
    out_clusters: tuple[int, ...] = ()

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        return (
            bytes([self.seq])
            + _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")
            + check_uint(self.profile_id, 16, "profile_id").to_bytes(2, "little")
            + _u16_list(self.in_clusters, "in_clusters")
            + _u16_list(self.out_clusters, "out_clusters")
        )

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "Match_Desc_req")
        seq, nwk, profile = cur.u8("seq"), cur.u16("nwk addr"), cur.u16("profile")
        in_clusters = _read_u16_list(cur, "in cluster")
        out_clusters = _read_u16_list(cur, "out cluster")
        cur.expect_end()
        return cls(seq, nwk, profile, in_clusters, out_clusters)


# --------------------------------------------------------------------------- simple desc


@dataclass(frozen=True, slots=True)
class SimpleDescriptor:
    """Simple descriptor (R23 2.3.2.5): endpoint, profile, device id/version, clusters."""

    endpoint: int
    profile_id: int
    device_id: int
    device_version: int = 0
    in_clusters: tuple[int, ...] = ()
    out_clusters: tuple[int, ...] = ()

    def encode(self) -> bytes:
        return (
            bytes([check_uint(self.endpoint, 8, "endpoint")])
            + check_uint(self.profile_id, 16, "profile_id").to_bytes(2, "little")
            + check_uint(self.device_id, 16, "device_id").to_bytes(2, "little")
            + bytes([check_uint(self.device_version, 4, "device_version")])
            + _u16_list(self.in_clusters, "in_clusters")
            + _u16_list(self.out_clusters, "out_clusters")
        )

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "simple descriptor")
        out = cls._read(cur)
        cur.expect_end()
        return out

    @classmethod
    def _read(cls, cur: Cursor) -> Self:
        endpoint, profile, device_id = cur.u8("endpoint"), cur.u16("profile"), cur.u16("device")
        version = cur.u8("device version") & 0x0F
        in_clusters = _read_u16_list(cur, "in cluster")
        out_clusters = _read_u16_list(cur, "out cluster")
        return cls(endpoint, profile, device_id, version, in_clusters, out_clusters)


@dataclass(frozen=True, slots=True)
class SimpleDescReq:
    """Simple_Desc_req (0x0004): seq ‖ NWK addr of interest ‖ endpoint."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.SIMPLE_DESC_REQ

    seq: int
    nwk_addr: int
    endpoint: int

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.endpoint, 8, "endpoint")
        addr = _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")
        return bytes([self.seq]) + addr + bytes([self.endpoint])

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "Simple_Desc_req")
        out = cls(cur.u8("seq"), cur.u16("nwk addr"), cur.u8("endpoint"))
        cur.expect_end()
        return out


@dataclass(frozen=True, slots=True)
class SimpleDescRsp:
    """Simple_Desc_rsp (0x8004): seq ‖ status ‖ NWK addr ‖ length ‖ descriptor.

    On success the length byte must equal the descriptor's encoded size exactly;
    on failure it must be 0 with no descriptor (R23 2.4.4.2.5.1).
    """

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.SIMPLE_DESC_RSP

    seq: int
    status: int
    nwk_addr: int
    descriptor: SimpleDescriptor | None = None

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.status, 8, "status")
        out = bytes([self.seq, self.status])
        out += _short(self.nwk_addr, "nwk_addr").to_bytes(2, "little")
        if (self.status == ZdoStatus.SUCCESS) != (self.descriptor is not None):
            raise EncodeError("Simple_Desc_rsp: descriptor present iff status is SUCCESS")
        if self.descriptor is None:
            return out + b"\x00"
        desc = self.descriptor.encode()
        if len(desc) > 0xFF:
            raise EncodeError("Simple_Desc_rsp: descriptor too long")
        return out + bytes([len(desc)]) + desc

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = _cursor(data, "Simple_Desc_rsp")
        seq, status, nwk = cur.u8("seq"), cur.u8("status"), cur.u16("nwk addr")
        length = cur.u8("descriptor length")
        if status != ZdoStatus.SUCCESS:
            if length:
                raise cur.fail(f"failure status 0x{status:02X} with descriptor length {length}")
            cur.expect_end()
            return cls(seq, status, nwk)
        if length == 0:
            raise cur.fail("success response with empty descriptor")
        desc_bytes = cur.take(length, "simple descriptor")
        cur.expect_end()
        try:
            descriptor = SimpleDescriptor.decode(desc_bytes)
        except ZdoDecodeError as exc:
            raise ZdoDecodeError(f"Simple_Desc_rsp: length {length} inconsistent: {exc}") from exc
        return cls(seq, status, nwk, descriptor)
