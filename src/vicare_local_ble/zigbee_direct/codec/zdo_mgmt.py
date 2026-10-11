"""ZDO network management: Mgmt_Lqi_req / Mgmt_Lqi_rsp (Zigbee R23 2.4.3.3.2, 2.4.4.4.2).

Ports research tools/zvd_tunnel.py:463-497 with fixes: ``rx_on_when_idle`` and
``permit_joining`` are tri-state (``None`` = unknown) instead of ``bool``, the
extended PAN id / permit joining / depth are kept, and the neighbor count must
match the payload length exactly (the research parser stopped silently).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar, Self

from vicare_local_ble.zigbee_direct.codec._cursor import Cursor, check_uint
from vicare_local_ble.zigbee_direct.codec.zdo import ZdoCluster, ZdoStatus
from vicare_local_ble.zigbee_direct.errors import EncodeError, ZdoDecodeError
from vicare_local_ble.zigbee_direct.types import Eui64, validate_short

NEIGHBOR_RECORD_LEN = 22


class DeviceType(IntEnum):
    COORDINATOR = 0
    ROUTER = 1
    END_DEVICE = 2
    UNKNOWN = 3


class Relationship(IntEnum):
    """Known neighbor relationship values; decoded values stay plain ints."""

    PARENT = 0
    CHILD = 1
    SIBLING = 2
    NONE = 3
    PREVIOUS_CHILD = 4
    UNAUTHENTICATED_CHILD = 5


def _tri_to_bits(value: bool | None) -> int:
    return 2 if value is None else int(value)


def _bits_to_tri(bits: int, cur: Cursor, field: str) -> bool | None:
    if bits == 3:
        raise cur.fail(f"reserved {field} value 3")
    return None if bits == 2 else bool(bits)


@dataclass(frozen=True, slots=True)
class Neighbor:
    """One 22-byte neighbor table record."""

    extended_pan_id: int
    ieee: Eui64
    nwk_addr: int
    device_type: DeviceType
    rx_on_when_idle: bool | None
    relationship: int
    permit_joining: bool | None
    depth: int
    lqi: int

    def encode(self) -> bytes:
        try:
            validate_short(self.nwk_addr)
        except ValueError as exc:
            raise EncodeError(f"neighbor nwk_addr: {exc}") from exc
        flags = (
            check_uint(self.device_type, 2, "device_type")
            | _tri_to_bits(self.rx_on_when_idle) << 2
            | check_uint(self.relationship, 3, "relationship") << 4
        )
        return (
            check_uint(self.extended_pan_id, 64, "extended_pan_id").to_bytes(8, "little")
            + bytes(self.ieee)
            + self.nwk_addr.to_bytes(2, "little")
            + bytes([flags, _tri_to_bits(self.permit_joining)])
            + bytes([check_uint(self.depth, 8, "depth"), check_uint(self.lqi, 8, "lqi")])
        )

    @classmethod
    def _read(cls, cur: Cursor) -> Self:
        ext_pan, ieee, nwk = cur.u64("extended PAN id"), cur.eui("IEEE"), cur.u16("nwk addr")
        flags, permit = cur.u8("neighbor flags"), cur.u8("permit joining")
        depth, lqi = cur.u8("depth"), cur.u8("LQI")
        return cls(
            extended_pan_id=ext_pan,
            ieee=ieee,
            nwk_addr=nwk,
            device_type=DeviceType(flags & 0x03),
            rx_on_when_idle=_bits_to_tri((flags >> 2) & 0x03, cur, "rx_on_when_idle"),
            relationship=(flags >> 4) & 0x07,
            permit_joining=_bits_to_tri(permit & 0x03, cur, "permit_joining"),
            depth=depth,
            lqi=lqi,
        )


@dataclass(frozen=True, slots=True)
class MgmtLqiReq:
    """Mgmt_Lqi_req (0x0031): seq ‖ start index."""

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.MGMT_LQI_REQ

    seq: int
    start_index: int = 0

    def encode(self) -> bytes:
        return bytes([check_uint(self.seq, 8, "seq"), check_uint(self.start_index, 8, "start")])

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = Cursor(data, ZdoDecodeError, "Mgmt_Lqi_req")
        out = cls(cur.u8("seq"), cur.u8("start index"))
        cur.expect_end()
        return out


@dataclass(frozen=True, slots=True)
class MgmtLqiRsp:
    """Mgmt_Lqi_rsp (0x8031): seq ‖ status ‖ entries ‖ start ‖ count ‖ count x 22-byte records.

    On success, ``len == 5 + 22 * count`` exactly and ``start + count <= entries``.
    On failure only ``seq ‖ status`` (exactly 2 bytes) is accepted; R23 2.4.4.4
    (Mgmt_Lqi_rsp) does not define the remaining fields for a non-success status.
    """

    CLUSTER_ID: ClassVar[ZdoCluster] = ZdoCluster.MGMT_LQI_RSP

    seq: int
    status: int
    neighbor_table_entries: int = 0
    start_index: int = 0
    neighbors: tuple[Neighbor, ...] = ()

    def encode(self) -> bytes:
        check_uint(self.seq, 8, "seq")
        check_uint(self.status, 8, "status")
        if self.status != ZdoStatus.SUCCESS:
            return bytes([self.seq, self.status])
        check_uint(self.neighbor_table_entries, 8, "neighbor_table_entries")
        check_uint(self.start_index, 8, "start_index")
        if self.start_index + len(self.neighbors) > self.neighbor_table_entries:
            raise EncodeError("Mgmt_Lqi_rsp: start_index + count exceeds table entries")
        head = [self.seq, self.status, self.neighbor_table_entries, self.start_index]
        return bytes([*head, len(self.neighbors)]) + b"".join(n.encode() for n in self.neighbors)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        cur = Cursor(data, ZdoDecodeError, "Mgmt_Lqi_rsp")
        seq, status = cur.u8("seq"), cur.u8("status")
        if status != ZdoStatus.SUCCESS:
            cur.expect_end()
            return cls(seq, status)
        entries, start, count = cur.u8("entries"), cur.u8("start index"), cur.u8("count")
        if start + count > entries:
            raise cur.fail(f"start {start} + count {count} exceeds table entries {entries}")
        if cur.remaining() != count * NEIGHBOR_RECORD_LEN:
            raise cur.fail(
                f"count {count} needs {count * NEIGHBOR_RECORD_LEN} record bytes, "
                f"have {cur.remaining()}"
            )
        neighbors = tuple(Neighbor._read(cur) for _ in range(count))
        return cls(seq, status, entries, start, neighbors)
