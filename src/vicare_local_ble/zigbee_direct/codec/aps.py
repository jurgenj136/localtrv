"""APS frame codec (Zigbee R23 section 2.2.5).

Only unsecured, unfragmented APS *data* frames are decoded. ACK, command and
inter-PAN frames, APS-secured frames and frames with an extended header
(fragmentation) raise :class:`UnsupportedFrameError` -- their payload is never
treated as plaintext (the research code skipped a fake "aux header + MIC",
research tools/zvd_tunnel.py:348-388; that is dropped here).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from vicare_local_ble.zigbee_direct.codec._cursor import Cursor, check_uint
from vicare_local_ble.zigbee_direct.errors import ApsDecodeError, EncodeError, UnsupportedFrameError

ZDO_PROFILE_ID = 0x0000
HA_PROFILE_ID = 0x0104

_FT_MASK = 0x03
_DELIVERY_SHIFT = 2
_ACK_FORMAT = 0x10
_SECURITY = 0x20
_ACK_REQUEST = 0x40
_EXTENDED_HEADER = 0x80


class ApsFrameType(IntEnum):
    """APS frame type, frame control bits 0-1."""

    DATA = 0
    COMMAND = 1
    ACK = 2
    INTER_PAN = 3


class ApsDeliveryMode(IntEnum):
    """APS delivery mode, frame control bits 2-3 (0b01 is reserved in R23)."""

    UNICAST = 0
    BROADCAST = 2
    GROUP = 3


@dataclass(frozen=True, slots=True)
class ApsFrameControl:
    """Decoded APS frame control octet (R23 2.2.5.1.1)."""

    frame_type: ApsFrameType
    delivery_mode: int  # raw 2-bit value; 1 is reserved
    ack_format: bool
    security: bool
    ack_request: bool
    extended_header: bool

    @classmethod
    def from_byte(cls, fc: int) -> Self:
        return cls(
            frame_type=ApsFrameType(fc & _FT_MASK),
            delivery_mode=(fc >> _DELIVERY_SHIFT) & 0x03,
            ack_format=bool(fc & _ACK_FORMAT),
            security=bool(fc & _SECURITY),
            ack_request=bool(fc & _ACK_REQUEST),
            extended_header=bool(fc & _EXTENDED_HEADER),
        )


@dataclass(frozen=True, slots=True)
class ApsDataFrame:
    """Unsecured APS data frame.

    Unicast/broadcast frames carry ``dst_endpoint`` (``group_address`` is None);
    group frames carry ``group_address`` (``dst_endpoint`` is None).
    """

    cluster_id: int
    profile_id: int
    payload: bytes
    delivery_mode: ApsDeliveryMode = ApsDeliveryMode.UNICAST
    dst_endpoint: int | None = 0
    group_address: int | None = None
    src_endpoint: int = 0
    counter: int = 0
    ack_request: bool = False

    def __post_init__(self) -> None:
        try:
            mode = ApsDeliveryMode(self.delivery_mode)
        except ValueError as exc:
            raise EncodeError(f"invalid APS delivery mode: {self.delivery_mode!r}") from exc
        if mode is ApsDeliveryMode.GROUP:
            if self.group_address is None or self.dst_endpoint is not None:
                raise EncodeError("group delivery needs group_address and no dst_endpoint")
            check_uint(self.group_address, 16, "group_address")
        else:
            if self.dst_endpoint is None or self.group_address is not None:
                raise EncodeError(f"{mode.name} delivery needs dst_endpoint and no group_address")
            check_uint(self.dst_endpoint, 8, "dst_endpoint")
        check_uint(self.cluster_id, 16, "cluster_id")
        check_uint(self.profile_id, 16, "profile_id")
        check_uint(self.src_endpoint, 8, "src_endpoint")
        check_uint(self.counter, 8, "counter")
        if not isinstance(self.payload, bytes):
            raise EncodeError("payload must be bytes")

    def encode(self) -> bytes:
        fc = ApsFrameType.DATA | (self.delivery_mode << _DELIVERY_SHIFT)
        if self.ack_request:
            fc |= _ACK_REQUEST
        out = bytearray([fc])
        if self.group_address is not None:
            out += self.group_address.to_bytes(2, "little")
        elif self.dst_endpoint is not None:
            out.append(self.dst_endpoint)
        out += self.cluster_id.to_bytes(2, "little")
        out += self.profile_id.to_bytes(2, "little")
        out += bytes([self.src_endpoint, self.counter])
        return bytes(out) + self.payload

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Decode an APS data frame.

        Raises ApsDecodeError for malformed/truncated input or the reserved
        delivery mode, and UnsupportedFrameError for non-data, secured or
        extended-header frames.
        """
        cur = Cursor(data, ApsDecodeError, "APS frame")
        fc = ApsFrameControl.from_byte(cur.u8("frame control"))
        if fc.frame_type is not ApsFrameType.DATA:
            raise UnsupportedFrameError(f"APS {fc.frame_type.name} frames are not decoded")
        if fc.delivery_mode == 1:
            raise ApsDecodeError("APS frame: reserved delivery mode 0b01")
        if fc.security:
            raise UnsupportedFrameError("APS-secured data frame (payload is ciphertext)")
        if fc.extended_header:
            raise UnsupportedFrameError("APS extended header (fragmentation) not supported")
        mode = ApsDeliveryMode(fc.delivery_mode)
        dst_endpoint: int | None = None
        group_address: int | None = None
        if mode is ApsDeliveryMode.GROUP:
            group_address = cur.u16("group address")
        else:
            dst_endpoint = cur.u8("destination endpoint")
        cluster_id = cur.u16("cluster id")
        profile_id = cur.u16("profile id")
        src_endpoint = cur.u8("source endpoint")
        counter = cur.u8("APS counter")
        return cls(
            cluster_id=cluster_id,
            profile_id=profile_id,
            payload=cur.rest(),
            delivery_mode=mode,
            dst_endpoint=dst_endpoint,
            group_address=group_address,
            src_endpoint=src_endpoint,
            counter=counter,
            ack_request=fc.ack_request,
        )
