"""NWK frame codec (Zigbee R23 3.3.1), plaintext only.

Header layout::

    frame control(2) ‖ dst short(2) ‖ src short(2) ‖ radius(1) ‖ seq(1)
    [dst IEEE(8)] [src IEEE(8)] [multicast control(1)]
    [source route: relay_count(1) ‖ relay_index(1) ‖ relay_list(2*count)]
    payload

Frame control (little-endian 16 bit): bits 0-1 frame type, 2-5 protocol
version, 6-7 discover route, 8 multicast, 9 security, 10 source route,
11 dst IEEE, 12 src IEEE, 13 end-device initiator, 14-15 reserved.

The auxiliary NWK security header is never parsed: NPDUs delivered by the
Zigbee Direct tunnel are plaintext even when the security bit is set (the
ZDD applies/removes NWK security), so only the ``security`` flag is exposed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from vicare_direct.zigbee_direct.errors import EncodeError, NwkDecodeError
from vicare_direct.zigbee_direct.types import Eui64

NWK_PROTOCOL_VERSION = 2
NWK_HEADER_MIN_LEN = 8

DISCOVER_ROUTE_SUPPRESS = 0
DISCOVER_ROUTE_ENABLE = 1

_FC1_MULTICAST = 0x01
_FC1_SECURITY = 0x02
_FC1_SOURCE_ROUTE = 0x04
_FC1_DST_IEEE = 0x08
_FC1_SRC_IEEE = 0x10
_FC1_END_DEVICE_INITIATOR = 0x20


class NwkFrameType(IntEnum):
    """NWK frame type (FC bits 0-1); 0b10 is reserved."""

    DATA = 0
    COMMAND = 1
    INTER_PAN = 3


def _check_range(name: str, value: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise EncodeError(f"{name} out of range 0..0x{maximum:X}: {value!r}")


@dataclass(frozen=True, slots=True)
class NwkFrameControl:
    """The 2-byte NWK frame control field."""

    frame_type: NwkFrameType
    protocol_version: int = NWK_PROTOCOL_VERSION
    discover_route: int = DISCOVER_ROUTE_SUPPRESS
    multicast: bool = False
    security: bool = False
    source_route: bool = False
    dst_ieee: bool = False
    src_ieee: bool = False
    end_device_initiator: bool = False

    def __post_init__(self) -> None:
        _check_range("protocol_version", self.protocol_version, 0x0F)
        _check_range("discover_route", self.discover_route, 0x03)

    def encode(self) -> bytes:
        byte0 = int(self.frame_type) | (self.protocol_version << 2) | (self.discover_route << 6)
        byte1 = (
            (_FC1_MULTICAST if self.multicast else 0)
            | (_FC1_SECURITY if self.security else 0)
            | (_FC1_SOURCE_ROUTE if self.source_route else 0)
            | (_FC1_DST_IEEE if self.dst_ieee else 0)
            | (_FC1_SRC_IEEE if self.src_ieee else 0)
            | (_FC1_END_DEVICE_INITIATOR if self.end_device_initiator else 0)
        )
        return bytes((byte0, byte1))

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Decode exactly 2 bytes; reserved bits 14-15 are ignored."""
        if len(data) != 2:
            raise NwkDecodeError(f"NWK frame control needs 2 bytes, got {len(data)}")
        byte0, byte1 = data[0], data[1]
        try:
            frame_type = NwkFrameType(byte0 & 0x03)
        except ValueError:
            raise NwkDecodeError("reserved NWK frame type 0b10") from None
        return cls(
            frame_type=frame_type,
            protocol_version=(byte0 >> 2) & 0x0F,
            discover_route=(byte0 >> 6) & 0x03,
            multicast=bool(byte1 & _FC1_MULTICAST),
            security=bool(byte1 & _FC1_SECURITY),
            source_route=bool(byte1 & _FC1_SOURCE_ROUTE),
            dst_ieee=bool(byte1 & _FC1_DST_IEEE),
            src_ieee=bool(byte1 & _FC1_SRC_IEEE),
            end_device_initiator=bool(byte1 & _FC1_END_DEVICE_INITIATOR),
        )


@dataclass(frozen=True, slots=True)
class SourceRoute:
    """NWK source-route subframe: ``relay_count ‖ relay_index ‖ relays (2 bytes each)``."""

    relay_index: int
    relays: tuple[int, ...]

    def __post_init__(self) -> None:
        _check_range("relay_index", self.relay_index, 0xFF)
        _check_range("relay_count", len(self.relays), 0xFF)
        for relay in self.relays:
            _check_range("relay short", relay, 0xFFFF)

    def encode(self) -> bytes:
        out = bytearray((len(self.relays), self.relay_index))
        for relay in self.relays:
            out += relay.to_bytes(2, "little")
        return bytes(out)


@dataclass(frozen=True, slots=True)
class NwkFrame:
    """A plaintext NWK frame. Presence bits in the frame control derive from the optional fields.

    Encoding a frame with ``security=True`` just sets the FC bit; the ZDD
    applies the actual NWK security (handover §4).
    """

    frame_type: NwkFrameType
    dst: int
    src: int
    radius: int
    seq: int
    payload: bytes
    discover_route: int = DISCOVER_ROUTE_SUPPRESS
    security: bool = False
    end_device_initiator: bool = False
    protocol_version: int = NWK_PROTOCOL_VERSION
    dst_ieee: Eui64 | None = None
    src_ieee: Eui64 | None = None
    multicast_control: int | None = None
    source_route: SourceRoute | None = None

    def __post_init__(self) -> None:
        _check_range("dst", self.dst, 0xFFFF)
        _check_range("src", self.src, 0xFFFF)
        _check_range("radius", self.radius, 0xFF)
        _check_range("seq", self.seq, 0xFF)
        if self.multicast_control is not None:
            _check_range("multicast_control", self.multicast_control, 0xFF)
        # Validates protocol_version / discover_route.
        _ = self.frame_control

    @property
    def frame_control(self) -> NwkFrameControl:
        return NwkFrameControl(
            frame_type=self.frame_type,
            protocol_version=self.protocol_version,
            discover_route=self.discover_route,
            multicast=self.multicast_control is not None,
            security=self.security,
            source_route=self.source_route is not None,
            dst_ieee=self.dst_ieee is not None,
            src_ieee=self.src_ieee is not None,
            end_device_initiator=self.end_device_initiator,
        )

    def encode(self) -> bytes:
        out = bytearray(self.frame_control.encode())
        out += self.dst.to_bytes(2, "little")
        out += self.src.to_bytes(2, "little")
        out += bytes((self.radius, self.seq))
        if self.dst_ieee is not None:
            out += self.dst_ieee.wire
        if self.src_ieee is not None:
            out += self.src_ieee.wire
        if self.multicast_control is not None:
            out.append(self.multicast_control)
        if self.source_route is not None:
            out += self.source_route.encode()
        out += self.payload
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Decode a plaintext NWK frame; every optional field is bounds-checked."""
        if len(data) < NWK_HEADER_MIN_LEN:
            raise NwkDecodeError(f"NWK frame too short: {len(data)} < {NWK_HEADER_MIN_LEN}")
        fc = NwkFrameControl.decode(data[:2])
        offset = NWK_HEADER_MIN_LEN

        def take(n: int, what: str) -> bytes:
            nonlocal offset
            if offset + n > len(data):
                raise NwkDecodeError(f"NWK frame truncated in {what} at offset {offset}")
            chunk = bytes(data[offset : offset + n])
            offset += n
            return chunk

        dst_ieee = Eui64(take(8, "dst IEEE")) if fc.dst_ieee else None
        src_ieee = Eui64(take(8, "src IEEE")) if fc.src_ieee else None
        multicast_control = take(1, "multicast control")[0] if fc.multicast else None
        source_route = None
        if fc.source_route:
            count, relay_index = take(2, "source route header")
            raw = take(2 * count, "source route relay list")
            relays = tuple(int.from_bytes(raw[i : i + 2], "little") for i in range(0, len(raw), 2))
            source_route = SourceRoute(relay_index, relays)
        return cls(
            frame_type=fc.frame_type,
            dst=int.from_bytes(data[2:4], "little"),
            src=int.from_bytes(data[4:6], "little"),
            radius=data[6],
            seq=data[7],
            payload=bytes(data[offset:]),
            discover_route=fc.discover_route,
            security=fc.security,
            end_device_initiator=fc.end_device_initiator,
            protocol_version=fc.protocol_version,
            dst_ieee=dst_ieee,
            src_ieee=src_ieee,
            multicast_control=multicast_control,
            source_route=source_route,
        )
