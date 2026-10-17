"""Mesh-maintenance NWK command payloads (R23 3.4.5 Route Record, 3.4.8 Link Status).

Neither command is ever sent by the virtual device; both are decoded so the dispatcher can
count them and the debug recorder can log them structurally. They carry only short addresses
and link costs (no EUI, no key). As in ``nwk_commands``, ``encode()`` returns the full NWK
payload including the command id octet, ``decode()`` expects it, and bytes after the fixed
fields are kept raw in ``tlvs`` (never decoded; the redactor only accepts an empty tail).

Live shapes (ubisys R0 + ZK03840 valves, first hardware run):

* Route Record, NWK FC ``09 18`` (dst + src IEEE) to our short before every unicast from a
  device, because the virtual device is a many-to-one concentrator: ``05 00`` from the R0
  (no relay), ``05 02 <relay> <relay>`` from a valve.
* Link Status, NWK FC ``09 10`` (src IEEE) to 0xFFFC with radius 1 every ~15 s from the R0:
  ``08 <options> 2 x (<short> <costs>)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from localtrv.zigbee_direct.errors import EncodeError, NwkDecodeError

#: Command ids (equal to ``nwk_commands.NwkCommandId.ROUTE_RECORD`` / ``LINK_STATUS``).
ROUTE_RECORD_ID: Final = 0x05
LINK_STATUS_ID: Final = 0x08

_MAX_LINK_ENTRIES: Final = 0x1F  # options bits 0-4
_LS_FIRST_FRAME: Final = 0x20
_LS_LAST_FRAME: Final = 0x40
_LS_ENTRY_LEN: Final = 3
_COST_MASK: Final = 0x07
_OUTGOING_SHIFT: Final = 4


def _check(name: str, value: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise EncodeError(f"{name} out of range 0..0x{maximum:X}: {value!r}")


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _expect(data: bytes, command_id: int, name: str) -> None:
    if len(data) < 2 or data[0] != command_id:
        raise NwkDecodeError(f"not a {name} command or truncated")


@dataclass(frozen=True, slots=True)
class RouteRecord:
    """``05 ‖ relay count ‖ relay list (2 x count) ‖ tlvs`` (R23 3.4.5).

    ``relays`` lists the shorts of the routers that relayed the record, originator side
    first; an empty tuple means the originator is our direct neighbour (the R0)."""

    relays: tuple[int, ...] = ()
    tlvs: bytes = b""

    def __post_init__(self) -> None:
        _check("relay count", len(self.relays), 0xFF)
        for relay in self.relays:
            _check("relay", relay, 0xFFFF)

    def encode(self) -> bytes:
        out = bytearray((ROUTE_RECORD_ID, len(self.relays)))
        for relay in self.relays:
            out += relay.to_bytes(2, "little")
        return bytes(out) + self.tlvs

    @classmethod
    def decode(cls, data: bytes) -> Self:
        _expect(data, ROUTE_RECORD_ID, "ROUTE_RECORD")
        count = data[1]
        end = 2 + 2 * count
        if len(data) < end:
            raise NwkDecodeError(f"route record truncated: {count} relays need {end} B")
        relays = tuple(_u16(data, offset) for offset in range(2, end, 2))
        return cls(relays=relays, tlvs=bytes(data[end:]))


@dataclass(frozen=True, slots=True)
class LinkStatusEntry:
    """One Link Status list entry: neighbour short and its 3-bit link costs (R23 3.4.8.3.2)."""

    neighbor: int
    incoming_cost: int
    outgoing_cost: int

    def __post_init__(self) -> None:
        _check("neighbor", self.neighbor, 0xFFFF)
        _check("incoming_cost", self.incoming_cost, _COST_MASK)
        _check("outgoing_cost", self.outgoing_cost, _COST_MASK)

    def encode(self) -> bytes:
        costs = self.incoming_cost | (self.outgoing_cost << _OUTGOING_SHIFT)
        return self.neighbor.to_bytes(2, "little") + bytes((costs,))

    @classmethod
    def decode(cls, data: bytes) -> Self:
        if len(data) != _LS_ENTRY_LEN:
            raise NwkDecodeError(f"link status entry must be {_LS_ENTRY_LEN} B: {len(data)}")
        costs = data[2]
        return cls(
            neighbor=_u16(data, 0),
            incoming_cost=costs & _COST_MASK,
            outgoing_cost=(costs >> _OUTGOING_SHIFT) & _COST_MASK,
        )


@dataclass(frozen=True, slots=True)
class LinkStatus:
    """``08 ‖ options ‖ entries (3 x count) ‖ tlvs`` (R23 3.4.8).

    Options bits 0-4 entry count (derived), bit 5 first frame, bit 6 last frame; reserved
    bits (and the reserved bits of each entry's cost octet) are dropped on decode."""

    entries: tuple[LinkStatusEntry, ...] = ()
    first_frame: bool = True
    last_frame: bool = True
    tlvs: bytes = b""

    def __post_init__(self) -> None:
        _check("entry count", len(self.entries), _MAX_LINK_ENTRIES)

    @property
    def options(self) -> int:
        return (
            len(self.entries)
            | (_LS_FIRST_FRAME if self.first_frame else 0)
            | (_LS_LAST_FRAME if self.last_frame else 0)
        )

    def encode(self) -> bytes:
        body = b"".join(entry.encode() for entry in self.entries)
        return bytes((LINK_STATUS_ID, self.options)) + body + self.tlvs

    @classmethod
    def decode(cls, data: bytes) -> Self:
        _expect(data, LINK_STATUS_ID, "LINK_STATUS")
        options = data[1]
        count = options & _MAX_LINK_ENTRIES
        end = 2 + _LS_ENTRY_LEN * count
        if len(data) < end:
            raise NwkDecodeError(f"link status truncated: {count} entries need {end} B")
        entries = tuple(
            LinkStatusEntry.decode(data[offset : offset + _LS_ENTRY_LEN])
            for offset in range(2, end, _LS_ENTRY_LEN)
        )
        return cls(
            entries=entries,
            first_frame=bool(options & _LS_FIRST_FRAME),
            last_frame=bool(options & _LS_LAST_FRAME),
            tlvs=bytes(data[end:]),
        )


__all__ = ["LINK_STATUS_ID", "ROUTE_RECORD_ID", "LinkStatus", "LinkStatusEntry", "RouteRecord"]
