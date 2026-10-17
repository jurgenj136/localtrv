"""Route Record (R23 3.4.5) and Link Status (R23 3.4.8) codecs, incl. the live frame shapes.

Dummy shorts and EUIs only; the NWK headers mirror the redacted hardware log.
"""

from __future__ import annotations

import pytest

from fixtures import golden as g
from localtrv.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from localtrv.zigbee_direct.codec.nwk_commands import NwkCommandId, decode_nwk_command
from localtrv.zigbee_direct.codec.nwk_mesh import (
    LINK_STATUS_ID,
    ROUTE_RECORD_ID,
    LinkStatus,
    LinkStatusEntry,
    RouteRecord,
)
from localtrv.zigbee_direct.errors import EncodeError, NwkDecodeError
from localtrv.zigbee_direct.types import BROADCAST_ROUTERS, Eui64

h = g.h
OWN = 0xCB93  # wire 93 CB
VALVE = 0x1844  # wire 44 18
R0 = 0x96A1  # wire A1 96
OWN_EUI = Eui64.from_str("02:00:00:00:00:00:00:01")
VALVE_EUI = Eui64.from_str("02:00:00:00:00:01:00:01")
R0_EUI = Eui64.from_str("02:00:00:00:00:00:00:02")


def test_ids_match_the_command_enum() -> None:
    assert NwkCommandId(ROUTE_RECORD_ID) is NwkCommandId.ROUTE_RECORD
    assert NwkCommandId(LINK_STATUS_ID) is NwkCommandId.LINK_STATUS


# --- Route Record ----------------------------------------------------------------------------

#: Valve -> us, 30 B: FC 09 18 (command, dst + src IEEE), radius 0x1D, 6 B Route Record.
VALVE_ROUTE_RECORD = h(
    "09 18 93 CB 44 18 1D 21", OWN_EUI.wire.hex(), VALVE_EUI.wire.hex(), "05 02 A1 96 00 00"
)
#: R0 -> us, 26 B: no relay.
R0_ROUTE_RECORD = h("09 18 93 CB A1 96 1E 07", OWN_EUI.wire.hex(), R0_EUI.wire.hex(), "05 00")


def test_live_valve_route_record() -> None:
    assert len(VALVE_ROUTE_RECORD) == 30
    frame = NwkFrame.decode(VALVE_ROUTE_RECORD)
    assert frame.frame_type is NwkFrameType.COMMAND
    assert (frame.dst, frame.src) == (OWN, VALVE)
    assert (frame.dst_ieee, frame.src_ieee) == (OWN_EUI, VALVE_EUI)
    record = decode_nwk_command(frame.payload)
    assert record == RouteRecord(relays=(R0, 0x0000))
    assert record.encode() == frame.payload


def test_live_r0_route_record_has_no_relays() -> None:
    assert len(R0_ROUTE_RECORD) == 26
    frame = NwkFrame.decode(R0_ROUTE_RECORD)
    assert decode_nwk_command(frame.payload) == RouteRecord()
    assert RouteRecord().encode() == h("05 00")


def test_route_record_keeps_a_tail_raw() -> None:
    record = RouteRecord.decode(h("05 01 34 12 AA BB"))
    assert record == RouteRecord(relays=(0x1234,), tlvs=h("AA BB"))
    assert record.encode() == h("05 01 34 12 AA BB")


@pytest.mark.parametrize("wire", [h("05"), h("05 02 34 12"), h("08 00"), b""])
def test_route_record_decode_errors(wire: bytes) -> None:
    with pytest.raises(NwkDecodeError):
        RouteRecord.decode(wire)


@pytest.mark.parametrize("relays", [(0x10000,), (-1,), tuple(range(256))])
def test_route_record_encode_ranges(relays: tuple[int, ...]) -> None:
    with pytest.raises(EncodeError):
        RouteRecord(relays=relays)


# --- Link Status -----------------------------------------------------------------------------

#: R0 broadcast, 24 B: FC 09 10 (src IEEE), dst 0xFFFC, radius 1, 8 B Link Status
#: (options 0x62: 2 entries, first + last frame).
R0_LINK_STATUS = h("09 10 FC FF A1 96 01 33", R0_EUI.wire.hex(), "08 62 00 00 11 93 CB 33")


def test_live_r0_link_status() -> None:
    assert len(R0_LINK_STATUS) == 24
    frame = NwkFrame.decode(R0_LINK_STATUS)
    assert (frame.dst, frame.radius, frame.src_ieee) == (BROADCAST_ROUTERS, 1, R0_EUI)
    status = decode_nwk_command(frame.payload)
    assert status == LinkStatus(
        entries=(LinkStatusEntry(0x0000, 1, 1), LinkStatusEntry(OWN, 3, 3)),
        first_frame=True,
        last_frame=True,
    )
    assert isinstance(status, LinkStatus)
    assert status.options == 0x62
    assert status.encode() == frame.payload


def test_link_status_flags_and_reserved_bits() -> None:
    status = LinkStatus.decode(h("08 81 34 12 F9"))  # reserved bit 7; entry reserved bits 3, 7
    assert status == LinkStatus(
        entries=(LinkStatusEntry(0x1234, 1, 7),), first_frame=False, last_frame=False
    )
    assert status.encode() == h("08 01 34 12 71")
    assert LinkStatus().encode() == h("08 60")


def test_link_status_keeps_a_tail_raw() -> None:
    status = LinkStatus.decode(h("08 60 AA"))
    assert status == LinkStatus(tlvs=h("AA"))


@pytest.mark.parametrize("wire", [h("08"), h("08 61 34 12"), h("05 00"), b""])
def test_link_status_decode_errors(wire: bytes) -> None:
    with pytest.raises(NwkDecodeError):
        LinkStatus.decode(wire)


def test_link_status_entry_decode_needs_three_bytes() -> None:
    with pytest.raises(NwkDecodeError):
        LinkStatusEntry.decode(h("34 12"))


@pytest.mark.parametrize(
    ("neighbor", "incoming", "outgoing"), [(0x10000, 1, 1), (1, 8, 1), (1, 1, -1)]
)
def test_link_status_entry_ranges(neighbor: int, incoming: int, outgoing: int) -> None:
    with pytest.raises(EncodeError):
        LinkStatusEntry(neighbor, incoming, outgoing)


def test_link_status_entry_count_fits_five_bits() -> None:
    with pytest.raises(EncodeError):
        LinkStatus(entries=tuple(LinkStatusEntry(i, 1, 1) for i in range(32)))
