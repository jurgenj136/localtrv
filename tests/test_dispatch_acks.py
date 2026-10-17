"""Dispatcher: which inbound frames get an APS ack, and NWK Route Record / Link Status counting.

Unit level with the recording ``Host`` of ``test_dispatch`` (``host.acks`` records every
``ack_aps`` call; the send path is covered in ``test_node_acks.py``).
"""

from __future__ import annotations

import dataclasses
import logging

import pytest

from fixtures import golden as g
from localtrv.zigbee_direct.codec.aps import ApsDataFrame, ApsDeliveryMode
from localtrv.zigbee_direct.codec.nwk import NwkFrame
from localtrv.zigbee_direct.types import Eui64
from test_dispatch import LOGGER, feed, read_envelope, setup
from test_nwk_mesh import R0_LINK_STATUS, VALVE_ROUTE_RECORD

h = g.h
ACK_REQUEST = 0x40


def with_ack_request(npdu: bytes, aps_offset: int = 8) -> bytes:
    """Set the APS ack-request bit of a golden NPDU (APS FC at ``aps_offset``)."""
    return npdu[:aps_offset] + bytes([npdu[aps_offset] | ACK_REQUEST]) + npdu[aps_offset + 1 :]


def with_dst(npdu: bytes, dst: int) -> bytes:
    return npdu[:2] + dst.to_bytes(2, "little") + npdu[4:]


def with_src(npdu: bytes, src: int) -> bytes:
    return npdu[:4] + src.to_bytes(2, "little") + npdu[6:]


def acked_counters(host: object) -> list[tuple[int, int]]:
    return [(src, aps.counter) for src, aps in host.acks]  # type: ignore[attr-defined]


async def test_response_is_acked_and_resolves() -> None:
    host, dispatcher = setup()
    pending = host.pending.register(read_envelope())
    feed(dispatcher, with_ack_request(g.ZCL_READ_RSP))
    assert (await pending.future).command.records[0].value == 1965  # type: ignore[union-attr]
    ((src, aps),) = host.acks
    assert (src, aps.counter, aps.cluster_id, aps.src_endpoint) == (g.VALVE_SHORT, 0x40, 0x0201, 1)


async def test_duplicate_of_a_resolved_response_is_acked_then_dropped() -> None:
    host, dispatcher = setup()
    pending = host.pending.register(read_envelope())
    frame = with_ack_request(g.ZCL_READ_RSP)
    feed(dispatcher, frame)
    await pending.future
    host.pending.retire(pending.envelope.key)
    feed(dispatcher, frame, frame)  # the sender's APS retransmissions
    assert acked_counters(host) == [(g.VALVE_SHORT, 0x40)] * 3
    assert host.stats.late_drops == 2


@pytest.mark.parametrize(
    "golden",
    ["MGMT_LQI_RSP", "ZCL_REPORT", "ZCL_DEFAULT_RSP", "ZCL_WRITE_RSP"],
)
def test_zdo_zcl_and_reports_are_acked_even_unmatched(golden: str) -> None:
    host, dispatcher = setup()
    npdu = g.ALL_NPDUS[golden]
    feed(dispatcher, with_ack_request(npdu))
    assert len(host.acks) == 1
    assert host.acks[0][0] == int.from_bytes(npdu[4:6], "little")


def test_undecodable_body_behind_a_plausible_header_is_acked() -> None:
    host, dispatcher = setup()
    feed(dispatcher, h("08 02 34 12 6F 5E 1E 50", "40 01 01 02 04 01 01 77", "18"))  # 1-B ZCL
    assert acked_counters(host) == [(g.VALVE_SHORT, 0x77)]
    assert host.stats.decode_errors == 1


def test_source_route_quirk_is_acked() -> None:
    # The NWK codec strips the source-route subframe: the APS header decodes cleanly.
    host, dispatcher = setup()
    feed(dispatcher, with_ack_request(g.QUIRK_SOURCE_ROUTE, aps_offset=12))
    assert len(host.acks) == 1


def test_plain_frames_are_not_acked() -> None:
    host, dispatcher = setup()
    feed(dispatcher, g.ZCL_READ_RSP, g.ZCL_REPORT, g.MGMT_LQI_RSP)
    assert host.acks == []
    assert host.stats.reports == 1


@pytest.mark.parametrize(
    "npdu",
    [
        # garbled header (fallback path): its endpoints/counter are not trusted
        with_ack_request(g.QUIRK_GARBAGE4, aps_offset=12),
        h("08 02 34 12 6F 5E 1E 51", "40 01 01 02 00 01 01 77", "18 2B 01"),  # profile 0x0100
        # NWK broadcast, APS unicast
        with_dst(with_ack_request(g.ZCL_REPORT), 0xFFFD),
        # for another short
        with_dst(with_ack_request(g.ZCL_REPORT), 0x7777),
        # from our own short
        with_src(with_ack_request(g.ZCL_REPORT), g.ZVD_SHORT),
        # APS command frame with ack request
        h("08 02 34 12 6F 5E 1E 52", "41 10 05"),
    ],
    ids=["garbage4", "implausible_profile", "nwk_broadcast", "other_dst", "own_src", "aps_cmd"],
)
async def test_frames_that_are_never_acked(npdu: bytes) -> None:
    host, dispatcher = setup()
    host.pending.register(read_envelope())
    feed(dispatcher, npdu)
    assert host.acks == []


@pytest.mark.parametrize("src", [0xFFFC, 0xFFFD, 0xFFFF, 0xFFF8])
def test_no_ack_to_a_broadcast_or_reserved_source(src: int) -> None:
    # An ack to such a "source" would be a radius-30 mesh broadcast (amplification).
    host, dispatcher = setup()
    feed(dispatcher, with_src(with_ack_request(g.ZCL_REPORT), src))
    assert host.acks == []
    assert host.stats.reports == 1  # still processed


def ieee_report(*, dst_ieee: Eui64 | None, multicast: int | None = None) -> bytes:
    """``ZCL_REPORT`` (ack request) rebuilt with a dst IEEE and/or NWK multicast control."""
    frame = NwkFrame.decode(with_ack_request(g.ZCL_REPORT))
    return dataclasses.replace(frame, dst_ieee=dst_ieee, multicast_control=multicast).encode()


def test_multicast_to_our_short_is_not_acked() -> None:
    host, dispatcher = setup()
    feed(dispatcher, ieee_report(dst_ieee=None, multicast=0x00))
    assert host.acks == []


def test_foreign_dst_ieee_is_not_acked() -> None:
    host, dispatcher = setup()
    feed(dispatcher, ieee_report(dst_ieee=Eui64.from_str("02:00:00:00:00:00:00:99")))
    assert host.acks == []


def test_matching_dst_ieee_is_acked() -> None:
    host, dispatcher = setup()
    feed(dispatcher, ieee_report(dst_ieee=g.ZVD_EUI))
    assert len(host.acks) == 1


@pytest.mark.parametrize("mode", [ApsDeliveryMode.BROADCAST, ApsDeliveryMode.GROUP])
def test_aps_broadcast_and_group_frames_are_not_acked(mode: ApsDeliveryMode) -> None:
    host, dispatcher = setup()
    aps = ApsDataFrame(
        cluster_id=0x0201,
        profile_id=0x0104,
        payload=h("18 2F 0A 00 00 29 AD 07"),
        delivery_mode=mode,
        dst_endpoint=None if mode is ApsDeliveryMode.GROUP else 1,
        group_address=0x0001 if mode is ApsDeliveryMode.GROUP else None,
        src_endpoint=1,
        counter=9,
        ack_request=True,
    )
    feed(dispatcher, h("08 02 34 12 6F 5E 1E 53") + aps.encode())
    assert host.acks == []


def test_nothing_is_acked_before_the_join() -> None:
    host, dispatcher = setup(current_short=None)
    feed(dispatcher, with_ack_request(g.ZCL_REPORT))
    assert host.acks == []


# --- Route Record / Link Status --------------------------------------------------------------


def test_route_record_and_link_status_are_counted_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    host, dispatcher = setup(current_short=0xCB93)
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        feed(dispatcher, VALVE_ROUTE_RECORD, R0_LINK_STATUS, R0_LINK_STATUS)
    assert (host.stats.route_records, host.stats.link_status) == (1, 2)
    assert host.stats.decode_errors == 0
    assert caplog.records == []


def test_route_record_for_another_short_is_dropped() -> None:
    host, dispatcher = setup()  # own short 0x1234; the record is for 0xCB93
    feed(dispatcher, VALVE_ROUTE_RECORD)
    assert host.stats.route_records == 0


def test_truncated_route_record_is_a_decode_error() -> None:
    host, dispatcher = setup(current_short=0xCB93)
    feed(dispatcher, VALVE_ROUTE_RECORD[:-2])
    assert (host.stats.route_records, host.stats.decode_errors) == (0, 1)
