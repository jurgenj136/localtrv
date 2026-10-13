"""APS ack frame codec (R23 2.2.5.2.3, ack format 0) and the ack NPDU builder."""

from __future__ import annotations

import pytest

from fixtures import golden as g
from vicare_local_ble.zigbee_direct.codec.aps import (
    APS_ACK_LENGTH,
    HA_PROFILE_ID,
    ZDO_PROFILE_ID,
    ApsAckFrame,
    ApsDataFrame,
    ApsDeliveryMode,
    ApsFrameControl,
    ApsFrameType,
)
from vicare_local_ble.zigbee_direct.codec.nwk import DISCOVER_ROUTE_ENABLE, NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.errors import ApsDecodeError, EncodeError, UnsupportedFrameError
from vicare_local_ble.zigbee_direct.frames import aps_ack_npdu

h = g.h

#: Live valve response header (APS FC 0x40: data, unicast, ack request), counter 0x51.
LIVE_VALVE_APS = h("40 01 0102 0401 01 51")
#: Its ack: FC 0x02, endpoints swapped (both 1), cluster/profile/counter echoed.
LIVE_VALVE_ACK = h("02 01 0102 0401 01 51")


def live_response() -> ApsDataFrame:
    return ApsDataFrame.decode(LIVE_VALVE_APS + h("08 03 01 0000 00 29 3608"))


def test_live_valve_response_requests_an_ack() -> None:
    aps = live_response()
    assert aps.ack_request is True
    assert (aps.dst_endpoint, aps.cluster_id, aps.profile_id) == (1, 0x0201, HA_PROFILE_ID)
    assert (aps.src_endpoint, aps.counter) == (1, 0x51)


def test_ack_of_the_live_valve_response_matches_spec_layout() -> None:
    ack = ApsAckFrame.for_frame(live_response())
    assert ack.encode() == LIVE_VALVE_ACK
    assert len(LIVE_VALVE_ACK) == APS_ACK_LENGTH
    fc = ApsFrameControl.from_byte(LIVE_VALVE_ACK[0])
    assert fc.frame_type is ApsFrameType.ACK
    assert fc.delivery_mode == 0
    assert not fc.ack_format
    assert not fc.ack_request
    assert not fc.security
    assert ApsAckFrame.decode(LIVE_VALVE_ACK) == ack


def test_for_frame_swaps_endpoints_and_echoes_the_counter() -> None:
    aps = ApsDataFrame(
        cluster_id=0x8031,
        profile_id=ZDO_PROFILE_ID,
        payload=b"\x04\x00",
        dst_endpoint=0x0B,
        src_endpoint=0x0A,
        counter=0xFE,
        ack_request=True,
    )
    ack = ApsAckFrame.for_frame(aps)
    assert ack == ApsAckFrame(
        dst_endpoint=0x0A, cluster_id=0x8031, profile_id=0, src_endpoint=0x0B, counter=0xFE
    )
    assert ack.encode() == h("02 0A 3180 0000 0B FE")


@pytest.mark.parametrize(
    "aps",
    [
        ApsDataFrame(0x0006, HA_PROFILE_ID, b"", delivery_mode=ApsDeliveryMode.BROADCAST),
        ApsDataFrame(
            0x0006,
            HA_PROFILE_ID,
            b"",
            delivery_mode=ApsDeliveryMode.GROUP,
            dst_endpoint=None,
            group_address=0x1234,
        ),
    ],
    ids=["broadcast", "group"],
)
def test_only_unicast_frames_are_acked(aps: ApsDataFrame) -> None:
    with pytest.raises(EncodeError, match="unicast"):
        ApsAckFrame.for_frame(aps)


@pytest.mark.parametrize(
    ("wire", "error", "match"),
    [
        (h("40 01 0102 0401 01 51"), ApsDecodeError, "DATA"),  # a data frame
        (h("12 51"), UnsupportedFrameError, "ack format 1"),  # command ack
        (h("22 01 0102 0401 01 51"), UnsupportedFrameError, "secured"),
        (h("82 01 0102 0401 01 51"), UnsupportedFrameError, "extended"),
        (h("0A 01 0102 0401 01 51"), ApsDecodeError, "unicast"),  # broadcast delivery
        (h("02 01 0102 0401 01"), ApsDecodeError, "truncated"),
        (h("02 01 0102 0401 01 51 00"), ApsDecodeError, "trailing"),
        (b"", ApsDecodeError, "truncated"),
    ],
)
def test_decode_rejects(wire: bytes, error: type[Exception], match: str) -> None:
    with pytest.raises(error, match=match):
        ApsAckFrame.decode(wire)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dst_endpoint": 256},
        {"cluster_id": -1},
        {"profile_id": 0x10000},
        {"src_endpoint": True},
        {"counter": 256},
    ],
)
def test_field_ranges(kwargs: dict[str, int]) -> None:
    base = {"dst_endpoint": 1, "cluster_id": 0, "profile_id": 0, "src_endpoint": 1, "counter": 0}
    with pytest.raises(EncodeError):
        ApsAckFrame(**(base | kwargs))


def test_data_frame_decoder_still_refuses_acks() -> None:
    with pytest.raises(UnsupportedFrameError, match="ACK"):
        ApsDataFrame.decode(LIVE_VALVE_ACK)


def test_aps_ack_npdu_layout() -> None:
    npdu = aps_ack_npdu(
        dst=g.VALVE_SHORT, own_short=g.ZVD_SHORT, nwk_seq=0x42, inbound=live_response()
    )
    # NWK 48 02 <dst> <own> 1E seq: data, discover route, security bit (as every unicast).
    assert npdu == h("48 02 6F 5E 34 12 1E 42") + LIVE_VALVE_ACK
    frame = NwkFrame.decode(npdu)
    assert frame.frame_type is NwkFrameType.DATA
    assert frame.discover_route == DISCOVER_ROUTE_ENABLE
    assert frame.security is True
    assert (frame.dst, frame.src, frame.radius) == (g.VALVE_SHORT, g.ZVD_SHORT, 30)
