"""frames.py: production builders emit the hand-written golden bytes exactly."""

from __future__ import annotations

from fixtures import golden as g
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID
from vicare_local_ble.zigbee_direct.codec.nwk_commands import many_to_one_route_request_npdu
from vicare_local_ble.zigbee_direct.codec.zcl import (
    AttributeRecord,
    ReadAttributes,
    WriteAttributes,
    ZclFrame,
)
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiReq
from vicare_local_ble.zigbee_direct.frames import (
    DEFAULT_RADIUS,
    LOCAL_ENDPOINT,
    device_annce_npdu,
    zcl_unicast_npdu,
    zdo_unicast_npdu,
)

THERMOSTAT = 0x0201


def zcl(nwk_seq: int, tsn: int, frame: ZclFrame) -> bytes:
    """Golden ZCL frames use APS counter = TSN (live)."""
    return zcl_unicast_npdu(
        dst=g.VALVE_SHORT,
        own_short=g.ZVD_SHORT,
        nwk_seq=nwk_seq,
        dst_endpoint=1,
        cluster_id=THERMOSTAT,
        profile_id=HA_PROFILE_ID,
        zcl_frame=frame.encode(),
        aps_counter=tsn,
    )


def test_constants() -> None:
    assert (DEFAULT_RADIUS, LOCAL_ENDPOINT) == (30, 1)


def test_device_annce() -> None:
    npdu = device_annce_npdu(
        own_short=g.ZVD_SHORT, own_eui=g.ZVD_EUI, nwk_seq=2, zdo_seq=1, aps_counter=0
    )
    assert npdu == g.DEVICE_ANNCE


def test_mtorr() -> None:
    npdu = many_to_one_route_request_npdu(
        route_id=1, src_short=g.ZVD_SHORT, src_ieee=g.ZVD_EUI, seq=3, radius=DEFAULT_RADIUS
    )
    assert npdu == g.MTORR


def test_zdo_unicast_mgmt_lqi() -> None:
    npdu = zdo_unicast_npdu(
        dst=0x0000,
        own_short=g.ZVD_SHORT,
        nwk_seq=5,
        cluster_id=MgmtLqiReq.CLUSTER_ID,
        zdo_payload=MgmtLqiReq(seq=0x0A, start_index=0).encode(),
    )
    assert npdu == g.MGMT_LQI_REQ  # APS counter 0 by default


def test_zcl_read() -> None:
    frame = ZclFrame.build(0x2B, ReadAttributes((0x0000, 0x0008, 0x0012, 0x001C)))
    assert zcl(6, 0x2B, frame) == g.ZCL_READ


def test_zcl_read_manufacturer_specific() -> None:
    frame = ZclFrame.build(0x2C, ReadAttributes((0x4000,)), manufacturer_code=0x1221)
    assert zcl(7, 0x2C, frame) == g.ZCL_READ_MFR


def test_zcl_write() -> None:
    record = AttributeRecord(0x0012, ZclDataType.INT16, 2150)
    frame = ZclFrame.build(0x2D, WriteAttributes((record,)))
    assert zcl(8, 0x2D, frame) == g.ZCL_WRITE
