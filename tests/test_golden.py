"""Golden wire fixtures decode with the phase-1 decoders; phase-1 encoders reproduce them.

The fixtures (``tests/fixtures/golden.py``) are hand-written from the PN. Production NPDU
builders (``zigbee_direct.frames``) are asserted against them by T11/T12; here only phase-1
codecs are used, composed by hand.
"""

from __future__ import annotations

import pytest

from fixtures import golden as g
from vicare_local_ble.testing import FakeZdd
from vicare_local_ble.zigbee_direct.codec.aps import (
    HA_PROFILE_ID,
    ZDO_PROFILE_ID,
    ApsDataFrame,
    ApsDeliveryMode,
)
from vicare_local_ble.zigbee_direct.codec.fallback import ExpectedZcl, ScanMatch, scan_for_response
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType, SourceRoute
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningRequest,
    CommissioningResponse,
    ManyToOne,
    NetworkStatus,
    RouteReply,
    RouteRequest,
    commissioning_request_npdu,
    decode_nwk_command,
    many_to_one_route_request_npdu,
)
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
from vicare_local_ble.zigbee_direct.codec.zcl import (
    AttributeRecord,
    DefaultResponse,
    ReadAttributes,
    ReadAttributesResponse,
    ReadAttributeStatus,
    ReportAttributes,
    WriteAttributes,
    WriteAttributesResponse,
    WriteAttributeStatus,
    ZclDirection,
    ZclFrame,
)
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import (
    ActiveEpRsp,
    DeviceAnnce,
    SimpleDescriptor,
    SimpleDescRsp,
)
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import (
    DeviceType,
    MgmtLqiReq,
    MgmtLqiRsp,
    Neighbor,
    Relationship,
)
from vicare_local_ble.zigbee_direct.crypto import SecretType
from vicare_local_ble.zigbee_direct.session import (
    OPCODE_SE1,
    OPCODE_SE2,
    OPCODE_SE3,
    OPCODE_SE4,
    TLV_C25519_POINT,
    TLV_MAC_TAG,
    TLV_SELECTED_METHOD,
    HandshakeInitiator,
    parse_handshake_message,
)
from vicare_local_ble.zigbee_direct.types import BROADCAST_ROUTERS, BROADCAST_RX_ON, SecretBytes

DUMMY_PSK = SecretBytes(bytes(range(0x40, 0x50)))
THERMOSTAT = 0x0201


def nwk(raw: bytes) -> NwkFrame:
    return NwkFrame.decode(raw)


def aps(raw: bytes) -> ApsDataFrame:
    return ApsDataFrame.decode(nwk(raw).payload)


def zcl(raw: bytes) -> ZclFrame:
    return ZclFrame.decode(aps(raw).payload)


def post_join(dst: int, seq: int, payload: bytes, *, frame_type: NwkFrameType) -> NwkFrame:
    """The live post-join NWK header: discover_route 1, security, radius 30, src = us."""
    return NwkFrame(
        frame_type=frame_type,
        dst=dst,
        src=g.ZVD_SHORT,
        radius=30,
        seq=seq,
        payload=payload,
        discover_route=1,
        security=True,
    )


def thermostat_aps(counter: int, payload: bytes) -> ApsDataFrame:
    return ApsDataFrame(
        cluster_id=THERMOSTAT,
        profile_id=HA_PROFILE_ID,
        payload=payload,
        dst_endpoint=1,
        src_endpoint=1,
        counter=counter,
    )


@pytest.mark.parametrize("name", sorted(g.ALL_NPDUS))
def test_every_npdu_decodes_as_nwk_and_reencodes(name: str) -> None:
    raw = g.ALL_NPDUS[name]
    frame = nwk(raw)
    assert frame.encode() == raw


# --- PN §1.1 -------------------------------------------------------------------------------


def test_se1_layout_matches_handshake_initiator() -> None:
    assert len(g.SE1) == 47
    tlvs = parse_handshake_message(
        g.SE1, opcode=OPCODE_SE1, known={TLV_SELECTED_METHOD: 2, TLV_C25519_POINT: 40}
    )
    assert tlvs[TLV_SELECTED_METHOD] == bytes([1, SecretType.BASIC_AUTHORIZATION_KEY])
    assert tlvs[TLV_C25519_POINT][:8] == g.ZVD_EUI.wire
    se1 = HandshakeInitiator(
        own_eui=g.ZVD_EUI, psk=DUMMY_PSK, secret_type=SecretType.BASIC_AUTHORIZATION_KEY
    ).start()
    # Everything but the 32-byte public point (random per handshake) is byte-identical.
    assert len(se1) == len(g.SE1)
    assert se1[:-32] == g.SE1[:-32]


def test_se2_layout_matches_fake_zdd() -> None:
    tlvs = parse_handshake_message(g.SE2, opcode=OPCODE_SE2, known={TLV_C25519_POINT: 40})
    assert tlvs[TLV_C25519_POINT][:8] == g.ZDD_EUI.wire
    se1 = HandshakeInitiator(
        own_eui=g.ZVD_EUI, psk=DUMMY_PSK, secret_type=SecretType.BASIC_AUTHORIZATION_KEY
    ).start()
    se2 = FakeZdd(eui=g.ZDD_EUI, psk=DUMMY_PSK).handle_se1(se1)
    assert len(se2) == len(g.SE2)
    assert se2[:-32] == g.SE2[:-32]


@pytest.mark.parametrize(("raw", "opcode"), [(g.SE3, OPCODE_SE3), (g.SE4, OPCODE_SE4)])
def test_se3_se4_layout(raw: bytes, opcode: int) -> None:
    tlvs = parse_handshake_message(raw, opcode=opcode, known={TLV_MAC_TAG: 16})
    assert len(tlvs[TLV_MAC_TAG]) == 16
    assert len(raw) == 19


# --- PN §1.3 -------------------------------------------------------------------------------


def test_commissioning_request_equals_phase1_builder() -> None:
    assert len(g.COMMISSIONING_REQUEST) == 52
    built = commissioning_request_npdu(
        zvd_eui=g.ZVD_EUI,
        zdd_eui=g.ZDD_EUI,
        zdd_short=g.ZDD_SHORT,
        placeholder_short=g.ZVD_SHORT,
        seq=1,
    )
    assert built == g.COMMISSIONING_REQUEST
    frame = nwk(g.COMMISSIONING_REQUEST)
    assert (frame.frame_type, frame.discover_route, frame.radius) == (NwkFrameType.COMMAND, 0, 1)
    assert (frame.dst_ieee, frame.src_ieee, frame.security) == (g.ZDD_EUI, g.ZVD_EUI, False)
    req = CommissioningRequest.decode(frame.payload)
    assert (req.association_type, req.capability) == (0, 0x8E)
    assert [t.tag for t in req.tlvs] == [0x48]


def test_tunnel_tlv_wraps_commissioning_request() -> None:
    tlv = TunnelNpdu.decode(g.TUNNEL_COMMISSIONING_REQUEST)
    assert tlv == TunnelNpdu(g.COMMISSIONING_REQUEST, nwk_security=False)
    assert tlv.encode() == g.TUNNEL_COMMISSIONING_REQUEST


def test_commissioning_responses_decode() -> None:
    frame = nwk(g.COMMISSIONING_RESPONSE)
    assert (frame.src, frame.dst, frame.dst_ieee) == (g.ZDD_SHORT, g.ZVD_SHORT, g.ZVD_EUI)
    rsp = decode_nwk_command(frame.payload)
    assert rsp == CommissioningResponse(short=g.ZVD_SHORT, status=0)
    assert rsp.encode() == frame.payload
    other = nwk(g.COMMISSIONING_RESPONSE_OTHER)
    assert other.dst == g.OTHER_PLACEHOLDER
    assert other.dst_ieee is None
    assert decode_nwk_command(other.payload) == CommissioningResponse(g.OTHER_PLACEHOLDER, 0)


# --- PN §1.4 -------------------------------------------------------------------------------


def test_device_annce_decodes_and_composes() -> None:
    frame = nwk(g.DEVICE_ANNCE)
    assert (frame.dst, frame.discover_route, frame.security) == (BROADCAST_RX_ON, 1, True)
    frame_aps = aps(g.DEVICE_ANNCE)
    assert frame_aps.delivery_mode is ApsDeliveryMode.BROADCAST
    assert (frame_aps.cluster_id, frame_aps.profile_id) == (0x0013, ZDO_PROFILE_ID)
    annce = DeviceAnnce.decode(frame_aps.payload)
    assert annce == DeviceAnnce(seq=1, nwk_addr=g.ZVD_SHORT, ieee=g.ZVD_EUI, capability=0x8E)
    composed = post_join(
        BROADCAST_RX_ON,
        2,
        ApsDataFrame(
            cluster_id=0x0013,
            profile_id=ZDO_PROFILE_ID,
            payload=annce.encode(),
            delivery_mode=ApsDeliveryMode.BROADCAST,
            counter=0,
        ).encode(),
        frame_type=NwkFrameType.DATA,
    ).encode()
    assert composed == g.DEVICE_ANNCE


def test_mtorr_equals_phase1_builder() -> None:
    built = many_to_one_route_request_npdu(
        route_id=1, src_short=g.ZVD_SHORT, src_ieee=g.ZVD_EUI, seq=3
    )
    assert built == g.MTORR
    rreq = decode_nwk_command(nwk(g.MTORR).payload)
    assert isinstance(rreq, RouteRequest)
    assert (rreq.dst, rreq.many_to_one) == (BROADCAST_ROUTERS, ManyToOne.WITH_ROUTE_RECORD_TABLE)


def test_rrep_live_shows_why_options_override_exists() -> None:
    """Spec-derived decode reads the live 0x20 frame as 'responder IEEE only' (PN §5.1)."""
    frame = nwk(g.RREP_LIVE)
    assert (frame.frame_type, frame.discover_route, frame.security) == (
        NwkFrameType.COMMAND,
        1,
        True,
    )
    assert g.RREP_LIVE[:2] == bytes.fromhex("4902")
    rrep = RouteReply.decode(frame.payload)
    assert (rrep.route_id, rrep.originator, rrep.responder) == (7, g.VALVE_SHORT, g.ZVD_SHORT)
    assert rrep.originator_ieee is None
    assert rrep.responder_ieee == g.VALVE_EUI  # misread: this is the originator's EUI
    assert rrep.tlvs == g.ZVD_EUI.wire  # the real responder EUI ends up as "TLVs"


def test_rrep_spec_equals_phase1_composition() -> None:
    reply = RouteReply(
        route_id=7,
        originator=g.VALVE_SHORT,
        responder=g.ZVD_SHORT,
        originator_ieee=g.VALVE_EUI,
        responder_ieee=g.ZVD_EUI,
    )
    assert reply.options == 0x30
    composed = post_join(g.VALVE_SHORT, 4, reply.encode(), frame_type=NwkFrameType.COMMAND)
    assert composed.encode() == g.RREP_SPEC
    assert RouteReply.decode(nwk(g.RREP_SPEC).payload) == reply
    # LIVE differs from SPEC only in the options byte.
    assert g.RREP_LIVE.replace(b"\x02\x20\x07", b"\x02\x30\x07", 1) == g.RREP_SPEC


def test_rreq_from_valve_decodes() -> None:
    frame = nwk(g.RREQ_FROM_VALVE)
    assert (frame.src, frame.src_ieee) == (g.VALVE_SHORT, g.VALVE_EUI)
    rreq = decode_nwk_command(frame.payload)
    assert rreq == RouteRequest(route_id=7, dst=g.ZVD_SHORT, dst_ieee=g.ZVD_EUI)
    bare = nwk(g.RREQ_NO_SRC_IEEE)
    assert bare.src_ieee is None
    assert decode_nwk_command(bare.payload) == RouteRequest(8, g.ZVD_SHORT, dst_ieee=g.ZVD_EUI)


def test_mgmt_lqi_req_zdo_unicast_with_aps_counter_zero() -> None:
    frame_aps = aps(g.MGMT_LQI_REQ)
    assert (frame_aps.cluster_id, frame_aps.counter, frame_aps.dst_endpoint) == (0x0031, 0, 0)
    req = MgmtLqiReq.decode(frame_aps.payload)
    assert req == MgmtLqiReq(seq=10, start_index=0)
    composed = post_join(
        0x0000,
        5,
        ApsDataFrame(cluster_id=0x0031, profile_id=ZDO_PROFILE_ID, payload=req.encode()).encode(),
        frame_type=NwkFrameType.DATA,
    ).encode()
    assert composed == g.MGMT_LQI_REQ


def test_mgmt_lqi_rsp_decodes() -> None:
    frame_aps = aps(g.MGMT_LQI_RSP)
    assert frame_aps.cluster_id == 0x8031
    rsp = MgmtLqiRsp.decode(frame_aps.payload)
    assert (rsp.status, rsp.neighbor_table_entries, rsp.start_index) == (0, 3, 0)
    valve, r0 = rsp.neighbors
    assert valve == Neighbor(
        extended_pan_id=g.EXT_PAN.as_int(),
        ieee=g.VALVE_EUI,
        nwk_addr=g.VALVE_SHORT,
        device_type=DeviceType.END_DEVICE,
        rx_on_when_idle=False,
        relationship=Relationship.CHILD,
        permit_joining=None,
        depth=1,
        lqi=0xB4,
    )
    assert (r0.ieee, r0.nwk_addr, r0.device_type, r0.rx_on_when_idle) == (
        g.ZDD_EUI,
        g.ZDD_SHORT,
        DeviceType.ROUTER,
        True,
    )
    assert rsp.encode() == frame_aps.payload


def test_active_ep_and_simple_desc() -> None:
    assert ActiveEpRsp.decode(g.ACTIVE_EP_RSP_ZDO) == ActiveEpRsp(0x0B, 0, g.VALVE_SHORT, (1,))
    desc = SimpleDescriptor(
        endpoint=1,
        profile_id=HA_PROFILE_ID,
        device_id=0x0301,
        in_clusters=(0x0000, 0x0001, 0x0003, 0x000A, 0x0020, 0x0201, 0x0204, 0x0B05),
        out_clusters=(0x0000, 0x0019),
    )
    rsp = SimpleDescRsp(0x0C, 0, g.VALVE_SHORT, desc)
    assert SimpleDescRsp.decode(g.SIMPLE_DESC_RSP_ZDO) == rsp
    assert rsp.encode() == g.SIMPLE_DESC_RSP_ZDO


# --- PN §1.6 -------------------------------------------------------------------------------


def test_zcl_read_equals_phase1_composition() -> None:
    read = ReadAttributes((0x0000, 0x0008, 0x0012, 0x001C))
    zcl_bytes = ZclFrame.build(0x2B, read).encode()
    assert zcl_bytes[:3] == bytes.fromhex("002B00")
    composed = post_join(
        g.VALVE_SHORT, 6, thermostat_aps(0x2B, zcl_bytes).encode(), frame_type=NwkFrameType.DATA
    )
    assert composed.encode() == g.ZCL_READ
    assert zcl(g.ZCL_READ).global_command() == read


def test_zcl_mfr_read_equals_phase1_composition() -> None:
    frame = zcl(g.ZCL_READ_MFR)
    assert frame.header.manufacturer_code == 0x1221
    built = ZclFrame.build(0x2C, ReadAttributes((0x4000,)), manufacturer_code=0x1221).encode()
    assert built == aps(g.ZCL_READ_MFR).payload
    assert built[:5] == bytes.fromhex("0421122C00")


def test_zcl_read_response_values() -> None:
    frame = zcl(g.ZCL_READ_RSP)
    assert frame.header.direction is ZclDirection.SERVER_TO_CLIENT
    rsp = frame.global_command()
    assert isinstance(rsp, ReadAttributesResponse)
    assert rsp.records == (
        ReadAttributeStatus(0x0000, 0, ZclDataType.INT16, 1965),  # 19.65 °C
        ReadAttributeStatus(0x0008, 0, ZclDataType.UINT8, 2),
        ReadAttributeStatus(0x0012, 0, ZclDataType.INT16, 2200),
        ReadAttributeStatus(0x001C, 0, ZclDataType.ENUM8, 9),
    )
    assert aps(g.ZCL_READ_RSP).payload[3:9] == bytes.fromhex("00000029AD07")


@pytest.mark.parametrize(
    ("raw", "mfr"), [(g.ZCL_READ_RSP_MFR, 0x1221), (g.ZCL_READ_RSP_MFR_NO_HEADER, None)]
)
def test_zcl_mfr_read_responses(raw: bytes, mfr: int | None) -> None:
    frame = zcl(raw)
    assert frame.header.manufacturer_code == mfr
    assert frame.header.tsn == 0x2C
    assert frame.global_command() == ReadAttributesResponse(
        (ReadAttributeStatus(0x4000, 0, ZclDataType.ENUM8, 1),)
    )


def test_zcl_write_and_response() -> None:
    record = AttributeRecord(0x0012, ZclDataType.INT16, 2150)
    built = ZclFrame.build(0x2D, WriteAttributes((record,))).encode()
    assert built == aps(g.ZCL_WRITE).payload
    assert built[:6] == bytes.fromhex("002D02120029")
    rsp = zcl(g.ZCL_WRITE_RSP).global_command()
    assert rsp == WriteAttributesResponse((WriteAttributeStatus(0),))
    assert aps(g.ZCL_WRITE_RSP).payload[2:] == bytes.fromhex("0400")


def test_zcl_default_response() -> None:
    frame_aps = aps(g.ZCL_DEFAULT_RSP)
    assert frame_aps.cluster_id == 0x0004
    frame = ZclFrame.decode(frame_aps.payload)
    assert frame.global_command() == DefaultResponse(command_id=0x00, status=0xC3)


def test_zcl_report() -> None:
    assert zcl(g.ZCL_REPORT).global_command() == ReportAttributes(
        (AttributeRecord(0x0000, ZclDataType.INT16, 1965),)
    )


# --- quirk and network status ----------------------------------------------------------------


def test_source_route_quirk_decodes_through_standard_path() -> None:
    frame = nwk(g.QUIRK_SOURCE_ROUTE)
    assert frame.source_route == SourceRoute(relay_index=0, relays=(g.ZDD_SHORT,))
    frame_aps = ApsDataFrame.decode(frame.payload)
    assert frame_aps.cluster_id == THERMOSTAT
    assert ZclFrame.decode(frame_aps.payload).header.tsn == 0x2B


def test_garbage4_quirk_needs_the_fallback_at_offset_12() -> None:
    frame = nwk(g.QUIRK_GARBAGE4)
    assert frame.source_route is None
    expected = ExpectedZcl(
        src_short=g.VALVE_SHORT, tsn=0x2B, command_id=0x01, cluster_id=THERMOSTAT
    )
    match = scan_for_response(frame.payload, expected, src_short=frame.src)
    assert isinstance(match, ScanMatch)
    assert match.offset == 12
    assert match.response == ReadAttributesResponse(
        (ReadAttributeStatus(0x0000, 0, ZclDataType.INT16, 1965),)
    )


@pytest.mark.parametrize(
    ("raw", "status", "dst"),
    [
        (g.NETWORK_STATUS_NO_ROUTE, 0x02, g.VALVE_SHORT),
        (g.NETWORK_STATUS_CONFLICT, 0x0D, g.ZVD_SHORT),
    ],
)
def test_network_status(raw: bytes, status: int, dst: int) -> None:
    assert decode_nwk_command(nwk(raw).payload) == NetworkStatus(status=status, destination=dst)
