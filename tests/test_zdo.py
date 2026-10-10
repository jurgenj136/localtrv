"""Tests for the ZDO codec (R23 2.4). Dummy shorts/EUIs only."""

from __future__ import annotations

import pytest

from vicare_direct.zigbee_direct.codec.zdo import (
    ActiveEpReq,
    ActiveEpRsp,
    DeviceAnnce,
    IeeeAddrReq,
    IeeeAddrRsp,
    MatchDescReq,
    MatchDescRsp,
    NwkAddrReq,
    NwkAddrRsp,
    SimpleDescReq,
    SimpleDescriptor,
    SimpleDescRsp,
    ZdoCluster,
    ZdoStatus,
)
from vicare_direct.zigbee_direct.codec.zdo_mgmt import (
    DeviceType,
    MgmtLqiReq,
    MgmtLqiRsp,
    Neighbor,
    Relationship,
)
from vicare_direct.zigbee_direct.errors import EncodeError, UnsupportedFrameError, ZdoDecodeError
from vicare_direct.zigbee_direct.types import Eui64

EUI_A = Eui64.from_str("02:00:00:00:00:00:00:0A")
EUI_B = Eui64.from_str("02:00:00:00:00:00:00:0B")
SHORT_A = 0x4A11
SHORT_B = 0x5B22


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


# --------------------------------------------------------------------------- annce


def test_device_annce_layout() -> None:
    frame = DeviceAnnce(seq=1, nwk_addr=SHORT_A, ieee=EUI_A, capability=0x8E)
    wire = frame.encode()
    assert wire == h("01 114A 0A00000000000002 8E")
    assert DeviceAnnce.decode(wire) == frame
    assert DeviceAnnce.CLUSTER_ID == 0x0013


def test_device_annce_strict_length() -> None:
    wire = DeviceAnnce(1, SHORT_A, EUI_A, 0x8E).encode()
    with pytest.raises(ZdoDecodeError, match="trailing"):
        DeviceAnnce.decode(wire + b"\x00")
    with pytest.raises(ZdoDecodeError, match="truncated"):
        DeviceAnnce.decode(wire[:-1])


def test_device_annce_rejects_bad_short() -> None:
    with pytest.raises(EncodeError):
        DeviceAnnce(1, 0x10000, EUI_A, 0x8E).encode()


# --------------------------------------------------------------------------- address


def test_ieee_addr_req_and_rsp() -> None:
    req = IeeeAddrReq(seq=3, nwk_addr=SHORT_A)
    assert req.encode() == h("03 114A 00 00")
    assert IeeeAddrReq.decode(req.encode()) == req
    rsp = IeeeAddrRsp(seq=3, status=0, ieee=EUI_A, nwk_addr=SHORT_A)
    assert rsp.encode() == h("03 00 0A00000000000002 114A")
    assert IeeeAddrRsp.decode(rsp.encode()) == rsp
    assert IeeeAddrRsp.CLUSTER_ID == ZdoCluster.IEEE_ADDR_RSP


def test_nwk_addr_req_and_rsp() -> None:
    req = NwkAddrReq(seq=4, ieee=EUI_B)
    assert req.encode() == h("04 0B00000000000002 00 00")
    assert NwkAddrReq.decode(req.encode()) == req
    rsp = NwkAddrRsp(seq=4, status=0, ieee=EUI_B, nwk_addr=SHORT_B)
    assert NwkAddrRsp.decode(rsp.encode()) == rsp


def test_addr_rsp_non_success_layout() -> None:
    """R23 2.4.4.2.1/2.4.4.2.2: IEEE and NWK fields are present on failure too."""
    wire = h("04 81") + bytes(EUI_B) + h("FFFF")
    rsp = NwkAddrRsp.decode(wire)
    assert rsp == NwkAddrRsp(4, ZdoStatus.DEVICE_NOT_FOUND, EUI_B, 0xFFFF)
    assert rsp.encode() == wire


@pytest.mark.parametrize(
    "tail", ["", "0B000000000000", "0B00000000000002 FF", "0B00000000000002 FFFF 00"]
)
def test_addr_rsp_non_success_rejects_bad_lengths(tail: str) -> None:
    with pytest.raises(ZdoDecodeError):
        NwkAddrRsp.decode(h("04 81" + tail))
    with pytest.raises(ZdoDecodeError):
        IeeeAddrRsp.decode(h("04 81" + tail))


def test_addr_rsp_extended_form_unsupported() -> None:
    wire = IeeeAddrRsp(3, 0, EUI_A, SHORT_A).encode() + h("01 00 224B")
    with pytest.raises(UnsupportedFrameError):
        IeeeAddrRsp.decode(wire)


def test_addr_rsp_success_requires_fields() -> None:
    with pytest.raises(EncodeError):
        IeeeAddrRsp(3, 0, EUI_A, 0x10000).encode()
    with pytest.raises(ZdoDecodeError):
        IeeeAddrRsp.decode(h("03 00 0A000000"))


# --------------------------------------------------------------------------- endpoints


def test_active_ep_req_rsp() -> None:
    req = ActiveEpReq(seq=7, nwk_addr=SHORT_A)
    assert req.encode() == h("07 114A")
    assert ActiveEpReq.decode(req.encode()) == req
    rsp = ActiveEpRsp(seq=7, status=0, nwk_addr=SHORT_A, endpoints=(1, 242))
    assert rsp.encode() == h("07 00 114A 02 01F2")
    assert ActiveEpRsp.decode(rsp.encode()) == rsp


@pytest.mark.parametrize("wire", ["07 00 114A 02 01", "07 00 114A 01 01 02", "07 00 11"])
def test_active_ep_rsp_length_consistency(wire: str) -> None:
    with pytest.raises(ZdoDecodeError):
        ActiveEpRsp.decode(h(wire))


def test_active_ep_rsp_error_form() -> None:
    """R23 2.4.4.2.6.1: failure = status ‖ NWKAddrOfInterest ‖ ActiveEPCount 0."""
    assert ActiveEpRsp.decode(h("07 81 114A 00")) == ActiveEpRsp(7, 0x81, SHORT_A)
    assert ActiveEpRsp(7, 0x81, SHORT_A).encode() == h("07 81 114A 00")
    with pytest.raises(EncodeError):
        ActiveEpRsp(7, 0x81, SHORT_A, (1,)).encode()


@pytest.mark.parametrize(
    "wire",
    ["42 81", "42 81 11", "42 81 114A", "42 81 114A ff", "42 81 114A 01 ff", "42 81 114A 00 00"],
)
def test_endpoint_rsp_error_form_is_exact(wire: str) -> None:
    with pytest.raises(ZdoDecodeError):
        ActiveEpRsp.decode(h(wire))
    with pytest.raises(ZdoDecodeError):
        MatchDescRsp.decode(h(wire))


def test_match_desc_req_rsp() -> None:
    req = MatchDescReq(seq=9, nwk_addr=0xFFFD, profile_id=0x0104, in_clusters=(0x0201,))
    assert req.encode() == h("09 FDFF 0401 01 0102 00")
    assert MatchDescReq.decode(req.encode()) == req
    rsp = MatchDescRsp(seq=9, status=0, nwk_addr=SHORT_B, endpoints=(1,))
    assert MatchDescRsp.decode(rsp.encode()) == rsp
    no_match = MatchDescRsp(seq=9, status=0, nwk_addr=SHORT_B)
    assert MatchDescRsp.decode(no_match.encode()) == no_match
    failed = MatchDescRsp(seq=9, status=ZdoStatus.NOT_SUPPORTED, nwk_addr=SHORT_B)
    assert failed.encode() == h("09 84 225B 00")
    assert MatchDescRsp.decode(failed.encode()) == failed
    with pytest.raises(ZdoDecodeError):
        MatchDescReq.decode(h("09 FDFF 0401 02 0102 00"))


def test_cluster_list_limits() -> None:
    with pytest.raises(EncodeError):
        MatchDescReq(1, 0, 0x0104, in_clusters=tuple(range(256))).encode()
    with pytest.raises(EncodeError):
        ActiveEpRsp(1, 0, 0, endpoints=tuple(range(256))).encode()


# --------------------------------------------------------------------------- simple desc

DESC = SimpleDescriptor(
    endpoint=1,
    profile_id=0x0104,
    device_id=0x0301,
    device_version=1,
    in_clusters=(0x0000, 0x0201),
    out_clusters=(0x000A,),
)
DESC_WIRE = h("01 0401 0103 01 02 0000 0102 01 0A00")


def test_simple_descriptor_layout() -> None:
    assert DESC.encode() == DESC_WIRE
    assert SimpleDescriptor.decode(DESC_WIRE) == DESC


def test_simple_desc_req_rsp() -> None:
    req = SimpleDescReq(seq=8, nwk_addr=SHORT_A, endpoint=1)
    assert req.encode() == h("08 114A 01")
    assert SimpleDescReq.decode(req.encode()) == req
    rsp = SimpleDescRsp(seq=8, status=0, nwk_addr=SHORT_A, descriptor=DESC)
    wire = rsp.encode()
    assert wire == h("08 00 114A") + bytes([len(DESC_WIRE)]) + DESC_WIRE
    assert SimpleDescRsp.decode(wire) == rsp


@pytest.mark.parametrize("delta", [-1, 1])
def test_simple_desc_rsp_length_mismatch(delta: int) -> None:
    body = DESC_WIRE + (b"\x00" if delta > 0 else b"")
    length = len(DESC_WIRE) + delta
    with pytest.raises(ZdoDecodeError):
        SimpleDescRsp.decode(h("08 00 114A") + bytes([length]) + body)


def test_simple_desc_rsp_error_and_empty() -> None:
    """R23 2.4.4.2.5.1: failure = status ‖ NWKAddrOfInterest ‖ Length 0."""
    assert SimpleDescRsp.decode(h("08 82 114A 00")) == SimpleDescRsp(8, 0x82, SHORT_A)
    assert SimpleDescRsp(8, 0x82, SHORT_A).encode() == h("08 82 114A 00")
    with pytest.raises(ZdoDecodeError, match="empty"):
        SimpleDescRsp.decode(h("08 00 114A 00"))
    with pytest.raises(EncodeError):
        SimpleDescRsp(8, 0, SHORT_A).encode()
    with pytest.raises(EncodeError):
        SimpleDescRsp(8, 0x82, SHORT_A, DESC).encode()


@pytest.mark.parametrize(
    "wire", ["08 82", "08 82 11", "08 82 114A", "08 82 114A 01 05", "08 82 114A 00 00"]
)
def test_simple_desc_rsp_error_form_is_exact(wire: str) -> None:
    with pytest.raises(ZdoDecodeError):
        SimpleDescRsp.decode(h(wire))


def test_active_ep_and_simple_desc_are_ambiguous_headerless() -> None:
    """Why the fallback needs the expected kind: one blob decodes as both."""
    blob = h("07 00 114A 01 05")  # Active_EP_rsp: one endpoint (5)
    assert ActiveEpRsp.decode(blob).endpoints == (5,)
    with pytest.raises(ZdoDecodeError):
        SimpleDescRsp.decode(blob)


# --------------------------------------------------------------------------- mgmt lqi

NB = Neighbor(
    extended_pan_id=0x00DEADBEEF000001,
    ieee=EUI_B,
    nwk_addr=SHORT_B,
    device_type=DeviceType.END_DEVICE,
    rx_on_when_idle=False,
    relationship=Relationship.CHILD,
    permit_joining=None,
    depth=2,
    lqi=0xC8,
)
NB_WIRE = h("010000EFBEADDE00 0B00000000000002 225B 12 02 02 C8")


def test_neighbor_record_layout() -> None:
    assert NB.encode() == NB_WIRE
    assert len(NB_WIRE) == 22


def test_mgmt_lqi_req() -> None:
    assert MgmtLqiReq(seq=10, start_index=3).encode() == h("0A 03")
    assert MgmtLqiReq.decode(h("0A 03")) == MgmtLqiReq(10, 3)


def test_mgmt_lqi_rsp_roundtrip() -> None:
    nb2 = NB.__class__(
        extended_pan_id=1,
        ieee=EUI_A,
        nwk_addr=SHORT_A,
        device_type=DeviceType.ROUTER,
        rx_on_when_idle=True,
        relationship=Relationship.SIBLING,
        permit_joining=True,
        depth=1,
        lqi=255,
    )
    rsp = MgmtLqiRsp(seq=10, status=0, neighbor_table_entries=5, start_index=3, neighbors=(NB, nb2))
    wire = rsp.encode()
    assert wire[:5] == h("0A 00 05 03 02")
    assert wire[5:27] == NB_WIRE
    decoded = MgmtLqiRsp.decode(wire)
    assert decoded == rsp
    assert decoded.neighbors[0].rx_on_when_idle is False
    assert decoded.neighbors[0].permit_joining is None
    assert decoded.neighbors[1].rx_on_when_idle is True


def test_mgmt_lqi_rx_on_unknown_tristate() -> None:
    wire = bytearray(MgmtLqiRsp(1, 0, 1, 0, (NB,)).encode())
    wire[5 + 18] = (wire[5 + 18] & ~0x0C) | (2 << 2)
    assert MgmtLqiRsp.decode(bytes(wire)).neighbors[0].rx_on_when_idle is None
    wire[5 + 18] |= 0x0C
    with pytest.raises(ZdoDecodeError, match="reserved"):
        MgmtLqiRsp.decode(bytes(wire))


@pytest.mark.parametrize("mutation", ["extra", "short", "count", "start"])
def test_mgmt_lqi_count_consistency(mutation: str) -> None:
    wire = bytearray(MgmtLqiRsp(1, 0, 2, 0, (NB,)).encode())
    if mutation == "extra":
        wire += b"\x00"
    elif mutation == "short":
        del wire[-1]
    elif mutation == "count":
        wire[4] = 2
    else:
        wire[3] = 2
    with pytest.raises(ZdoDecodeError):
        MgmtLqiRsp.decode(bytes(wire))


def test_mgmt_lqi_rsp_error_and_encode_guard() -> None:
    assert MgmtLqiRsp.decode(h("0A 84")) == MgmtLqiRsp(10, 0x84)
    assert MgmtLqiRsp(10, 0x84).encode() == h("0A 84")
    with pytest.raises(ZdoDecodeError):
        MgmtLqiRsp.decode(h("0A 84 00"))
    with pytest.raises(EncodeError):
        MgmtLqiRsp(10, 0, 0, 0, (NB,)).encode()
    with pytest.raises(EncodeError):
        Neighbor(0, EUI_A, -1, DeviceType.ROUTER, True, 0, False, 0, 0).encode()


@pytest.mark.parametrize(
    ("cls", "wire"),
    [
        (ActiveEpReq, "07 114A 00"),
        (SimpleDescReq, "08 114A"),
        (IeeeAddrReq, "03 114A 00"),
        (NwkAddrReq, "04 0B00"),
        (MgmtLqiReq, "0A"),
        (SimpleDescriptor, "01 0401 0103 01 00 00 00"),
    ],
)
def test_requests_strict_length(cls: type[ActiveEpReq], wire: str) -> None:
    with pytest.raises(ZdoDecodeError):
        cls.decode(h(wire))
