"""Tests for NWK command payloads (R23 3.4) and the Commissioning Request builders."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fixtures import golden as g
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    AssociationType,
    CommissioningRequest,
    CommissioningResponse,
    ManyToOne,
    NetworkStatus,
    NwkCommandId,
    RouteReply,
    RouteRequest,
    UnsupportedNwkCommandError,
    commissioning_request_npdu,
    decode_nwk_command,
    many_to_one_route_request,
    many_to_one_route_request_npdu,
    zvd_commissioning_tlvs,
)
from vicare_local_ble.zigbee_direct.codec.tlv import Tlv
from vicare_local_ble.zigbee_direct.errors import (
    EncodeError,
    NwkDecodeError,
    UnsupportedFrameError,
)
from vicare_local_ble.zigbee_direct.types import Eui64

ZVD_EUI = Eui64.from_str("02:00:00:00:00:00:00:01")
ZDD_EUI = Eui64.from_str("02:00:00:00:00:00:00:02")
VALVE_EUI = Eui64.from_str("02:00:00:00:00:00:00:03")
ZVD_WIRE = "0100000000000002"
ZDD_WIRE = "0200000000000002"
VALVE_WIRE = "0300000000000002"
ZDD_SHORT = 0x5A5A
PLACEHOLDER = 0x1234


# --- Commissioning Request (docs/protocol.md §6.1) --------------------------

EXPECTED_COMMISSIONING_NPDU = bytes.fromhex(
    "0918"  # FC: command, v2, discover route 0; dst + src IEEE
    "5a5a"  # dst short = ZDD
    "3412"  # src short = placeholder
    "01"  # radius 1
    "01" + ZDD_WIRE + ZVD_WIRE + "0e"  # seq  # Commissioning Request
    "00"  # initial join
    "8e"  # capability
    "4816"  # Joiner Encapsulation, 23 bytes
    "41090100" + ZVD_WIRE + "4704341201cf00"  # Fragmentation Parameters
    "4c010100"  # Device Capability Extension
)


def test_commissioning_request_npdu_byte_exact() -> None:
    npdu = commissioning_request_npdu(
        zvd_eui=ZVD_EUI,
        zdd_eui=ZDD_EUI,
        zdd_short=ZDD_SHORT,
        placeholder_short=PLACEHOLDER,
        seq=1,
    )
    assert npdu == EXPECTED_COMMISSIONING_NPDU


def test_commissioning_request_discover_route_variant() -> None:
    npdu = commissioning_request_npdu(
        zvd_eui=ZVD_EUI,
        zdd_eui=ZDD_EUI,
        zdd_short=ZDD_SHORT,
        placeholder_short=PLACEHOLDER,
        seq=1,
        discover_route=1,
    )
    assert npdu[:2] == bytes.fromhex("4918")
    assert npdu[2:] == EXPECTED_COMMISSIONING_NPDU[2:]


def test_commissioning_request_shorts_are_required() -> None:
    with pytest.raises(TypeError):
        commissioning_request_npdu(zvd_eui=ZVD_EUI, zdd_eui=ZDD_EUI, seq=1)  # type: ignore[call-arg]


def test_commissioning_request_decodes_back() -> None:
    frame = NwkFrame.decode(EXPECTED_COMMISSIONING_NPDU)
    assert frame.frame_type is NwkFrameType.COMMAND
    assert frame.radius == 1
    assert frame.security is False
    assert (frame.dst_ieee, frame.src_ieee) == (ZDD_EUI, ZVD_EUI)
    cmd = decode_nwk_command(frame.payload)
    assert cmd == CommissioningRequest(
        association_type=AssociationType.INITIAL_JOIN,
        capability=0x8E,
        tlvs=zvd_commissioning_tlvs(zvd_eui=ZVD_EUI, placeholder_short=PLACEHOLDER),
    )
    assert isinstance(cmd, CommissioningRequest)
    assert cmd.tlvs[0].tag == 0x48
    assert len(cmd.tlvs[0].value) == 0x16 + 1


def test_commissioning_request_truncated_tlv() -> None:
    with pytest.raises(NwkDecodeError, match="commissioning request"):
        CommissioningRequest.decode(bytes.fromhex("0e008e4816aa"))


# --- Commissioning Response -------------------------------------------------


def test_commissioning_response_decode() -> None:
    resp = decode_nwk_command(bytes.fromhex("0f341200"))
    assert resp == CommissioningResponse(short=0x1234, status=0)
    assert isinstance(resp, CommissioningResponse)
    assert resp.success


def test_commissioning_response_with_tlvs_round_trip() -> None:
    resp = CommissioningResponse(short=0x4321, status=0x01, tlvs=(Tlv(0x40, b"\x01\x02"),))
    encoded = resp.encode()
    assert encoded == bytes.fromhex("0f21430140010102")
    decoded = CommissioningResponse.decode(encoded)
    assert decoded == resp
    assert not decoded.success


@pytest.mark.parametrize("data", ["0f3412", "0f34120040", "0e341200"])
def test_commissioning_response_malformed(data: str) -> None:
    with pytest.raises(NwkDecodeError):
        CommissioningResponse.decode(bytes.fromhex(data))


# --- Route Request ----------------------------------------------------------


def test_many_to_one_route_request_bytes() -> None:
    assert many_to_one_route_request(0x50).encode() == bytes.fromhex("010850fcff00")


def test_many_to_one_route_request_npdu() -> None:
    npdu = many_to_one_route_request_npdu(
        route_id=0x51, src_short=PLACEHOLDER, src_ieee=ZVD_EUI, seq=0x28
    )
    assert npdu == bytes.fromhex("0912fcff34121e28" + ZVD_WIRE + "010851fcff00")


def test_route_request_with_dst_ieee_round_trip() -> None:
    data = bytes.fromhex("012077341205" + ZVD_WIRE)
    req = RouteRequest.decode(data)
    assert req == RouteRequest(route_id=0x77, dst=0x1234, path_cost=5, dst_ieee=ZVD_EUI)
    assert req.encode() == data


def test_route_request_options_and_trailing_tlvs() -> None:
    req = RouteRequest(
        route_id=1,
        dst=0xFFFC,
        many_to_one=ManyToOne.WITHOUT_ROUTE_RECORD_TABLE,
        multicast=True,
        tlvs=b"\x00\x00\x01",
    )
    assert req.options == 0x50
    assert RouteRequest.decode(req.encode()) == req


@pytest.mark.parametrize(
    ("data", "match"),
    [
        ("0118010000", "too short"),
        ("011801fcff00", "reserved"),
        ("012001341200aabb", "dst IEEE"),
        ("020801fcff00", "not a ROUTE_REQUEST"),
    ],
)
def test_route_request_malformed(data: str, match: str) -> None:
    with pytest.raises(NwkDecodeError, match=match):
        RouteRequest.decode(bytes.fromhex(data))


# --- Route Reply ------------------------------------------------------------


@pytest.mark.parametrize(
    ("orig", "resp", "options", "tail"),
    [
        (None, None, 0x00, ""),
        (VALVE_EUI, None, 0x10, VALVE_WIRE),
        (None, ZVD_EUI, 0x20, ZVD_WIRE),
        (VALVE_EUI, ZVD_EUI, 0x30, VALVE_WIRE + ZVD_WIRE),
    ],
)
def test_route_reply_ieee_presence_combinations(
    orig: Eui64 | None, resp: Eui64 | None, options: int, tail: str
) -> None:
    reply = RouteReply(
        route_id=0x42,
        originator=0x4B4B,
        responder=PLACEHOLDER,
        path_cost=0,
        originator_ieee=orig,
        responder_ieee=resp,
    )
    expected = bytes((0x02, options)) + bytes.fromhex("424b4b341200" + tail)
    assert reply.options == options
    assert reply.encode() == expected
    assert RouteReply.decode(expected) == reply


def test_route_reply_both_euis_is_0x30_spec_correct() -> None:
    """Research sent 0x20 with both EUIs live; spec-correct 0x30 is unverified live."""
    reply = RouteReply(1, 0x4B4B, PLACEHOLDER, originator_ieee=VALVE_EUI, responder_ieee=ZVD_EUI)
    assert reply.encode()[1] == 0x30


def test_route_reply_options_override_matches_golden_live_payload() -> None:
    reply = RouteReply(
        route_id=7,
        originator=g.VALVE_SHORT,
        responder=g.ZVD_SHORT,
        originator_ieee=g.VALVE_EUI,
        responder_ieee=g.ZVD_EUI,
        options_override=0x20,
    )
    payload = reply.encode()
    assert payload == g.RREP_LIVE[-len(payload) :]  # 02 20 rid orig own 00 EUI_orig EUI_own
    assert payload[:3] == bytes.fromhex("022007")
    assert reply.options == 0x30  # derived value untouched
    spec = replace(reply, options_override=None)
    assert spec.encode()[1] == 0x30
    assert spec.encode()[2:] == payload[2:]  # only the options byte differs


def test_route_reply_options_override_validation_and_decode_ignores_it() -> None:
    with pytest.raises(EncodeError):
        RouteReply(1, 2, 3, options_override=0x100)
    reply = RouteReply(1, 2, 3, originator_ieee=VALVE_EUI, options_override=0x20)
    assert RouteReply.decode(reply.encode()).options_override is None


def test_route_reply_multicast_and_path_cost() -> None:
    reply = RouteReply(9, 1, 2, path_cost=7, multicast=True, tlvs=b"\xaa")
    assert reply.encode() == bytes.fromhex("0240090100020007aa")
    assert decode_nwk_command(reply.encode()) == reply


@pytest.mark.parametrize(
    "data", ["02000101000200", "02100101000200000102", "02300101000200" + "00"]
)
def test_route_reply_truncated(data: str) -> None:
    with pytest.raises(NwkDecodeError):
        RouteReply.decode(bytes.fromhex(data))


# --- Network Status / dispatcher -------------------------------------------


def test_network_status_round_trip() -> None:
    status = decode_nwk_command(bytes.fromhex("03023412"))
    assert status == NetworkStatus(status=0x02, destination=0x1234)
    assert isinstance(status, NetworkStatus)
    assert status.encode() == bytes.fromhex("03023412")
    with pytest.raises(NwkDecodeError):
        NetworkStatus.decode(b"\x03\x02\x34")


def test_dispatcher_unknown_command() -> None:
    with pytest.raises(UnsupportedNwkCommandError) as info:
        decode_nwk_command(bytes((NwkCommandId.LEAVE, 0x00)))
    assert info.value.command_id == 0x04
    assert isinstance(info.value, UnsupportedFrameError)


def test_dispatcher_empty_payload() -> None:
    with pytest.raises(NwkDecodeError):
        decode_nwk_command(b"")


def test_dispatcher_route_request() -> None:
    assert decode_nwk_command(bytes.fromhex("010850fcff00")) == many_to_one_route_request(0x50)


@pytest.mark.parametrize(
    "build",
    [
        lambda: RouteRequest(route_id=256, dst=0),
        lambda: RouteReply(0, 0x10000, 0),
        lambda: NetworkStatus(0x100, 0),
        lambda: CommissioningRequest(0, 0x100),
        lambda: CommissioningResponse(-1, 0),
        lambda: zvd_commissioning_tlvs(zvd_eui=ZVD_EUI, placeholder_short=0x10000),
    ],
)
def test_encode_validation(build: object) -> None:
    assert callable(build)
    with pytest.raises(EncodeError):
        build()
