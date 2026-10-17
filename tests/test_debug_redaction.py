"""Structural EUI redaction of the NPDU recorder.

Dummy identities only. The golden fixtures use ``02:00:..:NN`` EUIs, which have the same shape
as the recorder's pseudonyms, so the leak tests run on copies of the golden frames whose EUIs
are swapped for distinct dummies under the documentation OUI ``AC:DE:48``.
"""

from __future__ import annotations

import pytest

from fixtures import golden as g
from localtrv.zigbee_direct.codec.aps import ApsDataFrame
from localtrv.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from localtrv.zigbee_direct.codec.nwk_commands import RouteReply, decode_nwk_command
from localtrv.zigbee_direct.codec.zcl import ZclFrame
from localtrv.zigbee_direct.debug import EuiPseudonymizer, RedactedNpdu, redact_npdu
from localtrv.zigbee_direct.redact import inspect_npdu
from localtrv.zigbee_direct.types import Eui64

h = g.h

# --- distinct dummy identities (not pseudonym-shaped) ----------------------------------------

EUI_A = Eui64.from_str("AC:DE:48:00:00:00:00:0A")
EUI_B = Eui64.from_str("AC:DE:48:00:00:00:00:0B")
EUI_C = Eui64.from_str("AC:DE:48:00:00:00:00:0C")
EUI_D = Eui64.from_str("AC:DE:48:00:00:00:00:0D")
PAN_X = Eui64.from_str("AC:DE:48:FF:FF:FF:FF:0E")
A, B = EUI_A.wire.hex(), EUI_B.wire.hex()
X = PAN_X.wire.hex()

P1 = "0100000000000002"  # wire of 02:00:00:00:00:00:00:01
P2 = "0200000000000002"
PAN1 = "01dddddddddddddd"  # wire of DD:DD:DD:DD:DD:DD:DD:01

SWAP = {
    g.ZVD_EUI.wire: EUI_A.wire,
    g.ZDD_EUI.wire: EUI_B.wire,
    g.VALVE_EUI.wire: EUI_C.wire,
    g.COORDINATOR_EUI.wire: EUI_D.wire,
    g.EXT_PAN.wire: PAN_X.wire,
}
DUMMIES = (EUI_A, EUI_B, EUI_C, EUI_D, PAN_X)


def swapped(frame: bytes) -> bytes:
    for old, new in SWAP.items():
        frame = frame.replace(old, new)
    return frame


SWAPPED = {name: swapped(frame) for name, frame in g.ALL_NPDUS.items()}


def forms(eui: Eui64) -> list[str]:
    """Every hex text form an EUI could leak in: both byte orders, both cases."""
    out = []
    for raw in (eui.wire, eui.wire[::-1]):
        out += [raw.hex(), raw.hex().upper(), raw.hex(":"), raw.hex(":").upper()]
    return out


def redact(frame: bytes, p: EuiPseudonymizer | None = None) -> RedactedNpdu:
    return redact_npdu(frame, p if p is not None else EuiPseudonymizer())


def redacted_hex(frame: bytes, p: EuiPseudonymizer | None = None) -> str:
    out = redact(frame, p)
    assert out.hex is not None, out
    return out.hex


# --- hand-written frames for every EUI field -------------------------------------------------

NWK_DATA = "08 00 34 12 6F 5E 1E 40"  # data, dst us, src valve, radius 30, seq 0x40
NWK_CMD = "09 00 34 12 6F 5E 1E 41"  # command, same addressing
APS_ZDO = "00 00 {cl} 00 00 00 07"  # unicast, ep 0, cluster, profile 0, ep 0, counter 7
APS_HA = "00 01 01 02 04 01 01 2B"  # unicast, ep 1, thermostat, HA, ep 1, counter 0x2B

FIELD_FRAMES: dict[str, tuple[bytes, tuple[Eui64, ...]]] = {
    "nwk_dst_src_ieee": (
        h("08 18 34 12 6F 5E 1E 40", A, B, APS_HA, "00 2B 00 00 00"),
        (EUI_A, EUI_B),
    ),
    "device_annce": (
        h("08 00 FD FF 34 12 1E 02", "08 00 13 00 00 00 00 00", "01 34 12", A, "8E"),
        (EUI_A,),
    ),
    "nwk_addr_req": (h(NWK_DATA, APS_ZDO.format(cl="00 00"), "07", A, "00 00"), (EUI_A,)),
    "nwk_addr_rsp": (h(NWK_DATA, APS_ZDO.format(cl="00 80"), "07 00", A, "6F 5E"), (EUI_A,)),
    "ieee_addr_rsp": (h(NWK_DATA, APS_ZDO.format(cl="01 80"), "07 00", A, "6F 5E"), (EUI_A,)),
    "mgmt_lqi_rsp": (
        h(NWK_DATA, APS_ZDO.format(cl="31 80"), "0A 00 01 00 01", X, A, "6F 5E 12 02 01 B4"),
        (PAN_X, EUI_A),
    ),
    "rreq_dst_ieee": (h(NWK_CMD, "01 20 07 34 12 00", A), (EUI_A,)),
    "rrep_spec_0x30": (h(NWK_CMD, "02 30 07 6F 5E 34 12 00", A, B), (EUI_A, EUI_B)),
    "rrep_live_0x20": (h(NWK_CMD, "02 20 07 6F 5E 34 12 00", A, B), (EUI_A, EUI_B)),
    "commissioning_request_tlv": (
        h(
            "09 00 1B 2A 34 12 01 01",  # no NWK IEEEs: the TLV EUI is the only one
            "0E 00 8E",
            "48 16 41 09 01 00",
            A,
            "47 04 34 12 01 CF 00 4C 01 01 00",
        ),
        (EUI_A,),
    ),
    "commissioning_response_tlv": (
        h("09 00 34 12 1B 2A 1E 05", "0F 34 12 00", "41 09 01 00", A),
        (EUI_A,),
    ),
    "zcl_read_rsp_eui64": (h(NWK_DATA, APS_HA, "18 2B 01", "10 00 00 F0", A), (EUI_A,)),
    "zcl_report_eui64": (h(NWK_DATA, APS_HA, "18 2F 0A", "10 00 F0", A), (EUI_A,)),
    "zcl_write_eui64": (h(NWK_DATA, APS_HA, "00 2D 02", "10 00 F0", A), (EUI_A,)),
}


@pytest.mark.parametrize("name", sorted(FIELD_FRAMES))
def test_every_eui_field_is_redacted_on_first_sight(name: str) -> None:
    frame, euis = FIELD_FRAMES[name]
    assert inspect_npdu(frame).verdict == "ok"
    p = EuiPseudonymizer()  # nothing known yet: the decoders alone must find every field
    out = redacted_hex(frame, p)
    assert len(out) == 2 * len(frame)
    for eui in euis:
        for text in forms(eui):
            assert text.lower() not in out
    expected = frame.hex()
    for eui in euis:
        expected = expected.replace(eui.wire.hex(), p.eui(eui).wire.hex())
    assert out == expected


def test_structural_redaction_keeps_length_and_byte_order() -> None:
    frame = SWAPPED["DEVICE_ANNCE"]
    out = redacted_hex(frame)
    # Only the 8 IEEE bytes change, to pseudonym 1 in wire (little-endian) order.
    assert out == frame.hex().replace(A, P1)
    assert bytes.fromhex(out)[-9:-1] == Eui64.from_str("02:00:00:00:00:00:00:01").wire


def test_mgmt_lqi_ext_pan_and_ieee_pseudonyms() -> None:
    out = redacted_hex(SWAPPED["MGMT_LQI_RSP"])
    assert out == SWAPPED["MGMT_LQI_RSP"].hex().replace(X, PAN1).replace(
        EUI_C.wire.hex(), P1
    ).replace(B, P2)


def test_rrep_live_misdecode_trailing_eui_redacted() -> None:
    frame = SWAPPED["RREP_LIVE"]
    nwk = NwkFrame.decode(frame)
    rrep = decode_nwk_command(nwk.payload)
    assert isinstance(rrep, RouteReply)
    assert rrep.tlvs == EUI_A.wire  # the known misdecode: own EUI lands in tlvs
    out = bytes.fromhex(redacted_hex(frame))
    redacted_rrep = decode_nwk_command(NwkFrame.decode(out).payload)
    assert isinstance(redacted_rrep, RouteReply)
    assert redacted_rrep.responder_ieee == Eui64.from_str("02:00:00:00:00:00:00:01")
    assert redacted_rrep.tlvs == Eui64.from_str("02:00:00:00:00:00:00:02").wire


@pytest.mark.parametrize(
    "frame",
    [
        h(NWK_CMD, "03 0B 34 12", "00"),  # Network Status, 1 junk byte
        h(NWK_CMD, "03 0B 34 12", A),  # Network Status, EUI-sized junk
        h(NWK_CMD, "01 00 07 34 12 00", A),  # RREQ without dst IEEE bit, 8-byte tail
        h(NWK_CMD, "01 20 07 34 12 00", A, "00"),  # RREQ with dst IEEE, 1 junk byte
        h(NWK_CMD, "02 30 07 6F 5E 34 12 00", A, B, "00"),  # spec RREP, junk byte
        h(NWK_CMD, "02 30 07 6F 5E 34 12 00", A, B, A),  # spec RREP, extra 8 bytes
        h(NWK_CMD, "02 20 07 6F 5E 34 12 00", A, B, A),  # live RREP, two trailing EUIs
        h(NWK_CMD, "02 20 07 6F 5E 34 12 00", A, "00 11 22 33"),  # live RREP, short tail
        h(NWK_CMD, "02 60 07 6F 5E 34 12 00", A, B),  # 0x20 + multicast: not the live byte
        h(NWK_CMD, "02 00 07 6F 5E 34 12 00", A),  # no IEEE bits, 8-byte tail
    ],
    ids=lambda frame: frame[8:].hex(),
)
def test_route_command_junk_tail_is_undecodable(frame: bytes) -> None:
    assert inspect_npdu(frame).verdict == "undecodable"
    out = redact(frame)
    assert out.hex is None
    assert out.nwk_header_hex == h(NWK_CMD).hex()


@pytest.mark.parametrize("name", ["RREP_LIVE", "RREP_SPEC"])
def test_golden_route_replies_stay_ok_with_both_euis_redacted(name: str) -> None:
    frame = SWAPPED[name]
    assert inspect_npdu(frame).verdict == "ok"
    out = redacted_hex(frame)
    for eui in DUMMIES:
        for form in forms(eui):
            assert form not in out
    assert out.count(P1) + out.count(P2) >= 2


def octstr_report(data: bytes) -> bytes:
    """Report Attributes with one octet-string value: opaque bytes inside a decoded frame."""
    return h(NWK_DATA, APS_HA, "18 2F 0A 00 00 41") + bytes([len(data)]) + data


def test_eui_seen_earlier_is_replaced_anywhere_in_later_frames() -> None:
    p = EuiPseudonymizer()
    redacted_hex(FIELD_FRAMES["device_annce"][0], p)  # learns EUI_A
    display = EUI_A.wire[::-1]
    opaque = EUI_A.wire + display + display.hex().upper().encode() + str(EUI_A).encode()
    frame = octstr_report(opaque)  # the decoders see bytes, not an EUI field
    out = bytes.fromhex(redacted_hex(frame, p))
    assert len(out) == len(frame)
    fake = p.eui(EUI_A)
    assert out[-len(opaque) :] == (
        fake.wire + fake.wire[::-1] + fake.wire[::-1].hex().upper().encode() + str(fake).encode()
    )


def test_overlapping_matches_leave_no_original_bytes() -> None:
    p = EuiPseudonymizer()
    redacted_hex(FIELD_FRAMES["rrep_spec_0x30"][0], p)  # learns A and B
    blob = EUI_A.wire[:4] + EUI_B.wire + EUI_A.wire[4:]  # B splits a broken A
    frame = octstr_report(EUI_A.wire + blob)
    out = redacted_hex(frame, p)
    assert A not in out
    assert B not in out


@pytest.mark.parametrize("name", sorted(g.ALL_NPDUS))
def test_redacted_golden_frames_still_decode(name: str) -> None:
    for frame in (g.ALL_NPDUS[name], SWAPPED[name]):
        out = bytes.fromhex(redacted_hex(frame))
        assert len(out) == len(frame)
        before, after = NwkFrame.decode(frame), NwkFrame.decode(out)
        assert (after.frame_type, after.dst, after.src, after.seq) == (
            before.frame_type,
            before.dst,
            before.src,
            before.seq,
        )
        assert len(after.payload) == len(before.payload)
        if after.frame_type is NwkFrameType.COMMAND:
            assert type(decode_nwk_command(after.payload)) is type(
                decode_nwk_command(before.payload)
            )
        assert inspect_npdu(out).verdict == "ok"


def test_redacted_zcl_payload_is_byte_identical() -> None:
    out = bytes.fromhex(redacted_hex(g.ZCL_READ_RSP))
    aps = ApsDataFrame.decode(NwkFrame.decode(out).payload)
    assert (
        ZclFrame.decode(aps.payload).global_command()
        == ZclFrame.decode(
            ApsDataFrame.decode(NwkFrame.decode(g.ZCL_READ_RSP).payload).payload
        ).global_command()
    )


def test_quirk_frame_decodes_through_fallback() -> None:
    assert redacted_hex(g.QUIRK_GARBAGE4) == g.QUIRK_GARBAGE4.hex()
    assert redacted_hex(g.QUIRK_SOURCE_ROUTE) == g.QUIRK_SOURCE_ROUTE.hex()


def test_zdo_quirk_frame_decodes_through_fallback() -> None:
    # 4 garbage bytes before a ZDO header: the scan finds IEEE_addr_rsp at offset 12.
    frame = h(NWK_DATA, "00 5A 5A 00", APS_ZDO.format(cl="01 80"), "07 00", A, "6F 5E")
    assert inspect_npdu(frame).verdict == "ok"
    p = EuiPseudonymizer()
    assert redacted_hex(frame, p) == frame.hex().replace(A, p.eui(EUI_A).wire.hex())


def test_quirk_candidates_at_several_offsets_are_ambiguous() -> None:
    # Garbled header (profile 0x0100), nothing at offset 8, but Read Attributes frames decode
    # at both offset 10 and offset 12: ambiguous, so header only.
    frame = h(NWK_DATA, "00 5A 5A 00 00 01 01 02", "2B 2B 00 2C 00 2D 00 00 00")
    assert inspect_npdu(frame).verdict == "undecodable"
    assert redact_npdu(frame, EuiPseudonymizer()).hex is None


@pytest.mark.parametrize("name", sorted(SWAPPED))
def test_no_dummy_eui_survives_any_golden_frame(name: str) -> None:
    for p in (EuiPseudonymizer(), None):
        out = redact(SWAPPED[name], p)
        text = repr(out)
        for eui in DUMMIES:
            for form in forms(eui):
                assert form not in text, (name, str(eui))


def test_no_dummy_eui_survives_a_whole_session() -> None:
    p = EuiPseudonymizer()
    outputs = [repr(redact(frame, p)) for frame in SWAPPED.values()]
    outputs += [repr(redact(frame, p)) for frame, _ in FIELD_FRAMES.values()]
    text = "\n".join(outputs)
    for eui in DUMMIES:
        for form in forms(eui):
            assert form not in text


# --- pseudonymizer ---------------------------------------------------------------------------


def test_mapping_is_stable_and_per_recorder() -> None:
    p, q = EuiPseudonymizer(), EuiPseudonymizer()
    assert str(p.eui(EUI_C)) == "02:00:00:00:00:00:00:01"
    assert str(p.eui(EUI_A)) == "02:00:00:00:00:00:00:02"
    assert str(p.eui(EUI_C)) == "02:00:00:00:00:00:00:01"
    assert str(p.extended_pan(PAN_X)) == "DD:DD:DD:DD:DD:DD:DD:01"
    assert str(q.eui(EUI_A)) == "02:00:00:00:00:00:00:01"  # fresh table, own numbering
    out1 = redacted_hex(FIELD_FRAMES["device_annce"][0], p)
    out2 = redacted_hex(FIELD_FRAMES["nwk_addr_rsp"][0], p)
    assert P2 in out1
    assert P2 in out2
    assert len(p) == 3  # C, PAN_X, A
    assert "AC:DE" not in repr(p)


def test_pseudonym_maps_to_itself_and_is_never_reissued() -> None:
    p = EuiPseudonymizer()
    first = p.eui(EUI_A)
    assert p.eui(first) == first
    assert p.extended_pan(first) == first
    # A real value shaped like the next pseudonym is never handed out to another value.
    lookalike = Eui64.from_str("02:00:00:00:00:00:00:03")
    assert str(p.eui(lookalike)) == "02:00:00:00:00:00:00:02"
    assert str(p.eui(EUI_B)) == "02:00:00:00:00:00:00:04"


def test_same_bytes_as_eui_and_ext_pan_share_one_pseudonym() -> None:
    p = EuiPseudonymizer()
    assert p.extended_pan(EUI_A) == p.eui(EUI_A)


def test_pseudonyms_beyond_255() -> None:
    p, q = EuiPseudonymizer(), EuiPseudonymizer()
    euis = [p.eui(Eui64((0xACDE480000000000 + n).to_bytes(8, "little"))) for n in range(256)]
    pans = [
        q.extended_pan(Eui64((0xACDE48FF00000000 + n).to_bytes(8, "little"))) for n in range(256)
    ]
    assert str(euis[255]) == "02:00:00:00:00:00:01:00"
    assert str(pans[254]) == "DD:DD:DD:DD:DD:DD:DD:FF"
    assert str(pans[255]) == "DD:00:00:00:00:00:01:00"
    assert len(set(euis)) == len(set(pans)) == 256
