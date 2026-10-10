"""Tests for the offset-scan fallback decoder (handover section 6, BUILD_SPEC A4)."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from vicare_direct.zigbee_direct.codec import fallback
from vicare_direct.zigbee_direct.codec.aps import HA_PROFILE_ID, ApsDataFrame
from vicare_direct.zigbee_direct.codec.fallback import (
    ExpectedZcl,
    ExpectedZdo,
    ScanFailure,
    ScanMatch,
    scan_for_response,
)
from vicare_direct.zigbee_direct.codec.zcl import (
    ReadAttributesResponse,
    ReadAttributeStatus,
    WriteAttributesResponse,
    WriteAttributeStatus,
)
from vicare_direct.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_direct.zigbee_direct.codec.zdo import (
    ActiveEpRsp,
    SimpleDescriptor,
    SimpleDescRsp,
    ZdoCluster,
)

SRC = 0x4A11  # dummy valve short
OTHER = 0x5B22


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


# 4 leading bytes as hypothesised (1-relay source-route subframe). Its first byte
# 0x01 reads as an APS *command* frame control, which the standard decode refuses
# as unsupported -- so scanning behind it needs ``allow_secured_aps=True``.
SOURCE_ROUTE = h("01 00 225B")
# A 4-byte prefix whose first byte (0x04: data frame, reserved delivery mode) is a
# recoverable APS framing error, so the scan runs by default.
PREFIX = h("04 00 225B")
FILL = 0x04  # filler byte that never starts an APS data header


def fill(n: int) -> bytes:
    return bytes([FILL]) * n


def quirk(
    cluster: int, profile: int, inner: bytes, counter: int = 5, prefix: bytes = PREFIX
) -> bytes:
    aps = ApsDataFrame(cluster_id=cluster, profile_id=profile, payload=inner, counter=counter)
    return prefix + aps.encode()


def secured(cluster: int, profile: int, inner: bytes, dst_endpoint: int = 1) -> bytes:
    """Synthetic APS-secured data frame: 8-byte header, 5-byte aux header, then ``inner``."""
    header = bytes([0x20, dst_endpoint]) + cluster.to_bytes(2, "little")
    header += profile.to_bytes(2, "little") + h("01 80")
    return header + h("00 01000000") + inner  # sec ctrl (data key) + frame counter


ACTIVE_EP = ActiveEpRsp(seq=0x42, status=0, nwk_addr=SRC, endpoints=(1,))
ZCL_RSP = h("18 80 01 1200 00 29 6608")


def test_standard_aps_path_reports_no_offset() -> None:
    payload = ApsDataFrame(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode()).encode()
    result = scan_for_response(
        payload, ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x42), src_short=SRC
    )
    assert isinstance(result, ScanMatch)
    assert result.offset is None
    assert result.aps is not None
    assert result.response == ACTIVE_EP


def test_valid_after_invalid_offsets_zdo() -> None:
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode())
    result = scan_for_response(
        payload, ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x42), src_short=SRC
    )
    assert isinstance(result, ScanMatch)
    assert result.offset == 12  # offsets 8..11 were tried and rejected
    assert result.candidate_offsets == (12,)
    assert result.response == ACTIVE_EP
    assert result.aps is None


def test_valid_after_invalid_offsets_zcl() -> None:
    payload = quirk(0x0201, HA_PROFILE_ID, ZCL_RSP, counter=0x80)
    expected = ExpectedZcl(SRC, tsn=0x80, command_id=0x01, cluster_id=0x0201)
    result = scan_for_response(payload, expected, src_short=SRC)
    assert isinstance(result, ScanMatch)
    assert result.offset == 12
    assert result.zcl_header is not None
    assert result.zcl_header.tsn == 0x80
    assert result.response == ReadAttributesResponse(
        (ReadAttributeStatus(0x0012, 0, ZclDataType.INT16, 2150),)
    )


def test_standard_zcl_path_checks_cluster() -> None:
    good = ApsDataFrame(0x0201, HA_PROFILE_ID, ZCL_RSP, dst_endpoint=1, src_endpoint=1).encode()
    expected = ExpectedZcl(SRC, tsn=0x80, command_id=0x01, cluster_id=0x0201)
    match = scan_for_response(good, expected, src_short=SRC)
    assert isinstance(match, ScanMatch)
    assert match.offset is None
    wrong = ApsDataFrame(0x0006, HA_PROFILE_ID, ZCL_RSP, dst_endpoint=1, src_endpoint=1).encode()
    # payload offset 8 was judged with its real (wrong-cluster) header; the scan skips it
    assert isinstance(scan_for_response(wrong, expected, src_short=SRC), ScanFailure)


def test_wrong_seq_fails() -> None:
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode())
    result = scan_for_response(
        payload, ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x43), src_short=SRC
    )
    assert isinstance(result, ScanFailure)
    assert "no offset" in result.reason


def test_wrong_tsn_or_command_fails() -> None:
    payload = quirk(0x0201, HA_PROFILE_ID, ZCL_RSP, counter=0x80)
    for expected in (ExpectedZcl(SRC, 0x81, 0x01), ExpectedZcl(SRC, 0x80, 0x04)):
        assert isinstance(scan_for_response(payload, expected, src_short=SRC), ScanFailure)


def test_wrong_source_fails() -> None:
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode())
    result = scan_for_response(
        payload, ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x42), src_short=OTHER
    )
    assert isinstance(result, ScanFailure)
    assert "source" in result.reason


def test_active_ep_vs_simple_desc_by_expected_kind() -> None:
    """The recovered APS header (offset 4) tells the two apart (review finding 4)."""
    desc = SimpleDescriptor(1, HA_PROFILE_ID, 0x0301, 1, (0x0000, 0x0201), ())
    simple = SimpleDescRsp(seq=0x42, status=0, nwk_addr=SRC, descriptor=desc)
    simple_payload = quirk(ZdoCluster.SIMPLE_DESC_RSP, 0, simple.encode())
    active_payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode())
    as_simple = ExpectedZdo(SRC, ZdoCluster.SIMPLE_DESC_RSP, 0x42)
    as_active = ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x42)

    match = scan_for_response(simple_payload, as_simple, src_short=SRC)
    assert isinstance(match, ScanMatch)
    assert match.response == simple
    # The payload alone is also a structurally valid Active_EP_rsp (length byte read
    # as endpoint count), but its recoverable APS header says cluster 0x8004.
    misread = scan_for_response(simple_payload, as_active, src_short=SRC)
    assert isinstance(misread, ScanFailure)
    assert "header mismatch" in misread.reason
    # Headerless, only the expected kind tells them apart (handover section 6).
    headerless = fill(12) + simple.encode()
    misread = scan_for_response(headerless, as_active, src_short=SRC)
    assert isinstance(misread, ScanMatch)
    assert isinstance(misread.response, ActiveEpRsp)
    assert misread.response.endpoints == tuple(desc.encode())

    match = scan_for_response(active_payload, as_active, src_short=SRC)
    assert isinstance(match, ScanMatch)
    assert match.response == ACTIVE_EP
    assert isinstance(scan_for_response(active_payload, as_simple, src_short=SRC), ScanFailure)


def test_multiple_offsets_with_different_results_are_ambiguous() -> None:
    # At offset 8: Active_EP_rsp nwk=0x0007, endpoints (05, 01, 09).
    # At offset 10: Active_EP_rsp nwk=0x0503, endpoints (09,). Both strictly valid.
    payload = fill(8) + h("07 00 07 00 03 05 01 09")
    result = scan_for_response(
        payload, ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x07), src_short=SRC
    )
    assert isinstance(result, ScanFailure)
    assert "ambiguous" in result.reason
    assert result.candidate_offsets == (8, 10)


def test_multiple_offsets_with_same_result_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lenient decoder can yield identical results at several offsets: accept, report first."""
    same = ActiveEpRsp(seq=0x07, status=0, nwk_addr=SRC, endpoints=(1,))
    monkeypatch.setattr(
        fallback,
        "ZDO_RESPONSE_DECODERS",
        MappingProxyType({ZdoCluster.ACTIVE_EP_RSP: lambda _data: same}),
    )
    payload = fill(9) + h("07") + fill(3) + h("07") + fill(1)
    result = scan_for_response(
        payload, ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x07), src_short=SRC
    )
    assert isinstance(result, ScanMatch)
    assert result.offset == 9
    assert result.candidate_offsets == (9, 13)


def test_scanned_non_success_must_be_canonical() -> None:
    expected = ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x42)
    canonical = fill(12) + h("42 81 114A 00")
    match = scan_for_response(canonical, expected, src_short=SRC)
    assert isinstance(match, ScanMatch)
    assert match.response == ActiveEpRsp(0x42, 0x81, SRC)
    padded = fill(12) + h("42 81 114A 00 11")
    assert isinstance(scan_for_response(padded, expected, src_short=SRC), ScanFailure)


def test_short_payload_fails_cleanly() -> None:
    result = scan_for_response(b"\x01", ExpectedZdo(SRC, ZdoCluster.MGMT_LQI_RSP, 1), src_short=SRC)
    assert isinstance(result, ScanFailure)


def test_expected_zdo_rejects_unknown_cluster() -> None:
    with pytest.raises(ValueError, match="decoder"):
        ExpectedZdo(SRC, 0x0005, 1)


def test_standard_zdo_header_mismatch_or_bad_payload() -> None:
    expected = ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x42)
    wrong_cluster = ApsDataFrame(ZdoCluster.MATCH_DESC_RSP, 0, ACTIVE_EP.encode()).encode()
    assert isinstance(scan_for_response(wrong_cluster, expected, src_short=SRC), ScanFailure)
    bad_payload = ApsDataFrame(ZdoCluster.ACTIVE_EP_RSP, 0, h("42 00 114A 05")).encode()
    assert isinstance(scan_for_response(bad_payload, expected, src_short=SRC), ScanFailure)


MIC = h("DE AD BE EF")  # dummy 4-byte trailer (presumed MIC-32 / frame counter)
EXPECT_EP = ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x42)


def test_exact_match_preferred_over_trim() -> None:
    result = scan_for_response(
        quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode()),
        EXPECT_EP,
        src_short=SRC,
        max_trailing=4,
    )
    assert isinstance(result, ScanMatch)
    assert result.trailing == 0


def test_exact_wins_when_trim_would_also_validate(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lenient decoder accepts both the exact and the trimmed candidate: exact is reported."""
    seen: list[bytes] = []

    def lenient(data: bytes) -> ActiveEpRsp:
        seen.append(data)
        return ACTIVE_EP

    monkeypatch.setattr(
        fallback, "ZDO_RESPONSE_DECODERS", MappingProxyType({ZdoCluster.ACTIVE_EP_RSP: lenient})
    )
    payload = fill(12) + ACTIVE_EP.encode() + MIC
    result = scan_for_response(payload, EXPECT_EP, src_short=SRC, max_trailing=4)
    assert isinstance(result, ScanMatch)
    assert result.trailing == 0
    assert seen == [ACTIVE_EP.encode() + MIC]  # trimmed variant never tried


def test_four_trailing_bytes_accepted_on_scan_when_opted_in() -> None:
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode()) + MIC
    result = scan_for_response(payload, EXPECT_EP, src_short=SRC, max_trailing=4)
    assert isinstance(result, ScanMatch)
    assert result.offset == 12
    assert result.trailing == 4
    assert result.response == ACTIVE_EP


def test_four_trailing_bytes_accepted_on_standard_path_when_opted_in() -> None:
    payload = ApsDataFrame(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode() + MIC).encode()
    result = scan_for_response(payload, EXPECT_EP, src_short=SRC, max_trailing=4)
    assert isinstance(result, ScanMatch)
    assert result.offset is None
    assert result.aps is not None
    assert result.trailing == 4
    assert result.response == ACTIVE_EP


@pytest.mark.parametrize("extra", [h("AA"), h("AA BB"), h("AA BB CC"), h("AA BB CC DD EE")])
def test_non_mic_trailing_lengths_rejected(extra: bytes) -> None:
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode()) + extra
    result = scan_for_response(payload, EXPECT_EP, src_short=SRC, max_trailing=8)
    assert isinstance(result, ScanFailure)


@pytest.mark.parametrize("max_trailing", [0, 3])
def test_max_trailing_below_mic_disables_trim(max_trailing: int) -> None:
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode()) + MIC
    result = scan_for_response(payload, EXPECT_EP, src_short=SRC, max_trailing=max_trailing)
    assert isinstance(result, ScanFailure)
    standard = ApsDataFrame(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode() + MIC).encode()
    result = scan_for_response(standard, EXPECT_EP, src_short=SRC, max_trailing=max_trailing)
    assert isinstance(result, ScanFailure)


def test_trim_is_opt_in_by_default() -> None:
    """Review finding 2: no trimming unless max_trailing is passed explicitly."""
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode()) + MIC
    assert isinstance(scan_for_response(payload, EXPECT_EP, src_short=SRC), ScanFailure)
    standard = ApsDataFrame(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode() + MIC).encode()
    assert isinstance(scan_for_response(standard, EXPECT_EP, src_short=SRC), ScanFailure)


def test_trimmed_candidates_count_for_ambiguity() -> None:
    # Same bytes as the plain ambiguity test plus a MIC: both offsets 8 and 10 now
    # validate only after trimming 4 bytes, with different results.
    payload = fill(8) + h("07 00 07 00 03 05 01 09") + MIC
    expected = ExpectedZdo(SRC, ZdoCluster.ACTIVE_EP_RSP, 0x07)
    result = scan_for_response(payload, expected, src_short=SRC, max_trailing=4)
    assert isinstance(result, ScanFailure)
    assert "ambiguous" in result.reason
    assert result.candidate_offsets == (8, 10)


def test_negative_max_trailing_rejected() -> None:
    with pytest.raises(ValueError, match="max_trailing"):
        scan_for_response(b"", EXPECT_EP, src_short=SRC, max_trailing=-1)


# --------------------------------------------------------------------------- review regressions

WRITE_OK_EXPECTED = ExpectedZcl(SRC, tsn=0x80, command_id=0x04, cluster_id=0x0201)
WRITE_OK = WriteAttributesResponse((WriteAttributeStatus(0),))


def test_secured_aps_frame_not_scanned_by_default() -> None:
    """Review finding 1: ciphertext behind an APS security header is never plaintext."""
    payload = secured(0x0201, HA_PROFILE_ID, h("18 80 04 00"))
    assert payload.index(h("18 80 04 00")) == 13
    result = scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC)
    assert isinstance(result, ScanFailure)
    assert "unsupported" in result.reason


def test_secured_aps_frame_scanned_when_opted_in() -> None:
    payload = secured(0x0201, HA_PROFILE_ID, h("18 80 04 00"))
    result = scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC, allow_secured_aps=True)
    assert isinstance(result, ScanMatch)
    assert result.offset == 13
    assert result.aps_secured
    assert result.response == WRITE_OK
    wrong = secured(0x0006, HA_PROFILE_ID, h("18 80 04 00"))
    result = scan_for_response(wrong, WRITE_OK_EXPECTED, src_short=SRC, allow_secured_aps=True)
    assert isinstance(result, ScanFailure)


def test_secured_aps_frame_behind_prefix_not_scanned_by_default() -> None:
    payload = PREFIX + secured(0x0201, HA_PROFILE_ID, h("18 80 04 00"))
    result = scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC)
    assert isinstance(result, ScanFailure)
    assert "unsupported" in result.reason
    result = scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC, allow_secured_aps=True)
    assert isinstance(result, ScanMatch)
    assert result.offset == 17
    assert result.aps_secured


def test_command_frame_control_prefix_needs_opt_in() -> None:
    """The source-route hypothesis prefix starts with 0x01 = APS command FC: refused by default."""
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode(), prefix=SOURCE_ROUTE)
    assert isinstance(scan_for_response(payload, EXPECT_EP, src_short=SRC), ScanFailure)
    result = scan_for_response(payload, EXPECT_EP, src_short=SRC, allow_secured_aps=True)
    assert isinstance(result, ScanMatch)
    assert result.offset == 12
    assert result.aps_secured
    assert result.response == ACTIVE_EP


def test_unsecured_match_reports_not_secured() -> None:
    payload = quirk(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode())
    result = scan_for_response(payload, EXPECT_EP, src_short=SRC, allow_secured_aps=True)
    assert isinstance(result, ScanMatch)
    assert not result.aps_secured


def test_trailing_bytes_never_turn_malformed_into_success_by_default() -> None:
    """Review finding 2: ``00 86 12 00 29`` is a malformed write response, not ``00`` + MIC."""
    payload = ApsDataFrame(
        0x0201, HA_PROFILE_ID, h("18 80 04 00 86 12 00 29"), dst_endpoint=1, src_endpoint=1
    ).encode()
    assert isinstance(scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC), ScanFailure)


def test_key128_never_in_match_repr() -> None:
    """Review finding 3: a decoded KEY128 must not leak through the returned object."""
    key = bytes(range(0xA0, 0xB0))
    zcl = h("18 80 01") + h("0000 00 F1") + key
    payload = ApsDataFrame(0x0201, HA_PROFILE_ID, zcl, dst_endpoint=1, src_endpoint=1).encode()
    expected = ExpectedZcl(SRC, tsn=0x80, command_id=0x01, cluster_id=0x0201)
    match = scan_for_response(payload, expected, src_short=SRC)
    assert isinstance(match, ScanMatch)
    assert match.aps is not None
    assert key in match.aps.payload  # still available programmatically
    for text in (repr(match), str(match)):
        assert key.hex() not in text.lower()
        assert repr(key)[2:-1] not in text
        assert "a0a1a2" not in text.lower()


def test_wrong_cluster_on_fallback_path_rejected() -> None:
    """Review finding 4: the recoverable APS header at offset 4 is checked before offset 12."""
    payload = quirk(0x0006, HA_PROFILE_ID, ZCL_RSP, counter=0x80)
    expected = ExpectedZcl(SRC, tsn=0x80, command_id=0x01, cluster_id=0x0201)
    result = scan_for_response(payload, expected, src_short=SRC)
    assert isinstance(result, ScanFailure)
    assert "header mismatch" in result.reason
    any_cluster = ExpectedZcl(SRC, tsn=0x80, command_id=0x01)
    assert isinstance(scan_for_response(payload, any_cluster, src_short=SRC), ScanMatch)


def test_wrong_zdo_profile_or_endpoint_on_fallback_path_rejected() -> None:
    wrong_profile = quirk(ZdoCluster.ACTIVE_EP_RSP, HA_PROFILE_ID, ACTIVE_EP.encode())
    assert isinstance(scan_for_response(wrong_profile, EXPECT_EP, src_short=SRC), ScanFailure)
    aps = ApsDataFrame(ZdoCluster.ACTIVE_EP_RSP, 0, ACTIVE_EP.encode(), dst_endpoint=1)
    wrong_ep = PREFIX + aps.encode()
    assert isinstance(scan_for_response(wrong_ep, EXPECT_EP, src_short=SRC), ScanFailure)


MS_WRITE_OK = h("1c 34 12 80 04 00")  # manufacturer 0x1234, global Write Attributes Response


def test_manufacturer_code_must_match() -> None:
    """Review finding 5: manufacturer-specific global responses decode and match on the code."""
    payload = quirk(0x0201, HA_PROFILE_ID, MS_WRITE_OK, counter=0x80)
    ms = ExpectedZcl(SRC, tsn=0x80, command_id=0x04, cluster_id=0x0201, manufacturer_code=0x1234)
    match = scan_for_response(payload, ms, src_short=SRC)
    assert isinstance(match, ScanMatch)
    assert match.response == WRITE_OK
    assert match.zcl_header is not None
    assert match.zcl_header.manufacturer_code == 0x1234
    assert isinstance(scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC), ScanFailure)
    other = ExpectedZcl(SRC, tsn=0x80, command_id=0x04, manufacturer_code=0x4321)
    assert isinstance(scan_for_response(payload, other, src_short=SRC), ScanFailure)
    standard = ApsDataFrame(0x0201, HA_PROFILE_ID, h("18 80 04 00"), dst_endpoint=1).encode()
    assert isinstance(scan_for_response(standard, ms, src_short=SRC), ScanFailure)


def test_fragmented_aps_frame_behind_prefix_not_scanned_by_default() -> None:
    # FC 0x80: data, extended header; ext FC 0x01 (first fragment) + block number 0.
    frame = h("80 01 0102 0401 01 80") + h("01 00") + h("18 80 04 00")
    payload = PREFIX + frame
    assert payload.index(h("18 80 04 00")) == 14
    result = scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC)
    assert isinstance(result, ScanFailure)
    assert "unsupported" in result.reason
    result = scan_for_response(payload, WRITE_OK_EXPECTED, src_short=SRC, allow_secured_aps=True)
    assert isinstance(result, ScanMatch)
    assert result.aps_secured


@pytest.mark.parametrize(
    ("data", "start"),
    [
        ("", None),
        ("00 01 0102", None),  # truncated addressing
        ("80 01 0102 0401 01 80", None),  # extended header missing
        ("20 01 0102 0401 01 80", None),  # aux header missing
        ("20 01 0102 0401 01 80 00 0100", None),  # aux header truncated
        ("20 01 0102 0401 01 80 08 01000000 00", 14),  # network key: + key seq
        ("20 01 0102 0401 01 80 20 01000000" + " 00" * 8, 21),  # extended nonce
        ("0C 3412 0102 0401 01 80", 9),  # group delivery: no dst endpoint
        ("80 01 0102 0401 01 80 00", 9),  # extended header, not fragmented
    ],
)
def test_header_at_layouts(data: str, start: int | None) -> None:
    hdr = fallback._header_at(h(data), 0)
    assert (hdr.payload_start if hdr else None) == start
