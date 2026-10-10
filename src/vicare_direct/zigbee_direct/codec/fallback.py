"""Offset-scan fallback decoder for incoming APS frames (handover section 6 quirk).

Background: during research, frames indicated by the ZDD through the tunnel
did not decode as a standard APS frame at offset 0 of the (research-parsed)
NWK payload; the ZDO/ZCL payload was found 12 bytes in instead of 8. The
research client scanned offsets 8..17 for something that looked right
(tools/zvd_client.py:750-761 ``_scan_zdo``, :855-868 for ZCL, :876-892 for
ZDO). That ZDO loop ``break``s on the first offset whose first byte is not a
pending sequence number (:882-883) and after the first parse attempt that
succeeds (:892), so in practice it mostly tested offset 8 only.

Hypothesis (unverified): the extra 4 bytes are an NWK source-route subframe
(relay_count, relay_index, one 2-byte relay) that the research NWK parser did
not skip. ``nwk.py`` now parses that subframe, so the standard APS decode
should succeed and this fallback may become unnecessary. Phase-2 fixtures
must confirm before it is removed.

Algorithm (BUILD_SPEC A4):

1. reject frames from an unexpected source short;
2. try the standard APS decode at offset 0 and validate it against the
   expected kind;
3. otherwise test *every* offset 8..17 (relative to the NWK payload after the
   NWK header) as a bare ZDO payload (``seq ‖ ...``) or ZCL frame, validated
   structurally with the expected kind's strict decoder;
4. if several candidates validate with *different* results the match is
   ambiguous and rejected; identical results are accepted (first offset
   reported, all offsets kept for diagnostics).

Trailing bytes: live research frames reportedly carried extra bytes including
a 4-byte frame counter (handover section 6), so a trailing MIC-32 may follow
the real payload. Each candidate (the standard APS payload and every scanned
offset) is first decoded up to the exact end; only if that fails is it retried
with exactly 4 bytes (one MIC-32) trimmed. No other trim length is tried, so 1-3
or 5+ stray bytes still fail. ``max_trailing`` caps the trim (``0`` disables
it); the match records the trim in ``trailing``. Ambiguity rule 4 applies
across all (offset, trim) candidates. A trimmed match is weaker evidence: a
lenient payload (e.g. a ZCL attribute list) can sometimes absorb 4 stray bytes
in the exact decode instead, which is why exact always wins per offset.

ZCL validation cannot check the cluster id on scanned candidates (the APS
cluster field is exactly what is unreliable); it is checked on the standard
path only. When the standard decode yields a well-formed APS data frame that
does not match, its payload offset is skipped by the scan (it was already
judged with its real header, e.g. a wrong cluster). Non-success ZDO responses
found by scanning must be in canonical short form (re-encode equals the
candidate), since a lone status byte is weak evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from vicare_direct.zigbee_direct.codec.aps import ZDO_PROFILE_ID, ApsDataFrame
from vicare_direct.zigbee_direct.codec.zcl import (
    ZclFrame,
    ZclFrameType,
    ZclGlobalCommand,
    ZclHeader,
)
from vicare_direct.zigbee_direct.codec.zdo import (
    ActiveEpRsp,
    IeeeAddrRsp,
    MatchDescRsp,
    NwkAddrRsp,
    SimpleDescRsp,
    ZdoCluster,
    ZdoStatus,
)
from vicare_direct.zigbee_direct.codec.zdo_mgmt import MgmtLqiRsp
from vicare_direct.zigbee_direct.errors import DecodeError

if TYPE_CHECKING:
    from collections.abc import Callable

SCAN_OFFSETS = range(8, 18)
MIC_TRIM = 4  # ENC-MIC-32; the only trailing length the scan tolerates

type ZdoResponse = (
    ActiveEpRsp | SimpleDescRsp | MatchDescRsp | MgmtLqiRsp | IeeeAddrRsp | NwkAddrRsp
)

ZDO_RESPONSE_DECODERS: MappingProxyType[int, Callable[[bytes], ZdoResponse]] = MappingProxyType(
    {
        ZdoCluster.NWK_ADDR_RSP: NwkAddrRsp.decode,
        ZdoCluster.IEEE_ADDR_RSP: IeeeAddrRsp.decode,
        ZdoCluster.SIMPLE_DESC_RSP: SimpleDescRsp.decode,
        ZdoCluster.ACTIVE_EP_RSP: ActiveEpRsp.decode,
        ZdoCluster.MATCH_DESC_RSP: MatchDescRsp.decode,
        ZdoCluster.MGMT_LQI_RSP: MgmtLqiRsp.decode,
    }
)


@dataclass(frozen=True, slots=True)
class ExpectedZdo:
    """A pending ZDO request: response cluster id (e.g. 0x8005), seq and target short."""

    src_short: int
    cluster_id: int
    seq: int

    def __post_init__(self) -> None:
        if self.cluster_id not in ZDO_RESPONSE_DECODERS:
            raise ValueError(f"no ZDO response decoder for cluster 0x{self.cluster_id:04X}")


@dataclass(frozen=True, slots=True)
class ExpectedZcl:
    """A pending ZCL exchange: expected response tsn/command, target short, optional cluster."""

    src_short: int
    tsn: int
    command_id: int
    cluster_id: int | None = None


type Expected = ExpectedZdo | ExpectedZcl
type ScanResponse = ZdoResponse | ZclGlobalCommand


@dataclass(frozen=True, slots=True)
class ScanMatch:
    """A validated response.

    ``offset`` is None when the standard APS decode succeeded (``aps`` set);
    otherwise the payload offset where the fallback found it. ``trailing`` is
    the number of bytes ignored at the end (0, or 4 for a presumed MIC-32).
    """

    response: ScanResponse
    offset: int | None = None
    zcl_header: ZclHeader | None = None
    aps: ApsDataFrame | None = None
    candidate_offsets: tuple[int, ...] = ()
    trailing: int = 0


@dataclass(frozen=True, slots=True)
class ScanFailure:
    """No unique validated response; ``reason`` is meant for debug logging."""

    reason: str
    candidate_offsets: tuple[int, ...] = ()


type _Decoded = tuple[ZclHeader | None, ScanResponse]


def _validate_zdo(candidate: bytes, expected: ExpectedZdo, *, scanned: bool) -> _Decoded | None:
    if not candidate or candidate[0] != expected.seq:
        return None
    try:
        rsp = ZDO_RESPONSE_DECODERS[expected.cluster_id](candidate)
    except DecodeError:
        return None
    if scanned and rsp.status != ZdoStatus.SUCCESS and rsp.encode() != candidate:
        return None
    return None, rsp


def _validate_zcl(candidate: bytes, expected: ExpectedZcl) -> _Decoded | None:
    try:
        frame = ZclFrame.decode(candidate)
        header = frame.header
        if (
            header.tsn != expected.tsn
            or header.command_id != expected.command_id
            or header.frame_type is not ZclFrameType.GLOBAL
        ):
            return None
        return header, frame.global_command()
    except DecodeError:
        return None


def _validate(candidate: bytes, expected: Expected, *, scanned: bool) -> _Decoded | None:
    if isinstance(expected, ExpectedZdo):
        return _validate_zdo(candidate, expected, scanned=scanned)
    return _validate_zcl(candidate, expected)


def _trims(max_trailing: int) -> tuple[int, ...]:
    return (0, MIC_TRIM) if max_trailing >= MIC_TRIM else (0,)


def _validate_trimmed(
    candidate: bytes, expected: Expected, *, scanned: bool, trims: tuple[int, ...]
) -> tuple[int, _Decoded] | None:
    """Exact end first; then each allowed trim. Returns (trailing, decoded)."""
    for trim in trims:
        if trim and len(candidate) <= trim:
            break
        decoded = _validate(candidate[: len(candidate) - trim], expected, scanned=scanned)
        if decoded is not None:
            return trim, decoded
    return None


def _standard(
    nwk_payload: bytes, expected: Expected, trims: tuple[int, ...]
) -> tuple[ScanMatch | None, int | None]:
    """Standard decode: (match or None, payload offset of a well-formed APS frame or None)."""
    try:
        aps = ApsDataFrame.decode(nwk_payload)
    except DecodeError:
        return None, None
    payload_offset = len(nwk_payload) - len(aps.payload)
    if isinstance(expected, ExpectedZdo):
        if (
            aps.profile_id != ZDO_PROFILE_ID
            or aps.cluster_id != expected.cluster_id
            or aps.dst_endpoint != 0
        ):
            return None, payload_offset
    elif expected.cluster_id is not None and aps.cluster_id != expected.cluster_id:
        return None, payload_offset
    result = _validate_trimmed(aps.payload, expected, scanned=False, trims=trims)
    if result is None:
        return None, payload_offset
    trailing, (header, response) = result
    return (
        ScanMatch(response=response, zcl_header=header, aps=aps, trailing=trailing),
        payload_offset,
    )


def scan_for_response(
    nwk_payload: bytes, expected: Expected, *, src_short: int, max_trailing: int = MIC_TRIM
) -> ScanMatch | ScanFailure:
    """Find the expected response in an NWK payload (see module docstring).

    ``src_short`` is the NWK source of the received frame; it must equal
    ``expected.src_short``. ``max_trailing`` bounds the tolerated trailing
    bytes; only a 4-byte MIC-32 trim is ever tried, so values below 4 disable it.
    """
    if max_trailing < 0:
        raise ValueError("max_trailing must be >= 0")
    if src_short != expected.src_short:
        return ScanFailure(
            f"source 0x{src_short:04X} is not the expected 0x{expected.src_short:04X}"
        )
    trims = _trims(max_trailing)
    standard, judged_offset = _standard(nwk_payload, expected, trims)
    if standard is not None:
        return standard
    found: list[tuple[int, int, _Decoded]] = []
    for offset in SCAN_OFFSETS:
        if offset == judged_offset:
            continue  # already rejected together with its real APS header
        result = _validate_trimmed(nwk_payload[offset:], expected, scanned=True, trims=trims)
        if result is not None:
            found.append((offset, *result))
    offsets = tuple(off for off, _, _ in found)
    if not found:
        return ScanFailure(f"no offset in {SCAN_OFFSETS.start}..{SCAN_OFFSETS.stop - 1} validated")
    first_offset, first_trailing, first = found[0]
    if any(decoded != first for _, _, decoded in found[1:]):
        return ScanFailure(f"ambiguous: offsets {offsets} decode to different results", offsets)
    header, response = first
    return ScanMatch(
        response=response,
        offset=first_offset,
        zcl_header=header,
        candidate_offsets=offsets,
        trailing=first_trailing,
    )
