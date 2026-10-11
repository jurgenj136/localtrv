"""Offset-scan fallback decoder for incoming APS frames (handover section 6 quirk).

Background: during research, frames indicated by the ZDD through the tunnel
did not decode as a standard APS frame at offset 0 of the (research-parsed)
NWK payload; the ZDO/ZCL payload was found 12 bytes in instead of 8. The
research client scanned offsets 8..17 for something that looked right
(tools/zvd_client.py:750-761 ``_scan_zdo``, :855-868 for ZCL, :876-892 for
ZDO). Hypothesis (unverified): the extra 4 bytes were an NWK source-route
subframe the research NWK parser did not skip; ``nwk.py`` now strips it, so
the standard decode may simply work. Phase-2 fixtures must confirm.

Rule. The NWK payload handed in always starts with the real APS frame control
at offset 0 (``nwk.py`` strips multicast/source-route subframes; no other
prefix exists). Hence:

1. reject frames from an unexpected source short;
2. strict APS decode at offset 0, checked against the expected header (ZDO:
   profile 0, response cluster, dst endpoint 0; ZCL: cluster if given) and
   payload -> match with ``offset=None`` and ``cluster_verified=True``;
3. otherwise classify only the offset-0 frame control (R23 2.2.5.1.1). A
   non-data frame, the reserved delivery mode 0b01, APS security or an
   extended header (fragmentation) means the payload may be ciphertext or a
   fragment: refuse (BUILD_SPEC A2) unless ``allow_unsupported_aps=True``.
   The opt-in exists because research tools/zvd_tunnel.py:348-387 had a
   secured-APS path and handover section 6 mentions a 4-byte frame counter
   (hypothesis); such matches carry ``aps_unsupported=True``;
4. scan every offset 8..17 as a bare ZDO payload (``seq ...``) or ZCL frame,
   validated strictly against the expected kind (seq / tsn, command,
   manufacturer code, exact decode). The offset where a successful step-2
   decode put the payload is skipped: it was already judged together with its
   real header. Nothing else is inferred from bytes before a candidate;
5. several candidates with *different* results are ambiguous and rejected;
   identical results are accepted (first offset reported, all kept).

The APS cluster/profile/endpoint cannot be verified in scan mode -- those
header bytes are exactly what the quirk garbles -- so scan matches have
``cluster_verified=False``.

Residual risk: behind a plain unsecured data frame control, a crafted or
garbled frame may yield a false match. Mitigation is correlation on
(src_short, seq/tsn, command, exact length). The definitive fix is an explicit,
fixture-backed quirk-layout decoder in phase 2 that replaces this scan.

Trailing bytes: strict by default (``max_trailing=0``). Only with
``max_trailing >= 4`` is each candidate retried with exactly 4 bytes (presumed
MIC-32) trimmed after the exact decode failed; no capture yet proves those
bytes are a MIC. The trim is recorded in ``trailing``; rule 5 applies across
all (offset, trim) candidates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from vicare_local_ble.zigbee_direct.codec.aps import (
    ZDO_PROFILE_ID,
    ApsDataFrame,
    ApsFrameControl,
    ApsFrameType,
)
from vicare_local_ble.zigbee_direct.codec.zcl import (
    ZclFrame,
    ZclFrameType,
    ZclGlobalCommand,
    ZclHeader,
)
from vicare_local_ble.zigbee_direct.codec.zdo import (
    ActiveEpRsp,
    IeeeAddrRsp,
    MatchDescRsp,
    NwkAddrRsp,
    SimpleDescRsp,
    ZdoCluster,
)
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiRsp
from vicare_local_ble.zigbee_direct.errors import DecodeError

if TYPE_CHECKING:
    from collections.abc import Callable

SCAN_OFFSETS = range(8, 18)
MIC_TRIM = 4  # ENC-MIC-32; the only trailing length the scan can trim (opt-in)

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
    """A pending ZCL exchange: expected response tsn/command, target short, optional cluster.

    ``manufacturer_code`` must equal the response header's code exactly (None
    means a standard, non-manufacturer-specific frame).
    """

    src_short: int
    tsn: int
    command_id: int
    cluster_id: int | None = None
    manufacturer_code: int | None = None


type Expected = ExpectedZdo | ExpectedZcl
type ScanResponse = ZdoResponse | ZclGlobalCommand


@dataclass(frozen=True, slots=True)
class ScanMatch:
    """A validated response.

    ``offset`` is None when the standard APS decode succeeded (``aps`` set);
    otherwise the payload offset where the scan found it. ``trailing`` is the
    number of bytes ignored at the end (0, or 4 with opt-in trimming).
    ``cluster_verified`` is True only on the standard path (scan mode cannot
    check the APS header). ``aps_unsupported`` is True when the match was only
    reachable through ``allow_unsupported_aps``. ``aps`` is excluded from the
    repr: its raw payload may hold key material.
    """

    response: ScanResponse
    offset: int | None = None
    zcl_header: ZclHeader | None = None
    aps: ApsDataFrame | None = field(default=None, repr=False)
    candidate_offsets: tuple[int, ...] = ()
    trailing: int = 0
    cluster_verified: bool = False
    aps_unsupported: bool = False


@dataclass(frozen=True, slots=True)
class ScanFailure:
    """No unique validated response; ``reason`` is meant for debug logging."""

    reason: str
    candidate_offsets: tuple[int, ...] = ()


type _Decoded = tuple[ZclHeader | None, ScanResponse]


def _unsupported_fc(fc_byte: int) -> str | None:
    """Why the offset-0 APS frame control rules out scanning, or None (plain data)."""
    fc = ApsFrameControl.from_byte(fc_byte)
    reasons = []
    if fc.frame_type is not ApsFrameType.DATA:
        reasons.append(f"a {fc.frame_type.name} frame")
    if fc.delivery_mode == 1:
        reasons.append("reserved delivery mode 0b01")
    if fc.security:
        reasons.append("APS-secured")
    if fc.extended_header:
        reasons.append("extended header (fragmentation)")
    return ", ".join(reasons) or None


def _header_matches(
    cluster_id: int, profile_id: int, dst_endpoint: int | None, expected: Expected
) -> bool:
    if isinstance(expected, ExpectedZdo):
        return (
            profile_id == ZDO_PROFILE_ID and cluster_id == expected.cluster_id and dst_endpoint == 0
        )
    return expected.cluster_id is None or cluster_id == expected.cluster_id


def _validate_zdo(candidate: bytes, expected: ExpectedZdo) -> _Decoded | None:
    if not candidate or candidate[0] != expected.seq:
        return None
    try:
        return None, ZDO_RESPONSE_DECODERS[expected.cluster_id](candidate)
    except DecodeError:
        return None


def _validate_zcl(candidate: bytes, expected: ExpectedZcl) -> _Decoded | None:
    try:
        frame = ZclFrame.decode(candidate)
        header = frame.header
        if (
            header.tsn != expected.tsn
            or header.command_id != expected.command_id
            or header.frame_type is not ZclFrameType.GLOBAL
            or header.manufacturer_code != expected.manufacturer_code
        ):
            return None
        return header, frame.global_command()
    except DecodeError:
        return None


def _validate(candidate: bytes, expected: Expected) -> _Decoded | None:
    if isinstance(expected, ExpectedZdo):
        return _validate_zdo(candidate, expected)
    return _validate_zcl(candidate, expected)


def _trims(max_trailing: int) -> tuple[int, ...]:
    return (0, MIC_TRIM) if max_trailing >= MIC_TRIM else (0,)


def _validate_trimmed(
    candidate: bytes, expected: Expected, trims: tuple[int, ...]
) -> tuple[int, _Decoded] | None:
    """Exact end first; then each allowed trim. Returns (trailing, decoded)."""
    for trim in trims:
        if trim and len(candidate) <= trim:
            break
        decoded = _validate(candidate[: len(candidate) - trim], expected)
        if decoded is not None:
            return trim, decoded
    return None


def _standard(
    nwk_payload: bytes, expected: Expected, trims: tuple[int, ...]
) -> tuple[ScanMatch | None, int | None]:
    """Strict decode at offset 0: (match, payload offset of a well-formed frame)."""
    try:
        aps = ApsDataFrame.decode(nwk_payload)
    except DecodeError:  # incl. UnsupportedFrameError; classified by the caller
        return None, None
    payload_offset = len(nwk_payload) - len(aps.payload)
    if not _header_matches(aps.cluster_id, aps.profile_id, aps.dst_endpoint, expected):
        return None, payload_offset
    result = _validate_trimmed(aps.payload, expected, trims)
    if result is None:
        return None, payload_offset
    trailing, (header, response) = result
    match = ScanMatch(
        response=response, zcl_header=header, aps=aps, trailing=trailing, cluster_verified=True
    )
    return match, payload_offset


def scan_for_response(
    nwk_payload: bytes,
    expected: Expected,
    *,
    src_short: int,
    max_trailing: int = 0,
    allow_unsupported_aps: bool = False,
) -> ScanMatch | ScanFailure:
    """Find the expected response in an NWK payload (see module docstring).

    ``src_short`` is the NWK source of the received frame; it must equal
    ``expected.src_short``. ``max_trailing`` (default 0: strict) bounds the
    tolerated trailing bytes; only a 4-byte MIC-32 trim is ever tried, so
    values below 4 disable it. ``allow_unsupported_aps`` permits scanning when
    the offset-0 APS frame control is not a plain unsecured data frame
    (hypothesis only).
    """
    if max_trailing < 0:
        raise ValueError("max_trailing must be >= 0")
    if src_short != expected.src_short:
        return ScanFailure(
            f"source 0x{src_short:04X} is not the expected 0x{expected.src_short:04X}"
        )
    if not nwk_payload:
        return ScanFailure("empty NWK payload")
    trims = _trims(max_trailing)
    standard, judged_offset = _standard(nwk_payload, expected, trims)
    if standard is not None:
        return standard
    unsupported = _unsupported_fc(nwk_payload[0])
    if unsupported is not None and not allow_unsupported_aps:
        return ScanFailure(
            f"offset-0 APS frame control 0x{nwk_payload[0]:02X} is {unsupported}; not scanned"
        )
    found = [
        (offset, *result)
        for offset in SCAN_OFFSETS
        if offset != judged_offset
        and (result := _validate_trimmed(nwk_payload[offset:], expected, trims)) is not None
    ]
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
        aps_unsupported=unsupported is not None,
    )
