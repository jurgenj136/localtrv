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
   expected kind (header cluster/profile/endpoint, then payload);
3. otherwise test *every* offset 8..17 (relative to the NWK payload after the
   NWK header) as a bare ZDO payload (``seq ‖ ...``) or ZCL frame, validated
   structurally with the expected kind's strict decoder;
4. if several candidates validate with *different* results the match is
   ambiguous and rejected; identical results are accepted (first offset
   reported, all offsets kept for diagnostics).

APS security (review finding 1). The standard decode distinguishes a
recoverable framing error (``ApsDecodeError``: truncation, reserved delivery
mode -- the kind of quirk the scan exists for) from ``UnsupportedFrameError``
(APS security, extended header / fragmentation, ACK, command or inter-PAN
frame). By default the scan never runs inside an unsupported frame, because
its payload may be ciphertext or a fragment. This applies to the frame at
offset 0 and to any APS header recoverable *before* a candidate whose secured
or extended payload starts exactly at that candidate. Note that a 1-relay
source-route prefix starts with ``0x01``, which reads as an APS command frame
control, so the hypothesised layout below is refused by default too.

``allow_secured_aps=True`` lifts the block. Rationale: research
tools/zvd_tunnel.py:348-387 had a secured-APS path and handover section 6
mentions "a 4-byte frame counter", so live ZDD-delivered frames *may* carry an
APS security header with a plaintext payload. That is a hypothesis to verify
with phase-2 fixtures; a match found this way has ``aps_secured=True``.

Recovered headers (review finding 4). For each candidate offset, every APS
header that can be parsed at an earlier position and whose payload starts
exactly at the candidate is checked against the expected cluster/profile/
endpoint (the same rule as the standard path); one mismatch rejects the
candidate. Headerless candidates cannot be checked. When the standard decode
at offset 0 yields a well-formed but non-matching APS data frame, its payload
offset is skipped entirely.

Trailing bytes (review finding 2). Off by default: ``max_trailing=0``. Only
with an explicit ``max_trailing >= 4`` is each candidate (standard payload and
scanned offsets) retried with exactly 4 bytes (one presumed MIC-32) trimmed,
after the exact decode failed. No framing evidence yet shows these bytes are a
MIC, and a trim can turn a malformed response into a success, so it must be
an explicit, capture-backed choice. The match records the trim in
``trailing``; ambiguity rule 4 applies across all (offset, trim) candidates.

ZCL matching includes the manufacturer code (``ExpectedZcl.manufacturer_code``,
None for standard attributes). ZDO candidates rely on the strict decoders,
which enforce the exact R23 failure layouts (a lone status byte never
validates).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from vicare_direct.zigbee_direct.codec.aps import (
    ZDO_PROFILE_ID,
    ApsDataFrame,
    ApsDeliveryMode,
    ApsFrameControl,
    ApsFrameType,
)
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
)
from vicare_direct.zigbee_direct.codec.zdo_mgmt import MgmtLqiRsp
from vicare_direct.zigbee_direct.errors import DecodeError, UnsupportedFrameError

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
    otherwise the payload offset where the fallback found it. ``trailing`` is
    the number of bytes ignored at the end (0, or 4 with opt-in trimming).
    ``aps_secured`` is True when the match was only reachable through
    ``allow_secured_aps`` (APS security, extended header or non-data frame).
    ``aps`` is excluded from the repr: its raw payload may hold key material.
    """

    response: ScanResponse
    offset: int | None = None
    zcl_header: ZclHeader | None = None
    aps: ApsDataFrame | None = field(default=None, repr=False)
    candidate_offsets: tuple[int, ...] = ()
    trailing: int = 0
    aps_secured: bool = False


@dataclass(frozen=True, slots=True)
class ScanFailure:
    """No unique validated response; ``reason`` is meant for debug logging."""

    reason: str
    candidate_offsets: tuple[int, ...] = ()


type _Decoded = tuple[ZclHeader | None, ScanResponse]


@dataclass(frozen=True, slots=True)
class _ApsHeader:
    """APS addressing fields recovered at some position, plus where its payload starts."""

    cluster_id: int
    profile_id: int
    dst_endpoint: int | None
    unsupported: bool  # secured or extended header: payload is not known plaintext
    payload_start: int


_SEC_EXT_NONCE = 0x20
_KEY_ID_NETWORK = 1


def _header_at(data: bytes, pos: int) -> _ApsHeader | None:
    """Parse an APS data header (R23 2.2.5.1) at ``pos``, incl. extended/aux headers."""
    if pos >= len(data):
        return None
    fc = ApsFrameControl.from_byte(data[pos])
    if fc.frame_type is not ApsFrameType.DATA or fc.delivery_mode == 1:
        return None
    i = pos + 1
    dst_endpoint: int | None = None
    if fc.delivery_mode == ApsDeliveryMode.GROUP:
        i += 2
    elif i < len(data):
        dst_endpoint = data[i]
        i += 1
    if i + 6 > len(data):
        return None
    cluster = int.from_bytes(data[i : i + 2], "little")
    profile = int.from_bytes(data[i + 2 : i + 4], "little")
    i += 6  # cluster, profile, src endpoint, APS counter
    if fc.extended_header:
        if i >= len(data):
            return None
        i += 2 if data[i] & 0x03 else 1  # ext FC (+ block number when fragmented)
    if fc.security:
        if i >= len(data):
            return None
        sec = data[i]
        i += 5 + (8 if sec & _SEC_EXT_NONCE else 0)  # sec ctrl + frame counter [+ source]
        i += 1 if (sec >> 3) & 0x03 == _KEY_ID_NETWORK else 0  # key sequence number
    if i > len(data):
        return None
    unsupported = fc.security or fc.extended_header
    return _ApsHeader(cluster, profile, dst_endpoint, unsupported, i)


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


@dataclass(frozen=True, slots=True)
class _Standard:
    match: ScanMatch | None = None
    judged_offset: int | None = None  # payload offset of a well-formed APS frame
    unsupported: str | None = None  # UnsupportedFrameError message, if raised


def _standard(nwk_payload: bytes, expected: Expected, trims: tuple[int, ...]) -> _Standard:
    try:
        aps = ApsDataFrame.decode(nwk_payload)
    except UnsupportedFrameError as exc:  # must precede DecodeError (its base class)
        return _Standard(unsupported=str(exc))
    except DecodeError:
        return _Standard()  # recoverable framing error: the scan may run
    payload_offset = len(nwk_payload) - len(aps.payload)
    if not _header_matches(aps.cluster_id, aps.profile_id, aps.dst_endpoint, expected):
        return _Standard(judged_offset=payload_offset)
    result = _validate_trimmed(aps.payload, expected, trims)
    if result is None:
        return _Standard(judged_offset=payload_offset)
    trailing, (header, response) = result
    match = ScanMatch(response=response, zcl_header=header, aps=aps, trailing=trailing)
    return _Standard(match=match, judged_offset=payload_offset)


def scan_for_response(
    nwk_payload: bytes,
    expected: Expected,
    *,
    src_short: int,
    max_trailing: int = 0,
    allow_secured_aps: bool = False,
) -> ScanMatch | ScanFailure:
    """Find the expected response in an NWK payload (see module docstring).

    ``src_short`` is the NWK source of the received frame; it must equal
    ``expected.src_short``. ``max_trailing`` (default 0: strict) bounds the
    tolerated trailing bytes; only a 4-byte MIC-32 trim is ever tried, so
    values below 4 disable it. ``allow_secured_aps`` permits scanning inside
    APS frames the strict decoder refuses as unsupported (hypothesis only).
    """
    if max_trailing < 0:
        raise ValueError("max_trailing must be >= 0")
    if src_short != expected.src_short:
        return ScanFailure(
            f"source 0x{src_short:04X} is not the expected 0x{expected.src_short:04X}"
        )
    trims = _trims(max_trailing)
    standard = _standard(nwk_payload, expected, trims)
    if standard.match is not None:
        return standard.match
    if standard.unsupported is not None and not allow_secured_aps:
        return ScanFailure(
            f"standard APS decode: {standard.unsupported}; unsupported frame not scanned"
        )
    found: list[tuple[int, int, _Decoded, bool]] = []
    blocked: list[int] = []
    mismatched: list[int] = []
    for offset in SCAN_OFFSETS:
        if offset == standard.judged_offset:
            continue  # already rejected together with its real APS header
        headers = [
            hdr
            for pos in range(offset)
            if (hdr := _header_at(nwk_payload, pos)) is not None and hdr.payload_start == offset
        ]
        secured = standard.unsupported is not None or any(hdr.unsupported for hdr in headers)
        if secured and not allow_secured_aps:
            blocked.append(offset)
            continue
        if not all(
            _header_matches(hdr.cluster_id, hdr.profile_id, hdr.dst_endpoint, expected)
            for hdr in headers
        ):
            mismatched.append(offset)
            continue
        result = _validate_trimmed(nwk_payload[offset:], expected, trims)
        if result is not None:
            found.append((offset, *result, secured))
    offsets = tuple(off for off, _, _, _ in found)
    if not found:
        reason = f"no offset in {SCAN_OFFSETS.start}..{SCAN_OFFSETS.stop - 1} validated"
        if blocked:
            reason += f"; offsets {tuple(blocked)} start an unsupported (secured) APS payload"
        if mismatched:
            reason += f"; recovered APS header mismatch at offsets {tuple(mismatched)}"
        return ScanFailure(reason)
    first_offset, first_trailing, first, _ = found[0]
    if any(decoded != first for _, _, decoded, _ in found[1:]):
        return ScanFailure(f"ambiguous: offsets {offsets} decode to different results", offsets)
    header, response = first
    return ScanMatch(
        response=response,
        offset=first_offset,
        zcl_header=header,
        candidate_offsets=offsets,
        trailing=first_trailing,
        aps_secured=any(sec for _, _, _, sec in found),
    )
