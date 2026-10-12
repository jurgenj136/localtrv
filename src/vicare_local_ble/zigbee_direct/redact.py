"""NPDU inspection for the debug recorder: classify one NPDU and list its EUI fields.

Pure helper of ``debug.py`` (spec §1.8); it only reads bytes and never logs. ``inspect_npdu``
decodes with the production codecs and returns a verdict plus every EUI-64 and extended PAN the
decoders expose. The caller (``debug.redact_npdu``) maps those to pseudonyms and replaces the
wire bytes; nothing here produces output text.

Verdicts
    ``ok``           the frame decoded (standard path or fallback scan); its hex may be logged
                     after EUI replacement.
    ``aps_command``  APS command frame (may carry key material): never logged.
    ``zcl_secret``   a ZCL value of a security type (``SECURITY_TYPES``): never logged.
    ``undecodable``  anything else: only the NWK header may be logged.

Design choices (all err towards logging less):
    * EUIs are collected by walking the decoded dataclasses generically: every ``Eui64`` value at
      any depth, plus ``extended_pan_id`` integers. A decoder that grows a new EUI field is
      covered without touching this module.
    * Route Request / Reply / Network Status keep trailing bytes raw in ``tlvs``. A tail whose
      length is a multiple of 8 is treated as EUIs. This catches the live Route Reply layout
      (options 0x20 with both EUIs: the trailing own EUI lands in ``tlvs``).
    * Commissioning Request / Response TLVs are checked against an allowlist of tags with known,
      key-free layouts. An unknown tag (for example 0x45, symmetric passphrase) makes the frame
      ``undecodable``.
    * A secured, extended-header (fragment), ACK or inter-PAN APS frame is ``undecodable``; an
      APS command frame is ``aps_command``. Both are decided on the frame control alone.
    * The fallback scan (offsets 8..17 of the NWK payload, as ``codec.fallback``) replaces the
      standard inner decode when the APS header looks garbled (the bytes right behind a
      garbled header are never decoded), and is used only then: the APS decode failed, the
      profile is neither ZDO nor HA, or a ZDO profile frame does not have endpoints 0/0. A
      plausible frame with an unknown ZDO cluster or ZCL command (for example Bind_req) is
      ``undecodable`` instead of being scanned, so a coincidental scan match cannot expose its
      payload. The scan looks for ZDO responses behind a ZDO-profile header and ZCL frames
      otherwise, and rejects candidates found at more than one offset (``_scan``).
    * A cluster-specific ZCL frame is ``undecodable`` (NWK header + length only): its payload is
      opaque to the codecs and could carry key material that cannot be detected. v1 uses only
      global read / write / report / default-response frames. The fallback scan likewise
      accepts GLOBAL candidates only.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal

from vicare_local_ble.zigbee_direct.codec.aps import (
    HA_PROFILE_ID,
    ZDO_PROFILE_ID,
    ApsDataFrame,
    ApsFrameControl,
    ApsFrameType,
)
from vicare_local_ble.zigbee_direct.codec.fallback import SCAN_OFFSETS, ZDO_RESPONSE_DECODERS
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningRequest,
    CommissioningResponse,
    NetworkStatus,
    RouteReply,
    RouteRequest,
    decode_nwk_command,
)
from vicare_local_ble.zigbee_direct.codec.tlv import Tlv, decode_tlvs
from vicare_local_ble.zigbee_direct.codec.zcl import ZclFrame, ZclFrameType
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import (
    ActiveEpReq,
    DeviceAnnce,
    IeeeAddrReq,
    MatchDescReq,
    NwkAddrReq,
    SimpleDescReq,
    ZdoCluster,
)
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiReq
from vicare_local_ble.zigbee_direct.errors import DecodeError
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

#: ZCL data types whose values are secrets. KEY128 (0xF1) is the only security type of ZCL rev 8
#: that ``zcl_types`` knows; unknown type codes fail to decode and the frame is not logged.
SECURITY_TYPES: Final = frozenset({ZclDataType.KEY128})
_SECURITY_CODES: Final = frozenset(int(t) for t in SECURITY_TYPES)

type Verdict = Literal["ok", "aps_command", "zcl_secret", "undecodable"]
type FieldKind = Literal["eui", "pan"]

_EUI_LEN: Final = 8
_MAX_DEPTH: Final = 8

# Commissioning TLV tags (R23 Annex I) with key-free layouts, plus the encapsulating ones.
_TLV_KEY_NEGOTIATION: Final = 0x41  # protocols(1) ‖ pre-shared secrets(1) ‖ [EUI-64]
_TLV_SAFE_PLAIN: Final = frozenset({0x46, 0x47, 0x4B, 0x4C})  # router info, fragmentation,
# configuration parameters, device capability extension: no EUI, no key
_TLV_ENCAPSULATING: Final = frozenset({0x48, 0x49, 0x4A})  # joiner, beacon appendix, BDB

_ZDO_DECODERS: Final[Mapping[int, Callable[[bytes], object]]] = MappingProxyType(
    {
        ZdoCluster.NWK_ADDR_REQ: NwkAddrReq.decode,
        ZdoCluster.IEEE_ADDR_REQ: IeeeAddrReq.decode,
        ZdoCluster.SIMPLE_DESC_REQ: SimpleDescReq.decode,
        ZdoCluster.ACTIVE_EP_REQ: ActiveEpReq.decode,
        ZdoCluster.MATCH_DESC_REQ: MatchDescReq.decode,
        ZdoCluster.DEVICE_ANNCE: DeviceAnnce.decode,
        ZdoCluster.MGMT_LQI_REQ: MgmtLqiReq.decode,
        **ZDO_RESPONSE_DECODERS,
    }
)


def is_security_code(data_type: int | None) -> bool:
    """True if ``data_type`` is a ZCL security type (``SECURITY_TYPES``)."""
    return data_type is not None and int(data_type) in _SECURITY_CODES


@dataclass(frozen=True, slots=True)
class Inspection:
    """Result of ``inspect_npdu``.

    ``header_len`` is the NWK header length (``None`` if the NWK frame did not decode).
    ``fields`` lists every EUI-64 / extended PAN found, in frame order, duplicates kept.
    """

    verdict: Verdict
    header_len: int | None
    fields: tuple[tuple[FieldKind, Eui64], ...]


class _Collector:
    __slots__ = ("found", "secret")

    def __init__(self) -> None:
        self.found: list[tuple[FieldKind, Eui64]] = []
        self.secret = False

    def eui(self, value: Eui64 | None) -> None:
        if value is not None:
            self.found.append(("eui", value))

    def pan(self, value: int) -> None:
        self.found.append(("pan", Eui64(value.to_bytes(_EUI_LEN, "little"))))

    def walk(self, obj: object, depth: int = 0) -> None:
        """Collect every ``Eui64`` / extended PAN and flag secrets in a decoded object."""
        if depth > _MAX_DEPTH:
            raise RecursionError("decoded object nested too deeply")
        if isinstance(obj, Eui64):
            self.eui(obj)
        elif isinstance(obj, SecretBytes):
            self.secret = True
        elif isinstance(obj, tuple):
            for item in obj:
                self.walk(item, depth + 1)
        elif is_dataclass(obj) and not isinstance(obj, type):
            for f in fields(obj):
                value = getattr(obj, f.name)
                if f.name == "extended_pan_id" and isinstance(value, int):
                    self.pan(value)
                elif f.name == "data_type" and isinstance(value, int):
                    self.secret = self.secret or is_security_code(value)
                else:
                    self.walk(value, depth + 1)

    def tail(self, raw: bytes) -> None:
        """Trailing route-command bytes: a multiple of 8 is taken as EUIs (live RREP 0x20)."""
        if raw and len(raw) % _EUI_LEN == 0:
            for i in range(0, len(raw), _EUI_LEN):
                self.eui(Eui64(raw[i : i + _EUI_LEN]))


def _commissioning_tlvs(tlvs: tuple[Tlv, ...], c: _Collector, depth: int = 0) -> bool:
    """Collect EUIs from allowlisted TLVs; False if any tag is unknown or malformed."""
    if depth > _MAX_DEPTH:
        return False
    for tlv in tlvs:
        if tlv.tag in _TLV_ENCAPSULATING:
            try:
                inner = decode_tlvs(tlv.value)
            except DecodeError:
                return False
            if not _commissioning_tlvs(inner, c, depth + 1):
                return False
        elif tlv.tag == _TLV_KEY_NEGOTIATION:
            if len(tlv.value) == 2 + _EUI_LEN:
                c.eui(Eui64(tlv.value[2:]))
            elif len(tlv.value) != 2:
                return False
        elif tlv.tag not in _TLV_SAFE_PLAIN:
            return False
    return True


def _nwk_command(payload: bytes, c: _Collector) -> Verdict:
    try:
        command = decode_nwk_command(payload)
    except DecodeError:
        return "undecodable"
    c.walk(command)
    if isinstance(command, RouteRequest | RouteReply | NetworkStatus):
        c.tail(command.tlvs)
        return "ok"
    if isinstance(command, CommissioningRequest | CommissioningResponse):
        return "ok" if _commissioning_tlvs(command.tlvs, c) else "undecodable"
    return "undecodable"  # pragma: no cover - decode_nwk_command returns only the above


def _decoded(obj: object, c: _Collector) -> Verdict:
    c.walk(obj)
    return "zcl_secret" if c.secret else "ok"


def _zcl(data: bytes, c: _Collector) -> Verdict | None:
    """Decode a ZCL frame; None if it does not decode. Cluster-specific frames are
    ``undecodable`` outright (opaque payload, never scanned)."""
    try:
        frame = ZclFrame.decode(data)
        if frame.header.frame_type is not ZclFrameType.GLOBAL:
            return "undecodable"
        return _decoded(frame.global_command(), c)
    except DecodeError:
        return None


def _zdo(cluster_id: int, data: bytes, c: _Collector) -> Verdict | None:
    decoder = _ZDO_DECODERS.get(cluster_id)
    if decoder is None:
        return None
    try:
        return _decoded(decoder(data), c)
    except DecodeError:
        return None


def _scan_candidates(candidate: bytes, *, zcl: bool, zdo: bool) -> list[object]:
    found: list[object] = []
    if zcl:
        try:
            frame = ZclFrame.decode(candidate)
            if frame.header.frame_type is ZclFrameType.GLOBAL:
                found.append(frame.global_command())
        except DecodeError:
            pass
    if zdo:
        for decoder in ZDO_RESPONSE_DECODERS.values():
            try:
                found.append(decoder(candidate))
            except DecodeError:
                continue
    return found


def _scan(
    payload: bytes, c: _Collector, *, zcl: bool, zdo: bool, skip: int | None = None
) -> Verdict:
    """Fallback: a ZCL global frame or ZDO response at NWK-payload offsets 8..17 (exact).

    Without a pending request the expected kind is unknown, so it is taken from the garbled
    APS header (ZDO profile -> ZDO responses, other profile -> ZCL, no header -> both).
    Candidates at more than one offset are ambiguous (stricter than ``codec.fallback`` rule
    5): the frame is then ``undecodable``, because a spurious candidate could hide a payload
    the scan does not understand and would corrupt real bytes. Several decoders accepting the
    same offset (NWK_addr_rsp / IEEE_addr_rsp, Active_EP_rsp / Match_Desc_rsp share a layout)
    are one candidate; the EUIs of every reading are collected. ``skip`` is the payload offset
    behind a garbled APS header: those bytes were already judged untrustworthy.
    """
    found: list[tuple[int, object]] = []
    for offset in SCAN_OFFSETS:
        candidate = payload[offset:]
        if offset == skip:
            continue
        if not candidate:
            break
        found += [(offset, obj) for obj in _scan_candidates(candidate, zcl=zcl, zdo=zdo)]
    if len({offset for offset, _ in found}) != 1:
        return "undecodable"
    for _, obj in found:
        c.walk(obj)
    return "zcl_secret" if c.secret else "ok"


def _looks_garbled(aps: ApsDataFrame) -> bool:
    if aps.profile_id == ZDO_PROFILE_ID:
        return (aps.dst_endpoint, aps.src_endpoint) != (0, 0)
    return aps.profile_id != HA_PROFILE_ID


def _aps(payload: bytes, c: _Collector) -> Verdict:
    if not payload:
        return "undecodable"
    fc = ApsFrameControl.from_byte(payload[0])
    if fc.frame_type is ApsFrameType.COMMAND:
        return "aps_command"
    if (
        fc.frame_type is not ApsFrameType.DATA
        or fc.delivery_mode == 1
        or fc.security
        or fc.extended_header
    ):
        return "undecodable"
    try:
        aps: ApsDataFrame | None = ApsDataFrame.decode(payload)
    except DecodeError:
        aps = None
    if aps is None:
        return _scan(payload, c, zcl=True, zdo=True)
    is_zdo = aps.profile_id == ZDO_PROFILE_ID
    if _looks_garbled(aps):
        # Never decode the bytes behind a garbled header: failure-status Read Attributes
        # Response records (3 bytes each) accept almost any byte string, key material included.
        skip = len(payload) - len(aps.payload)
        return _scan(payload, c, zcl=not is_zdo, zdo=is_zdo, skip=skip)
    verdict = _zdo(aps.cluster_id, aps.payload, c) if is_zdo else _zcl(aps.payload, c)
    return "undecodable" if verdict is None else verdict


def inspect_npdu(npdu: bytes) -> Inspection:
    """Classify ``npdu`` and list its EUI fields (module docstring). May raise on a codec bug;
    ``debug.redact_npdu`` turns any exception into a length-only record."""
    try:
        frame = NwkFrame.decode(npdu)
    except DecodeError:
        return Inspection("undecodable", None, ())
    c = _Collector()
    c.eui(frame.dst_ieee)
    c.eui(frame.src_ieee)
    header_len = len(npdu) - len(frame.payload)
    if frame.frame_type is NwkFrameType.COMMAND:
        verdict = _nwk_command(frame.payload, c)
    elif frame.frame_type is NwkFrameType.DATA:
        verdict = _aps(frame.payload, c)
    else:
        verdict = "undecodable"
    return Inspection(verdict, header_len, tuple(c.found))


__all__ = ["SECURITY_TYPES", "FieldKind", "Inspection", "Verdict", "inspect_npdu"]
