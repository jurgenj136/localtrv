"""Envelope verdicts shared by ``requests.Envelope`` and the dispatcher's fallback path (T11).

Private helper module of the node (spec §1.3 Envelope table). The standard path has the APS
header and a decoded ZCL frame or ZDO response; the fallback path (``codec.fallback`` scan) only
has the ZCL header and command, or the ZDO response. Both end in the same header/command and
address-of-interest checks here, so a ``ScanMatch`` passes exactly the envelope parts it can.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID, ZDO_PROFILE_ID
from vicare_local_ble.zigbee_direct.codec.zcl import (
    DefaultResponse,
    ZclCommandId,
    ZclDirection,
    ZclFrameType,
)
from vicare_local_ble.zigbee_direct.codec.zdo import (
    ActiveEpReq,
    ActiveEpRsp,
    IeeeAddrReq,
    IeeeAddrRsp,
    MatchDescRsp,
    NwkAddrRsp,
    SimpleDescReq,
    SimpleDescRsp,
)
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiRsp
from vicare_local_ble.zigbee_direct.errors import DecodeError

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
    from vicare_local_ble.zigbee_direct.codec.fallback import ZdoResponse
    from vicare_local_ble.zigbee_direct.codec.zcl import ZclGlobalCommand, ZclHeader
    from vicare_local_ble.zigbee_direct.requests import Envelope

type Verdict = Literal["no_match", "match", "match_mfr_header_missing"]
"""``requests.EnvelopeMatch`` values (``EnvelopeMatch(verdict)`` converts)."""

NO_MATCH: Final = "no_match"
MATCH: Final = "match"
MFR_HEADER_MISSING: Final = "match_mfr_header_missing"

#: Standard ZDP request clusters (Zigbee R23 2.4.3; R22 discovery-cache clusters included):
#: NWK/IEEE_addr, Node/Power/Simple_Desc, Active_EP, Match_Desc, Complex/User_Desc,
#: Discovery_Cache, Device_annce (0x0013, no response), User_Desc_set, System_Server_Discovery,
#: the discovery-store family, Parent_annce (0x001F), End_Device_Bind, Bind/Unbind and the
#: bind-cache family, Clear_All_Bindings, Mgmt_NWK_Disc/Lqi/Rtg/Bind/Leave/Direct_Join/
#: Permit_Joining/Cache/NWK_Update/NWK_Enhanced_Update/NWK_IEEE_Joining_List,
#: Mgmt_NWK_Beacon_Survey, and the R23 security clusters 0x0040..0x0047.
ZDO_REQUEST_CLUSTERS: Final = frozenset(
    (
        *range(0x0007),
        *range(0x000A, 0x002C),
        *range(0x0030, 0x003B),
        0x003C,
        *range(0x0040, 0x0048),
    )
)
#: Their responses (request | 0x8000); Device_annce has none.
ZDO_RESPONSE_CLUSTERS: Final = frozenset(c | 0x8000 for c in ZDO_REQUEST_CLUSTERS if c != 0x0013)
STANDARD_ZDO_CLUSTERS: Final = ZDO_REQUEST_CLUSTERS | ZDO_RESPONSE_CLUSTERS


def plausible_aps_header(aps: ApsDataFrame) -> bool:
    """False when a decoded APS header cannot be a real frame for us (the quirk garbled it):
    a profile other than ZDO/HA, or a ZDO frame whose endpoints are not 0/0 or whose cluster is
    no standard ZDP cluster. Only implausible headers are offset-scanned (fallback)."""
    if aps.profile_id == HA_PROFILE_ID:
        return True
    return (
        aps.profile_id == ZDO_PROFILE_ID
        and aps.dst_endpoint == 0
        and aps.src_endpoint == 0
        and aps.cluster_id in STANDARD_ZDO_CLUSTERS
    )


def aps_header_matches(envelope: Envelope, aps: ApsDataFrame) -> bool:
    """The APS part of the envelope: profile, cluster and (ZCL) both endpoints."""
    if aps.profile_id != envelope.profile_id or aps.cluster_id != envelope.cluster_id:
        return False
    if envelope.kind == "zdo":
        return True
    return (envelope.remote_endpoint is None or aps.src_endpoint == envelope.remote_endpoint) and (
        envelope.local_endpoint is None or aps.dst_endpoint == envelope.local_endpoint
    )


#: ZDO responses whose ``nwk_addr`` is the NWK address of interest (Envelope docstring).
ADDRESS_OF_INTEREST_RESPONSES = (ActiveEpRsp, SimpleDescRsp, IeeeAddrRsp)
#: The requests answered by those responses (their ``nwk_addr`` sets the envelope's check).
ADDRESS_OF_INTEREST_REQUESTS = (ActiveEpReq, SimpleDescReq, IeeeAddrReq)
#: Every ``codec.fallback.ZdoResponse`` class (for narrowing a ``ScanMatch.response``).
ZDO_RESPONSE_TYPES = (ActiveEpRsp, SimpleDescRsp, MatchDescRsp, MgmtLqiRsp, IeeeAddrRsp, NwkAddrRsp)


def default_response_command(payload: bytes) -> int | None:
    """``command_id`` of a Default Response payload, or ``None`` if it does not decode."""
    try:
        return DefaultResponse.decode(payload).command_id
    except DecodeError:
        return None


def zcl_verdict(envelope: Envelope, header: ZclHeader, default_command: int | None) -> Verdict:
    """Header, TSN, command and manufacturer checks of a ZCL response.

    ``default_command`` is the Default Response's ``command_id`` (``None`` for other commands
    or an undecodable Default Response).
    """
    if (
        envelope.kind != "zcl"
        or header.frame_type is not ZclFrameType.GLOBAL
        or header.direction is not ZclDirection.SERVER_TO_CLIENT
        or header.tsn != envelope.seq
    ):
        return NO_MATCH
    command = header.command_id
    if command not in envelope.response_commands and not (
        command == ZclCommandId.DEFAULT_RESPONSE
        and envelope.request_command is not None
        and default_command == envelope.request_command
    ):
        return NO_MATCH
    code = header.manufacturer_code
    if code is not None:
        return MATCH if code == envelope.manufacturer_code else NO_MATCH
    if envelope.manufacturer_code is not None:
        return MFR_HEADER_MISSING
    return MATCH


def zcl_command_verdict(
    envelope: Envelope, header: ZclHeader, command: ZclGlobalCommand
) -> Verdict:
    """``zcl_verdict`` for an already decoded command (fallback ``ScanMatch``)."""
    default_command = command.command_id if isinstance(command, DefaultResponse) else None
    return zcl_verdict(envelope, header, default_command)


def zdo_verdict(envelope: Envelope, response: ZdoResponse) -> bool:
    """Seq and NWK-address-of-interest checks of a ZDO response."""
    if envelope.kind != "zdo" or response.seq != envelope.seq:
        return False
    noi = envelope.nwk_addr_of_interest
    return (
        noi is None
        or not isinstance(response, ADDRESS_OF_INTEREST_RESPONSES)
        or response.nwk_addr == noi
    )


__all__ = [
    "ADDRESS_OF_INTEREST_REQUESTS",
    "ADDRESS_OF_INTEREST_RESPONSES",
    "MATCH",
    "MFR_HEADER_MISSING",
    "NO_MATCH",
    "STANDARD_ZDO_CLUSTERS",
    "ZDO_REQUEST_CLUSTERS",
    "ZDO_RESPONSE_CLUSTERS",
    "ZDO_RESPONSE_TYPES",
    "Verdict",
    "aps_header_matches",
    "default_response_command",
    "plausible_aps_header",
    "zcl_command_verdict",
    "zcl_verdict",
    "zdo_verdict",
]
