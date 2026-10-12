"""Envelope verdicts shared by ``requests.Envelope`` and the dispatcher's fallback path (T11).

Private helper module of the node (spec §1.3 Envelope table). The standard path has the APS
header and a decoded ZCL frame or ZDO response; the fallback path (``codec.fallback`` scan) only
has the ZCL header and command, or the ZDO response. Both end in the same header/command and
address-of-interest checks here, so a ``ScanMatch`` passes exactly the envelope parts it can.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

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
    from vicare_local_ble.zigbee_direct.codec.fallback import ZdoResponse
    from vicare_local_ble.zigbee_direct.codec.zcl import ZclGlobalCommand, ZclHeader
    from vicare_local_ble.zigbee_direct.requests import Envelope

type Verdict = Literal["no_match", "match", "match_mfr_header_missing"]
"""``requests.EnvelopeMatch`` values (``EnvelopeMatch(verdict)`` converts)."""

NO_MATCH: Final = "no_match"
MATCH: Final = "match"
MFR_HEADER_MISSING: Final = "match_mfr_header_missing"

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
    "ZDO_RESPONSE_TYPES",
    "Verdict",
    "default_response_command",
    "zcl_command_verdict",
    "zcl_verdict",
    "zdo_verdict",
]
