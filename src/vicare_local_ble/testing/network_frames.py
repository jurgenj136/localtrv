"""NPDU builders for ``SimNetwork`` (T9): frames the mesh sends into the tunnel.

Pure helpers over the phase-1 codecs. Header shapes follow the golden fixtures
(``tests/fixtures/golden.py``): data frames ``08 02`` (security, no discover), commands
``09 02`` / ``09 12`` / ``09 08``, radius 30.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

from vicare_local_ble.zigbee_direct.codec.aps import (
    HA_PROFILE_ID,
    ZDO_PROFILE_ID,
    ApsDataFrame,
    ApsDeliveryMode,
)
from vicare_local_ble.zigbee_direct.codec.nwk import (
    DISCOVER_ROUTE_SUPPRESS,
    NwkFrame,
    NwkFrameType,
    SourceRoute,
)
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningResponse,
    NetworkStatus,
    RouteRequest,
)
from vicare_local_ble.zigbee_direct.codec.zcl import (
    AttributeRecord,
    ReportAttributes,
    ZclCommandId,
    ZclDirection,
    ZclHeader,
)
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import (
    DeviceAnnce,
    MatchDescReq,
    ZdoCluster,
    ZdoStatus,
)
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import (
    DeviceType,
    MgmtLqiReq,
    MgmtLqiRsp,
    Neighbor,
    Relationship,
)
from vicare_local_ble.zigbee_direct.types import BROADCAST_RX_ON, COORDINATOR, Eui64

if TYPE_CHECKING:
    from collections.abc import Mapping

type FrameVariant = Literal["plain", "source_route", "garbage4"]
type NoiseKind = Literal["foreign_annce", "foreign_broadcast", "network_status_other", "other_dst"]

_VARIANTS: Final[tuple[FrameVariant, ...]] = ("plain", "source_route", "garbage4")

RADIUS: Final = 0x1E
#: Four bytes before the APS header that are NOT a source-route subframe (PN §3.8).
GARBAGE4: Final = bytes.fromhex("005A5A00")
#: Capability of a sleepy end device (allocate address only).
END_DEVICE_CAPABILITY: Final = 0x80
NETWORK_STATUS_NO_ROUTE: Final = 0x02
NETWORK_STATUS_NO_INDIRECT_CAPACITY: Final = 0x05
NETWORK_STATUS_INDIRECT_EXPIRY: Final = 0x06
NETWORK_STATUS_ADDRESS_CONFLICT: Final = 0x0D
_LQI_END_DEVICE: Final = 0xB4
_LQI_ROUTER: Final = 0xC8
_THERMOSTAT: Final = 0x0201


def data_npdu(
    *,
    dst: int,
    src: int,
    seq: int,
    aps: ApsDataFrame,
    variant: FrameVariant,
    relay: int,
    src_ieee: Eui64 | None = None,
) -> bytes:
    """A data frame from the mesh in one of the three quirk variants (relay = ZDD short)."""
    payload = aps.encode()
    source_route = None
    if variant == "source_route":
        source_route = SourceRoute(relay_index=0, relays=(relay,))
    elif variant == "garbage4":
        payload = GARBAGE4 + payload
    return NwkFrame(
        frame_type=NwkFrameType.DATA,
        dst=dst,
        src=src,
        radius=RADIUS,
        seq=seq,
        payload=payload,
        security=True,
        source_route=source_route,
        src_ieee=src_ieee,
    ).encode()


def command_npdu(
    *,
    dst: int,
    src: int,
    seq: int,
    payload: bytes,
    dst_ieee: Eui64 | None = None,
    src_ieee: Eui64 | None = None,
    security: bool = True,
) -> bytes:
    return NwkFrame(
        frame_type=NwkFrameType.COMMAND,
        dst=dst,
        src=src,
        radius=RADIUS,
        seq=seq,
        payload=payload,
        discover_route=DISCOVER_ROUTE_SUPPRESS,
        security=security,
        dst_ieee=dst_ieee,
        src_ieee=src_ieee,
    ).encode()


def commissioning_response_npdu(
    *, placeholder: int, zdd_short: int, seq: int, short: int, status: int, zvd: Eui64 | None
) -> bytes:
    """``09 08 <ph> <zdd> 1E seq [EUI_zvd] 0F short status`` (no NWK security, pre-join)."""
    return command_npdu(
        dst=placeholder,
        src=zdd_short,
        seq=seq,
        payload=CommissioningResponse(short, status).encode(),
        dst_ieee=zvd,
        security=False,
    )


def network_status_npdu(*, dst: int, src: int, seq: int, status: int, about: int) -> bytes:
    """``09 02 <dst> <src> 1E seq 03 status <about>``."""
    return command_npdu(dst=dst, src=src, seq=seq, payload=NetworkStatus(status, about).encode())


def route_request_npdu(
    *,
    src: int,
    seq: int,
    route_id: int,
    target: int,
    target_ieee: Eui64 | None,
    src_ieee: Eui64 | None,
    broadcast: int,
) -> bytes:
    """RREQ as the R0 relays it: ``09 12 FC FF <orig> 1E seq [EUI_orig] 01 opt rid ...``."""
    request = RouteRequest(route_id=route_id, dst=target, dst_ieee=target_ieee)
    return command_npdu(
        dst=broadcast, src=src, seq=seq, payload=request.encode(), src_ieee=src_ieee
    )


def device_annce_aps(*, zdo_seq: int, short: int, eui: Eui64, counter: int) -> ApsDataFrame:
    return ApsDataFrame(
        cluster_id=ZdoCluster.DEVICE_ANNCE,
        profile_id=ZDO_PROFILE_ID,
        payload=DeviceAnnce(zdo_seq, short, eui, END_DEVICE_CAPABILITY).encode(),
        delivery_mode=ApsDeliveryMode.BROADCAST,
        dst_endpoint=0,
        counter=counter,
    )


def match_desc_broadcast_aps(*, zdo_seq: int, counter: int) -> ApsDataFrame:
    """Foreign noise: a Match_Desc_req broadcast for HA thermostats (PN §6 "Noise")."""
    req = MatchDescReq(zdo_seq, BROADCAST_RX_ON, HA_PROFILE_ID, (_THERMOSTAT,), ())
    return ApsDataFrame(
        cluster_id=ZdoCluster.MATCH_DESC_REQ,
        profile_id=ZDO_PROFILE_ID,
        payload=req.encode(),
        delivery_mode=ApsDeliveryMode.BROADCAST,
        dst_endpoint=0,
        counter=counter,
    )


def zcl_report_aps(*, counter: int) -> ApsDataFrame:
    """Noise for another destination: a localTemperature report (to the coordinator)."""
    header = ZclHeader(
        tsn=counter,
        command_id=ZclCommandId.REPORT_ATTRIBUTES,
        direction=ZclDirection.SERVER_TO_CLIENT,
        disable_default_response=True,
    )
    body = ReportAttributes((AttributeRecord(0x0000, ZclDataType.INT16, 2000),)).encode()
    return ApsDataFrame(
        cluster_id=_THERMOSTAT,
        profile_id=HA_PROFILE_ID,
        payload=header.encode() + body,
        dst_endpoint=1,
        src_endpoint=1,
        counter=counter,
    )


def check_variant_weights(
    weights: Mapping[FrameVariant, float] | None,
) -> tuple[tuple[FrameVariant, ...], tuple[float, ...]] | None:
    """Validate ``variant_weights`` into ``(variants, weights)`` for ``rng.choices``."""
    if weights is None:
        return None
    if any(k not in _VARIANTS for k in weights) or any(w < 0 for w in weights.values()):
        raise ValueError(f"invalid variant_weights: {dict(weights)!r}")
    if sum(weights.values()) <= 0:
        raise ValueError("variant_weights need a positive total")
    return tuple(weights), tuple(weights.values())


def noise_npdu(
    kind: NoiseKind,
    *,
    seq: int,
    zdo_seq: int,
    counter: int,
    foreign_short: int,
    valve_short: int,
    zdd_short: int,
) -> bytes:
    """One foreign frame the ZVD must ignore (PN §6 "Noise")."""
    match kind:
        case "foreign_annce":
            eui = Eui64.from_wire(bytes([0xEE, foreign_short & 0xFF, 0, 0, 0, 0, 0, 0x02]))
            aps = device_annce_aps(zdo_seq=zdo_seq, short=foreign_short, eui=eui, counter=counter)
            src = foreign_short
        case "foreign_broadcast":
            aps = match_desc_broadcast_aps(zdo_seq=zdo_seq, counter=counter)
            src = COORDINATOR
        case "network_status_other":
            return network_status_npdu(
                dst=BROADCAST_RX_ON,
                src=zdd_short,
                seq=seq,
                status=NETWORK_STATUS_NO_ROUTE,
                about=foreign_short,
            )
        case "other_dst":
            aps = zcl_report_aps(counter=counter)
            return data_npdu(
                dst=foreign_short, src=valve_short, seq=seq, aps=aps, variant="plain", relay=0
            )
    return broadcast_npdu(src=src, seq=seq, aps=aps)


def broadcast_npdu(*, src: int, seq: int, aps: ApsDataFrame) -> bytes:
    """A plain data broadcast to 0xFFFD (Device_annce, Match_Desc)."""
    return data_npdu(dst=BROADCAST_RX_ON, src=src, seq=seq, aps=aps, variant="plain", relay=0)


def end_device_neighbor(ext_pan: int, eui: Eui64, short: int, depth: int) -> Neighbor:
    return Neighbor(
        extended_pan_id=ext_pan,
        ieee=eui,
        nwk_addr=short,
        device_type=DeviceType.END_DEVICE,
        rx_on_when_idle=False,
        relationship=Relationship.CHILD,
        permit_joining=None,
        depth=depth,
        lqi=_LQI_END_DEVICE,
    )


def router_neighbor(ext_pan: int, eui: Eui64, short: int, depth: int) -> Neighbor:
    return Neighbor(
        extended_pan_id=ext_pan,
        ieee=eui,
        nwk_addr=short,
        device_type=DeviceType.ROUTER,
        rx_on_when_idle=True,
        relationship=Relationship.CHILD,
        permit_joining=False,
        depth=depth,
        lqi=_LQI_ROUTER,
    )


def lqi_page(req: MgmtLqiReq, table: tuple[Neighbor, ...], page_size: int) -> MgmtLqiRsp:
    """At most ``page_size`` records from ``req.start_index`` (count 0 past the end)."""
    start = min(req.start_index, len(table))
    page = table[start : start + page_size]
    return MgmtLqiRsp(req.seq, ZdoStatus.SUCCESS, len(table), start, page)


__all__ = [
    "END_DEVICE_CAPABILITY",
    "GARBAGE4",
    "NETWORK_STATUS_ADDRESS_CONFLICT",
    "NETWORK_STATUS_INDIRECT_EXPIRY",
    "NETWORK_STATUS_NO_INDIRECT_CAPACITY",
    "NETWORK_STATUS_NO_ROUTE",
    "RADIUS",
    "FrameVariant",
    "NoiseKind",
    "broadcast_npdu",
    "check_variant_weights",
    "command_npdu",
    "commissioning_response_npdu",
    "data_npdu",
    "device_annce_aps",
    "end_device_neighbor",
    "lqi_page",
    "match_desc_broadcast_aps",
    "network_status_npdu",
    "noise_npdu",
    "route_request_npdu",
    "router_neighbor",
    "zcl_report_aps",
]
