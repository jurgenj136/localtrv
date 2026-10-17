"""Pure post-join NPDU builders; sans-IO, no allocation, no state.

Every builder returns the complete plaintext NPDU (NWK header + APS + ZDO/ZCL) that the node
hands to ``ZigbeeDirectTransport.send_npdu`` with ``secure=True``. Sequence numbers and
counters are parameters: the node's allocators (``requests.Allocators``) choose them, so the
builders are deterministic and golden-testable (``tests/fixtures/golden.py``).

Common NWK layout for post-join frames: security bit set (FC byte1 bit 0x02, the ZDD applies
the real NWK security), radius 30, src = our short. Unicast data uses ``discover_route=1``
(FC ``48 02``); a suppressed route discovery gave Network Status 0x02 live (docs/protocol.md §6.3).

Builders: ``device_annce_npdu``, ``zdo_unicast_npdu``, ``zcl_unicast_npdu`` and
``route_reply_npdu`` (which uses ``RouteReply.options_override``). The many-to-one Route
Request NPDU already exists as ``codec.nwk_commands.many_to_one_route_request_npdu`` (live
``09 12``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from localtrv.zigbee_direct.codec.aps import (
    ZDO_PROFILE_ID,
    ApsAckFrame,
    ApsDataFrame,
    ApsDeliveryMode,
)
from localtrv.zigbee_direct.codec.nwk import DISCOVER_ROUTE_ENABLE, NwkFrame, NwkFrameType
from localtrv.zigbee_direct.codec.nwk_commands import DEFAULT_ZVD_CAPABILITY, RouteReply
from localtrv.zigbee_direct.codec.zdo import DeviceAnnce, ZdoCluster
from localtrv.zigbee_direct.types import BROADCAST_RX_ON

if TYPE_CHECKING:
    from localtrv.zigbee_direct.types import Eui64

#: Radius of every post-join frame we originate.
DEFAULT_RADIUS: Final = 30
#: Our application endpoint for ZCL traffic (APS src endpoint of requests, ``01``).
LOCAL_ENDPOINT: Final = 1
#: Options byte the live client sent in Route Replies, with both EUIs appended (protocol.md §6.4).
LIVE_ROUTE_REPLY_OPTIONS: Final = 0x20


def _data_npdu(
    *, dst: int, own_short: int, nwk_seq: int, radius: int, aps: ApsDataFrame | ApsAckFrame
) -> bytes:
    """Post-join NWK data frame: discover_route=1, security bit set (FC ``48 02``)."""
    return NwkFrame(
        frame_type=NwkFrameType.DATA,
        dst=dst,
        src=own_short,
        radius=radius,
        seq=nwk_seq,
        payload=aps.encode(),
        discover_route=DISCOVER_ROUTE_ENABLE,
        security=True,
    ).encode()


def device_annce_npdu(
    *,
    own_short: int,
    own_eui: Eui64,
    nwk_seq: int,
    zdo_seq: int,
    aps_counter: int,
    capability: int = DEFAULT_ZVD_CAPABILITY,
    radius: int = DEFAULT_RADIUS,
) -> bytes:
    """Device_annce broadcast to 0xFFFD.

    NWK ``48 02 FD FF <own> 1E seq`` (data, discover_route=1, security), APS broadcast
    ``08 00 13 00 00 00 00 ctr``, ZDO ``zdo_seq <own> EUI_own capability``.
    """
    annce = DeviceAnnce(seq=zdo_seq, nwk_addr=own_short, ieee=own_eui, capability=capability)
    aps = ApsDataFrame(
        cluster_id=ZdoCluster.DEVICE_ANNCE,
        profile_id=ZDO_PROFILE_ID,
        payload=annce.encode(),
        delivery_mode=ApsDeliveryMode.BROADCAST,
        dst_endpoint=0,
        src_endpoint=0,
        counter=aps_counter,
    )
    return _data_npdu(
        dst=BROADCAST_RX_ON, own_short=own_short, nwk_seq=nwk_seq, radius=radius, aps=aps
    )


def zdo_unicast_npdu(
    *,
    dst: int,
    own_short: int,
    nwk_seq: int,
    cluster_id: int,
    zdo_payload: bytes,
    aps_counter: int = 0,
    radius: int = DEFAULT_RADIUS,
) -> bytes:
    """ZDO unicast request: NWK ``48 02 <dst> <own> 1E seq``, APS ``00 00 <cluster> 00 00 00
    ctr`` (endpoints 0, profile 0), then ``zdo_payload`` (``seq ‖ body`` as encoded by the
    ``codec.zdo``/``zdo_mgmt`` request classes). The live client always used APS counter 0."""
    aps = ApsDataFrame(
        cluster_id=cluster_id,
        profile_id=ZDO_PROFILE_ID,
        payload=bytes(zdo_payload),
        dst_endpoint=0,
        src_endpoint=0,
        counter=aps_counter,
    )
    return _data_npdu(dst=dst, own_short=own_short, nwk_seq=nwk_seq, radius=radius, aps=aps)


def zcl_unicast_npdu(
    *,
    dst: int,
    own_short: int,
    nwk_seq: int,
    dst_endpoint: int,
    cluster_id: int,
    profile_id: int,
    zcl_frame: bytes,
    aps_counter: int,
    src_endpoint: int = LOCAL_ENDPOINT,
    radius: int = DEFAULT_RADIUS,
) -> bytes:
    """ZCL unicast request: NWK ``48 02 <dst> <own> 1E seq``, APS ``00 <dst_ep> <cluster>
    <profile> <src_ep> ctr`` (live: ``00 01 01 02 04 01 01 ctr``), then the encoded
    ``ZclFrame``."""
    aps = ApsDataFrame(
        cluster_id=cluster_id,
        profile_id=profile_id,
        payload=bytes(zcl_frame),
        dst_endpoint=dst_endpoint,
        src_endpoint=src_endpoint,
        counter=aps_counter,
    )
    return _data_npdu(dst=dst, own_short=own_short, nwk_seq=nwk_seq, radius=radius, aps=aps)


def aps_ack_npdu(
    *,
    dst: int,
    own_short: int,
    nwk_seq: int,
    inbound: ApsDataFrame,
    radius: int = DEFAULT_RADIUS,
) -> bytes:
    """APS ack (R23 2.2.5.2.3, ack format 0) of the unicast data frame ``inbound`` from
    ``dst``: NWK ``48 02 <dst> <own> 1E seq`` (as every unicast we send), APS ``02 <inbound src
    ep> <cluster> <profile> <inbound dst ep> <inbound counter>`` (``ApsAckFrame.for_frame``).

    Hardware example: the valve's ``40 01 0102 0401 01 51`` is acked with
    ``02 01 0102 0401 01 51``."""
    return _data_npdu(
        dst=dst,
        own_short=own_short,
        nwk_seq=nwk_seq,
        radius=radius,
        aps=ApsAckFrame.for_frame(inbound),
    )


def route_reply_npdu(
    *,
    originator: int,
    own_short: int,
    own_eui: Eui64,
    nwk_seq: int,
    route_id: int,
    originator_ieee: Eui64 | None,
    options_override: int | None,
    radius: int = DEFAULT_RADIUS,
) -> bytes:
    """Route Reply to ``originator``: NWK ``49 02 <orig> <own> 1E seq`` (command,
    discover_route=1, security), payload ``RouteReply(route_id, originator, own_short,
    path_cost=0, originator_ieee, responder_ieee=own_eui, options_override)``.

    LIVE mode passes ``options_override=LIVE_ROUTE_REPLY_OPTIONS`` and gives ``02 20 rid <orig>
    <own> 00 EUI_orig EUI_own``; SPEC mode passes ``None`` (derived options, 0x30 with both
    EUIs). ``originator_ieee=None`` omits that EUI (unknown originator).
    """
    reply = RouteReply(
        route_id=route_id,
        originator=originator,
        responder=own_short,
        path_cost=0,
        originator_ieee=originator_ieee,
        responder_ieee=own_eui,
        options_override=options_override,
    )
    return NwkFrame(
        frame_type=NwkFrameType.COMMAND,
        dst=originator,
        src=own_short,
        radius=radius,
        seq=nwk_seq,
        payload=reply.encode(),
        discover_route=DISCOVER_ROUTE_ENABLE,
        security=True,
    ).encode()


__all__ = [
    "DEFAULT_RADIUS",
    "LIVE_ROUTE_REPLY_OPTIONS",
    "LOCAL_ENDPOINT",
    "aps_ack_npdu",
    "device_annce_npdu",
    "route_reply_npdu",
    "zcl_unicast_npdu",
    "zdo_unicast_npdu",
]
