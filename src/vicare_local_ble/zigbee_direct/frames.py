"""Pure post-join NPDU builders (PN §1.4); sans-IO, no allocation, no state.

Every builder returns the complete plaintext NPDU (NWK header + APS + ZDO/ZCL) that the node
hands to ``ZigbeeDirectTransport.send_npdu`` with ``secure=True``. Sequence numbers and
counters are parameters: the node's allocators (``requests.Allocators``) choose them, so the
builders are deterministic and golden-testable (``tests/fixtures/golden.py``).

Common NWK layout for post-join frames: security bit set (FC byte1 bit 0x02, the ZDD applies
the real NWK security), radius 30, src = our short. Unicast data uses ``discover_route=1``
(FC ``48 02``); a suppressed route discovery gave Network Status 0x02 live (PN §5.6).

Task ownership: T11 implements ``device_annce_npdu``, ``zdo_unicast_npdu`` and
``zcl_unicast_npdu``; T12 implements ``route_reply_npdu`` (needs T3's
``RouteReply.options_override``). The many-to-one Route Request NPDU already exists as
``codec.nwk_commands.many_to_one_route_request_npdu`` (live ``09 12``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from vicare_local_ble.zigbee_direct.codec.nwk_commands import DEFAULT_ZVD_CAPABILITY

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.types import Eui64

#: Radius of every post-join frame we originate (PN §1.4).
DEFAULT_RADIUS: Final = 30
#: Our application endpoint for ZCL traffic (APS src endpoint of requests; PN §1.4 ``01``).
LOCAL_ENDPOINT: Final = 1
#: Options byte the live client sent in Route Replies (PN §5.1), with both EUIs appended.
LIVE_ROUTE_REPLY_OPTIONS: Final = 0x20


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
    ``08 00 13 00 00 00 00 ctr``, ZDO ``zdo_seq <own> EUI_own capability`` (PN §1.4).
    """
    raise NotImplementedError("T11")


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
    raise NotImplementedError("T11")


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
    <profile> <src_ep> ctr`` (PN §1.4: ``00 01 01 02 04 01 01 ctr``), then the encoded
    ``ZclFrame``."""
    raise NotImplementedError("T11")


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
    raise NotImplementedError("T12")


__all__ = [
    "DEFAULT_RADIUS",
    "LIVE_ROUTE_REPLY_OPTIONS",
    "LOCAL_ENDPOINT",
    "device_annce_npdu",
    "route_reply_npdu",
    "zcl_unicast_npdu",
    "zdo_unicast_npdu",
]
