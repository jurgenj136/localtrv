"""Ingress dispatch: one decrypted tunnel NPDU in, routed to exactly one consumer (spec §1.3).

Implemented by T11; frozen interface (T2). ``Dispatcher.handle`` is installed as the
transport's NPDU handler (``transport.set_npdu_handler``) by the node's constructor. It runs
synchronously on the loop inside the BLE notify callback: it never awaits, never sends, and
never raises (every exception is caught, counted in ``decode_errors`` and logged at DEBUG).

Per NPDU (spec §1.3 "Ingress dispatch"):

1. ``NwkFrame.decode`` (strips multicast and source-route data); error -> ``decode_errors``.
   A ``src_ieee`` in the header is noted in ``host.neighbors``.
2. Command frames (``decode_nwk_command``). First the address filter: a command frame whose NWK
   dst is not ``host.current_short``, not the active join token's placeholder
   (``host.join_slot.active``) and not a broadcast (>= 0xFFF8) is dropped (DEBUG). Then:
   * Commissioning Response (0x0F) -> ``host.join_slot.offer(frame, rsp)``; unclaimed responses
     (no token, other placeholder including an older attempt's) are dropped with DEBUG.
   * Route Request -> ``host.router.on_route_request(frame, rreq)``.
   * Network Status -> ``host.router.on_network_status(frame, status)`` (the router decides:
     ``RouteError`` only for frames unicast to our short; 0x0D whenever the status
     destination is our short).
   * Others are ignored.
3. Data frames whose dst is neither ``host.current_short`` nor a broadcast are dropped. Before the
   join completed (``current_short is None``) every data frame is dropped. Otherwise
   ``ApsDataFrame.decode``:
   * ZDO profile: Device_annce -> ``host.neighbors.note`` + ``host.emit_device_annce``;
     responses resolve a pending entry only if ``Envelope.match_zdo`` passes; a retired key
     counts ``late_drops``; ZDO requests to us are ignored in v1.
   * HA profile (any non-ZDO profile): ``ZclFrame.decode``. Report Attributes (0x0A,
     server->client) ALWAYS goes to ``host.emit_report`` and never touches pending; everything
     else is matched with ``Envelope.match_zcl`` against the entry for
     ``(src, "zcl", tsn)``.
4. Fallback: only if the standard APS/ZCL/ZDO decode failed AND ``host.pending.for_src(src)`` is
   non-empty, run ``scan_for_response(nwk_payload, envelope.expected(), src_short=src)``
   (strict, ``max_trailing=0``) for each; a ``ScanMatch`` must still pass command, tsn/seq and
   manufacturer checks. Counted in ``fallback_hits``.
5. Never reply to anything (reports, broadcasts) in v1.

Logging (logger ``vicare_local_ble.zigbee_direct.node``): DEBUG only, and only decoded,
sanitised fields (``debug.sanitize_records`` before logging any attribute records). Never
payload bytes: the NPDU log is the recorder's job.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce
    from vicare_local_ble.zigbee_direct.node_types import NodeStats, ReportEvent
    from vicare_local_ble.zigbee_direct.requests import JoinSlot, PendingMap
    from vicare_local_ble.zigbee_direct.routing import NeighborTable, Router


class DispatchHost(Protocol):
    """What the dispatcher needs from its node (``ZigbeeDirectNode`` implements it, T11)."""

    @property
    def current_short(self) -> int | None:
        """Validated own short, or ``None`` before the Commissioning Response was accepted.

        (The public ``ZigbeeDirectNode.own_short`` raises before the join instead.)"""
        ...

    @property
    def pending(self) -> PendingMap: ...

    @property
    def join_slot(self) -> JoinSlot: ...

    @property
    def router(self) -> Router: ...

    @property
    def neighbors(self) -> NeighborTable: ...

    @property
    def stats(self) -> NodeStats: ...

    def emit_report(self, event: ReportEvent) -> None:
        """Call every ``on_report`` listener; listener exceptions are logged and swallowed."""
        ...

    def emit_device_annce(self, annce: DeviceAnnce, src_short: int) -> None:
        """Call every ``on_device_annce`` listener with the annce and its NWK src short."""
        ...


class Dispatcher:
    """Stateless router of ingress NPDUs (all state lives in the host's collaborators)."""

    def __init__(self, host: DispatchHost) -> None:
        raise NotImplementedError("T11")

    def handle(self, npdu: TunnelNpdu) -> None:
        """Process one NPDU (see module docstring). Never raises."""
        raise NotImplementedError("T11")


__all__ = ["DispatchHost", "Dispatcher"]
