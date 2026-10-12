"""Routing duties of the virtual node: announce, MTORR, RREQ->RREP, Network Status (spec §1.3).

Frozen interface (T2). Task split inside this module:

* **T11** (must be complete on its own; nothing on the T11 path may raise
  ``NotImplementedError("T12")``): ``NeighborTable``, ``Router.announce``,
  ``Router.send_mtorr``, ``Router.send_mtorr_burst``, ``Router.on_network_status``, a minimal
  ``Router.start_periodic``/``Router.stop`` (task lifecycle of the periodic MTORR loop), and a
  minimal ``Router.on_route_request`` that only counts ``NodeStats.rreq_seen`` and never
  raises.
* **T12**: replaces ``on_route_request`` with the full RREP responder (dedupe TTL, per-originator
  rate limit, originator EUI lookup, ``frames.route_reply_npdu``) and finishes/hardens the
  periodic MTORR if T11 left it minimal.

The router never touches the transport, allocators' owners or pending map directly: it goes
through ``RoutingHost``, which ``ZigbeeDirectNode`` implements. All methods run on the loop
thread. Sync entry points (``on_route_request``, ``on_network_status``) are called by the
dispatcher from the transport's notify callback: they must not await; any send is started with
``host.start_task``, which the node owns, cancels and awaits at ``close()``.

Logging (logger ``vicare_local_ble.zigbee_direct.node``): DEBUG for RREQ seen/deduped, RREP
sent, MTORR sent, Network Status; never payload bytes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:
    import asyncio
    from collections.abc import Coroutine, Iterable
    from typing import Any

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
    from vicare_local_ble.zigbee_direct.codec.nwk_commands import NetworkStatus, RouteRequest
    from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import Neighbor
    from vicare_local_ble.zigbee_direct.node_types import NodeConfig, NodeStats
    from vicare_local_ble.zigbee_direct.requests import Allocators, PendingMap
    from vicare_local_ble.zigbee_direct.types import Eui64

#: At most one RREP per originator in this many seconds (on top of the (orig, rid) dedupe).
RREP_MIN_INTERVAL: Final = 2.0
#: At most one MTORR triggered by Network Status 0x02 in this many seconds.
MTORR_ON_ROUTE_FAILURE_INTERVAL: Final = 30.0
#: Network Status codes with a dedicated reaction.
NWK_STATUS_NO_ROUTE: Final = 0x02
NWK_STATUS_ADDRESS_CONFLICT: Final = 0x0D


class NeighborTable:
    """Short <-> EUI knowledge of the node, for RREP originator EUIs and ``ReportEvent.src_ieee``.

    Fed by ``note_neighbors`` (Mgmt_Lqi records via ``walk_topology``), Device_annce and NWK
    headers carrying a src IEEE (``note``). The latest observation wins in both directions.
    """

    def __init__(self) -> None:
        raise NotImplementedError("T11")

    def note(self, short: int, eui: Eui64) -> None:
        raise NotImplementedError("T11")

    def note_neighbors(self, neighbors: Iterable[Neighbor]) -> None:
        raise NotImplementedError("T11")

    def ieee_for(self, short: int) -> Eui64 | None:
        raise NotImplementedError("T11")

    def short_for(self, eui: Eui64) -> int | None:
        raise NotImplementedError("T11")


class RoutingHost(Protocol):
    """What the router needs from its node (``ZigbeeDirectNode`` implements it, T11)."""

    @property
    def clock(self) -> Clock: ...

    @property
    def config(self) -> NodeConfig: ...

    @property
    def stats(self) -> NodeStats: ...

    @property
    def allocators(self) -> Allocators: ...

    @property
    def pending(self) -> PendingMap: ...

    @property
    def neighbors(self) -> NeighborTable: ...

    @property
    def own_short(self) -> int:
        """Validated own short; only valid once the Commissioning Response was accepted."""
        ...

    @property
    def own_eui(self) -> Eui64: ...

    async def send_secure(self, npdu: bytes) -> None:
        """``transport.send_npdu(npdu, secure=True)``; raises ``ConnectionLostError`` if the
        node is closed or the transport broken."""
        ...

    def start_task(self, coro: Coroutine[Any, Any, None], *, name: str) -> asyncio.Task[None]:
        """Start a node-owned task (cancelled and awaited by ``node.close``). Exceptions other
        than cancellation are logged at DEBUG and swallowed."""
        ...

    def fire_address_conflict(self) -> None:
        """Call every ``on_address_conflict`` listener (sync)."""
        ...


class Router:
    """Routing logic for one node (one generation)."""

    def __init__(self, host: RoutingHost) -> None:
        raise NotImplementedError("T11")

    # --- T11 -----------------------------------------------------------------------------

    async def announce(self) -> None:
        """Send one Device_annce (``frames.device_annce_npdu``) with fresh NWK/ZDO/APS values."""
        raise NotImplementedError("T11")

    async def send_mtorr(self) -> None:
        """Send one many-to-one Route Request (live ``09 12``) with a fresh route id and NWK seq.

        Route ids come from a router-owned 8-bit counter (distinct per send)."""
        raise NotImplementedError("T11")

    async def send_mtorr_burst(self) -> None:
        """``config.mtorr_count`` MTORRs, ``config.mtorr_spacing`` apart (``clock.sleep``)."""
        raise NotImplementedError("T11")

    def on_network_status(self, frame: NwkFrame, status: NetworkStatus) -> None:
        """React to a NWK Network Status command (sync, from dispatch). Never raises.

        The dispatcher only forwards Network Status frames whose NWK dst is our short, our
        active join placeholder, or a broadcast. Then:

        * Fail pending requests to ``status.destination`` with ``RouteError(dst, status)``
          (``host.pending.fail_dst``) ONLY if the NWK ``frame.dst == own_short`` (a unicast
          status about our own traffic; broadcast statuses about others never fail requests).
          Before the join completed nothing is pending, so this is skipped.
        * 0x02 (no route), under the same condition, also schedules one MTORR, at most every
          ``MTORR_ON_ROUTE_FAILURE_INTERVAL`` seconds.
        * 0x0D (address conflict): whenever ``status.destination == own_short``, regardless of
          the frame's NWK dst (conflicts are usually broadcast), call
          ``host.fire_address_conflict()``.
        """
        raise NotImplementedError("T11")

    def on_route_request(self, frame: NwkFrame, request: RouteRequest) -> None:
        """Handle a Route Request (sync, from dispatch). Never raises.

        T11 (minimal): count ``stats.rreq_seen`` and return.

        T12 (full responder): answer only if ``request.dst == own_short`` and the mode is not
        ``RouteReplyMode.OFF`` (others are counted and ignored). Dedupe on
        ``(frame.src, route_id)`` for ``config.rreq_dedupe_ttl``; at most one RREP per
        originator every ``RREP_MIN_INTERVAL``. The originator EUI is ``frame.src_ieee``, else
        ``neighbors.ieee_for(frame.src)``, else omitted. The RREP
        (``frames.route_reply_npdu``) is sent from a ``host.start_task``.
        """
        raise NotImplementedError("T11 (minimal), T12 (full)")

    def start_periodic(self) -> None:
        """Start the periodic MTORR task (one ``send_mtorr`` every ``config.mtorr_interval``,
        via ``clock.sleep`` in a ``host.start_task``). Idempotent. Called by ``node.join`` after
        the join burst. Send failures are logged at DEBUG and the loop continues; it ends on
        cancellation or ``ConnectionLostError``. T11 implements; T12 may harden."""
        raise NotImplementedError("T11")

    def stop(self) -> None:
        """Cancel the periodic MTORR task (the node also cancels and awaits all its tasks at
        close). Idempotent. T11."""
        raise NotImplementedError("T11")


__all__ = [
    "MTORR_ON_ROUTE_FAILURE_INTERVAL",
    "NWK_STATUS_ADDRESS_CONFLICT",
    "NWK_STATUS_NO_ROUTE",
    "RREP_MIN_INTERVAL",
    "NeighborTable",
    "Router",
    "RoutingHost",
]
