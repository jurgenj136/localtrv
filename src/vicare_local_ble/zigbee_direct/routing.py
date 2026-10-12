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

import logging
from typing import TYPE_CHECKING, Final, Protocol

from vicare_local_ble.zigbee_direct.codec.nwk_commands import many_to_one_route_request_npdu
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, RouteError
from vicare_local_ble.zigbee_direct.frames import (
    DEFAULT_RADIUS,
    LIVE_ROUTE_REPLY_OPTIONS,
    device_annce_npdu,
    route_reply_npdu,
)
from vicare_local_ble.zigbee_direct.node_types import RouteReplyMode
from vicare_local_ble.zigbee_direct.requests import SeqAllocator

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
#: At most one MTORR triggered by a route-failure Network Status in this many seconds.
MTORR_ON_ROUTE_FAILURE_INTERVAL: Final = 30.0
#: NWK Network Status codes (Zigbee R23 3.4.3.3.1, table "Status Codes for Network Status").
NWK_STATUS_NO_ROUTE_AVAILABLE: Final = 0x00
NWK_STATUS_TREE_LINK_FAILURE: Final = 0x01
NWK_STATUS_NON_TREE_LINK_FAILURE: Final = 0x02
NWK_STATUS_SOURCE_ROUTE_FAILURE: Final = 0x0B
NWK_STATUS_MANY_TO_ONE_ROUTE_FAILURE: Final = 0x0C
NWK_STATUS_ADDRESS_CONFLICT: Final = 0x0D
#: Statuses (addressed to us) that schedule the rate-limited MTORR.
ROUTE_FAILURE_STATUSES: Final = frozenset(
    {
        NWK_STATUS_NO_ROUTE_AVAILABLE,
        NWK_STATUS_TREE_LINK_FAILURE,
        NWK_STATUS_NON_TREE_LINK_FAILURE,
        NWK_STATUS_SOURCE_ROUTE_FAILURE,
        NWK_STATUS_MANY_TO_ONE_ROUTE_FAILURE,
    }
)
#: Hard cap on the dedupe set (oldest key dropped first), against RREQ floods.
_MAX_DEDUPE_ENTRIES: Final = 256
#: Shorts at or above this are broadcast addresses (never noted in the neighbor table).
_FIRST_BROADCAST: Final = 0xFFF8

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.node")


class NeighborTable:
    """Short <-> EUI knowledge of the node, for RREP originator EUIs and ``ReportEvent.src_ieee``.

    Fed by ``note_neighbors`` (Mgmt_Lqi records via ``walk_topology``), Device_annce and NWK
    headers carrying a src IEEE (``note``). The latest observation wins in both directions.
    """

    __slots__ = ("_by_eui", "_by_short")

    def __init__(self) -> None:
        self._by_short: dict[int, Eui64] = {}
        self._by_eui: dict[Eui64, int] = {}

    def note(self, short: int, eui: Eui64) -> None:
        if not 0 <= short < _FIRST_BROADCAST:
            return
        old_eui = self._by_short.get(short)
        if old_eui is not None and old_eui != eui and self._by_eui.get(old_eui) == short:
            del self._by_eui[old_eui]
        old_short = self._by_eui.get(eui)
        if old_short is not None and old_short != short and self._by_short.get(old_short) == eui:
            del self._by_short[old_short]
        self._by_short[short] = eui
        self._by_eui[eui] = short

    def note_neighbors(self, neighbors: Iterable[Neighbor]) -> None:
        for neighbor in neighbors:
            self.note(neighbor.nwk_addr, neighbor.ieee)

    def ieee_for(self, short: int) -> Eui64 | None:
        return self._by_short.get(short)

    def short_for(self, eui: Eui64) -> int | None:
        return self._by_eui.get(eui)

    def __len__(self) -> int:
        return len(self._by_short)


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

    __slots__ = (
        "_host",
        "_last_failure_mtorr",
        "_last_rrep",
        "_periodic",
        "_route_ids",
        "_rreq_expiry",
    )

    def __init__(self, host: RoutingHost) -> None:
        self._host = host
        #: ``(originator, route_id)`` -> expiry time, oldest first.
        self._rreq_expiry: dict[tuple[int, int], float] = {}
        #: originator -> time of its last RREP (only while inside ``RREP_MIN_INTERVAL``).
        self._last_rrep: dict[int, float] = {}
        self._route_ids = SeqAllocator(1)
        self._periodic: asyncio.Task[None] | None = None
        self._last_failure_mtorr: float | None = None

    # --- T11 -----------------------------------------------------------------------------

    async def announce(self) -> None:
        """Send one Device_annce (``frames.device_annce_npdu``) with fresh NWK/ZDO/APS values."""
        host = self._host
        allocators, pending = host.allocators, host.pending
        npdu = device_annce_npdu(
            own_short=host.own_short,
            own_eui=host.own_eui,
            nwk_seq=allocators.nwk.next(),
            zdo_seq=allocators.zdo.next(skip=lambda seq: pending.seq_in_use("zdo", seq)),
            aps_counter=allocators.aps.next(),
        )
        await host.send_secure(npdu)
        _LOGGER.debug("Device_annce sent for 0x%04X", host.own_short)

    async def send_mtorr(self) -> None:
        """Send one many-to-one Route Request (live ``09 12``) with a fresh route id and NWK seq.

        Route ids come from a router-owned 8-bit counter (distinct per send)."""
        host = self._host
        route_id = self._route_ids.next()
        npdu = many_to_one_route_request_npdu(
            route_id=route_id,
            src_short=host.own_short,
            src_ieee=host.own_eui,
            seq=host.allocators.nwk.next(),
            radius=DEFAULT_RADIUS,
        )
        await host.send_secure(npdu)
        host.stats.mtorr_sent += 1
        _LOGGER.debug("MTORR sent (route id %d)", route_id)

    async def send_mtorr_burst(self) -> None:
        """``config.mtorr_count`` MTORRs, ``config.mtorr_spacing`` apart (``clock.sleep``)."""
        host = self._host
        for index in range(host.config.mtorr_count):
            if index:
                await host.clock.sleep(host.config.mtorr_spacing)
            await self.send_mtorr()

    def on_network_status(self, frame: NwkFrame, status: NetworkStatus) -> None:
        """React to a NWK Network Status command (sync, from dispatch). Never raises.

        The dispatcher only forwards Network Status frames whose NWK dst is our short, our
        active join placeholder, or a broadcast. Then:

        * Fail pending requests to ``status.destination`` with ``RouteError(dst, status)``
          (``host.pending.fail_dst``) ONLY if the NWK ``frame.dst == own_short`` (a unicast
          status about our own traffic; broadcast statuses about others never fail requests).
          Before the join completed nothing is pending, so this is skipped.
        * A route failure (``ROUTE_FAILURE_STATUSES``: 0x00 no route available, 0x01 tree
          link, 0x02 non-tree link, 0x0B source route, 0x0C many-to-one route), under the same
          condition, also schedules one MTORR, at most every
          ``MTORR_ON_ROUTE_FAILURE_INTERVAL`` seconds (shared across codes).
        * 0x0D (address conflict): whenever ``status.destination == own_short``, regardless of
          the frame's NWK dst (conflicts are usually broadcast), call
          ``host.fire_address_conflict()``.
        """
        try:
            self._on_network_status(frame, status)
        except Exception as exc:  # never raise into the notify callback
            _LOGGER.debug("Network Status handling failed: %s", type(exc).__name__)

    def _on_network_status(self, frame: NwkFrame, status: NetworkStatus) -> None:
        host = self._host
        try:
            own = host.own_short
        except RuntimeError:  # not joined yet: nothing is pending, no conflict possible
            _LOGGER.debug("Network Status 0x%02X before the join ignored", status.status)
            return
        code, about = status.status, status.destination
        _LOGGER.debug("Network Status 0x%02X about 0x%04X (to 0x%04X)", code, about, frame.dst)
        if frame.dst == own:
            failed = host.pending.fail_dst(about, RouteError(about, code))
            if failed:
                _LOGGER.debug("%d request(s) to 0x%04X failed with a route error", failed, about)
            if code in ROUTE_FAILURE_STATUSES:
                self._schedule_failure_mtorr()
        if code == NWK_STATUS_ADDRESS_CONFLICT and about == own:
            host.fire_address_conflict()

    def _schedule_failure_mtorr(self) -> None:
        now = self._host.clock.now()
        last = self._last_failure_mtorr
        if last is not None and now - last < MTORR_ON_ROUTE_FAILURE_INTERVAL:
            return
        self._last_failure_mtorr = now
        self._host.start_task(self.send_mtorr(), name="mtorr-route-failure")

    def on_route_request(self, frame: NwkFrame, request: RouteRequest) -> None:
        """Handle a Route Request (sync, from dispatch). Never raises.

        T11 (minimal): count ``stats.rreq_seen`` and return.

        Counting (T12): ``stats.rreq_seen`` counts every Route Request from another node,
        whatever its destination; echoes of our own MTORRs (NWK src == our short, or src IEEE ==
        our EUI) are not counted. ``stats.rrep_sent`` counts the replies actually sent.

        T12 (full responder): answer only if ``request.dst == own_short`` and the mode is not
        ``RouteReplyMode.OFF`` (others are counted and ignored). Dedupe on
        ``(frame.src, route_id)`` for ``config.rreq_dedupe_ttl``; at most one RREP per
        originator every ``RREP_MIN_INTERVAL``. The originator EUI is ``frame.src_ieee``, else
        ``neighbors.ieee_for(frame.src)``, else omitted. The RREP
        (``frames.route_reply_npdu``) is sent from a ``host.start_task``.
        """
        try:
            self._on_route_request(frame, request)
        except Exception as exc:  # never raise into the notify callback
            _LOGGER.debug("RREQ handling failed: %s", type(exc).__name__)

    def _on_route_request(self, frame: NwkFrame, request: RouteRequest) -> None:
        host = self._host
        originator, route_id = frame.src, request.route_id
        try:
            own: int | None = host.own_short
        except RuntimeError:  # not joined yet: no short to answer for
            own = None
        if originator == own or (frame.src_ieee is not None and frame.src_ieee == host.own_eui):
            return  # our own MTORR relayed back
        host.stats.rreq_seen += 1
        _LOGGER.debug(
            "RREQ seen from 0x%04X for 0x%04X (route id %d)", originator, request.dst, route_id
        )
        if own is None:
            return
        mode = host.config.route_reply_mode
        if request.dst != own or mode is RouteReplyMode.OFF:
            return
        now = host.clock.now()
        self._prune(now)
        key = (originator, route_id)
        if key in self._rreq_expiry:
            _LOGGER.debug("RREQ from 0x%04X (route id %d) deduped", originator, route_id)
            return
        if originator in self._last_rrep:
            _LOGGER.debug("RREQ from 0x%04X rate limited", originator)
            return
        # Only an answered RREQ enters the dedupe set: a rate-limited one may be answered when
        # the originator retries it after RREP_MIN_INTERVAL.
        self._rreq_expiry[key] = now + host.config.rreq_dedupe_ttl
        if len(self._rreq_expiry) > _MAX_DEDUPE_ENTRIES:
            del self._rreq_expiry[next(iter(self._rreq_expiry))]
        self._last_rrep[originator] = now
        originator_ieee = frame.src_ieee
        if originator_ieee is None:
            originator_ieee = host.neighbors.ieee_for(originator)
        npdu = route_reply_npdu(
            originator=originator,
            own_short=own,
            own_eui=host.own_eui,
            nwk_seq=host.allocators.nwk.next(),
            route_id=route_id,
            originator_ieee=originator_ieee,
            options_override=LIVE_ROUTE_REPLY_OPTIONS if mode is RouteReplyMode.LIVE else None,
        )
        host.start_task(self._send_rrep(npdu, originator, route_id), name="rrep")

    def _prune(self, now: float) -> None:
        """Drop expired dedupe keys and finished rate-limit windows (both dicts are in
        insertion order, which is time order, so pruning stops at the first live entry)."""
        expiry = self._rreq_expiry
        while expiry:
            key = next(iter(expiry))
            if expiry[key] > now:
                break
            del expiry[key]
        last = self._last_rrep
        while last:
            originator = next(iter(last))
            if now - last[originator] < RREP_MIN_INTERVAL:
                break
            del last[originator]

    async def _send_rrep(self, npdu: bytes, originator: int, route_id: int) -> None:
        host = self._host
        await host.send_secure(npdu)
        host.stats.rrep_sent += 1
        _LOGGER.debug("RREP sent to 0x%04X (route id %d)", originator, route_id)

    def start_periodic(self) -> None:
        """Start the periodic MTORR task (one ``send_mtorr`` every ``config.mtorr_interval``,
        via ``clock.sleep`` in a ``host.start_task``). Idempotent. Called by ``node.join`` after
        the join burst. Send failures are logged at DEBUG and the loop continues; it ends on
        cancellation or ``ConnectionLostError``. T11 implements; T12 may harden."""
        task = self._periodic
        if task is not None and not task.done():
            return
        interval = self._host.config.mtorr_interval
        if not interval > 0:  # 0, negative or NaN would flood the link: periodic MTORR off
            _LOGGER.debug("periodic MTORR disabled (interval %r)", interval)
            return
        self._periodic = self._host.start_task(self._periodic_mtorr(), name="mtorr-periodic")

    def stop(self) -> None:
        """Cancel the periodic MTORR task (the node also cancels and awaits all its tasks at
        close). Idempotent. T11."""
        task, self._periodic = self._periodic, None
        if task is not None:
            task.cancel()

    async def _periodic_mtorr(self) -> None:
        host = self._host
        while True:
            await host.clock.sleep(host.config.mtorr_interval)
            try:
                await self.send_mtorr()
            except ConnectionLostError:
                _LOGGER.debug("periodic MTORR stopped: connection lost")
                return
            except Exception as exc:
                _LOGGER.debug("periodic MTORR failed: %s", type(exc).__name__)


__all__ = [
    "MTORR_ON_ROUTE_FAILURE_INTERVAL",
    "NWK_STATUS_ADDRESS_CONFLICT",
    "NWK_STATUS_MANY_TO_ONE_ROUTE_FAILURE",
    "NWK_STATUS_NON_TREE_LINK_FAILURE",
    "NWK_STATUS_NO_ROUTE_AVAILABLE",
    "NWK_STATUS_SOURCE_ROUTE_FAILURE",
    "NWK_STATUS_TREE_LINK_FAILURE",
    "ROUTE_FAILURE_STATUSES",
    "RREP_MIN_INTERVAL",
    "NeighborTable",
    "Router",
    "RoutingHost",
]
