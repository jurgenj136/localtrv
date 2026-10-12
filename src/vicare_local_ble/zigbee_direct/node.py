"""Virtual Zigbee node behind a ZDD: join, requests, listeners (spec §1.3).

Implemented by T11, complete on its own (minimal RREQ counting and periodic MTORR included);
T12 later swaps in the full RREP responder inside ``routing.Router``. Frozen interface (T2).

Composition (one node per connection generation, built by ``ZdConnection``, T13)
    The node owns ``requests.Allocators``, ``requests.PendingMap``, ``requests.JoinSlot``,
    ``routing.NeighborTable``, ``routing.Router`` and ``dispatch.Dispatcher``. It implements
    ``dispatch.DispatchHost`` and ``routing.RoutingHost`` (directly or through a private core
    object; T11's choice, invisible to callers). The constructor installs
    ``dispatcher.handle`` with ``transport.set_npdu_handler``; it never installs the
    transport's fatal handler (the connection does).

Tasks
    Node-owned tasks (join-burst MTORRs, the periodic MTORR, RREP sends, the rate-limited MTORR
    after Network Status 0x02) are created on the running loop, kept in a strong set, and
    cancelled **and awaited** by ``close()``. Request coroutines run in the caller's task.

Requests
    ``zdo_request``/``zcl_read``/``zcl_write`` take the per-destination lock, then the global
    ``max_in_flight`` semaphore, allocate the ZDO seq or TSN (skipping values whose
    ``(dst, kind, seq)`` key is pending or retired for that destination; all 256 in use ->
    ``SequenceExhaustedError``), and register the pending entry BEFORE sending. Then up to
    ``request_attempts`` attempts; each attempt sends (new NWK seq, new APS counter, same ZDO
    seq/TSN) and awaits ``asyncio.shield(pending.future)`` inside
    ``clock.timeout(request_timeout)``. The shield matters: an attempt timeout cancels only the
    wait, never the pending future, so a late answer to attempt 1 that arrives during attempt 2
    still resolves the request, and an answer racing the last timeout still wins. Only
    ``PendingMap.retire`` (in a ``finally`` once the request ends) or ``node.close`` completes
    or cancels a pending future. Errors: ``RequestTimeoutError`` after the last attempt,
    ``RouteError`` from Network Status, ``ZclStatusError(status)`` for a matched ZCL Default
    Response (any status for a read; a non-zero status for a write, whose SUCCESS Default
    Response returns an all-success ``WriteAttributesResponse`` instead),
    ``ConnectionLostError`` if the node is or becomes closed or the transport is broken
    (``TransportError`` chained as ``__cause__``). Cancelling the caller retires the key and
    propagates.

Join (``join``): STATUS -> COMMISSIONING -> ANNOUNCED -> ROUTED, exactly as spec §1.3 steps 1-8.
    Each of the ``join_attempts`` attempts draws a NEW placeholder short (``preferred_short``
    only for the first attempt), avoiding ``avoid_shorts | {0x0000, zdd_short}`` plus every
    placeholder already used in this join (a per-join avoid set), and opens a new
    ``JoinToken`` (``JoinSlot.open`` replaces the old one). A late response to an older
    attempt's placeholder therefore no longer matches and is dropped with DEBUG.
    Validated assigned short 0x0001..0xFFF7 and not 0x0000 or the ZDD short, else
    ``JoinError``; status != 0 -> ``JoinRejectedError``; no response after ``join_attempts``
    tokens -> ``JoinError``; Commissioning Status without TLV 0x06 -> ``JoinError``; TLV 0x08
    differing from the SE2 EUI -> WARNING, SE2 wins; transport failures ->
    ``ConnectionLostError``/``TransportError`` as raised. The status is reduced to
    ``NetworkSummary`` immediately and never logged.

Listeners
    ``on_report``/``on_device_annce``/``on_address_conflict`` return an unsubscribe callable.
    Listeners are called synchronously from ingress (the BLE notify callback), address-conflict
    listeners included; exceptions are logged and swallowed; they must not await. The conflict
    listeners fire once per Network Status 0x0D frame naming our short (several frames, several
    calls: the connection, T13, de-duplicates).

Logging (logger ``vicare_local_ble.zigbee_direct.node``): INFO join result (shorts, never
keys); DEBUG pending lifecycle, RREP, fallback hits, late drops.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from vicare_local_ble.zigbee_direct import node_requests
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID
from vicare_local_ble.zigbee_direct.node_core import NodeCore
from vicare_local_ble.zigbee_direct.node_join import run_join
from vicare_local_ble.zigbee_direct.node_types import (
    JoinInfo,
    NetworkSummary,
    NodeConfig,
    NodeStats,
    ReportEvent,
    RouteReplyMode,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.fallback import ZdoResponse
    from vicare_local_ble.zigbee_direct.codec.zcl import (
        AttributeRecord,
        ReadAttributeStatus,
        WriteAttributesResponse,
    )
    from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce
    from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import Neighbor
    from vicare_local_ble.zigbee_direct.requests import ZdoRequest
    from vicare_local_ble.zigbee_direct.transport import ZigbeeDirectTransport
    from vicare_local_ble.zigbee_direct.types import Eui64

type Unsubscribe = Callable[[], None]


class ZigbeeDirectNode:
    """Virtual Zigbee node attached to a ZDD through an open transport (see module docstring).

    ``transport`` must be open. ``rng`` (default: a fresh ``random.Random()``) is used only for
    the placeholder short; tests inject ``random.Random(seed)``.
    """

    def __init__(
        self,
        transport: ZigbeeDirectTransport,
        *,
        clock: Clock,
        config: NodeConfig | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self._config = config if config is not None else NodeConfig()
        self._core = NodeCore(
            transport,
            clock=clock,
            config=self._config,
            rng=rng if rng is not None else random.Random(),  # noqa: S311 - not crypto
        )

    async def join(self) -> JoinInfo:
        """Commissioning, Device_annce and the MTORR burst; returns once routed.

        Starts the periodic MTORR (``Router.start_periodic``) before returning. Call once.
        After a failed join the node is unusable: the caller closes it.
        """
        return await run_join(self._core)

    async def zdo_request[R: ZdoResponse](
        self, dst: int, request: ZdoRequest, *, response: type[R]
    ) -> R:
        """Send a ZDO unicast and return the matched response of type ``response``.

        ``request.seq`` is replaced with the allocated ZDO seq. The response's ZDO status is
        not checked (callers inspect ``status``). ``TypeError`` if ``response`` does not match
        the request's response cluster.
        """
        return await node_requests.zdo_request(self._core, dst, request, response)

    async def zcl_read(
        self,
        dst: int,
        endpoint: int,
        cluster: int,
        attrs: Sequence[int],
        *,
        profile: int = HA_PROFILE_ID,
        manufacturer: int | None = None,
    ) -> tuple[ReadAttributeStatus, ...]:
        """Read Attributes in one frame (no splitting: callers keep requests small).

        Returns the response records in wire order, including non-success statuses.
        ``manufacturer`` sets the ZCL MS bit and code (manufacturer-specific attributes need
        their own request).
        """
        return await node_requests.zcl_read(
            self._core,
            dst=dst,
            endpoint=endpoint,
            cluster=cluster,
            attrs=attrs,
            profile=profile,
            manufacturer=manufacturer,
        )

    async def zcl_write(
        self,
        dst: int,
        endpoint: int,
        cluster: int,
        records: Sequence[AttributeRecord],
        *,
        profile: int = HA_PROFILE_ID,
        manufacturer: int | None = None,
    ) -> WriteAttributesResponse:
        """Write Attributes; returns the response (per-record failures are not raised;
        callers check ``.success``). A Default Response for the write with status SUCCESS
        (0x00) returns ``WriteAttributesResponse((WriteAttributeStatus(0x00),))``, the value an
        all-success ``04 00`` response decodes to; any other status raises
        ``ZclStatusError(status)``."""
        return await node_requests.zcl_write(
            self._core,
            dst=dst,
            endpoint=endpoint,
            cluster=cluster,
            records=records,
            profile=profile,
            manufacturer=manufacturer,
        )

    async def send_mtorr(self) -> None:
        """Send one many-to-one Route Request now (``Router.send_mtorr``)."""
        self._core.check_ready()
        await self._core.router.send_mtorr()

    def on_report(self, cb: Callable[[ReportEvent], None]) -> Unsubscribe:
        return self._core.on_report(cb)

    def on_device_annce(self, cb: Callable[[DeviceAnnce, int], None]) -> Unsubscribe:
        """``cb(annce, nwk_src_short)`` for every Device_annce in the tunnel (ours excluded)."""
        return self._core.on_device_annce(cb)

    def on_address_conflict(self, cb: Callable[[], None]) -> Unsubscribe:
        """``cb()`` synchronously from ingress for every Network Status 0x0D frame naming our
        own short (may fire more than once; the caller de-duplicates)."""
        return self._core.on_address_conflict(cb)

    def note_neighbors(self, neighbors: Iterable[Neighbor]) -> None:
        """Feed Mgmt_Lqi records into the neighbor table (``walk_topology`` results)."""
        self._core.check_open()
        self._core.neighbors.note_neighbors(neighbors)

    def lookup_ieee(self, short: int) -> Eui64 | None:
        """EUI last seen for ``short`` (neighbor table), or ``None``."""
        self._core.check_open()
        return self._core.neighbors.ieee_for(short)

    @property
    def own_short(self) -> int:
        """Validated own short; ``RuntimeError`` before ``join()`` accepted a response."""
        return self._core.own_short

    @property
    def own_eui(self) -> Eui64:
        return self._core.own_eui

    @property
    def join_info(self) -> JoinInfo | None:
        return self._core.join_info

    @property
    def config(self) -> NodeConfig:
        return self._config

    @property
    def closed(self) -> bool:
        return self._core.closed

    @property
    def stats(self) -> NodeStats:
        return self._core.stats

    async def close(self, exc: BaseException | None = None) -> None:
        """Idempotent. Fail pending futures and the join with ``exc`` (default
        ``ConnectionLostError``; the one instance is shared by every failed future), cancel and
        await node tasks, drop listeners. Does not close the transport. A concurrent second
        call waits until the first finished (except from a node-owned task, which returns at
        once to avoid awaiting itself). Afterwards every API raises ``ConnectionLostError``."""
        await self._core.close(exc)


__all__ = [
    "JoinInfo",
    "NetworkSummary",
    "NodeConfig",
    "NodeStats",
    "ReportEvent",
    "RouteReplyMode",
    "Unsubscribe",
    "ZigbeeDirectNode",
]
