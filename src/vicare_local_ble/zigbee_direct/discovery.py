"""Generic topology discovery: Mgmt_Lqi paging plus a breadth-first router walk (spec §1.3).

Implemented by T12; frozen interface (T2). No vendor knowledge: which neighbors are valves is
the bridge's question (``valves.is_supported_valve`` after a Basic read).

Algorithm (``walk_topology``)
    Breadth-first from ``root`` (the coordinator). For each router, including the ZDD, page
    ``Mgmt_Lqi_req`` with ``start_index += count`` until ``start + count >= total``,
    ``count == 0`` or ``max_pages`` pages. Neighbors of type router/coordinator not seen before
    are queued (at most ``max_routers`` routers are paged in total). A router whose page times
    out (``RequestTimeoutError``) or fails (``RouteError``, non-success ZDO status) is skipped
    and the result is ``complete=False``. ``ConnectionLostError`` propagates. Every neighbor
    list is fed to ``node.note_neighbors`` as it arrives. Requests go through the node one at a
    time (the node serialises per destination anyway).
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal

from vicare_local_ble.zigbee_direct.codec.zdo import ZdoStatus
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import (
    DeviceType,
    MgmtLqiReq,
    MgmtLqiRsp,
    Relationship,
)
from vicare_local_ble.zigbee_direct.errors import RequestTimeoutError, RouteError
from vicare_local_ble.zigbee_direct.types import COORDINATOR

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import Neighbor
    from vicare_local_ble.zigbee_direct.node import ZigbeeDirectNode
    from vicare_local_ble.zigbee_direct.types import Eui64

type _Outcome = Literal["done", "truncated", "failed"]

#: Neighbor types whose own tables are walked.
_ROUTING_TYPES: Final = frozenset({DeviceType.COORDINATOR, DeviceType.ROUTER})

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Topology:
    """Result of one walk.

    ``neighbors`` maps each EUI to its latest record (any reporter). ``parent_of`` maps an
    end device's EUI to the short of the router/coordinator that listed it as a child.
    ``routers_walked`` are the shorts that answered every page. ``complete`` is False if any
    router or page timed out or failed, or a limit cut the walk short.
    """

    neighbors: dict[Eui64, Neighbor]
    parent_of: dict[Eui64, int]
    complete: bool
    routers_walked: tuple[int, ...] = ()


async def walk_topology(
    node: ZigbeeDirectNode, *, root: int = COORDINATOR, max_routers: int = 16, max_pages: int = 10
) -> Topology:
    """Walk the neighbor tables reachable from ``root`` (see module docstring)."""
    if max_routers < 1 or max_pages < 1:
        raise ValueError("max_routers and max_pages must be >= 1")
    own = node.own_short
    seen: set[int] = {root}
    queue: deque[int] = deque((root,))
    info = node.join_info
    if info is not None and info.zdd_short not in seen:
        # The ZDD is paged even when no table lists it (e.g. the coordinator stays silent).
        seen.add(info.zdd_short)
        queue.append(info.zdd_short)
    neighbors: dict[Eui64, Neighbor] = {}
    parent_of: dict[Eui64, int] = {}
    walked: list[int] = []
    complete = True
    paged = 0
    while queue:
        if paged >= max_routers:
            _LOGGER.debug("topology walk stopped at %d routers", paged)
            complete = False
            break
        short = queue.popleft()
        paged += 1
        records, outcome = await _page_router(node, short, max_pages)
        for neighbor in records:
            neighbors[neighbor.ieee] = neighbor
            if (
                neighbor.device_type is DeviceType.END_DEVICE
                and neighbor.relationship == Relationship.CHILD
            ):
                parent_of[neighbor.ieee] = short
            addr = neighbor.nwk_addr
            if neighbor.device_type in _ROUTING_TYPES and addr not in seen and addr != own:
                seen.add(addr)
                queue.append(addr)
        if outcome != "failed":
            walked.append(short)
        if outcome != "done":
            complete = False
    return Topology(neighbors, parent_of, complete, tuple(walked))


async def _page_router(
    node: ZigbeeDirectNode, short: int, max_pages: int
) -> tuple[list[Neighbor], _Outcome]:
    """All Mgmt_Lqi pages of one router; records received before a failure are kept."""
    records: list[Neighbor] = []
    start = 0
    for _ in range(max_pages):
        try:
            rsp = await node.zdo_request(
                short, MgmtLqiReq(seq=0, start_index=start), response=MgmtLqiRsp
            )
        except (RequestTimeoutError, RouteError) as exc:
            _LOGGER.debug("Mgmt_Lqi to 0x%04X failed: %s", short, type(exc).__name__)
            return records, "failed"
        if rsp.status != ZdoStatus.SUCCESS:
            _LOGGER.debug("Mgmt_Lqi to 0x%04X: status 0x%02X", short, rsp.status)
            return records, "failed"
        page = rsp.neighbors
        if page:
            node.note_neighbors(page)
            records.extend(page)
        start += len(page)
        if not page or start >= rsp.neighbor_table_entries:
            return records, "done"
    _LOGGER.debug("Mgmt_Lqi to 0x%04X stopped after %d pages", short, max_pages)
    return records, "truncated"


__all__ = ["Topology", "walk_topology"]
