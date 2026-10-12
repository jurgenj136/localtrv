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

from dataclasses import dataclass
from typing import TYPE_CHECKING

from vicare_local_ble.zigbee_direct.types import COORDINATOR

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import Neighbor
    from vicare_local_ble.zigbee_direct.node import ZigbeeDirectNode
    from vicare_local_ble.zigbee_direct.types import Eui64


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
    raise NotImplementedError("T12")


__all__ = ["Topology", "walk_topology"]
