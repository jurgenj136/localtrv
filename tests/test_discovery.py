"""T12 discovery: Mgmt_Lqi paging and the breadth-first router walk (``walk_topology``).

Simulator tests drive a joined node on ``VirtualClock``; the paging edge cases (count 0, page
limit, failures, limits) use a scripted fake node.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest

from test_node import Rig, rig
from vicare_local_ble.testing.network import SimRouter
from vicare_local_ble.testing.network_aps import is_aps_ack
from vicare_local_ble.testing.scenario import ROUTER_EUI
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.zdo import ZdoCluster, ZdoStatus
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import (
    DeviceType,
    MgmtLqiReq,
    MgmtLqiRsp,
    Neighbor,
    Relationship,
)
from vicare_local_ble.zigbee_direct.discovery import Topology, walk_topology
from vicare_local_ble.zigbee_direct.errors import (
    ConnectionLostError,
    RequestTimeoutError,
    RouteError,
)
from vicare_local_ble.zigbee_direct.types import COORDINATOR, Eui64

if TYPE_CHECKING:
    from collections.abc import Iterable

    from vicare_local_ble.zigbee_direct.node import ZigbeeDirectNode

EXTRA_ROUTER = 0x0B0B
EXTRA_VALVE = 0x0C0C
EXTRA_VALVE_EUI = Eui64.from_str("02:00:00:00:00:00:00:99")


def add_extra_router(r: Rig) -> SimValve:
    """A second router (child of the coordinator) carrying one valve."""
    net = r.inst.network
    net.add_router(SimRouter(eui=ROUTER_EUI, short=EXTRA_ROUTER))
    valve = SimValve(r.clock, eui=EXTRA_VALVE_EUI, short=EXTRA_VALVE, rng=random.Random(1))  # noqa: S311
    net.add_valve(valve, parent=EXTRA_ROUTER)
    return valve


def lqi_requests(r: Rig) -> list[tuple[int, int]]:
    """``(dst, start_index)`` of every Mgmt_Lqi_req the node wrote."""
    out: list[tuple[int, int]] = []
    for raw in r.writes():
        frame = NwkFrame.decode(raw)
        if frame.frame_type is not NwkFrameType.DATA or is_aps_ack(frame):
            continue
        aps = ApsDataFrame.decode(frame.payload)
        if aps.cluster_id == ZdoCluster.MGMT_LQI_REQ:
            out.append((frame.dst, MgmtLqiReq.decode(aps.payload).start_index))
    return out


async def walk(r: Rig, **kw: int) -> Topology:
    return await r.clock.run_task(walk_topology(r.node, **kw))


# --- against the simulator ---------------------------------------------------------------


async def test_lqi_paging_respects_page_size_and_total() -> None:
    async with rig() as r:
        add_extra_router(r)
        assert r.inst.network.lqi_page_size == 2
        topo = await walk(r)
        zdd = r.inst.r0.zdd_short
        # coordinator: 3 valves + R0 + extra router = 5 records -> pages at 0, 2, 4
        assert lqi_requests(r) == [
            (COORDINATOR, 0),
            (COORDINATOR, 2),
            (COORDINATOR, 4),
            (zdd, 0),  # empty table: total 0, count 0
            (EXTRA_ROUTER, 0),
        ]
        assert topo.complete


async def test_router_walk_finds_valve_behind_extra_router() -> None:
    async with rig() as r:
        extra = add_extra_router(r)
        topo = await walk(r)
        zdd = r.inst.r0.zdd_short
        assert topo.complete
        assert topo.routers_walked == (COORDINATOR, zdd, EXTRA_ROUTER)
        valves = (*r.inst.valves, extra)
        assert set(topo.neighbors) == {v.eui for v in valves} | {r.inst.zdd_eui, ROUTER_EUI}
        assert topo.parent_of == {
            **{v.eui: COORDINATOR for v in r.inst.valves},
            EXTRA_VALVE_EUI: EXTRA_ROUTER,
        }
        assert topo.neighbors[EXTRA_VALVE_EUI].nwk_addr == EXTRA_VALVE
        # fed to note_neighbors as pages arrived
        assert r.node.lookup_ieee(EXTRA_VALVE) == EXTRA_VALVE_EUI
        assert r.node.lookup_ieee(EXTRA_ROUTER) == ROUTER_EUI
        assert all(r.node.lookup_ieee(v.short) == v.eui for v in r.inst.valves)


async def test_router_timeout_gives_incomplete_result() -> None:
    async with rig() as r:
        add_extra_router(r)
        r.inst.network.router_timeout = frozenset({EXTRA_ROUTER})
        topo = await walk(r)
        assert not topo.complete
        assert topo.routers_walked == (COORDINATOR, r.inst.r0.zdd_short)
        assert EXTRA_VALVE_EUI not in topo.neighbors
        assert ROUTER_EUI in topo.neighbors  # listed by the coordinator
        assert {v.eui for v in r.inst.valves} <= set(topo.neighbors)
        assert r.node.stats.timeouts == 1


# --- scripted fake node ------------------------------------------------------------------

EXT_PAN = 0xDDDDDDDDDDDDDD01


def eui(n: int) -> Eui64:
    return Eui64.from_str(f"02:00:00:00:00:00:{n >> 8:02X}:{n & 0xFF:02X}")


def nb(
    short: int,
    kind: DeviceType = DeviceType.END_DEVICE,
    rel: Relationship = Relationship.CHILD,
) -> Neighbor:
    return Neighbor(
        extended_pan_id=EXT_PAN,
        ieee=eui(short),
        nwk_addr=short,
        device_type=kind,
        rx_on_when_idle=kind is not DeviceType.END_DEVICE,
        relationship=rel,
        permit_joining=None,
        depth=1,
        lqi=0x80,
    )


@dataclass
class FakeInfo:
    zdd_short: int


type Script = list[Neighbor] | BaseException | MgmtLqiRsp


@dataclass
class FakeNode:
    """Answers Mgmt_Lqi from per-router scripts: a table (paged by ``page_size``), an exception
    to raise, or a fixed response."""

    tables: dict[int, Script]
    page_size: int = 2
    own_short: int = 0x1234
    join_info: FakeInfo | None = None
    requests: list[tuple[int, int]] = field(default_factory=list)
    noted: list[tuple[Neighbor, ...]] = field(default_factory=list)

    async def zdo_request(
        self, dst: int, request: MgmtLqiReq, *, response: type[MgmtLqiRsp]
    ) -> MgmtLqiRsp:
        assert response is MgmtLqiRsp
        self.requests.append((dst, request.start_index))
        script = self.tables.get(dst, RequestTimeoutError(dst, "zdo", 0))
        if isinstance(script, BaseException):
            raise script
        if isinstance(script, MgmtLqiRsp):
            return script
        start = request.start_index
        page = tuple(script[start : start + self.page_size])
        return MgmtLqiRsp(request.seq, ZdoStatus.SUCCESS, len(script), start, page)

    def note_neighbors(self, neighbors: Iterable[Neighbor]) -> None:
        self.noted.append(tuple(neighbors))


async def fake_walk(fake: FakeNode, **kw: int) -> Topology:
    return await walk_topology(cast("ZigbeeDirectNode", fake), **kw)


async def test_count_zero_stops_paging() -> None:
    lying = MgmtLqiRsp(0, ZdoStatus.SUCCESS, neighbor_table_entries=5, start_index=0)
    fake = FakeNode({COORDINATOR: lying})
    topo = await fake_walk(fake)
    assert fake.requests == [(COORDINATOR, 0)]
    assert topo == Topology({}, {}, complete=True, routers_walked=(COORDINATOR,))
    assert fake.noted == []


async def test_max_pages_stops_paging_and_marks_incomplete() -> None:
    fake = FakeNode({COORDINATOR: [nb(0x0100 + i) for i in range(10)]}, page_size=1)
    topo = await fake_walk(fake, max_pages=3)
    assert fake.requests == [(COORDINATOR, 0), (COORDINATOR, 1), (COORDINATOR, 2)]
    assert not topo.complete
    assert topo.routers_walked == (COORDINATOR,)  # it answered every page asked
    assert len(topo.neighbors) == 3
    assert len(fake.noted) == 3


@pytest.mark.parametrize(
    "failure",
    [
        RouteError(0x0200, 0x02),
        MgmtLqiRsp(0, ZdoStatus.NOT_SUPPORTED),
        RequestTimeoutError(0x0200, "zdo", 0),
    ],
    ids=["route-error", "zdo-status", "timeout"],
)
async def test_failing_router_is_skipped(failure: BaseException | MgmtLqiRsp) -> None:
    fake = FakeNode(
        {
            COORDINATOR: [nb(0x0101), nb(0x0200, DeviceType.ROUTER), nb(0x0300, DeviceType.ROUTER)],
            0x0200: failure,
            0x0300: [nb(0x0301)],
        }
    )
    topo = await fake_walk(fake)
    assert not topo.complete
    assert topo.routers_walked == (COORDINATOR, 0x0300)
    assert topo.parent_of == {eui(0x0101): COORDINATOR, eui(0x0301): 0x0300}


async def test_records_before_a_failed_page_are_kept() -> None:
    class Flaky(FakeNode):
        async def zdo_request(
            self, dst: int, request: MgmtLqiReq, *, response: type[MgmtLqiRsp]
        ) -> MgmtLqiRsp:
            if request.start_index:
                self.requests.append((dst, request.start_index))
                raise RequestTimeoutError(dst, "zdo", 1)
            return await super().zdo_request(dst, request, response=response)

    fake = Flaky({COORDINATOR: [nb(0x0101), nb(0x0200, DeviceType.ROUTER), nb(0x0102)]})
    fake.tables[0x0200] = [nb(0x0201)]
    topo = await fake_walk(fake)
    assert not topo.complete
    assert topo.routers_walked == (0x0200,)
    assert set(topo.neighbors) == {eui(0x0101), eui(0x0200), eui(0x0201)}
    assert fake.noted[0] == (nb(0x0101), nb(0x0200, DeviceType.ROUTER))


async def test_connection_lost_propagates() -> None:
    fake = FakeNode({COORDINATOR: ConnectionLostError("gone")})
    with pytest.raises(ConnectionLostError):
        await fake_walk(fake)


async def test_max_routers_cuts_the_walk() -> None:
    routers = [nb(0x0200 + i, DeviceType.ROUTER) for i in range(3)]
    fake = FakeNode({COORDINATOR: routers, **{r.nwk_addr: [] for r in routers}})
    topo = await fake_walk(fake, max_routers=2)
    assert fake.requests == [(COORDINATOR, 0), (COORDINATOR, 2), (0x0200, 0)]
    assert not topo.complete
    assert topo.routers_walked == (COORDINATOR, 0x0200)
    assert len(topo.neighbors) == 3


async def test_zdd_is_paged_even_if_nobody_lists_it() -> None:
    fake = FakeNode({0x2A1B: [nb(0x0101)]}, join_info=FakeInfo(zdd_short=0x2A1B))
    topo = await fake_walk(fake)  # the coordinator times out
    assert [dst for dst, _ in fake.requests] == [COORDINATOR, 0x2A1B]
    assert not topo.complete
    assert topo.routers_walked == (0x2A1B,)
    assert topo.parent_of == {eui(0x0101): 0x2A1B}


async def test_walk_rules_for_types_relationships_and_own_short() -> None:
    fake = FakeNode(
        {
            COORDINATOR: [
                nb(0x0101),  # end device child -> parent_of
                nb(0x0102, rel=Relationship.SIBLING),  # not a child
                nb(0x0103, DeviceType.UNKNOWN),  # unknown type: not a child entry, not walked
                nb(0x1234, DeviceType.ROUTER),  # our own short: never paged
                nb(0x0200, DeviceType.ROUTER),
            ],
            0x0200: [
                nb(COORDINATOR, DeviceType.COORDINATOR, Relationship.PARENT),  # already seen
                nb(0x0201),
            ],
        },
        join_info=FakeInfo(zdd_short=0x0200),  # the ZDD is also listed: paged once
    )
    topo = await fake_walk(fake)
    assert topo.complete
    assert fake.requests == [(COORDINATOR, 0), (COORDINATOR, 2), (COORDINATOR, 4), (0x0200, 0)]
    assert topo.parent_of == {eui(0x0101): COORDINATOR, eui(0x0201): 0x0200}
    assert len(topo.neighbors) == 7


@pytest.mark.parametrize("kw", [{"max_routers": 0}, {"max_pages": 0}])
async def test_limits_are_validated(kw: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="must be >= 1"):
        await fake_walk(FakeNode({}), **kw)
