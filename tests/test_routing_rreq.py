"""Routing: the RREP responder (golden bytes per mode, dedupe, rate limit, originator EUI)
and the periodic MTORR loop, on ``VirtualClock`` against the simulator."""

from __future__ import annotations

import logging

import pytest

from fixtures import golden as g
from localtrv.zigbee_direct import routing
from localtrv.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from localtrv.zigbee_direct.codec.nwk_commands import RouteReply, RouteRequest
from localtrv.zigbee_direct.codec.zdo_mgmt import DeviceType, Neighbor, Relationship
from localtrv.zigbee_direct.errors import ConnectionLostError
from localtrv.zigbee_direct.frames import LIVE_ROUTE_REPLY_OPTIONS, route_reply_npdu
from localtrv.zigbee_direct.node import NodeConfig, RouteReplyMode
from localtrv.zigbee_direct.requests import SeqAllocator
from localtrv.zigbee_direct.routing import RREP_MIN_INTERVAL, Router
from localtrv.zigbee_direct.types import BROADCAST_ROUTERS, Eui64
from test_node import Rig, rig

RID_OFFSET = 10  # NWK header (8 B), then 02 options rid
GOLDEN_NWK_SEQ = 4  # NWK seq of RREP_LIVE / RREP_SPEC


def golden_config(
    mode: RouteReplyMode = RouteReplyMode.LIVE, *, rreq_dedupe_ttl: float = 60.0
) -> NodeConfig:
    """Own short = golden ZVD short (the simulator echoes the placeholder)."""
    return NodeConfig(
        preferred_short=g.ZVD_SHORT, route_reply_mode=mode, rreq_dedupe_ttl=rreq_dedupe_ttl
    )


def rreps(r: Rig) -> list[bytes]:
    return [rec.raw for rec in r.inst.network.route_replies]


def with_rid(npdu: bytes, rid: int) -> bytes:
    return npdu[:RID_OFFSET] + bytes([rid]) + npdu[RID_OFFSET + 1 :]


def rreq_frame(
    src: int, dst: int, route_id: int, *, src_ieee: Eui64 | None = None
) -> tuple[NwkFrame, RouteRequest]:
    request = RouteRequest(route_id=route_id, dst=dst)
    frame = NwkFrame(
        frame_type=NwkFrameType.COMMAND,
        dst=BROADCAST_ROUTERS,
        src=src,
        radius=30,
        seq=1,
        payload=request.encode(),
        security=True,
        src_ieee=src_ieee,
    )
    return frame, request


# --- pure builder ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("override", "golden"),
    [(LIVE_ROUTE_REPLY_OPTIONS, g.RREP_LIVE), (None, g.RREP_SPEC)],
    ids=["live", "spec"],
)
def test_route_reply_npdu_matches_golden(override: int | None, golden: bytes) -> None:
    npdu = route_reply_npdu(
        originator=g.VALVE_SHORT,
        own_short=g.ZVD_SHORT,
        own_eui=g.ZVD_EUI,
        nwk_seq=GOLDEN_NWK_SEQ,
        route_id=7,
        originator_ieee=g.VALVE_EUI,
        options_override=override,
    )
    assert npdu == golden


def test_route_reply_npdu_without_originator_eui() -> None:
    npdu = route_reply_npdu(
        originator=g.VALVE_SHORT,
        own_short=g.ZVD_SHORT,
        own_eui=g.ZVD_EUI,
        nwk_seq=GOLDEN_NWK_SEQ,
        route_id=7,
        originator_ieee=None,
        options_override=None,
    )
    # options derived 0x20 = responder IEEE only: a spec-valid frame
    assert npdu == g.h("49 02 6F 5E 34 12 1E 04", "02 20 07 6F 5E 34 12 00", g.ZVD_EUI_WIRE)
    reply = RouteReply.decode(NwkFrame.decode(npdu).payload)
    assert (reply.originator_ieee, reply.responder_ieee) == (None, g.ZVD_EUI)


# --- responder through the node ----------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "golden"),
    [(RouteReplyMode.LIVE, g.RREP_LIVE), (RouteReplyMode.SPEC, g.RREP_SPEC)],
    ids=["live", "spec"],
)
async def test_rrep_npdu_equals_golden_per_mode(mode: RouteReplyMode, golden: bytes) -> None:
    async with rig(config=golden_config(mode)) as r:
        assert r.node.own_short == g.ZVD_SHORT
        assert r.node.own_eui == g.ZVD_EUI
        r.core.allocators.nwk = SeqAllocator(GOLDEN_NWK_SEQ)  # exact bytes, no masking
        r.inject(g.RREQ_FROM_VALVE)
        await r.clock.advance(0)
        assert rreps(r) == [golden]
        assert r.writes()[-1] == golden
        assert (r.node.stats.rreq_seen, r.node.stats.rrep_sent) == (1, 1)


async def test_rrep_off_sends_nothing() -> None:
    async with rig(config=golden_config(RouteReplyMode.OFF)) as r:
        before = len(r.writes())
        r.inject(g.RREQ_FROM_VALVE)
        await r.clock.advance(0)
        assert rreps(r) == []
        assert len(r.writes()) == before
        assert (r.node.stats.rreq_seen, r.node.stats.rrep_sent) == (1, 0)


async def test_unknown_originator_omits_its_eui() -> None:
    async with rig(config=golden_config()) as r:
        assert r.node.lookup_ieee(g.VALVE_SHORT) is None
        r.core.allocators.nwk = SeqAllocator(GOLDEN_NWK_SEQ)
        r.inject(g.RREQ_NO_SRC_IEEE)
        await r.clock.advance(0)
        # LIVE keeps the 0x20 options byte; only the responder EUI follows (spec-valid too)
        expected = g.h("49 02 6F 5E 34 12 1E 04", "02 20 08 6F 5E 34 12 00", g.ZVD_EUI_WIRE)
        assert rreps(r) == [expected]
        (recorded,) = r.inst.network.route_replies
        assert (recorded.reply.originator_ieee, recorded.reply.responder_ieee) == (
            None,
            g.ZVD_EUI,
        )


async def test_originator_eui_from_neighbor_table() -> None:
    async with rig(config=golden_config()) as r:
        r.node.note_neighbors(
            [
                Neighbor(
                    extended_pan_id=g.EXT_PAN.as_int(),
                    ieee=g.VALVE_EUI,
                    nwk_addr=g.VALVE_SHORT,
                    device_type=DeviceType.END_DEVICE,
                    rx_on_when_idle=False,
                    relationship=Relationship.CHILD,
                    permit_joining=None,
                    depth=1,
                    lqi=0xB4,
                )
            ]
        )
        r.core.allocators.nwk = SeqAllocator(GOLDEN_NWK_SEQ)
        r.inject(g.RREQ_NO_SRC_IEEE)
        await r.clock.advance(0)
        assert rreps(r) == [with_rid(g.RREP_LIVE, 8)]


async def test_other_destination_rreqs_are_ignored() -> None:
    async with rig() as r:
        valve, other = r.inst.valves[0], r.inst.valves[1]
        r.inst.network.emit_route_request(valve.short, route_id=7, dst=other.short)
        r.inst.network.emit_route_request(valve.short, route_id=8, dst=r.inst.r0.zdd_short)
        await r.clock.advance(0)
        assert rreps(r) == []
        assert (r.node.stats.rreq_seen, r.node.stats.rrep_sent) == (2, 0)


async def test_rreq_before_join_is_counted_only() -> None:
    async with rig(config=golden_config(), join=False) as r:
        r.inject(g.RREQ_FROM_VALVE)
        await r.clock.advance(0)
        assert rreps(r) == []
        assert r.node.stats.rreq_seen == 1


async def test_dedupe_ttl() -> None:
    async with rig(config=golden_config(rreq_dedupe_ttl=60.0)) as r:
        net, valve = r.inst.network, r.inst.valves[0]
        t0 = r.clock.now()
        net.emit_route_request(valve.short, route_id=7, repeat=3, spacing=1.0)  # repeated rid
        await r.clock.advance(3.0)
        assert len(rreps(r)) == 1
        await r.clock.advance_to(t0 + 59.0)  # outside the 2 s rate window, inside the TTL
        net.emit_route_request(valve.short, route_id=7)
        await r.clock.advance(0)
        assert len(rreps(r)) == 1
        await r.clock.advance_to(t0 + 60.0)  # TTL over: answered again
        net.emit_route_request(valve.short, route_id=7)
        await r.clock.advance(0)
        assert len(rreps(r)) == 2
        assert r.node.stats.rreq_seen == 5
        assert all(rec.reply.route_id == 7 for rec in net.route_replies)


async def test_rate_limit_per_originator() -> None:
    async with rig() as r:
        net = r.inst.network
        a, b = r.inst.valves[0], r.inst.valves[1]

        async def at(dt: float, src: int, rid: int) -> None:
            await r.clock.advance_to(t0 + dt)
            net.emit_route_request(src, route_id=rid)
            await r.clock.advance(0)

        def answered() -> list[tuple[int, int]]:
            return [(rec.frame.dst, rec.reply.route_id) for rec in net.route_replies]

        t0 = r.clock.now()
        await at(0.0, a.short, 1)  # answered
        await at(1.0, a.short, 2)  # rate limited (not deduped)
        await at(1.0, b.short, 1)  # another originator: answered
        await at(RREP_MIN_INTERVAL + 0.1, a.short, 3)  # window over: answered
        await at(3.0, a.short, 2)  # retry of the limited rid, inside the new window
        await at(4.5, a.short, 2)  # retry after that window: answered now
        assert answered() == [(a.short, 1), (b.short, 1), (a.short, 3), (a.short, 2)]
        assert r.node.stats.rrep_sent == 4
        assert r.node.stats.rreq_seen == 6


async def test_dedupe_set_is_capped() -> None:
    async with rig() as r:
        router, own = r.core.router, r.node.own_short
        originators = range(0x0100, 0x0100 + 257)
        for src in originators:
            router.on_route_request(*rreq_frame(src, own, 1))
        await r.clock.advance(RREP_MIN_INTERVAL + 0.5)
        assert r.node.stats.rrep_sent == 257
        router.on_route_request(*rreq_frame(0x0101, own, 1))  # still remembered
        router.on_route_request(*rreq_frame(0x0100, own, 1))  # evicted (oldest): answered
        await r.clock.advance(0)
        assert r.node.stats.rrep_sent == 258
        assert r.inst.network.route_replies[-1].frame.dst == 0x0100


async def test_rreq_handling_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(**_kw: object) -> bytes:
        raise ValueError("builder bug")

    monkeypatch.setattr(routing, "route_reply_npdu", broken)
    async with rig() as r:
        r.inst.network.emit_route_request(r.inst.valves[0].short, route_id=7)
        await r.clock.advance(0)
        assert (r.node.stats.rreq_seen, r.node.stats.rrep_sent) == (1, 0)
        assert r.node.stats.decode_errors == 0


async def test_rrep_send_failure_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    async with rig() as r:
        own = r.node.own_short

        async def failing(_npdu: bytes) -> None:
            raise ConnectionLostError("gone")

        monkeypatch.setattr(r.core, "send_secure", failing)
        r.core.router.on_route_request(*rreq_frame(0x0100, own, 1))
        await r.clock.advance(0)
        assert (r.node.stats.rreq_seen, r.node.stats.rrep_sent) == (1, 0)
        assert r.core.task_count == 1  # only the periodic MTORR remains


async def test_own_mtorr_echoes_are_not_counted() -> None:
    async with rig() as r:
        router, own = r.core.router, r.node.own_short
        router.on_route_request(*rreq_frame(own, 0xFFFC, 1))  # our MTORR relayed back
        router.on_route_request(*rreq_frame(0x0100, 0xFFFC, 2, src_ieee=r.node.own_eui))
        await r.clock.advance(0)
        assert (r.node.stats.rreq_seen, r.node.stats.rrep_sent) == (0, 0)
        assert r.node.stats.rreq_own_echo == 2
        router.on_route_request(*rreq_frame(0x0100, 0xFFFC, 3))  # someone else's MTORR
        assert (r.node.stats.rreq_seen, r.node.stats.rreq_own_echo) == (1, 2)


async def test_own_echo_is_not_logged_and_relayed_copies_log_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with rig() as r:
        router, own = r.core.router, r.node.own_short
        with caplog.at_level(logging.DEBUG, logger="localtrv.zigbee_direct.node"):
            router.on_route_request(*rreq_frame(own, 0xFFFC, 1))
            for _ in range(3):  # the coordinator's MTORR, relayed by three neighbours
                router.on_route_request(*rreq_frame(0x0000, 0xFFFC, 9))
            router.on_route_request(*rreq_frame(0x0000, 0xFFFC, 10))  # its next MTORR
        seen = [rec.getMessage() for rec in caplog.records if "RREQ seen" in rec.getMessage()]
        assert seen == [
            "RREQ seen from 0x0000 for 0xFFFC (route id 9)",
            "RREQ seen from 0x0000 for 0xFFFC (route id 10)",
        ]
        assert (r.node.stats.rreq_seen, r.node.stats.rreq_own_echo) == (4, 1)


async def test_rreq_log_dedupe_memory_is_bounded() -> None:
    async with rig() as r:
        router = r.core.router
        for src in range(1, 300):
            router.on_route_request(*rreq_frame(src, 0xFFFC, 1))
        assert len(router._last_seen) == 256
        assert r.node.stats.rreq_seen == 299


async def test_rreq_after_close_never_raises() -> None:
    async with rig() as r:
        router, own = r.core.router, r.node.own_short
        await r.node.close()
        router.on_route_request(*rreq_frame(0x0100, own, 1))  # start_task refuses: contained
        assert (r.node.stats.rreq_seen, r.node.stats.rrep_sent) == (1, 0)
        assert r.core.task_count == 0


# --- periodic MTORR ----------------------------------------------------------------------


def mtorr_count(r: Rig) -> int:
    count = 0
    for raw in r.writes():
        frame = NwkFrame.decode(raw)
        if frame.frame_type is NwkFrameType.COMMAND and frame.dst == 0xFFFC:
            count += 1
    return count


async def test_periodic_mtorr_interval_failure_and_close(monkeypatch: pytest.MonkeyPatch) -> None:
    async with rig(config=NodeConfig(mtorr_interval=10.0)) as r:
        assert mtorr_count(r) == 2  # join burst
        await r.clock.advance(9.9)
        assert mtorr_count(r) == 2
        await r.clock.advance(0.1)
        assert mtorr_count(r) == 3

        calls = 0
        original = Router.send_mtorr

        async def flaky(self: Router) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("one bad send")
            await original(self)

        monkeypatch.setattr(Router, "send_mtorr", flaky)
        await r.clock.advance(10.0)  # fails, loop survives
        assert mtorr_count(r) == 3
        await r.clock.advance(10.0)
        assert mtorr_count(r) == 4
        assert r.node.stats.mtorr_sent == 4

        await r.node.close()
        assert r.core.task_count == 0
        await r.clock.advance(100.0)
        assert mtorr_count(r) == 4


async def test_periodic_mtorr_ends_on_connection_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    async with rig(config=NodeConfig(mtorr_interval=10.0)) as r:
        calls = 0

        async def lost(_self: Router) -> None:
            nonlocal calls
            calls += 1
            raise ConnectionLostError("gone")

        monkeypatch.setattr(Router, "send_mtorr", lost)
        await r.clock.advance(10.0)
        assert calls == 1
        assert r.core.task_count == 0
        await r.clock.advance(50.0)
        assert calls == 1
        r.core.router.start_periodic()  # restartable once the old loop ended
        assert r.core.task_count == 1
        await r.clock.advance(0)  # let it start before close cancels it


@pytest.mark.parametrize("interval", [0.0, -1.0, float("nan")])
async def test_periodic_mtorr_disabled_for_non_positive_interval(interval: float) -> None:
    async with rig(config=NodeConfig(mtorr_interval=interval)) as r:
        assert r.core.task_count == 0
        await r.clock.advance(100.0)
        assert mtorr_count(r) == 2  # the join burst only
