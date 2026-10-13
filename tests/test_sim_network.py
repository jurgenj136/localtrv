"""SimNetwork (T9): join rules, gating, routing, Mgmt_Lqi, RREQs, quirks, noise and events.

Driven with the hand-written golden fixtures through a recording ``TunnelHost`` on a
``VirtualClock``; never with the production builders (spec §6 T9).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

import pytest

from fixtures import golden as g
from vicare_local_ble.testing.network import SimNetwork, SimRouter
from vicare_local_ble.testing.network_recorder import Indication, RecordingTunnelHost
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningResponse,
    NetworkStatus,
    RouteRequest,
    decode_nwk_command,
)
from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import DeviceType, MgmtLqiRsp, Neighbor
from vicare_local_ble.zigbee_direct.types import Eui64

h = g.h
SEQ = 7  # NWK seq offset in every header without IEEEs
ROUTER = SimRouter(eui=Eui64.from_str("02:00:00:00:00:00:00:05"), short=0x7A7A)
ROUTER_VALVE_EUI = Eui64.from_str("02:00:00:00:00:00:00:06")
ROUTER_VALVE_SHORT = 0x4C4C


def seeded(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 - deterministic simulator, not crypto


def masked(npdu: bytes, *offsets: int) -> bytes:
    """``npdu`` with the given byte offsets zeroed (NWK seq, APS counters)."""
    out = bytearray(npdu)
    for i in offsets:
        out[i] = 0
    return bytes(out)


def aps_of(ind: Indication) -> ApsDataFrame:
    return ApsDataFrame.decode(ind.frame.payload)


@dataclass
class Rig:
    clock: VirtualClock
    net: SimNetwork
    host: RecordingTunnelHost
    valve: SimValve

    def send(self, npdu: bytes, *, secure: bool = True) -> None:
        self.host.send(npdu, secure=secure)

    async def join(self) -> None:
        self.send(g.COMMISSIONING_REQUEST, secure=False)
        await self.clock.advance(2.0)
        self.send(g.DEVICE_ANNCE)
        self.send(g.MTORR)
        self.host.take()

    async def collect(self, seconds: float) -> tuple[Indication, ...]:
        await self.clock.advance(seconds)
        return self.host.take()


def make_rig(
    *, seed: int = 0, valve_latency: tuple[float, float] = (2.0, 30.0), **net_kwargs: object
) -> Rig:
    clock = VirtualClock()
    rng = seeded(seed)
    # The golden replies predate the APS ack-request capture and the recording host never acks:
    # unit rigs send plain frames once unless a test opts in (test_sim_network_aps.py).
    net_kwargs.setdefault("aps_ack_request", False)
    net = SimNetwork(
        clock,
        zdd_short=g.ZDD_SHORT,
        zdd_eui=g.ZDD_EUI,
        coordinator_eui=g.COORDINATOR_EUI,
        extended_pan_id=g.EXT_PAN,
        rng=rng,
        **net_kwargs,  # type: ignore[arg-type]
    )
    host = RecordingTunnelHost(clock)
    net.attach(host)
    valve = SimValve(clock, eui=g.VALVE_EUI, short=g.VALVE_SHORT, rng=rng, latency=valve_latency)
    net.add_valve(valve)
    return Rig(clock, net, host, valve)


def with_router_valve(rig: Rig) -> SimValve:
    rig.net.add_router(ROUTER)
    valve = SimValve(rig.clock, eui=ROUTER_VALVE_EUI, short=ROUTER_VALVE_SHORT, rng=seeded(5))
    rig.net.add_valve(valve, parent=ROUTER.short)
    return valve


# --- Join ------------------------------------------------------------------------------------


async def test_commissioning_response_echoes_placeholder_after_1_to_2_s() -> None:
    rig = make_rig()
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    assert await rig.collect(1.0) == ()
    (ind,) = await rig.collect(1.0)
    assert 1.0 <= ind.at <= 2.0
    assert ind.secure is False
    assert masked(ind.npdu, SEQ) == masked(g.COMMISSIONING_RESPONSE, SEQ)
    assert rig.net.joined_short == g.ZVD_SHORT
    assert rig.net.received[0].src_ieee == g.ZVD_EUI


@pytest.mark.parametrize(
    "npdu",
    [
        pytest.param(g.COMMISSIONING_REQUEST[:1] + b"\x1a" + g.COMMISSIONING_REQUEST[2:], id="fc1"),
        pytest.param(
            g.COMMISSIONING_REQUEST[:6] + b"\x1e" + g.COMMISSIONING_REQUEST[7:], id="radius"
        ),
        pytest.param(g.COMMISSIONING_REQUEST[:24] + h("0E 00 8E"), id="no-0x48-tlv"),
        pytest.param(g.COMMISSIONING_REQUEST[:24] + h("0E 00 8E 4C 01 01 00"), id="other-tlv-only"),
    ],
)
async def test_invalid_commissioning_request_is_silently_dropped(npdu: bytes) -> None:
    rig = make_rig()
    rig.send(npdu, secure=False)
    assert await rig.collect(30.0) == ()
    assert rig.net.joined_short is None
    assert len(rig.net.received) == 1  # it was seen, just not answered


@pytest.mark.parametrize("assigned", [0x3456, 0xFFFD])
async def test_assign_short_overrides_placeholder_even_when_invalid(assigned: int) -> None:
    rig = make_rig(assign_short=assigned)
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    (ind,) = await rig.collect(2.0)
    cmd = decode_nwk_command(ind.frame.payload)
    assert ind.npdu[-3:] == assigned.to_bytes(2, "little") + b"\x00"
    assert ind.frame.dst == g.ZVD_SHORT  # still addressed to the placeholder
    assert isinstance(cmd, CommissioningResponse)
    assert cmd.short == assigned
    assert rig.net.joined_short == assigned


async def test_reject_status_does_not_join() -> None:
    rig = make_rig(commissioning_status=0x01)
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    (ind,) = await rig.collect(2.0)
    assert ind.npdu[-4:] == h("0F 34 12 01")
    assert rig.net.joined_short is None


async def test_unrelated_commissioning_response_comes_first() -> None:
    rig = make_rig(unrelated_commissioning_response=True)
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    other, ours = await rig.collect(2.0)
    assert other.at < ours.at
    assert masked(other.npdu, SEQ) == masked(g.COMMISSIONING_RESPONSE_OTHER, SEQ)
    assert masked(ours.npdu, SEQ) == masked(g.COMMISSIONING_RESPONSE, SEQ)


async def test_drop_commissioning_requests_then_fresh_placeholder_joins() -> None:
    rig = make_rig()
    rig.net.drop_commissioning_requests(1)
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    assert await rig.collect(15.0) == ()
    retry = g.COMMISSIONING_REQUEST.replace(h("34 12"), h("99 07"))  # src + fragmentation TLV
    rig.send(retry, secure=False)
    (ind,) = await rig.collect(2.0)
    assert ind.frame.dst == 0x0799
    assert rig.net.joined_short == 0x0799
    with pytest.raises(ValueError, match=">= 0"):
        rig.net.drop_commissioning_requests(-1)


# --- Gating ----------------------------------------------------------------------------------


async def test_no_valve_traffic_until_device_annce_and_mtorr() -> None:
    rig = make_rig()
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    await rig.collect(2.0)
    rig.send(g.ZCL_READ)
    assert await rig.collect(60.0) == ()
    rig.send(g.DEVICE_ANNCE)
    rig.send(g.ZCL_READ)
    assert await rig.collect(60.0) == ()
    assert not rig.net.gated_open
    rig.send(g.MTORR)
    assert rig.net.gated_open
    rig.send(g.ZCL_READ)
    (ind,) = await rig.collect(60.0)
    assert masked(ind.npdu, SEQ, 15) == masked(g.ZCL_READ_RSP, SEQ, 15)


async def test_mtorr_before_join_does_not_count() -> None:
    rig = make_rig()
    rig.send(g.MTORR)
    rig.send(g.DEVICE_ANNCE)
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    await rig.collect(2.0)
    assert not rig.net.gated_open


async def test_discover_route_zero_unicast_gives_network_status_02() -> None:
    rig = make_rig()
    await rig.join()
    rig.send(b"\x08" + g.ZCL_READ[1:])  # FC byte0 0x48 -> 0x08 (discover_route 0)
    (ind,) = await rig.collect(60.0)
    assert masked(ind.npdu, SEQ) == masked(g.NETWORK_STATUS_NO_ROUTE, SEQ)


# --- Routing ---------------------------------------------------------------------------------


async def test_stale_or_unknown_short_goes_unanswered() -> None:
    rig = make_rig()
    await rig.join()
    rig.send(g.ZCL_READ.replace(h("6F 5E"), h("01 7E"), 1))
    assert await rig.collect(120.0) == ()


async def test_reply_from_the_device_short_to_the_joined_short() -> None:
    rig = make_rig(assign_short=0x0BB0)
    rig.send(g.COMMISSIONING_REQUEST, secure=False)
    await rig.collect(2.0)
    rig.send(g.DEVICE_ANNCE.replace(h("34 12"), h("B0 0B")))
    rig.send(g.MTORR.replace(h("34 12"), h("B0 0B")))
    rig.send(g.ZCL_READ.replace(h("34 12"), h("B0 0B")))
    (ind,) = await rig.collect(60.0)
    assert (ind.frame.dst, ind.frame.src) == (0x0BB0, g.VALVE_SHORT)
    assert ind.secure is True


async def test_frames_from_another_source_are_ignored() -> None:
    rig = make_rig()
    await rig.join()
    rig.send(g.ZCL_READ.replace(h("34 12"), h("35 12")))
    rig.send(b"\x00\x00\x00")  # undecodable NWK frame
    assert await rig.collect(60.0) == ()


# --- Mgmt_Lqi --------------------------------------------------------------------------------


def lqi_req(dst: int, start: int, seq: int = 0x0A) -> bytes:
    req = bytearray(g.MGMT_LQI_REQ)
    req[2:4] = dst.to_bytes(2, "little")
    req[-2:] = bytes([seq, start])
    return bytes(req)


async def test_mgmt_lqi_golden_first_page() -> None:
    rig = make_rig()
    with_router_valve(rig)  # coordinator: valve, R0, extra router -> 3 entries
    await rig.join()
    rig.send(g.MGMT_LQI_REQ)
    (ind,) = await rig.collect(2.0)
    assert masked(ind.npdu, SEQ, 15) == masked(g.MGMT_LQI_RSP, SEQ, 15)


async def test_mgmt_lqi_pages_at_most_two_records() -> None:
    rig = make_rig()
    rig.net.add_valve(
        SimValve(
            rig.clock,
            eui=Eui64.from_str("02:00:00:00:00:00:00:07"),
            short=0x1111,
            rng=seeded(1),
        )
    )
    with_router_valve(rig)
    await rig.join()
    seen: list[Neighbor] = []
    for start in (0, 2, 4, 6):
        rig.send(lqi_req(0x0000, start))
        (ind,) = await rig.collect(2.0)
        rsp = MgmtLqiRsp.decode(aps_of(ind).payload)
        assert rsp.neighbor_table_entries == 4
        assert len(rsp.neighbors) <= 2
        seen.extend(rsp.neighbors)
    assert [n.nwk_addr for n in seen] == [g.VALVE_SHORT, 0x1111, g.ZDD_SHORT, ROUTER.short]
    assert [n.device_type for n in seen] == [DeviceType.END_DEVICE] * 2 + [DeviceType.ROUTER] * 2
    assert all(n.rx_on_when_idle is (n.device_type is DeviceType.ROUTER) for n in seen)


async def test_extra_router_lists_its_valve_and_r0_lists_nothing() -> None:
    rig = make_rig()
    valve = with_router_valve(rig)
    await rig.join()
    rig.send(lqi_req(ROUTER.short, 0))
    (ind,) = await rig.collect(2.0)
    assert ind.frame.src == ROUTER.short
    rsp = MgmtLqiRsp.decode(aps_of(ind).payload)
    assert [(n.ieee, n.nwk_addr, n.depth) for n in rsp.neighbors] == [(valve.eui, valve.short, 2)]
    rig.send(lqi_req(g.ZDD_SHORT, 0))
    (ind,) = await rig.collect(2.0)
    assert MgmtLqiRsp.decode(aps_of(ind).payload).neighbor_table_entries == 0


async def test_router_timeout_never_answers() -> None:
    rig = make_rig(router_timeout=frozenset({ROUTER.short}))
    with_router_valve(rig)
    await rig.join()
    rig.send(lqi_req(ROUTER.short, 0))
    assert await rig.collect(60.0) == ()
    rig.send(lqi_req(0x0000, 0))
    assert len(await rig.collect(2.0)) == 1


async def test_mgmt_bind_to_coordinator_never_answers() -> None:
    rig = make_rig()
    await rig.join()
    rig.send(h("48 02 00 00 34 12 1E 0C", "00 00 33 00 00 00 00 00", "0D 00"))
    assert await rig.collect(120.0) == ()


# --- RREQ ------------------------------------------------------------------------------------


async def test_rreq_with_dst_ieee_and_repeated_route_id() -> None:
    rig = make_rig()
    await rig.join()
    rig.net.emit_route_request(g.VALVE_SHORT, route_id=7, repeat=3, spacing=1.0)
    inds = await rig.collect(3.0)
    assert [i.at for i in inds] == [0.0 + 2.0, 3.0, 4.0]
    for ind in inds:
        assert masked(ind.npdu, SEQ) == masked(g.RREQ_FROM_VALVE, SEQ)


async def test_rreq_unknown_originator_and_other_destination() -> None:
    rig = make_rig()
    await rig.join()
    rig.net.emit_route_request(g.VALVE_SHORT, route_id=8, with_src_ieee=False)
    rig.net.emit_route_request(0x6E6E, route_id=9)  # unknown originator: no src IEEE
    rig.net.emit_route_request(g.VALVE_SHORT, route_id=10, dst=0x0000)
    no_src, unknown, other = await rig.collect(0.0)
    assert masked(no_src.npdu, SEQ) == masked(g.RREQ_NO_SRC_IEEE, SEQ)
    assert unknown.frame.src == 0x6E6E
    assert unknown.frame.src_ieee is None
    rreq = decode_nwk_command(other.frame.payload)
    assert isinstance(rreq, RouteRequest)
    assert rreq.dst == 0x0000
    assert rreq.dst_ieee == g.COORDINATOR_EUI
    with pytest.raises(ValueError, match="repeat"):
        rig.net.emit_route_request(g.VALVE_SHORT, route_id=1, repeat=0)


async def test_rreq_needs_a_joined_target() -> None:
    rig = make_rig()
    with pytest.raises(RuntimeError, match="joined"):
        rig.net.emit_route_request(g.VALVE_SHORT, route_id=1)


async def test_rrep_recorder() -> None:
    rig = make_rig()
    await rig.join()
    rig.send(g.RREP_LIVE)
    rig.send(g.RREP_SPEC)
    live, spec = rig.net.route_replies
    assert live.raw == g.RREP_LIVE
    assert spec.raw == g.RREP_SPEC
    assert live.reply.route_id == 7
    assert live.frame.dst == g.VALVE_SHORT
    assert spec.reply.originator_ieee == g.VALVE_EUI
    rig.host.reset_session()
    assert len(rig.net.route_replies) == 2  # the recorder survives sessions


# --- Quirk and noise -------------------------------------------------------------------------

READ_TEMP = h("48 02 6F 5E 34 12 1E 06", "00 01 01 02 04 01 01 2B", "00 2B 00", "00 00")


@pytest.mark.parametrize(
    ("variant", "golden"),
    [("source_route", g.QUIRK_SOURCE_ROUTE), ("garbage4", g.QUIRK_GARBAGE4)],
)
async def test_quirk_variants_match_golden(variant: str, golden: bytes) -> None:
    rig = make_rig(variant_weights={variant: 1.0})
    await rig.join()
    rig.send(READ_TEMP)
    (ind,) = await rig.collect(60.0)
    assert masked(ind.npdu, SEQ, 19) == masked(golden, SEQ, 19)


async def test_mixed_variant_weights_are_seeded() -> None:
    async def variants(seed: int) -> list[bytes]:
        rig = make_rig(seed=seed, variant_weights={"plain": 1, "source_route": 1, "garbage4": 1})
        await rig.join()
        for _ in range(12):
            rig.send(lqi_req(0x0000, 0))
        return [i.npdu[1:2] + i.npdu[8:12] for i in await rig.collect(5.0)]

    first = await variants(3)
    assert first == await variants(3)
    assert {v[:1] for v in first} == {b"\x02", b"\x06"}
    assert any(v[1:] == bytes.fromhex("005A5A00") for v in first)


@pytest.mark.parametrize("weights", [{"bogus": 1.0}, {"plain": -1.0}, {"plain": 0.0}])
def test_variant_weights_are_validated(weights: dict[str, float]) -> None:
    with pytest.raises(ValueError, match="variant_weights"):
        make_rig(variant_weights=weights)


async def test_noise_kinds() -> None:
    rig = make_rig()
    await rig.join()
    for kind in ("foreign_annce", "foreign_broadcast", "network_status_other", "other_dst"):
        rig.net.emit_noise(kind)
    annce, match_desc, status, other = await rig.collect(0.0)
    zdo = DeviceAnnce.decode(aps_of(annce).payload)
    assert annce.frame.dst == 0xFFFD
    assert zdo.ieee not in {g.VALVE_EUI, g.ZVD_EUI}
    assert match_desc.frame.src == 0x0000
    assert aps_of(match_desc).cluster_id == 0x0006
    ns = decode_nwk_command(status.frame.payload)
    assert isinstance(ns, NetworkStatus)
    assert ns.destination != g.ZVD_SHORT
    assert other.frame.dst not in {g.ZVD_SHORT, 0xFFFD}
    assert other.frame.src == g.VALVE_SHORT


async def test_zvd_broadcasts_other_than_annce_are_ignored() -> None:
    rig = make_rig()
    await rig.join()
    rig.send(h("48 02 FD FF 34 12 1E 10", "08 00 06 00 00 00 00 01", "05 FD FF 04 01 01 01 02 00"))
    assert await rig.collect(60.0) == ()


# --- Events ----------------------------------------------------------------------------------


async def test_session_reset_closes_gate_and_drops_scheduled_replies() -> None:
    rig = make_rig()
    await rig.join()
    rig.send(g.ZCL_READ)
    rig.host.reset_session()  # what SimulatedR0.r0_reboot() does to its peer
    assert rig.net.joined_short is None
    assert not rig.net.gated_open
    assert rig.net.received == ()
    assert await rig.collect(60.0) == ()
    await rig.join()
    rig.send(g.ZCL_READ)
    assert len(await rig.collect(60.0)) == 1


async def test_report_needs_an_open_gate() -> None:
    rig = make_rig()
    rig.valve.report(0x0201, (0x0000,))
    assert await rig.collect(1.0) == ()
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    (ind,) = await rig.collect(0.0)
    assert masked(ind.npdu, SEQ, 15) == masked(g.ZCL_REPORT, SEQ, 15)


async def test_add_valve_later_announces_new_eui() -> None:
    rig = make_rig()
    await rig.join()
    new = SimValve(
        rig.clock, eui=Eui64.from_str("02:00:00:00:00:00:00:08"), short=0x2222, rng=seeded(2)
    )
    rig.net.add_valve_later(new)
    (ind,) = await rig.collect(0.0)
    assert ind.frame.dst == 0xFFFD
    assert ind.frame.src == 0x2222
    annce = DeviceAnnce.decode(aps_of(ind).payload)
    assert (annce.nwk_addr, annce.ieee, annce.capability) == (0x2222, new.eui, 0x80)
    assert rig.net.valves == (rig.valve, new)


async def test_valve_rejoin_makes_old_short_stale() -> None:
    rig = make_rig()
    await rig.join()
    rig.net.valve_rejoin(rig.valve, 0x3333)
    (ind,) = await rig.collect(0.0)
    assert DeviceAnnce.decode(aps_of(ind).payload).nwk_addr == 0x3333
    rig.send(g.ZCL_READ)
    assert await rig.collect(60.0) == ()
    rig.send(g.ZCL_READ.replace(h("6F 5E"), h("33 33"), 1))
    (ind,) = await rig.collect(60.0)
    assert ind.frame.src == 0x3333
    with pytest.raises(ValueError, match="in use"):
        rig.net.valve_rejoin(rig.valve, g.ZDD_SHORT)


async def test_address_conflict() -> None:
    rig = make_rig()
    with pytest.raises(RuntimeError, match="joined"):
        rig.net.address_conflict()
    await rig.join()
    rig.net.address_conflict()
    (ind,) = await rig.collect(0.0)
    assert ind.frame.frame_type is NwkFrameType.COMMAND
    assert masked(ind.npdu, SEQ) == masked(g.NETWORK_STATUS_CONFLICT, SEQ)


# --- Topology validation ---------------------------------------------------------------------


def test_duplicate_or_reserved_devices_are_rejected() -> None:
    rig = make_rig()
    rng = seeded(0)
    with pytest.raises(ValueError, match="EUI"):
        rig.net.add_valve(SimValve(rig.clock, eui=g.VALVE_EUI, short=0x0101, rng=rng))
    with pytest.raises(ValueError, match="in use"):
        rig.net.add_valve(SimValve(rig.clock, eui=ROUTER_VALVE_EUI, short=g.VALVE_SHORT, rng=rng))
    with pytest.raises(ValueError, match="reserved"):
        rig.net.add_router(SimRouter(eui=ROUTER.eui, short=0xFFFC))
    with pytest.raises(ValueError, match="parent"):
        rig.net.add_valve(
            SimValve(rig.clock, eui=ROUTER_VALVE_EUI, short=0x0101, rng=rng), parent=0x0101
        )
    stranger = SimValve(rig.clock, eui=ROUTER_VALVE_EUI, short=0x0101, rng=rng)
    with pytest.raises(ValueError, match="not in this network"):
        rig.net.valve_rejoin(stranger, 0x0202)
    with pytest.raises(ValueError, match="not in this network"):
        rig.net.deliver_from_valve(stranger, ApsDataFrame(0, 0, b""), delay=0.0)
    with pytest.raises(ValueError, match="lqi_page_size"):
        make_rig(lqi_page_size=0)
    assert rig.net.routers[0].short == g.ZDD_SHORT
