"""SimNetwork APS reliability (``testing.network_aps``): ack request, ack wait and retries.

Golden-driven through the recording host, like ``test_sim_network.py``, but with the
hardware-default ``aps_ack_request=True``.
"""

from __future__ import annotations

import pytest

from fixtures import golden as g
from test_sim_network import SEQ, aps_of, make_rig
from vicare_local_ble.testing.network_aps import (
    SIM_APS_ACK_WAIT,
    SIM_APS_MAX_FRAME_RETRIES,
    ApsRetransmitter,
)
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.aps import ApsAckFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType

h = g.h


def ack_npdu(
    src: int,
    ack: ApsAckFrame,
    *,
    dst: int = g.VALVE_SHORT,
    discover_route: int = 1,
    security: bool = True,
) -> bytes:
    """An APS ack from the ZVD (``src``) to ``dst``, as the node's builder lays it out."""
    return NwkFrame(
        frame_type=NwkFrameType.DATA,
        dst=dst,
        src=src,
        radius=30,
        seq=0x60,
        payload=ack.encode(),
        discover_route=discover_route,
        security=security,
    ).encode()


def test_constants_follow_the_spec() -> None:
    assert SIM_APS_MAX_FRAME_RETRIES == 3  # apscMaxFrameRetries
    assert pytest.approx(0.05 * 2 * 15 + 0.1) == SIM_APS_ACK_WAIT  # apscAckWaitDuration


def test_default_requests_acks() -> None:
    assert make_rig(aps_ack_request=True).net.aps_ack_request is True


@pytest.mark.parametrize(("bad_wait", "bad_retries"), [(0.0, 3), (1.0, -1)])
def test_retransmitter_rejects_bad_parameters(bad_wait: float, bad_retries: int) -> None:
    with pytest.raises(ValueError, match="ack_wait"):
        ApsRetransmitter(
            VirtualClock(), lambda _s, _a: True, ack_wait=bad_wait, max_retries=bad_retries
        )


async def test_unacked_report_is_retransmitted_three_times() -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    start = rig.clock.now()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    inds = await rig.collect(30.0)
    assert len(inds) == 1 + SIM_APS_MAX_FRAME_RETRIES
    assert [i.at - start for i in inds] == pytest.approx([n * SIM_APS_ACK_WAIT for n in range(4)])
    frames = [aps_of(i) for i in inds]
    assert all(f.ack_request for f in frames)
    assert len({f.counter for f in frames}) == 1  # the same APS frame every time
    assert len({i.npdu[SEQ] for i in inds}) == 4  # each a new NWK transmission
    assert inds[0].npdu[8] == 0x40  # live APS FC: data, unicast, ack request
    assert (rig.net.aps.retransmits, rig.net.aps.unacked, rig.net.aps.waiting) == (3, 1, 0)


async def test_ack_stops_the_retransmissions() -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    (first,) = await rig.collect(0.0)
    rig.send(ack_npdu(g.ZVD_SHORT, ApsAckFrame.for_frame(aps_of(first))))
    assert await rig.collect(30.0) == ()
    assert (rig.net.aps.acks_received, rig.net.aps.retransmits) == (1, 0)


async def test_late_ack_stops_the_remaining_retries() -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    inds = await rig.collect(SIM_APS_ACK_WAIT + 0.1)
    assert len(inds) == 2
    rig.send(ack_npdu(g.ZVD_SHORT, ApsAckFrame.for_frame(aps_of(inds[-1]))))
    assert await rig.collect(30.0) == ()
    assert rig.net.aps.retransmits == 1


async def test_mismatched_or_malformed_acks_are_ignored() -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    (first,) = await rig.collect(0.0)
    ack = ApsAckFrame.for_frame(aps_of(first))
    wrong_counter = ApsAckFrame(ack.dst_endpoint, ack.cluster_id, ack.profile_id, 1, 0x00)
    rig.send(ack_npdu(g.ZVD_SHORT, wrong_counter))
    rig.send(ack_npdu(g.ZVD_SHORT, ack, dst=0x7777))  # ack for another device
    rig.send(ack_npdu(g.ZVD_SHORT, ack)[:-1])  # truncated ack
    rig.send(ack_npdu(0x0BB0, ack))  # not from the joined ZVD
    assert len(await rig.collect(30.0)) == SIM_APS_MAX_FRAME_RETRIES
    assert rig.net.aps.acks_received == 0


@pytest.mark.parametrize(
    ("variant", "tunnel_secure"),
    [
        ("discover_route_0", True),
        ("no_nwk_security", True),
        ("no_tunnel_flag", False),
        ("broadcast", True),
        ("gate_closed", True),
    ],
)
async def test_undeliverable_ack_does_not_stop_retransmissions(
    variant: str, tunnel_secure: bool
) -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    (first,) = await rig.collect(0.0)
    ack = ApsAckFrame.for_frame(aps_of(first))
    kwargs: dict[str, int | bool] = {}
    if variant == "discover_route_0":
        kwargs["discover_route"] = 0
    elif variant == "no_nwk_security":
        kwargs["security"] = False
    elif variant == "broadcast":
        kwargs["dst"] = 0xFFFD
    elif variant == "gate_closed":
        rig.net._mtorr_seen = False  # the ack arrives while the gate is closed
    rig.send(ack_npdu(g.ZVD_SHORT, ack, **kwargs), secure=tunnel_secure)  # type: ignore[arg-type]
    if variant == "gate_closed":
        rig.net._mtorr_seen = True  # reopened: retries go out again
    inds = await rig.collect(30.0)
    retries = [i for i in inds if i.frame.frame_type is NwkFrameType.DATA]
    assert len(retries) == SIM_APS_MAX_FRAME_RETRIES
    assert rig.net.aps.acks_received == 0


async def test_valve_response_requests_an_ack_and_repeats() -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    rig.send(g.ZCL_READ)
    inds = await rig.collect(60.0)
    assert len(inds) == 4
    assert len({i.npdu[8:] for i in inds}) == 1  # identical APS frame and ZCL payload


async def test_session_reset_drops_waiting_frames() -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    await rig.collect(0.0)
    rig.host.reset_session()
    assert rig.net.aps.waiting == 0
    assert await rig.collect(30.0) == ()


async def test_closed_gate_stops_the_retries() -> None:
    rig = make_rig(aps_ack_request=True)
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    await rig.collect(0.0)
    rig.net._annce_seen = False  # gate closed (as after a rejoin) before the first retry
    assert await rig.collect(30.0) == ()
    assert (rig.net.aps.waiting, rig.net.aps.retransmits) == (0, 0)


async def test_without_ack_request_frames_are_sent_once() -> None:
    rig = make_rig()  # unit rigs default to aps_ack_request=False
    await rig.join()
    rig.valve.report(0x0201, (0x0000,), tsn=0x2F)
    (ind,) = await rig.collect(30.0)
    assert aps_of(ind).ack_request is False
