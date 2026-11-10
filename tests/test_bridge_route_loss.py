"""Partial silence after a reconnect: a router lost its return route to the ZVD.

Regression for the live failure of 2026-11-10: after a BLE proxy reconnect every valve under the
coordinator stayed unavailable for good, while a valve under another parent kept answering. The
all-silent rejoin never fired because one valve still answered.
"""

from __future__ import annotations

from localtrv.bridge import SILENT_REJOIN_BACKOFF, STUCK_POLLS_REFRESH, STUCK_POLLS_REJOIN
from localtrv.testing.network_aps import is_aps_ack
from localtrv.zigbee_direct.codec.aps import ZDO_PROFILE_ID, ApsDataFrame
from localtrv.zigbee_direct.codec.nwk import NwkFrameType
from localtrv.zigbee_direct.codec.nwk_commands import ManyToOne, RouteRequest, decode_nwk_command
from localtrv.zigbee_direct.codec.zdo import ZdoCluster
from localtrv.zigbee_direct.connection import ConnectionState
from localtrv.zigbee_direct.types import COORDINATOR
from test_bridge import BRig, discovered, make_rig, poll, ready_again, run_until, stop
from test_bridge_review import wait_initial_poll


def _refreshes(r: BRig, start: int = 0) -> tuple[int, int]:
    """(Device_annce, MTORR) frames the ZVD sent this session since ``start``."""
    annces = mtorrs = 0
    for frame in r.inst.network.received[start:]:
        if frame.frame_type is NwkFrameType.COMMAND:
            command = decode_nwk_command(frame.payload)
            if isinstance(command, RouteRequest) and command.many_to_one is not ManyToOne.NONE:
                mtorrs += 1
        elif frame.frame_type is NwkFrameType.DATA and not is_aps_ack(frame):
            aps = ApsDataFrame.decode(frame.payload)
            if aps.profile_id == ZDO_PROFILE_ID and aps.cluster_id == ZdoCluster.DEVICE_ANNCE:
                annces += 1
    return annces, mtorrs


async def _polls_until_rejoin(r: BRig) -> None:
    """Poll until a rejoin is requested; fails after ``STUCK_POLLS_REJOIN + 2`` polls."""
    for _ in range(STUCK_POLLS_REJOIN + 2):
        if r.conn.stats.rejoins:
            return
        await poll(r)
    assert r.conn.stats.rejoins, "no rejoin requested"


async def _reconnect_with_route_loss(r: BRig, *, heal_on_refresh: bool = False) -> int:
    """Discover, then drop the BLE link; the next session loses the coordinator's route."""
    gen = await discovered(r)
    assert all(r.snap().available.values())
    r.inst.network.route_loss.schedule(COORDINATOR, heal_on_refresh=heal_on_refresh)
    r.inst.r0.disconnect()
    await run_until(r.clock, lambda: r.conn.state is not ConnectionState.READY)
    await wait_initial_poll(r, gen.number)
    return r.conn.stats.generation


async def test_coordinator_children_recover_after_reconnect_via_rejoin() -> None:
    r = make_rig(n_valves=3, behind_router=1)
    number = await _reconnect_with_route_loss(r)
    stuck = [v.eui for v in r.inst.valves[:-1]]
    other = r.inst.valves[-1].eui
    assert r.inst.network.route_loss.parent == COORDINATOR
    # gen 2: the router's child answers, the coordinator's children do not.
    assert r.snap().available[other] is True
    start = len(r.inst.network.received)
    for _ in range(STUCK_POLLS_REFRESH):
        if r.core.route_refresh_at is not None:
            break
        await poll(r)
    assert r.conn.stats.rejoins == 0
    assert r.core.route_refresh_at is not None, "partial silence never refreshed the routes"
    await run_until(r.clock, lambda: _refreshes(r, start) == (1, 2))
    assert all(r.core.silent_polls[e] >= STUCK_POLLS_REFRESH for e in stuck)
    # The refresh does not heal this fault: escalate to a rejoin.
    await _polls_until_rejoin(r)
    assert r.conn.stats.last_failure == "rejoin:valves_silent"
    await ready_again(r, number)
    snap = await poll(r)
    assert all(snap.available[e] for e in stuck), snap.misses
    assert snap.misses[other] == 0
    assert r.inst.network.route_loss.parent is None
    await stop(r)


async def test_route_refresh_alone_recovers_without_rejoin() -> None:
    r = make_rig(n_valves=3, behind_router=1)
    await _reconnect_with_route_loss(r, heal_on_refresh=True)
    stuck = [v.eui for v in r.inst.valves[:-1]]
    for _ in range(STUCK_POLLS_REFRESH):
        await poll(r)
    await run_until(r.clock, lambda: r.inst.network.route_loss.parent is None)
    snap = await poll(r)
    assert all(snap.available[e] for e in stuck)
    for _ in range(STUCK_POLLS_REJOIN):
        await poll(r)
    assert r.conn.stats.rejoins == 0
    assert r.core.silent_polls == {}
    await stop(r)


async def test_one_dead_valve_backs_off_while_others_answer() -> None:
    r = make_rig(n_valves=3, behind_router=1)
    gen = await discovered(r)
    dead = r.inst.valves[0]
    dead.drop_rate = 1.0
    await _polls_until_rejoin(r)
    assert r.conn.stats.last_failure == "rejoin:valves_silent"
    first = r.core.last_silent_rejoin
    assert first is not None
    assert r.core.rejoin_silent == {dead.eui}
    await wait_initial_poll(r, gen.number)
    # The other valves answer every poll: that does not reset the backoff.
    for _ in range(STUCK_POLLS_REJOIN + 1):
        await poll(r)
    assert r.conn.stats.rejoins == 1
    assert r.core.silent_rejoins == 1
    # One refresh per ROUTE_REFRESH_INTERVAL, not one per poll.
    refreshed = r.core.route_refresh_at
    assert refreshed is not None
    await poll(r)
    assert r.core.route_refresh_at == refreshed
    # After the 1 h gap the next rejoin may go.
    await r.clock.advance_to(first + SILENT_REJOIN_BACKOFF)
    await poll(r)
    assert r.conn.stats.rejoins == 2
    number = r.conn.stats.generation
    await wait_initial_poll(r, number)
    dead.drop_rate = 0.0
    await poll(r)  # the silent valve answered: the backoff resets
    assert r.core.silent_rejoins == 0
    assert r.core.rejoin_silent == frozenset()
    await stop(r)


async def test_all_silent_rule_still_rejoins_without_a_refresh() -> None:
    r = make_rig(n_valves=2, behind_router=1)
    await discovered(r)
    for v in r.inst.valves:
        v.drop_rate = 1.0
    start = len(r.inst.network.received)
    await _polls_until_rejoin(r)
    assert r.conn.stats.last_failure == "rejoin:all_valves_silent"
    assert r.core.route_refresh_at is None
    assert _refreshes(r, start) == (0, 0)
    await stop(r)
