"""End to end: APS acks keep a poll cycle free of duplicate responses (hardware finding 1).

The simulator requests an APS ack on every unicast and retransmits unacked frames, as the R0
and the valves do live. With the node's acks every response arrives once; with the acks
switched off (test-only monkeypatch) the retransmissions show up as ``late_drops``, as in
the first hardware run (117 in 5 min).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from localtrv.testing.network_aps import SIM_APS_ACK_WAIT, SIM_APS_MAX_FRAME_RETRIES
from localtrv.zigbee_direct.node_core import NodeCore
from test_bridge import poll, stop
from test_e2e_sim import begin, e2e_rig

if TYPE_CHECKING:
    import pytest

    from localtrv.zigbee_direct.node_types import NodeStats
    from test_bridge import BRig

#: Long enough for every retransmission of the last response to have happened.
RETRY_WINDOW = SIM_APS_ACK_WAIT * (SIM_APS_MAX_FRAME_RETRIES + 1)


def node_stats(r: BRig) -> NodeStats:
    stats = r.conn.last_node_stats
    assert stats is not None
    return stats


async def poll_cycle(r: BRig) -> NodeStats:
    await begin(r)
    await poll(r)
    await r.clock.advance(RETRY_WINDOW)
    return node_stats(r)


async def test_poll_cycle_with_acks_has_no_late_drops() -> None:
    r = e2e_rig(n_valves=3, behind_router=1)
    stats = await poll_cycle(r)
    aps = r.inst.network.aps
    assert stats.aps_acks_sent > 0
    assert stats.aps_ack_failures == 0
    assert stats.late_drops == 0
    assert aps.retransmits == 0
    assert aps.unacked == 0
    assert aps.acks_received == stats.aps_acks_sent
    await stop(r)


async def test_without_acks_retransmissions_become_late_drops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(NodeCore, "ack_aps", lambda _self, _src, _aps: None)
    r = e2e_rig(n_valves=3, behind_router=1)
    stats = await poll_cycle(r)
    aps = r.inst.network.aps
    assert stats.aps_acks_sent == 0
    assert aps.retransmits > 0
    assert stats.late_drops > 0
    assert stats.late_drops <= aps.retransmits  # every late drop is a retransmitted copy
    await stop(r)
