"""``default_installation``: research layout, one source of truth, determinism."""

from __future__ import annotations

import pytest

from fixtures import golden as g
from vicare_local_ble.testing.scenario import default_installation
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import DeviceType
from vicare_local_ble.zigbee_direct.types import COORDINATOR


def test_research_layout() -> None:
    inst = default_installation()
    net = inst.network
    r0, extra = net.routers
    assert len(inst.valves) == 5
    assert net.valves == inst.valves
    coordinator = net.neighbor_table(COORDINATOR)
    end_devices = [n for n in coordinator if n.device_type is DeviceType.END_DEVICE]
    routers = [n for n in coordinator if n.device_type is DeviceType.ROUTER]
    assert len(end_devices) == 4
    assert [n.nwk_addr for n in routers] == [r0.short, extra.short]
    (behind,) = net.neighbor_table(extra.short)
    assert behind.ieee == inst.valves[-1].eui
    assert net.neighbor_table(r0.short) == ()


def test_one_source_of_truth_for_zdd_identity() -> None:
    inst = default_installation(seed=3)
    r0_router = inst.network.routers[0]
    assert r0_router.short == inst.r0.zdd_short
    assert r0_router.eui == inst.r0.eui == inst.zdd_eui
    assert inst.resolver() is not None


def test_dummy_identities_and_distinct_keys() -> None:
    inst = default_installation(n_valves=3, behind_router=0)
    euis = [inst.zvd_eui, inst.zdd_eui, *(v.eui for v in inst.valves)]
    assert all(str(e).startswith("02:00:") for e in euis)
    assert len(set(euis)) == len(euis)
    assert len(inst.network.routers) == 1  # no extra router without valves behind it
    assert len({v.short for v in inst.valves}) == 3


def test_same_seed_same_installation() -> None:
    def shorts(seed: int) -> list[int]:
        inst = default_installation(seed=seed)
        return [inst.r0.zdd_short, *(v.short for v in inst.valves)]

    assert shorts(1) == shorts(1)
    assert shorts(1) != shorts(2)


def test_shared_clock_and_validation() -> None:
    clock = VirtualClock()
    assert default_installation(clock=clock).clock is clock
    with pytest.raises(ValueError, match="behind_router"):
        default_installation(n_valves=1, behind_router=2)


async def test_r0_reboot_resets_the_network_session() -> None:
    inst = default_installation()
    net = inst.network
    request = bytearray(g.COMMISSIONING_REQUEST)
    request[2:4] = inst.r0.zdd_short.to_bytes(2, "little")
    request[24 - 16 : 24 - 8] = inst.zdd_eui.wire  # dst IEEE
    net.on_zvd_npdu(TunnelNpdu(bytes(request), nwk_security=False))
    await inst.clock.advance(2.0)  # the R0 drops the indication: no session
    assert net.joined_short == g.ZVD_SHORT
    inst.r0.r0_reboot()
    assert net.joined_short is None
