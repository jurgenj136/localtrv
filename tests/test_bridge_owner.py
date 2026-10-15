"""``bridge_owner.Ownership`` and IEEE_addr verification (review rounds 4-5)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from test_bridge import ACME_EUI, add_acme, discovered, make_rig, stop
from vicare_local_ble import bridge_verify, valves
from vicare_local_ble.bridge_owner import Ownership
from vicare_local_ble.bridge_types import ValveAddressUnknownError
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.types import Eui64

if TYPE_CHECKING:
    from collections.abc import Mapping

A = Eui64.from_str("02:00:00:00:00:01:00:01")
B = Eui64.from_str("02:00:00:00:00:01:00:02")


def valve(eui: Eui64, short: int) -> valves.Valve:
    return valves.Valve(
        eui=eui,
        short=short,
        endpoint=1,
        manufacturer=None,
        model=None,
        sw_build=None,
        limits=valves.DEFAULT_LIMITS,
    )


def owner_of(valve_map: Mapping[Eui64, valves.Valve]) -> tuple[Ownership, VirtualClock]:
    clock = VirtualClock()
    return Ownership(valve_map, clock), clock


async def test_restored_shorts_are_trusted_unless_listed_twice() -> None:
    owner, _ = owner_of({A: valve(A, 0x1111)})
    assert owner.unaddressed == set()
    assert owner.holds(owner.lease(A))
    twice, _ = owner_of({A: valve(A, 0x1111), B: valve(B, 0x1111)})
    assert twice.unaddressed == {A, B}
    with pytest.raises(ValveAddressUnknownError):
        twice.lease(A)


async def test_leases_break_on_any_change_of_the_short() -> None:
    owner, clock = owner_of({A: valve(A, 0x1111)})
    lease = owner.lease(A)
    owner.seen_at(A, 0x1111)  # the same device again: the lease holds
    assert owner.holds(lease)
    owner.seen_at(B, 0x1111)
    assert not owner.holds(lease)
    with pytest.raises(ValveAddressUnknownError):
        owner.check(lease)
    owner.claim(A, 0x1111, clock.now())  # A back: an old lease never holds again
    assert not owner.holds(lease)
    assert owner.holds(owner.lease(A))
    owner.seen_at(B, 0x2222)
    short = owner.short_lease(B, 0x2222)
    owner.check_short(short)
    owner.seen_at(A, 0x2222)
    owner.seen_at(B, 0x2222)  # flips back: still broken
    with pytest.raises(ValveAddressUnknownError):
        owner.check_short(short)


async def test_older_evidence_is_ignored() -> None:
    owner, clock = owner_of({A: valve(A, 0x1111)})
    await clock.advance(10)
    owner.claim(A, 0x1111, clock.now())
    assert owner.seen_at(B, 0x1111, at=5.0) is False
    assert A not in owner.unaddressed


async def test_verification_logs_and_learns_who_answers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, "vicare_local_ble.bridge")
    r = make_rig(n_valves=1, behind_router=0, setup=add_acme)
    gen = await discovered(r)
    sim = r.inst.valves[0]
    short = r.snap().valves[sim.eui].short
    acme = next(v for v in r.inst.network.valves if v.eui == ACME_EUI)
    assert await r.clock.run_task(bridge_verify.verify_address(r.core, gen, sim.eui, short))
    assert f"valve {sim.eui}: short 0x{short:04X} verified" in caplog.text
    sim.set_short(0x5A5A)
    acme.set_short(short)
    assert not await r.clock.run_task(bridge_verify.verify_address(r.core, gen, sim.eui, short))
    assert f"verification failed (answered by {ACME_EUI})" in caplog.text
    assert r.core.short_seen[short][0] == ACME_EUI
    assert sim.eui in r.core.unaddressed  # the device itself said so: authoritative
    acme.drop_rate = 1.0
    assert not await r.clock.run_task(bridge_verify.verify_address(r.core, gen, sim.eui, short))
    assert "verification failed (no answer (RequestTimeoutError))" in caplog.text
    await stop(r)
