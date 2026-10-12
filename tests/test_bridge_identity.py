"""ViCareBridge: valve identity under short reuse (Codex review fix round).

An explicit source IEEE outranks the short lookup, and a Device_annce that arrives while a
valve is being identified wins over the short the identification started with.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from test_bridge import NEW_EUI, discovered, make_rig, run_until, stop, zcl_requests
from vicare_local_ble import valves
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.node_types import ReportEvent

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.types import Eui64

THERMOSTAT = 0x0201
LOCAL_TEMPERATURE = 0x0000


def temperature_report(short: int, ieee: Eui64 | None, centi: int) -> ReportEvent:
    record = AttributeRecord(LOCAL_TEMPERATURE, ZclDataType.INT16, centi)
    return ReportEvent(short, ieee, valves.ENDPOINT, THERMOSTAT, None, (record,))


async def test_report_with_unknown_ieee_on_reused_short_is_not_applied() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    valve_a = r.inst.valves[0]
    assert valve_a.eui != NEW_EUI
    short = r.snap().valves[valve_a.eui].short
    before = r.snap().states[valve_a.eui]
    r.bridge._on_report(gen, temperature_report(short, NEW_EUI, 1234))
    assert r.snap().states[valve_a.eui] == before  # B's report never lands on A
    assert NEW_EUI in r.core.annce_seen  # B gets identified like a Device_annce sender
    assert r.core.annce_short[NEW_EUI][0] == short
    # Without an IEEE the short lookup is still the fallback.
    r.bridge._on_report(gen, temperature_report(short, None, 1234))
    assert r.snap().states[valve_a.eui].local_temperature_c == 12.34
    # A matching explicit IEEE applies too.
    r.bridge._on_report(gen, temperature_report(short, valve_a.eui, 1500))
    assert r.snap().states[valve_a.eui].local_temperature_c == 15.0
    await stop(r)


async def test_annce_during_identification_ends_at_the_new_short() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    net = r.inst.network
    newcomer = SimValve(r.clock, eui=NEW_EUI, short=0x3333, rng=random.Random(9))  # noqa: S311
    mark = len(net.received)
    net.add_valve_later(newcomer)

    def limits_read_started() -> bool:
        reqs = [req for to, req in zcl_requests(r, mark) if to == 0x3333]
        return valves.IDENTIFY in reqs and any(req != valves.IDENTIFY for req in reqs)

    await run_until(r.clock, limits_read_started)
    assert NEW_EUI not in r.snap().valves
    net.valve_rejoin(newcomer, 0x3334)  # re-announces while the limits read awaits
    await run_until(r.clock, lambda: NEW_EUI in r.snap().valves)
    assert r.snap().valves[NEW_EUI].short == 0x3334
    assert 0x3334 in r.conn.node_config.avoid_shorts
    await stop(r)
