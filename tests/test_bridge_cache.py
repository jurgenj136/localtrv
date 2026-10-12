"""ViCareBridge (T14): cache round trip, restart from cache, node config and attach/detach."""

from __future__ import annotations

import json
import logging
import math

import pytest

from test_bridge import (
    ACME_EUI,
    LOGGER,
    add_acme,
    discovered,
    make_rig,
    poll,
    ready_again,
    run_until,
    stop,
    zcl_requests,
)
from vicare_local_ble import valves
from vicare_local_ble.bridge import CACHE_VERSION, BridgeCache, CachedValve
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.testing.scenario import valve_eui
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType

GOOD_EUI = "02:00:00:00:00:01:00:01"


def good_valve(**changes: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "eui": GOOD_EUI,
        "short": 0x1234,
        "endpoint": 1,
        "manufacturer": "Viessmann",
        "model": "7637434",
        "sw_build": None,
        "min_c": 8.0,
        "max_c": 30.0,
    }
    entry.update(changes)
    return entry


def good(**changes: object) -> dict[str, object]:
    data: dict[str, object] = {
        "version": CACHE_VERSION,
        "own_short": 0x0BCD,
        "zdd_eui": "02:00:00:00:00:00:00:02",
        "valves": {GOOD_EUI: good_valve()},
        "ignored": [str(ACME_EUI)],
    }
    data.update(changes)
    return data


async def test_cache_round_trip_without_secrets(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    r = make_rig(setup=add_acme)
    gen = await discovered(r)
    cache = r.bridge.export_cache()
    assert cache.own_short == gen.join.own_short
    assert cache.zdd_eui == str(r.inst.zdd_eui)
    assert set(cache.valves) == {str(e) for e in r.euis()}
    assert cache.ignored == frozenset({str(ACME_EUI)})
    text = json.dumps(cache.to_json())
    assert BridgeCache.from_json(json.loads(text)) == cache
    assert set(json.loads(text)) == {"version", "own_short", "zdd_eui", "valves", "ignored"}
    for secret in (r.inst.network_key.reveal().hex(), r.inst.network_key.reveal().hex().upper()):
        assert secret not in text
        assert secret not in caplog.text
    assert r.caches[-1] == cache  # on_cache_changed carried the latest state
    count = len(r.caches)
    await poll(r)  # a poll changes no persisted field
    assert len(r.caches) == count
    await stop(r)


def test_cached_valve_round_trip_and_limit_revalidation() -> None:
    entry = CachedValve.from_json(good_valve())
    valve = entry.to_valve()
    assert str(valve.eui) == GOOD_EUI
    assert valve.limits == valves.SetpointLimits(8.0, 30.0, "limits")
    assert CachedValve.from_valve(valve) == entry
    default = CachedValve.from_valve(CachedValve.from_json(good_valve(min_c=None)).to_valve())
    assert (default.min_c, default.max_c) == (None, None)
    inverted = CachedValve.from_json(good_valve(min_c=30, max_c=10)).to_valve()
    assert inverted.limits == valves.DEFAULT_LIMITS


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        "cache",
        {},
        good(version=2),
        good(version=True),
        good(own_short=0x10000),
        good(own_short=True),
        good(zdd_eui=5),
        good(zdd_eui="nope"),
        good(valves=[]),
        good(ignored={}),
        good(ignored=[1]),
        good(valves={GOOD_EUI: "x"}),
        good(valves={GOOD_EUI: good_valve(eui="02:00:00:00:00:01:00:02")}),
        good(valves={GOOD_EUI: good_valve(short=-1)}),
        good(valves={GOOD_EUI: good_valve(endpoint=0)}),
        good(valves={GOOD_EUI: good_valve(model=7)}),
        good(valves={GOOD_EUI: good_valve(min_c="8")}),
        good(valves={GOOD_EUI: good_valve(min_c=True)}),
        good(valves={GOOD_EUI: good_valve(max_c=math.inf)}),
    ],
)
def test_from_json_never_raises(data: object, caplog: pytest.LogCaptureFixture) -> None:
    assert BridgeCache.from_json(data) == BridgeCache()
    assert "ignoring the stored bridge cache" in caplog.text
    assert "0BCD" not in caplog.text.upper()  # stored values are never echoed


def test_from_json_accepts_good_data_and_normalises_euis() -> None:
    cache = BridgeCache.from_json(good(ignored=[str(ACME_EUI).lower()]))
    assert cache.own_short == 0x0BCD
    assert cache.ignored == frozenset({str(ACME_EUI)})
    assert BridgeCache.from_json(cache.to_json()) == cache
    assert BridgeCache.from_json({"version": CACHE_VERSION}) == BridgeCache()


async def test_restart_from_cache_seeds_valves_and_node_config() -> None:
    first = make_rig(n_valves=2, behind_router=0)
    gen = await discovered(first)
    cache = BridgeCache.from_json(json.loads(json.dumps(first.bridge.export_cache().to_json())))
    await stop(first)

    r = make_rig(n_valves=2, behind_router=0, cache=cache)
    snap = r.snap()  # before start: cached valves, unavailable
    assert set(snap.valves) == set(r.euis())
    assert not any(snap.available.values())
    assert r.conn.node_config.preferred_short == gen.join.own_short
    assert {v.short for v in snap.valves.values()} <= r.conn.node_config.avoid_shorts
    gen2 = await discovered(r)
    assert gen2.join.requested_short == gen.join.own_short
    assert r.new_valves == []  # known from the cache
    basic = [req for _, req in zcl_requests(r) if req == valves.IDENTIFY]
    assert len(basic) == 2  # once each: the first poll's STATIC plan, not identification
    assert all(r.snap().available.values())
    await stop(r)


async def test_address_conflict_forgets_the_cached_short() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    gen = await discovered(r)
    old = gen.join.own_short
    r.inst.network.address_conflict()
    await run_until(r.clock, lambda: r.bridge.export_cache().own_short is None, limit=60)
    assert r.caches[-1].own_short is None
    gen2 = await ready_again(r, gen.number)
    assert gen2.join.own_short != old
    assert r.bridge.export_cache().own_short == gen2.join.own_short
    assert r.conn.node_config.preferred_short is None  # cleared by the conflict, never re-set
    await stop(r)


async def test_detach_removes_listeners() -> None:
    r = make_rig(n_valves=1, behind_router=0)
    await discovered(r)
    r.detach()
    r.detach()  # idempotent
    count = len(r.updates)
    sim = r.inst.valves[0]
    sim.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_LOCAL_TEMPERATURE, ZclDataType.INT16, 2300)
    sim.report(vt.CL_THERMOSTAT, (vt.ATTR_LOCAL_TEMPERATURE,))
    await r.clock.advance(0)
    assert len(r.updates) == count
    await stop(r)


async def test_callback_errors_are_logged_and_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    from vicare_local_ble.bridge import ViCareBridge
    from vicare_local_ble.testing.scenario import default_installation
    from vicare_local_ble.zigbee_direct.connection import ZdConnection

    inst = default_installation(n_valves=1, behind_router=0)
    conn = ZdConnection(
        inst.resolver,
        own_eui=inst.zvd_eui,
        network_key=inst.network_key,
        clock=inst.clock,
        connector=inst.connector,
    )

    def boom(_arg: object) -> None:
        raise RuntimeError("callback bug")

    bridge = ViCareBridge(
        conn, clock=inst.clock, on_update=boom, on_new_valve=boom, on_cache_changed=boom
    )
    bridge.attach()
    await inst.clock.run_task(conn.start())
    await run_until(inst.clock, lambda: valve_eui(0) in bridge.snapshot().valves)
    await inst.clock.advance(120)
    for name in ("on_update", "on_new_valve", "on_cache_changed"):
        assert f"{name} callback raised" in caplog.text
    assert any(r.name == LOGGER for r in caplog.records)
    await inst.clock.run_task(conn.stop())
