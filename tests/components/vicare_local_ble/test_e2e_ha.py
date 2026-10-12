"""End to end through Home Assistant: spec §3 edge table, HA-level rows (T18).

The row -> test map is in ``tests/test_e2e_sim.py``. Integration + library + simulator, library
time virtual (``Sim`` harness in ``conftest.py``).
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from custom_components.vicare_local_ble.const import (
    CONF_NETWORK_KEY,
    DOMAIN,
    STOP_TIMEOUT,
    issue_id,
    storage_key,
)
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import issue_registry as ir

from bluetooth_helpers import (
    UBISYS_SERVICE_UUID,
    inject_bluetooth_service_info,
    make_service_info,
)
from conftest import our_tasks
from test_climate import entity_id, loaded
from vicare_local_ble.bridge import BridgeCache
from vicare_local_ble.testing.gatt_client import FakeBleakClient
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.connection import (
    DISCONNECT_TIMEOUT,
    ConnectionIssue,
    ConnectionState,
)
from vicare_local_ble.zigbee_direct.types import Eui64

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from conftest import Sim

ADDRESS = "aabbcc001122"
WRONG_KEY = "99" * 16  # dummy
NEW_EUI = Eui64.from_str("02:00:00:00:00:01:00:0A")
READY = ConnectionState.READY


def _issue(hass: HomeAssistant, sim: Sim, issue: ConnectionIssue) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue(DOMAIN, issue_id(issue.value, sim.entry.entry_id))


def _entry_state(sim: Sim) -> ConfigEntryState:
    return sim.entry.state  # type: ignore[no-any-return]


def _state(hass: HomeAssistant, eid: str) -> str:
    state = hass.states.get(eid)
    assert state is not None, eid
    return state.state


async def test_r0_absent_at_startup_not_ready(hass: HomeAssistant, sim: Sim) -> None:
    seen = sim.device
    sim.device = lambda: None
    assert not await sim.setup()
    assert sim.entry.state is ConfigEntryState.SETUP_RETRY
    assert sim.entry.reason is not None
    assert sim.inst.r0.connect_count == 0
    assert our_tasks() == []
    sim.device = seen  # the R0 comes into range: HA's retry sets the entry up
    assert await sim.drive(hass.config_entries.async_reload(sim.entry.entry_id))
    assert _entry_state(sim) is ConfigEntryState.LOADED
    assert sim.runtime.connection.state is READY


async def test_r0_drops_bridge_entity_flips_at_once(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    connectivity = entity_id(hass, "binary_sensor", None, "connection", address=ADDRESS)
    state_sensor = entity_id(hass, "sensor", None, "connection_state", address=ADDRESS)
    climate = entity_id(hass, "climate", sim.inst.valves[0].eui, "thermostat")
    connection = sim.runtime.connection
    gen = connection.current
    assert gen is not None
    assert _state(hass, connectivity) == "on"
    sim.inst.r0.disconnect()
    await sim.drive_until(lambda: connection.state is not READY)
    await hass.async_block_till_done()
    assert _state(hass, connectivity) == "off"  # pushed with the state change, no poll
    assert _state(hass, state_sensor) in {"backoff", "connecting", "joining"}
    assert _state(hass, climate) != "unavailable"  # one outage is not three misses
    snap = await sim.drive(coordinator.bridge.poll())  # a scheduled poll during the outage
    assert all(m == 1 for m in snap.misses.values())
    await sim.drive_until(
        lambda: connection.current is not None and connection.current.number > gen.number
    )
    await hass.async_block_till_done()
    assert _state(hass, connectivity) == "on"
    assert _state(hass, state_sensor) == "ready"
    snap = await sim.drive(coordinator.bridge.poll())
    assert all(m == 0 for m in snap.misses.values())


async def test_two_adapters_one_entry_one_connection(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    connection = sim.runtime.connection
    seen: list[None] = []
    real = connection.notify_seen

    def counting() -> None:
        seen.append(None)
        real()

    with patch.object(connection, "notify_seen", counting):
        for source in ("hci0", "proxy-b"):  # the same R0 heard by two adapters
            info = make_service_info(service_uuids=[UBISYS_SERVICE_UUID], source=source)
            inject_bluetooth_service_info(hass, info)
            await hass.async_block_till_done()
    assert seen  # each advert shortens a backoff wait of the one connection
    assert hass.config_entries.flow.async_progress_by_handler(DOMAIN) == []
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1
    assert sim.inst.r0.connect_count == 1  # one ZdConnection, one BLE connection
    assert connection.current is not None
    assert connection.current.number == 1


async def test_wrong_key_reauth_and_supervisor_stops(hass: HomeAssistant, sim: Sim) -> None:
    hass.config_entries.async_update_entry(
        sim.entry, data={**sim.entry.data, CONF_NETWORK_KEY: WRONG_KEY}
    )
    assert not await sim.setup()
    assert sim.entry.state is ConfigEntryState.SETUP_ERROR
    await hass.async_block_till_done()
    flows = [
        f
        for f in hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        if f["context"]["source"] == SOURCE_REAUTH
    ]
    assert len(flows) == 1
    assert sim.inst.r0.connect_count == 2
    await sim.clock.advance(6 * 3600)
    assert sim.inst.r0.connect_count == 2  # the supervisor stopped
    assert our_tasks() == []


async def test_small_mtu_repair_issue(hass: HomeAssistant, sim: Sim) -> None:
    sim.inst.r0.mtu_size = 100
    coordinator = await loaded(sim)  # not fatal: valves still work
    issue = _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL)
    assert issue is not None
    assert issue.translation_key == "mtu_too_small"
    assert all(coordinator.data.available.values())


async def test_oversized_write_repair_issue(hass: HomeAssistant, sim: Sim) -> None:
    sim.inst.r0.mtu_size = 200
    sim.inst.r0.long_write_supported = False
    await loaded(sim)
    connection = sim.runtime.connection
    gen = connection.current
    assert gen is not None
    created: list[bool] = []
    connection.add_issue_listener(
        lambda issue, active: (
            created.append(active) if issue is ConnectionIssue.LONG_WRITE_UNSUPPORTED else None
        )
    )

    async def large_read() -> None:  # a frame > MTU - 3
        await gen.node.zcl_read(sim.inst.valves[0].short, 1, 0x0201, list(range(100)))

    connection.spawn(gen, large_read(), name="large read")
    await sim.drive_until(lambda: created == [True])
    assert _issue(hass, sim, ConnectionIssue.LONG_WRITE_UNSUPPORTED) is not None
    await sim.drive_until(lambda: connection.state is READY)  # reconnected
    assert connection.current is not None
    assert connection.current.number == gen.number + 1
    assert sim.entry.state is ConfigEntryState.LOADED


async def test_new_valve_gets_entities(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    new = SimValve(sim.clock, eui=NEW_EUI, short=0x2C2C, rng=random.Random(9))  # noqa: S311
    registry = er.async_get(hass)
    sim.inst.network.add_valve_later(new)
    await sim.drive_until(lambda: NEW_EUI in coordinator.data.valves)
    await hass.async_block_till_done()
    climate = entity_id(hass, "climate", NEW_EUI, "thermostat")
    await sim.drive(coordinator.bridge.poll())
    await hass.async_block_till_done()
    assert _state(hass, climate) == "heat"
    entry = registry.async_get(climate)
    assert entry is not None
    assert entry.config_entry_id == sim.entry.entry_id


async def test_unload_and_stop_bounded_cache_saved(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any]
) -> None:
    coordinator = await loaded(sim)
    connection = sim.runtime.connection
    gen = connection.current
    assert gen is not None

    async def hang(_self: FakeBleakClient) -> None:
        await sim.clock.sleep(10 * STOP_TIMEOUT)  # the proxy never confirms the disconnect

    started = sim.clock.now()
    with patch.object(FakeBleakClient, "disconnect", hang):
        assert await sim.unload()
    elapsed = sim.clock.now() - started
    assert DISCONNECT_TIMEOUT <= elapsed <= STOP_TIMEOUT  # the hang was hit, and bounded
    assert connection.state is ConnectionState.STOPPED
    await hass.async_block_till_done()
    assert our_tasks() == []
    raw = hass_storage.get(storage_key(sim.entry.entry_id))
    assert raw is not None
    stored = BridgeCache.from_json(raw["data"])
    assert set(stored.valves) == {str(e) for e in coordinator.data.valves}
    assert stored.own_short == gen.join.own_short
