"""Sensor platform (spec §2.5, §6 T17): values, units, classes, defaults, dynamic add."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from custom_components.vicare_local_ble.const import DOMAIN
from custom_components.vicare_local_ble.entity import eui_hex
from custom_components.vicare_local_ble.sensor import VicareValveSensor
from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
from homeassistant.const import EntityCategory
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler

from test_climate import entity_id, loaded
from vicare_local_ble import valves
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.connection import ConnectionState
from vicare_local_ble.zigbee_direct.types import Eui64

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from conftest import Sim

ADDRESS = "aabbcc001122"


async def test_enabled_sensor_values_units_classes(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    registry = er.async_get(hass)
    for valve in sim.inst.valves:
        battery = hass.states.get(entity_id(hass, "sensor", valve.eui, "battery"))
        assert battery is not None
        assert battery.state == "63.0"
        assert battery.attributes["unit_of_measurement"] == "%"
        assert battery.attributes["device_class"] == SensorDeviceClass.BATTERY
        assert battery.attributes["state_class"] == SensorStateClass.MEASUREMENT
        entry = registry.async_get(battery.entity_id)
        assert entry is not None
        assert entry.entity_category is EntityCategory.DIAGNOSTIC
        assert entry.disabled_by is None

        demand = hass.states.get(entity_id(hass, "sensor", valve.eui, "heating_demand"))
        assert demand is not None
        assert demand.state == "2"  # raw 0-5, not percent
        assert "unit_of_measurement" not in demand.attributes
        assert "device_class" not in demand.attributes
        assert demand.attributes["state_class"] == SensorStateClass.MEASUREMENT
        entry = registry.async_get(demand.entity_id)
        assert entry is not None
        assert entry.entity_category is None
        assert entry.disabled_by is None


async def test_lqi_and_rssi_disabled_by_default(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    registry = er.async_get(hass)
    valve = sim.inst.valves[0]
    for key in ("lqi", "rssi"):
        eid = entity_id(hass, "sensor", valve.eui, key)
        entry = registry.async_get(eid)
        assert entry is not None
        assert entry.disabled_by is RegistryEntryDisabler.INTEGRATION
        assert entry.entity_category is EntityCategory.DIAGNOSTIC
        assert hass.states.get(eid) is None
    # Values, units and classes of the disabled entities, straight from the entity classes.
    from custom_components.vicare_local_ble.sensor import VALVE_SENSORS

    by_key = {d.key: d for d in VALVE_SENSORS}
    info = coordinator.data.valves[valve.eui]
    lqi = VicareValveSensor(coordinator, info, by_key["lqi"])
    rssi = VicareValveSensor(coordinator, info, by_key["rssi"])
    assert lqi.native_value == 180
    assert lqi.native_unit_of_measurement is None
    assert lqi.device_class is None
    assert rssi.native_value == -60
    assert rssi.native_unit_of_measurement == "dBm"
    assert rssi.device_class is SensorDeviceClass.SIGNAL_STRENGTH
    assert not lqi.entity_registry_enabled_default
    assert not rssi.entity_registry_enabled_default


async def test_sensor_follows_reports(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    eid = entity_id(hass, "sensor", valve.eui, "heating_demand")
    from vicare_local_ble.testing import valve_table as vt
    from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType

    valve.set_attribute(vt.CL_THERMOSTAT, 0x0008, ZclDataType.UINT8, 4)
    await sim.drive(coordinator.bridge.poll())
    state = hass.states.get(eid)
    assert state is not None
    assert state.state == "4"


async def test_bridge_connection_state_sensor(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    eid = entity_id(hass, "sensor", None, "connection_state", address=ADDRESS)
    state = hass.states.get(eid)
    assert state is not None
    assert state.state == "ready"
    assert state.attributes["device_class"] == SensorDeviceClass.ENUM
    assert state.attributes["options"] == [s.value for s in ConnectionState]
    entry = er.async_get(hass).async_get(eid)
    assert entry is not None
    assert entry.entity_category is EntityCategory.DIAGNOSTIC
    assert entry.translation_key == "connection_state"
    # it sits on the R0 device, not on a valve
    from homeassistant.helpers import device_registry as dr

    device = dr.async_get(hass).async_get(entry.device_id or "")
    assert device is not None
    assert (DOMAIN, sim.entry.data["address"]) in device.identifiers

    connection = sim.runtime.connection
    connection.request_rejoin(connection.current, "test")  # type: ignore[arg-type]
    await sim.drive_until(lambda: (hass.states.get(eid) or state).state != "ready")
    assert hass.states.get(eid).state in {"connecting", "backoff", "joining", "idle"}  # type: ignore[union-attr]
    await sim.drive_until(lambda: hass.states.get(eid).state == "ready")  # type: ignore[union-attr]


async def test_new_valve_adds_sensors_once(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    new = SimValve(
        sim.clock,
        eui=Eui64.from_str("02:00:00:00:00:01:00:09"),
        short=0x2B2B,
        rng=random.Random(5),  # noqa: S311
    )
    registry = er.async_get(hass)
    unique = f"{eui_hex(new.eui)}_battery"
    assert registry.async_get_entity_id("sensor", DOMAIN, unique) is None
    sim.inst.network.add_valve_later(new)
    await sim.drive_until(
        lambda: registry.async_get_entity_id("sensor", DOMAIN, unique) is not None
    )
    eid = entity_id(hass, "sensor", new.eui, "battery")
    for _ in range(valves.SLOW_EVERY_N_POLLS):  # battery is in the SLOW plan
        await sim.drive(sim.runtime.coordinator.bridge.poll())
    await hass.async_block_till_done()
    state = hass.states.get(eid)
    assert state is not None
    assert state.state == "63.0"
    sensors = [
        e
        for e in registry.entities.values()
        if e.platform == DOMAIN
        and e.domain == "sensor"
        and e.unique_id.startswith(eui_hex(new.eui))
    ]
    assert sorted(e.translation_key or "" for e in sensors) == [
        "battery",
        "heating_demand",
        "lqi",
        "rssi",
    ]
