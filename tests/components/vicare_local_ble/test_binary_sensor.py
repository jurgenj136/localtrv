"""Binary sensors: window_open (experimental), bridge connection."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from custom_components.vicare_local_ble.binary_sensor import VicareWindowOpen
from custom_components.vicare_local_ble.const import DOMAIN
from custom_components.vicare_local_ble.entity import eui_hex
from homeassistant.components.binary_sensor.const import BinarySensorDeviceClass
from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler

from test_climate import entity_id, loaded
from vicare_local_ble import valves
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.connection import ConnectionState
from vicare_local_ble.zigbee_direct.types import Eui64

if TYPE_CHECKING:
    from custom_components.vicare_local_ble.coordinator import VicareCoordinator
    from homeassistant.core import HomeAssistant

    from conftest import Sim

ADDRESS = "aabbcc001122"


async def _poll_slow(sim: Sim, coordinator: VicareCoordinator) -> None:
    """Window state is read by the SLOW plan, which runs every n-th poll."""
    for _ in range(valves.SLOW_EVERY_N_POLLS):
        await sim.drive(coordinator.bridge.poll())


async def test_window_open_disabled_by_default_and_experimental(
    hass: HomeAssistant, sim: Sim
) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    eid = entity_id(hass, "binary_sensor", valve.eui, "window_open")
    entry = er.async_get(hass).async_get(eid)
    assert entry is not None
    assert entry.disabled_by is RegistryEntryDisabler.INTEGRATION
    assert entry.translation_key == "window_open"
    assert hass.states.get(eid) is None
    entity = VicareWindowOpen(coordinator, coordinator.data.valves[valve.eui])
    assert entity.device_class is BinarySensorDeviceClass.WINDOW
    assert not entity.entity_registry_enabled_default
    assert entity.is_on is False  # raw 1 = closed
    valve.set_attribute(vt.CL_THERMOSTAT, 0x4000, ZclDataType.ENUM8, 3, manufacturer=vt.MFR_CODE)
    await _poll_slow(sim, coordinator)
    assert entity.is_on is True
    valve.set_attribute(vt.CL_THERMOSTAT, 0x4000, ZclDataType.ENUM8, 99, manufacturer=vt.MFR_CODE)
    await _poll_slow(sim, coordinator)
    assert entity.is_on is None  # an unknown raw value never invents a state


async def test_bridge_connection_entity_on_r0_device(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    eid = entity_id(hass, "binary_sensor", None, "connection", address=ADDRESS)
    state = hass.states.get(eid)
    assert state is not None
    assert state.state == "on"
    assert state.attributes["device_class"] == BinarySensorDeviceClass.CONNECTIVITY
    entry = er.async_get(hass).async_get(eid)
    assert entry is not None
    assert entry.entity_category is EntityCategory.DIAGNOSTIC
    assert entry.disabled_by is None
    device = dr.async_get(hass).async_get(entry.device_id or "")
    assert isinstance(device, dr.DeviceEntry)
    assert device.identifiers == {(DOMAIN, sim.entry.data["address"])}
    assert device.model == "R0"
    # the valves hang below it
    valve_device = dr.async_get(hass).async_get_device_by_identifier(
        (DOMAIN, eui_hex(sim.inst.valves[0].eui)), sim.entry.entry_id
    )
    assert valve_device is not None
    assert valve_device.via_device_id == device.id


async def test_connection_entity_flips_immediately_on_state_change(
    hass: HomeAssistant, sim: Sim
) -> None:
    coordinator = await loaded(sim)
    eid = entity_id(hass, "binary_sensor", None, "connection", address=ADDRESS)
    connection = sim.runtime.connection
    assert hass.states.get(eid).state == "on"  # type: ignore[union-attr]
    connection.request_rejoin(connection.current, "test")  # type: ignore[arg-type]
    await sim.drive_until(lambda: connection.state is not ConnectionState.READY)
    await hass.async_block_till_done()
    # pushed with the state change, no poll in between
    assert coordinator.data.connection_state is connection.state
    assert hass.states.get(eid).state == "off"  # type: ignore[union-attr]
    await sim.drive_until(lambda: connection.state is ConnectionState.READY)
    await hass.async_block_till_done()
    assert hass.states.get(eid).state == "on"  # type: ignore[union-attr]


async def test_new_valve_adds_window_open_entity(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    registry = er.async_get(hass)
    new = SimValve(
        sim.clock,
        eui=Eui64.from_str("02:00:00:00:00:01:00:09"),
        short=0x2B2B,
        rng=random.Random(5),  # noqa: S311
    )
    unique = f"{eui_hex(new.eui)}_window_open"
    sim.inst.network.add_valve_later(new)
    await sim.drive_until(
        lambda: registry.async_get_entity_id("binary_sensor", DOMAIN, unique) is not None
    )
