"""Binary sensors: valve window detection (experimental) and the R0 connection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.components.binary_sensor.const import BinarySensorDeviceClass
from homeassistant.const import EntityCategory
from homeassistant.core import callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from vicare_local_ble import valves
from vicare_local_ble.zigbee_direct.connection import ConnectionState

from .const import signal_new_valve
from .entity import VicareBridgeEntity, VicareValveEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from vicare_local_ble.valves import Valve
    from vicare_local_ble.zigbee_direct.types import Eui64

    from .coordinator import VicareConfigEntry, VicareCoordinator

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: VicareConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    async_add_entities([VicareConnectionSensor(coordinator)])
    added: set[Eui64] = set()

    @callback
    def add_valve(valve: Valve) -> None:
        if valve.eui not in added:
            added.add(valve.eui)
            async_add_entities([VicareWindowOpen(coordinator, valve)])

    entry.async_on_unload(
        async_dispatcher_connect(hass, signal_new_valve(entry.entry_id), add_valve)
    )
    for valve in coordinator.bridge.snapshot().valves.values():
        add_valve(valve)


class VicareWindowOpen(VicareValveEntity, BinarySensorEntity):
    """Window detection; the raw-value mapping is a hypothesis, hence experimental."""

    _attr_device_class = BinarySensorDeviceClass.WINDOW
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: VicareCoordinator, valve: Valve) -> None:
        super().__init__(coordinator, valve, "window_open")

    @property
    def is_on(self) -> bool | None:
        state = self.valve_state
        return None if state is None else valves.window_open(state.window_open_raw)


class VicareConnectionSensor(VicareBridgeEntity, BinarySensorEntity):
    """On while the R0 connection is READY; flips on every connection state push."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: VicareCoordinator) -> None:
        super().__init__(coordinator, "connection")

    @property
    def available(self) -> bool:
        return True  # it reports the connection itself, also when polling fails

    @property
    def is_on(self) -> bool:
        return self.coordinator.data.connection_state is ConnectionState.READY
