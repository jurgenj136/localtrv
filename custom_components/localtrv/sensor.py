"""Sensors: per-valve battery, heating demand, LQI, RSSI; R0 connection state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, SIGNAL_STRENGTH_DECIBELS_MILLIWATT, EntityCategory
from homeassistant.core import callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from localtrv.zigbee_direct.connection import ConnectionState

from .const import signal_new_valve
from .entity import VicareBridgeEntity, VicareValveEntity

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from localtrv.valves import Valve, ValveState
    from localtrv.zigbee_direct.types import Eui64

    from .coordinator import VicareConfigEntry, VicareCoordinator

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class VicareSensorDescription(SensorEntityDescription):
    value_fn: Callable[[ValveState], float | int | None]


VALVE_SENSORS: tuple[VicareSensorDescription, ...] = (
    VicareSensorDescription(
        key="battery",
        translation_key="battery",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.battery_pct,
    ),
    VicareSensorDescription(
        key="heating_demand",
        translation_key="heating_demand",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda s: s.heating_demand,
    ),
    VicareSensorDescription(
        key="lqi",
        translation_key="lqi",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda s: s.lqi,
    ),
    VicareSensorDescription(
        key="rssi",
        translation_key="rssi",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda s: s.rssi,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: VicareConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    async_add_entities([VicareConnectionStateSensor(coordinator)])
    added: set[Eui64] = set()

    @callback
    def add_valve(valve: Valve) -> None:
        if valve.eui not in added:
            added.add(valve.eui)
            async_add_entities(
                VicareValveSensor(coordinator, valve, description) for description in VALVE_SENSORS
            )

    entry.async_on_unload(
        async_dispatcher_connect(hass, signal_new_valve(entry.entry_id), add_valve)
    )
    for valve in coordinator.bridge.snapshot().valves.values():
        add_valve(valve)


class VicareValveSensor(VicareValveEntity, SensorEntity):
    entity_description: VicareSensorDescription

    def __init__(
        self, coordinator: VicareCoordinator, valve: Valve, description: VicareSensorDescription
    ) -> None:
        super().__init__(coordinator, valve, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> float | int | None:
        state = self.valve_state
        return None if state is None else self.entity_description.value_fn(state)


class VicareConnectionStateSensor(VicareBridgeEntity, SensorEntity):
    """The R0 connection state as an enum sensor; updates on every state push."""

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: VicareCoordinator) -> None:
        super().__init__(coordinator, "connection_state")
        self._attr_options = [state.value for state in ConnectionState]

    @property
    def available(self) -> bool:
        return True

    @property
    def native_value(self) -> str:
        return self.coordinator.data.connection_state.value
