"""Entity base classes (spec §2.5); the platforms (T17) build on these."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from vicare_local_ble import valves

from .const import BRIDGE_MANUFACTURER, BRIDGE_MODEL, DOMAIN
from .coordinator import VicareCoordinator

if TYPE_CHECKING:
    from vicare_local_ble.valves import Valve, ValveState
    from vicare_local_ble.zigbee_direct.types import Eui64


def eui_hex(eui: Eui64) -> str:
    """Stable id form of an EUI: 16 lowercase hex digits, display (big-endian) order."""
    return f"{eui.as_int():016x}"


def bridge_device_info(address: str, name: str) -> DeviceInfo:
    """Device of the R0 itself; valves hang below it via ``via_device``."""
    return DeviceInfo(
        identifiers={(DOMAIN, address)},
        connections={(CONNECTION_BLUETOOTH, address)},
        manufacturer=BRIDGE_MANUFACTURER,
        model=BRIDGE_MODEL,
        name=name,
    )


def valve_device_info(valve: Valve, bridge_device_id: str | None) -> DeviceInfo:
    """Valve device, linked to the R0 device by its registry id (HA 2026.10 deprecates the
    ``via_device`` identifier tuple in favour of ``via_device_id``)."""
    info = DeviceInfo(
        identifiers={(DOMAIN, eui_hex(valve.eui))},
        name=f"ViCare valve {str(valve.eui)[-5:]}",
        manufacturer=valves.MANUFACTURER,
        model=valves.MODEL_NAME,
        model_id=valve.model,
        sw_version=valve.sw_build,
    )
    if bridge_device_id is not None:
        info["via_device_id"] = bridge_device_id
    return info


class VicareBridgeEntity(CoordinatorEntity[VicareCoordinator]):
    """An entity of the R0 device (connection state, connectivity)."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: VicareCoordinator, key: str) -> None:
        super().__init__(coordinator)
        address = coordinator.address
        self._attr_translation_key = key
        self._attr_unique_id = f"{address.replace(':', '').lower()}_{key}"
        self._attr_device_info = bridge_device_info(address, coordinator.config_entry.title)


class VicareValveEntity(CoordinatorEntity[VicareCoordinator]):
    """An entity of one valve. ``unique_id = f"{eui_hex}_{key}"``.

    Available while the coordinator is and the snapshot marks the valve available (it turns
    unavailable after ``MISSES_UNAVAILABLE`` missed polls; cached valves start unavailable).
    """

    _attr_has_entity_name = True

    def __init__(self, coordinator: VicareCoordinator, valve: Valve, key: str) -> None:
        super().__init__(coordinator)
        self.eui = valve.eui
        self._attr_translation_key = key
        self._attr_unique_id = f"{eui_hex(valve.eui)}_{key}"
        self._attr_device_info = valve_device_info(valve, coordinator.bridge_device_id)

    @property
    def valve(self) -> Valve | None:
        return self.coordinator.data.valves.get(self.eui)

    @property
    def valve_state(self) -> ValveState | None:
        return self.coordinator.data.states.get(self.eui)

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data.available.get(self.eui, False)
