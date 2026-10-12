"""Climate platform: one heat-only thermostat per valve (spec §2.5).

Override semantics (evidence-backed, research of 2026-10-11): a Zigbee Direct setpoint write
behaves exactly like turning the valve wheel by hand. The ViCare app then shows the room as
"manually set, for 2 hours". The 2 h duration is OPTO2/cloud logic, not a valve feature: the
thermostat cluster has no hold or duration attribute. After 2 h, or at the next schedule
transition, the OPTO2 pushes the schedule setpoint again (last writer wins). The manual state
cannot be cancelled over Zigbee, only in the app or by expiry.

Setting the temperature: validate (finite, inside the valve limits) -> the bridge records the
request and pushes it (optimistic UI) -> the call returns at the valve's write
acknowledgement -> the confirming read runs in the background and updates the state.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import ClimateEntityFeature, HVACMode
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from vicare_local_ble import valves
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, ZclStatusError

from .const import DOMAIN, signal_new_valve
from .entity import VicareValveEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from vicare_local_ble.valves import Valve
    from vicare_local_ble.zigbee_direct.types import Eui64

    from .coordinator import VicareConfigEntry, VicareCoordinator

# The coordinator pushes; entities never poll.
PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: VicareConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    added: set[Eui64] = set()

    @callback
    def add_valve(valve: Valve) -> None:
        if valve.eui not in added:
            added.add(valve.eui)
            async_add_entities([VicareClimate(coordinator, valve)])

    entry.async_on_unload(
        async_dispatcher_connect(hass, signal_new_valve(entry.entry_id), add_valve)
    )
    for valve in coordinator.bridge.snapshot().valves.values():
        add_valve(valve)


class VicareClimate(VicareValveEntity, ClimateEntity):
    """Heat-only thermostat. ``systemMode`` (9 "sleep" is normal) is not exposed; no
    ``hvac_action`` in v1."""

    _attr_name = None
    _attr_hvac_mode = HVACMode.HEAT
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_target_temperature_step = valves.SETPOINT_STEP_C

    def __init__(self, coordinator: VicareCoordinator, valve: Valve) -> None:
        super().__init__(coordinator, valve, "thermostat")
        self._attr_hvac_modes = [HVACMode.HEAT]

    @property
    def _limits(self) -> valves.SetpointLimits:
        valve = self.valve
        return valve.limits if valve is not None else valves.DEFAULT_LIMITS

    @property
    def min_temp(self) -> float:
        return self._limits.min_c

    @property
    def max_temp(self) -> float:
        return self._limits.max_c

    @property
    def current_temperature(self) -> float | None:
        state = self.valve_state
        return None if state is None else state.local_temperature_c

    @property
    def target_temperature(self) -> float | None:
        """The pending request, else the confirmed or polled setpoint, whichever is newer."""
        status = self.coordinator.data.setpoints.get(self.eui)
        if status is not None and status.pending and status.requested_c is not None:
            return status.requested_c
        state = self.valve_state
        polled = None if state is None else state.setpoint_c
        if (
            status is not None
            and status.confirmed_c is not None
            and (
                polled is None
                or state is None
                or state.updated_at is None
                or status.confirmed_at is None
                or status.confirmed_at >= state.updated_at
            )
        ):
            return status.confirmed_c
        return polled

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        status = self.coordinator.data.setpoints.get(self.eui)
        if status is None:
            return {}
        return {
            "setpoint_pending": status.pending,
            "setpoint_acknowledged": status.acknowledged_c,
            "setpoint_confirmed": status.confirmed_c,
        }

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        if hvac_mode is not HVACMode.HEAT:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="invalid_hvac_mode",
                translation_placeholders={"mode": str(hvac_mode)},
            )

    async def async_set_temperature(self, **kwargs: Any) -> None:
        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            return
        limits = self._limits
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, int | float)
            or not math.isfinite(temperature)
            or not limits.min_c <= temperature <= limits.max_c
        ):
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="invalid_temperature",
                translation_placeholders={
                    "temperature": str(temperature),
                    "min": str(limits.min_c),
                    "max": str(limits.max_c),
                },
            )
        try:
            await self.coordinator.bridge.set_setpoint(self.eui, float(temperature))
        except (ZclStatusError, TimeoutError, ConnectionLostError) as err:
            # The bridge already reverted its request and pushed the previous target.
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="write_failed",
                translation_placeholders={"valve": self.entity_id},
            ) from err
