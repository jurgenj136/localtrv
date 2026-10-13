"""Climate platform (spec §2.5, §6 T17), through the simulator."""

from __future__ import annotations

import asyncio
import math
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from custom_components.vicare_local_ble.const import DOMAIN
from custom_components.vicare_local_ble.entity import eui_hex
from homeassistant.components.climate.const import (
    ATTR_HVAC_MODES,
    ATTR_MAX_TEMP,
    ATTR_MIN_TEMP,
    ATTR_TARGET_TEMP_STEP,
    HVACAction,
    HVACMode,
)
from homeassistant.const import ATTR_ENTITY_ID, ATTR_TEMPERATURE
from homeassistant.core import Event, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.event import EventStateChangedData, async_track_state_change_event

from conftest import our_tasks
from vicare_local_ble import valves
from vicare_local_ble.bridge import ViCareBridge
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.zigbee_direct.codec.zcl import ZclCommandId, ZclStatus
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.errors import RouteError, SequenceExhaustedError
from vicare_local_ble.zigbee_direct.routing import NWK_STATUS_NON_TREE_LINK_FAILURE

if TYPE_CHECKING:
    from custom_components.vicare_local_ble.coordinator import VicareCoordinator
    from homeassistant.core import HomeAssistant, State

    from conftest import Sim
    from vicare_local_ble.bridge import SetpointStatus
    from vicare_local_ble.zigbee_direct.types import Eui64


async def loaded(sim: Sim) -> VicareCoordinator:
    """Set up and let discovery plus the bridge's own initial poll finish."""
    assert await sim.setup()
    coordinator = sim.runtime.coordinator
    euis = {v.eui for v in sim.inst.valves}

    def settled() -> bool:
        data = coordinator.data
        polled = all(data.available.get(e) and data.states[e].updated_at for e in euis)
        return polled and not any("initial poll" in t.get_name() for t in our_tasks())

    await sim.drive_until(settled)
    await sim.hass.async_block_till_done()
    return coordinator


def entity_id(
    hass: HomeAssistant, domain: str, eui: Eui64 | None, key: str, *, address: str = ""
) -> str:
    """Entity id by unique id (valve: ``{eui}_{key}``, bridge: ``{address}_{key}``)."""
    unique_id = f"{eui_hex(eui)}_{key}" if eui is not None else f"{address}_{key}"
    found = er.async_get(hass).async_get_entity_id(domain, DOMAIN, unique_id)
    assert found is not None, unique_id
    return found


def status(coordinator: VicareCoordinator, eui: Eui64) -> SetpointStatus:
    return coordinator.data.setpoints[eui]


async def _set(hass: HomeAssistant, entity: str, temperature: float) -> None:
    await hass.services.async_call(
        "climate",
        "set_temperature",
        {ATTR_ENTITY_ID: entity, ATTR_TEMPERATURE: temperature},
        blocking=True,
    )


def _state(hass: HomeAssistant, entity: str) -> State:
    state = hass.states.get(entity)
    assert state is not None
    return state


async def test_heat_only_with_limits_and_step(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    for valve in sim.inst.valves:
        state = _state(hass, entity_id(hass, "climate", valve.eui, "thermostat"))
        assert state.state == HVACMode.HEAT
        assert state.attributes[ATTR_HVAC_MODES] == [HVACMode.HEAT]
        assert state.attributes[ATTR_MIN_TEMP] == 8.0
        assert state.attributes[ATTR_MAX_TEMP] == 30.0
        assert state.attributes[ATTR_TARGET_TEMP_STEP] == valves.SETPOINT_STEP_C == 0.5
        assert state.attributes["current_temperature"] == 19.6  # shown to 0.1
        assert state.attributes[ATTR_TEMPERATURE] == 22.0
        assert state.attributes["hvac_action"] == HVACAction.HEATING  # simulator demand 2
        assert state.attributes["supported_features"] == 1  # TARGET_TEMPERATURE


async def test_limits_from_valve_and_fallback(hass: HomeAssistant, sim: Sim) -> None:
    narrow, fallback = sim.inst.valves
    narrow.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MIN_LIMIT, ZclDataType.INT16, 1000)
    narrow.set_attribute(vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, ZclDataType.INT16, 2600)
    # Invalid limits and invalid absolute limits: the library default applies.
    for attr, raw in ((vt.ATTR_MIN_LIMIT, 2500), (vt.ATTR_MAX_LIMIT, 1000)):
        fallback.set_attribute(vt.CL_THERMOSTAT, attr, ZclDataType.INT16, raw)
    for attr, raw in ((vt.ATTR_ABS_MIN, 2500), (vt.ATTR_ABS_MAX, 1000)):
        fallback.set_attribute(vt.CL_THERMOSTAT, attr, ZclDataType.INT16, raw)
    await loaded(sim)
    state = _state(hass, entity_id(hass, "climate", narrow.eui, "thermostat"))
    assert (state.attributes[ATTR_MIN_TEMP], state.attributes[ATTR_MAX_TEMP]) == (10.0, 26.0)
    state = _state(hass, entity_id(hass, "climate", fallback.eui, "thermostat"))
    assert (state.attributes[ATTR_MIN_TEMP], state.attributes[ATTR_MAX_TEMP]) == (
        valves.DEFAULT_LIMITS.min_c,
        valves.DEFAULT_LIMITS.max_c,
    )


async def test_set_temperature_optimistic_then_ack_then_confirm(
    hass: HomeAssistant, sim: Sim
) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 22.0

    call = asyncio.ensure_future(_set(hass, entity, 21.5))
    # 1. optimistic: the new target shows while the write is still in flight
    await sim.drive_until(lambda: _state(hass, entity).attributes[ATTR_TEMPERATURE] == 21.5)
    assert not call.done()
    assert status(coordinator, valve.eui).acknowledged_c is None
    assert valve.get_attribute(vt.CL_THERMOSTAT, vt.ATTR_SETPOINT) is not None
    # 2. the call returns at the acknowledgement, before the confirming read
    await sim.drive(call)
    after_ack = status(coordinator, valve.eui)
    assert after_ack.acknowledged_c == 21.5
    assert after_ack.confirmed_c is None
    assert after_ack.pending
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 21.5
    # 3. the background confirm updates the state
    await sim.drive_until(lambda: not status(coordinator, valve.eui).pending)
    done = status(coordinator, valve.eui)
    assert done.confirmed_c == 21.5
    assert coordinator.data.states[valve.eui].setpoint_c == 21.5
    state = _state(hass, entity)
    assert state.attributes[ATTR_TEMPERATURE] == 21.5
    assert state.attributes["setpoint_confirmed"] == 21.5
    assert state.attributes["setpoint_pending"] is False
    # the other valve is untouched
    other = _state(hass, entity_id(hass, "climate", sim.inst.valves[1].eui, "thermostat"))
    assert other.attributes[ATTR_TEMPERATURE] == 22.0


async def test_external_change_after_confirm_wins_when_newer(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    await sim.drive(_set(hass, entity, 21.5))
    await sim.drive_until(lambda: not status(coordinator, valve.eui).pending)
    valve.external_setpoint_change(18.0)  # the OPTO2 overwrites; the next poll sees it
    await sim.drive(coordinator.bridge.poll())
    assert coordinator.data.states[valve.eui].setpoint_c == 18.0
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 18.0


async def test_rejected_write_reverts_and_raises(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    valve.queue_default_response(ZclCommandId.WRITE_ATTRIBUTES, ZclStatus.INVALID_VALUE)
    call = asyncio.ensure_future(_set(hass, entity, 25.0))
    await sim.drive_until(lambda: _state(hass, entity).attributes[ATTR_TEMPERATURE] == 25.0)
    with pytest.raises(HomeAssistantError) as info:
        await sim.drive(call)
    assert not isinstance(info.value, ServiceValidationError)
    assert info.value.translation_key == "write_failed"
    assert info.value.translation_domain == DOMAIN
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 22.0
    assert not status(coordinator, valve.eui).pending


async def test_timeout_reverts_and_raises(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    valve.drop_rate = 1.0  # the valve never answers
    with pytest.raises(HomeAssistantError) as info:
        await sim.drive(_set(hass, entity, 24.0))
    assert info.value.translation_key == "write_failed"
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 22.0
    assert not status(coordinator, valve.eui).pending
    assert status(coordinator, valve.eui).requested_c is None


@pytest.mark.parametrize("failure", [RouteError(0x1234, 0x01), SequenceExhaustedError("full")])
async def test_route_and_sequence_failures_revert_and_raise(
    hass: HomeAssistant, sim: Sim, failure: Exception
) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    with (
        patch.object(ViCareBridge, "set_setpoint", AsyncMock(side_effect=failure)),
        pytest.raises(HomeAssistantError) as info,
    ):
        await sim.drive(_set(hass, entity, 24.0))
    assert not isinstance(info.value, ServiceValidationError)
    assert info.value.translation_key == "write_failed"
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 22.0
    assert not status(coordinator, valve.eui).pending


async def test_real_route_failure_shows_optimistic_then_reverts(
    hass: HomeAssistant, sim: Sim
) -> None:
    """Through the real bridge: a Network Status route error fails the in-flight write."""
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 22.0
    seen: list[float | None] = []

    @callback
    def record(_event: Event[EventStateChangedData]) -> None:
        seen.append(_state(hass, entity).attributes[ATTR_TEMPERATURE])

    unsub = async_track_state_change_event(hass, [entity], record)
    call = asyncio.ensure_future(_set(hass, entity, 25.0))
    await sim.drive_until(lambda: _state(hass, entity).attributes[ATTR_TEMPERATURE] == 25.0)
    assert not call.done()  # the optimistic target was visible while the write is in flight
    assert status(coordinator, valve.eui).requested_c == 25.0
    own_short = sim.runtime.bridge.snapshot().own_short
    assert own_short is not None
    sim.inst.network._status_later(own_short, NWK_STATUS_NON_TREE_LINK_FAILURE, about=valve.short)
    with pytest.raises(HomeAssistantError) as info:
        await sim.drive(call)
    unsub()
    assert not isinstance(info.value, ServiceValidationError)
    assert info.value.translation_key == "write_failed"
    assert isinstance(info.value.__cause__, RouteError)
    assert 25.0 in seen
    state = _state(hass, entity)
    assert state.attributes[ATTR_TEMPERATURE] == 22.0
    assert state.attributes["setpoint_pending"] is False
    assert status(coordinator, valve.eui).requested_c is None


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, 7.5, 30.5, 99.0])
async def test_invalid_temperature_is_rejected_and_nothing_written(
    hass: HomeAssistant, sim: Sim, value: float
) -> None:
    coordinator = await loaded(sim)
    valve = sim.inst.valves[0]
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    version = status(coordinator, valve.eui).version
    mark = len(sim.zcl_frames())
    with pytest.raises(ServiceValidationError):
        await sim.drive(_set(hass, entity, value))
    assert sim.zcl_frames()[mark:] == []
    assert valve.writes == ()
    assert status(coordinator, valve.eui).version == version
    assert _state(hass, entity).attributes[ATTR_TEMPERATURE] == 22.0


@pytest.mark.parametrize("value", [math.nan, math.inf, 7.5, 31.0])
async def test_entity_validates_itself(hass: HomeAssistant, sim: Sim, value: float) -> None:
    """Our own check (the service layer may reject first): translation and no write."""
    await loaded(sim)
    valve = sim.inst.valves[0]
    registry_id = entity_id(hass, "climate", valve.eui, "thermostat")
    component = hass.data["climate"]
    entity = component.get_entity(registry_id)
    with pytest.raises(ServiceValidationError) as info:
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: value})
    assert info.value.translation_key == "invalid_temperature"
    assert valve.writes == ()


async def test_set_hvac_mode(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    entity = entity_id(hass, "climate", sim.inst.valves[0].eui, "thermostat")
    await hass.services.async_call(
        "climate", "set_hvac_mode", {ATTR_ENTITY_ID: entity, "hvac_mode": "heat"}, blocking=True
    )
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(
            "climate", "set_hvac_mode", {ATTR_ENTITY_ID: entity, "hvac_mode": "off"}, blocking=True
        )


async def test_climate_unavailable_after_three_misses(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await loaded(sim)
    dead, alive = sim.inst.valves
    dead.drop_rate = 1.0
    dead_id = entity_id(hass, "climate", dead.eui, "thermostat")
    alive_id = entity_id(hass, "climate", alive.eui, "thermostat")
    for _ in range(2):
        await sim.drive(coordinator.bridge.poll())
    assert _state(hass, dead_id).state == HVACMode.HEAT  # two misses: still available
    await sim.drive(coordinator.bridge.poll())
    assert _state(hass, dead_id).state == "unavailable"
    assert "hvac_action" not in _state(hass, dead_id).attributes
    assert _state(hass, alive_id).state == HVACMode.HEAT
    dead.drop_rate = 0.0
    await sim.drive(coordinator.bridge.poll())
    assert _state(hass, dead_id).state == HVACMode.HEAT


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (0, HVACAction.IDLE),
        (1, HVACAction.HEATING),
        (7, HVACAction.HEATING),  # top of the 0-7 scale
        (8, None),  # above the scale: flagged demand_scale, action unknown
        (0xFF, None),  # sentinel: demand unknown
    ],
)
async def test_hvac_action_follows_heating_demand(
    hass: HomeAssistant, sim: Sim, raw: int, expected: HVACAction | None
) -> None:
    coordinator = await loaded(sim)
    valve, other = sim.inst.valves
    entity = entity_id(hass, "climate", valve.eui, "thermostat")
    valve.set_attribute(vt.CL_THERMOSTAT, valves.ATTR_PI_HEATING_DEMAND, ZclDataType.UINT8, raw)
    await sim.drive(coordinator.bridge.poll())
    await hass.async_block_till_done()
    assert _state(hass, entity).attributes.get("hvac_action") == expected
    other_id = entity_id(hass, "climate", other.eui, "thermostat")
    assert _state(hass, other_id).attributes["hvac_action"] == HVACAction.HEATING


async def test_valve_entity_ids_use_the_device_name(hass: HomeAssistant, sim: Sim) -> None:
    await loaded(sim)
    first, second = sim.inst.valves
    assert str(first.eui).endswith("00:01")
    assert entity_id(hass, "climate", first.eui, "thermostat") == "climate.vicare_valve_00_01"
    assert entity_id(hass, "climate", second.eui, "thermostat") == "climate.vicare_valve_00_02"
    assert entity_id(hass, "sensor", first.eui, "battery") == "sensor.vicare_valve_00_01_battery"
