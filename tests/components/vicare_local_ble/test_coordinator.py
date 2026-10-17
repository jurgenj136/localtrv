"""Coordinator: cached first refresh, poll schedule vs pushes, entity base.

HA time (the coordinator schedule) is driven with ``freezer`` + ``async_fire_time_changed``;
library and simulator time is the ``VirtualClock`` (``Sim.drive*``, ``clock.advance``). The
two are independent, so a push can never move the poll schedule by "real time passing".
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import PropertyMock, patch

from custom_components.vicare_local_ble.const import DOMAIN
from custom_components.vicare_local_ble.entity import (
    VicareBridgeEntity,
    VicareValveEntity,
    eui_hex,
)
from homeassistant.config_entries import SOURCE_REAUTH
from pytest_homeassistant_custom_component.common import (  # type: ignore[import-untyped]
    async_fire_time_changed,
)

from conftest import our_tasks
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.connection import ConnectionState, ZdConnection

if TYPE_CHECKING:
    import asyncio

    from custom_components.vicare_local_ble.coordinator import VicareCoordinator
    from freezegun.api import FrozenDateTimeFactory
    from homeassistant.core import HomeAssistant

    from conftest import Sim
    from vicare_local_ble.bridge import BridgeSnapshot

S = ConnectionState


def _refresh_handle(coordinator: VicareCoordinator) -> asyncio.TimerHandle:
    """The loop timer of the next scheduled refresh (``_unsub_refresh`` is its ``cancel``)."""
    unsub: Any = coordinator._unsub_refresh
    assert unsub is not None
    handle: asyncio.TimerHandle = unsub.__self__
    assert not handle.cancelled()
    return handle


async def _loaded(sim: Sim) -> VicareCoordinator:
    """Set up and let discovery plus the bridge's own initial poll finish."""
    assert await sim.setup()
    coordinator = sim.runtime.coordinator
    euis = {v.eui for v in sim.inst.valves}

    def settled() -> bool:
        data = coordinator.data
        polled = all(data.available.get(e) and data.states[e].updated_at for e in euis)
        return polled and not any("initial poll" in t.get_name() for t in our_tasks())

    await sim.drive_until(settled)
    return coordinator


class PollSpy:
    """Stands in for ``bridge.poll``: counts calls and returns the current snapshot."""

    def __init__(self, coordinator: VicareCoordinator) -> None:
        self._bridge = coordinator.bridge
        self.calls = 0

    async def __call__(self) -> BridgeSnapshot:
        self.calls += 1
        return self._bridge.snapshot()


def _tick(hass: HomeAssistant, freezer: FrozenDateTimeFactory, seconds: float) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass)


async def test_first_poll_on_schedule(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> None:
    coordinator = await _loaded(sim)
    spy = PollSpy(coordinator)
    with patch.object(coordinator.bridge, "poll", spy):
        _tick(hass, freezer, 250)
        await hass.async_block_till_done()
        assert spy.calls == 0
        _tick(hass, freezer, 51)
        await hass.async_block_till_done()
        assert spy.calls == 1
        _tick(hass, freezer, 301)
        await hass.async_block_till_done()
        assert spy.calls == 2
    assert coordinator.last_update_success


async def test_scheduled_poll_runs_the_real_bridge_poll(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> None:
    coordinator = await _loaded(sim)
    valve = sim.inst.valves[0]
    valve.set_attribute(vt.CL_THERMOSTAT, 0x0000, ZclDataType.INT16, 2345)
    mark = len(sim.zcl_frames())
    _tick(hass, freezer, 301)
    await sim.drive_until(lambda: coordinator.data.states[valve.eui].local_temperature_c == 23.45)
    assert len(sim.zcl_frames()) > mark


async def test_continuous_reports_do_not_reset_poll_schedule(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> None:
    coordinator = await _loaded(sim)
    pushes: list[BridgeSnapshot] = []
    coordinator.async_add_listener(lambda: pushes.append(coordinator.data))
    spy = PollSpy(coordinator)
    handle = _refresh_handle(coordinator)
    valve = sim.inst.valves[0]
    with patch.object(coordinator.bridge, "poll", spy):
        # 20 virtual minutes with a report every 10 s, while 290 s pass on HA's clock
        for report in range(120):
            temp = 1800 + report
            valve.set_attribute(vt.CL_THERMOSTAT, 0x0000, ZclDataType.INT16, temp)
            valve.report(vt.CL_THERMOSTAT, (0x0000,))
            await sim.clock.advance(10.0)
            if report % 12 == 11:
                _tick(hass, freezer, 29)
                await hass.async_block_till_done()
        assert len(pushes) >= 120
        assert coordinator.data.states[valve.eui].local_temperature_c == 19.19
        assert spy.calls == 0
        assert _refresh_handle(coordinator) is handle  # never rescheduled by a push
        _tick(hass, freezer, 11)  # 301 s after the schedule was set: the poll is due
        await hass.async_block_till_done()
        assert spy.calls == 1

        # control: the HA API that resets the interval really does move the timer
        handle = _refresh_handle(coordinator)
        coordinator.async_set_updated_data(coordinator.data)
        assert _refresh_handle(coordinator) is not handle


async def test_state_transitions_do_not_reset_poll_schedule(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> None:
    coordinator = await _loaded(sim)
    connection = sim.runtime.connection
    states: list[ConnectionState] = []
    connection.add_state_listener(states.append)
    pushed: list[ConnectionState] = []
    coordinator.async_add_listener(lambda: pushed.append(coordinator.data.connection_state))
    spy = PollSpy(coordinator)
    handle = _refresh_handle(coordinator)
    with patch.object(coordinator.bridge, "poll", spy):
        _tick(hass, freezer, 150)
        await hass.async_block_till_done()
        sim.inst.connector.fail_next(25)
        gen = connection.current
        assert gen is not None
        connection.request_rejoin(gen, "test")
        await sim.drive_until(lambda: connection.state is S.READY, limit=86_400.0)
        assert states.count(S.BACKOFF) >= 25
        assert len(states) >= 50
        assert S.BACKOFF in pushed  # the bridge entities see each state at once
        assert spy.calls == 0
        assert _refresh_handle(coordinator) is handle
        _tick(hass, freezer, 151)
        await hass.async_block_till_done()
        assert spy.calls == 1


async def test_update_raises_auth_failed_in_auth_failed_state(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> None:
    coordinator = await _loaded(sim)
    with patch.object(ZdConnection, "state", new_callable=PropertyMock, return_value=S.AUTH_FAILED):
        _tick(hass, freezer, 301)
        await hass.async_block_till_done()
    assert not coordinator.last_update_success
    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert [f["context"]["source"] for f in flows] == [SOURCE_REAUTH]


async def test_update_failed_if_never_ready(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> None:
    coordinator = await _loaded(sim)
    sim.runtime.connection.stats.generation = 0  # as if READY was never reached
    _tick(hass, freezer, 301)
    await hass.async_block_till_done()
    assert not coordinator.last_update_success


async def test_entity_base_classes(hass: HomeAssistant, sim: Sim) -> None:
    coordinator = await _loaded(sim)
    valve = coordinator.data.valves[sim.inst.valves[0].eui]
    entity = VicareValveEntity(coordinator, valve, "battery")
    assert entity.unique_id == f"{eui_hex(valve.eui)}_battery"
    assert entity.unique_id.startswith("0200000000010001_")
    info: dict[str, Any] = dict(entity.device_info or {})
    assert info["identifiers"] == {(DOMAIN, eui_hex(valve.eui))}
    assert info["manufacturer"] == "Viessmann"
    assert info["model"] == "ZK03840"
    assert info["via_device_id"] == coordinator.bridge_device_id
    assert entity.has_entity_name
    assert entity.valve == valve
    assert entity.valve_state is coordinator.data.states[valve.eui]
    assert entity.available

    connection = sim.runtime.connection
    connection.request_rejoin(connection.current, "test")  # type: ignore[arg-type]
    await sim.drive_until(lambda: connection.state is not S.READY)
    assert coordinator.data.connection_state is not S.READY

    bridge_entity = VicareBridgeEntity(coordinator, "connection")
    assert bridge_entity.unique_id == "aabbcc001122_connection"
    bridge_info = bridge_entity.device_info
    assert bridge_info is not None
    assert bridge_info["identifiers"] == {(DOMAIN, sim.entry.data["address"])}
