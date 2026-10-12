"""Setup, unload and shutdown (spec §2.3, §3 HA rows; task T16), against the simulator."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from custom_components.vicare_local_ble.const import (
    CONF_NETWORK_KEY,
    DOMAIN,
    issue_id,
    storage_key,
)
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import (  # type: ignore[import-untyped]
    async_fire_time_changed,
)

from conftest import INIT, our_tasks
from vicare_local_ble.bridge import BridgeCache, CachedValve, ViCareBridge
from vicare_local_ble.testing.errors import GATT_ERROR_REJECTED
from vicare_local_ble.zigbee_direct.connection import (
    ConnectionIssue,
    ConnectionState,
    ZdConnection,
)

if TYPE_CHECKING:
    import pytest
    from freezegun.api import FrozenDateTimeFactory
    from homeassistant.core import HomeAssistant

    from conftest import Sim
    from vicare_local_ble.bridge import BridgeSnapshot
    from vicare_local_ble.zigbee_direct.connection import Generation

READY = ConnectionState.READY
WRONG_KEY = "99" * 16  # dummy


def _reauth_flows(hass: HomeAssistant) -> list[Any]:
    return [
        flow
        for flow in hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        if flow["context"]["source"] == SOURCE_REAUTH
    ]


def _cached(sim: Sim) -> BridgeCache:
    """A cache from an earlier run: both valves known, identified."""
    valves = {
        str(v.eui): CachedValve(
            eui=str(v.eui),
            short=v.short,
            endpoint=1,
            manufacturer="Viessmann",
            model="7637434",
            sw_build="1.0",
        )
        for v in sim.inst.valves
    }
    return BridgeCache(own_short=None, zdd_eui=str(sim.inst.zdd_eui), valves=valves)


def _store(hass_storage: dict[str, Any], sim: Sim, cache: BridgeCache) -> None:
    key = storage_key(sim.entry.entry_id)
    hass_storage[key] = {"version": 1, "minor_version": 1, "key": key, "data": cache.to_json()}


def _stored(hass_storage: dict[str, Any], sim: Sim) -> BridgeCache | None:
    raw = hass_storage.get(storage_key(sim.entry.entry_id))
    return None if raw is None else BridgeCache.from_json(raw["data"])


def _current(sim: Sim) -> Generation:
    gen = sim.runtime.connection.current
    assert gen is not None
    return gen


# --- setup ---------------------------------------------------------------------------------


async def test_setup_reaches_ready_and_loads(hass: HomeAssistant, sim: Sim) -> None:
    assert await sim.setup()
    assert sim.entry.state is ConfigEntryState.LOADED
    runtime = sim.runtime
    assert runtime.connection.state is READY
    coordinator = runtime.coordinator
    assert coordinator.data.connection_state is READY
    assert coordinator.data.generation == 1
    device = dr.async_get(hass).async_get_device_by_identifier(
        (DOMAIN, sim.entry.data["address"]), sim.entry.entry_id
    )
    assert device is not None
    assert coordinator.bridge_device_id == device.id

    # discovery runs after READY, then the bridge's initial poll; both push to the coordinator
    euis = {v.eui for v in sim.inst.valves}

    def all_available() -> bool:
        data: BridgeSnapshot = coordinator.data
        return set(data.valves) == euis and all(
            data.available.get(e) and data.states[e].updated_at is not None for e in euis
        )

    await sim.drive_until(all_available)
    assert all(coordinator.data.states[e].updated_at is not None for e in euis)


async def test_first_refresh_returns_cache_without_polling(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any]
) -> None:
    _store(hass_storage, sim, _cached(sim))
    polls: list[ViCareBridge] = []
    real_poll = ViCareBridge.poll

    async def spy(self: ViCareBridge) -> BridgeSnapshot:
        polls.append(self)
        return await real_poll(self)

    with patch.object(ViCareBridge, "poll", spy):
        assert await sim.setup()
    data = sim.runtime.coordinator.data
    assert set(data.valves) == {v.eui for v in sim.inst.valves}  # from the cache
    assert not any(data.available.values())  # unavailable until polled
    assert all(state.updated_at is None for state in data.states.values())  # nothing read
    assert polls == []
    assert sim.zcl_frames() == []  # nothing but join/discovery traffic yet


async def test_not_ready_when_r0_absent(hass: HomeAssistant, sim: Sim) -> None:
    sim.device = lambda: None
    with patch(f"{INIT}.ZdConnection") as connection_cls:
        assert not await sim.setup()
    assert sim.entry.state is ConfigEntryState.SETUP_RETRY
    connection_cls.assert_not_called()  # nothing built, nothing to stop
    assert sim.inst.r0.connect_count == 0
    assert our_tasks() == []


async def test_not_ready_on_connect_timeout_stops_connection(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any]
) -> None:
    sim.inst.connector.fail_next(1000)  # seen over Bluetooth, but every connect fails
    created: list[ZdConnection] = []

    def build(*args: Any, **kwargs: Any) -> ZdConnection:
        created.append(ZdConnection(*args, **kwargs))
        return created[-1]

    with patch(f"{INIT}.ZdConnection", side_effect=build):
        assert not await sim.setup()
    assert sim.entry.state is ConfigEntryState.SETUP_RETRY
    assert len(created) == 1
    assert created[0].state is ConnectionState.STOPPED
    assert created[0].stats.connect_failures >= 3
    assert sim.inst.r0.client is None
    assert _stored(hass_storage, sim) is not None  # shutdown saved the (empty) cache
    assert our_tasks() == []


async def test_wrong_key_raises_auth_failed_and_starts_reauth(
    hass: HomeAssistant, sim: Sim
) -> None:
    hass.config_entries.async_update_entry(
        sim.entry, data={**sim.entry.data, CONF_NETWORK_KEY: WRONG_KEY}
    )
    assert not await sim.setup()
    assert sim.entry.state is ConfigEntryState.SETUP_ERROR
    await hass.async_block_till_done()
    assert len(_reauth_flows(hass)) == 1
    assert sim.inst.r0.connect_count == 2  # AUTH_FAILED after the 2nd rejection; stopped
    assert our_tasks() == []


async def test_auth_failed_later_starts_reauth(hass: HomeAssistant, sim: Sim) -> None:
    assert await sim.setup()
    r0 = sim.inst.r0
    r0.se3_fault = "gatt_error"
    r0.se3_error_code = GATT_ERROR_REJECTED  # the key was changed: every SE3 is rejected
    connection = sim.runtime.connection
    connection.request_rejoin(_current(sim), "test")
    await sim.drive_until(lambda: connection.state is ConnectionState.AUTH_FAILED)
    assert sim.runtime.coordinator.data.connection_state is ConnectionState.AUTH_FAILED
    await hass.async_block_till_done()
    assert len(_reauth_flows(hass)) == 1


# --- unload and stop -----------------------------------------------------------------------


async def test_forwarding_exception_shuts_down(hass: HomeAssistant, sim: Sim) -> None:
    async def boom(*_args: Any, **_kwargs: Any) -> None:
        msg = "platform forwarding failed"
        raise RuntimeError(msg)

    with patch.object(type(hass.config_entries), "async_forward_entry_setups", boom):
        assert not await sim.setup()
    assert sim.entry.state is ConfigEntryState.SETUP_ERROR
    assert sim.runtime.connection.state is ConnectionState.STOPPED
    assert sim.inst.r0.client is None
    await hass.async_block_till_done()
    assert our_tasks() == []


async def test_cancellation_during_forwarding_shuts_down(hass: HomeAssistant, sim: Sim) -> None:
    suspended = asyncio.Event()

    async def hang(*_args: Any, **_kwargs: Any) -> None:
        suspended.set()
        await asyncio.Event().wait()

    with patch.object(type(hass.config_entries), "async_forward_entry_setups", hang):
        setup = asyncio.ensure_future(hass.config_entries.async_setup(sim.entry.entry_id))
        await sim.drive_until(suspended.is_set)
        setup.cancel()
        await sim.drive(asyncio.gather(setup, return_exceptions=True))
    assert sim.runtime.connection.state is ConnectionState.STOPPED
    assert sim.inst.r0.client is None
    await hass.async_block_till_done()
    assert our_tasks() == []


async def test_unload_stops_and_saves_without_lingering_tasks(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any]
) -> None:
    assert await sim.setup()
    connection = sim.runtime.connection
    coordinator = sim.runtime.coordinator
    await sim.drive_until(lambda: len(coordinator.data.valves) == 2)
    assert storage_key(sim.entry.entry_id) not in hass_storage  # delayed save still pending
    assert our_tasks() != []  # the supervisor and generation tasks run while loaded
    own_short = _current(sim).join.own_short

    assert await sim.unload()
    assert sim.entry.state is ConfigEntryState.NOT_LOADED
    assert connection.state is ConnectionState.STOPPED
    assert sim.inst.r0.client is None
    await hass.async_block_till_done()
    assert our_tasks() == []
    stored = _stored(hass_storage, sim)
    assert stored is not None
    assert set(stored.valves) == {str(v.eui) for v in sim.inst.valves}
    assert stored.own_short == own_short


async def test_hass_stop_stops_and_saves(
    hass: HomeAssistant,
    sim: Sim,
    hass_storage: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert await sim.setup()
    connection = sim.runtime.connection
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await sim.drive_until(lambda: _stored(hass_storage, sim) is not None)
    assert connection.state is ConnectionState.STOPPED
    await hass.async_block_till_done()
    assert our_tasks() == []
    assert await sim.unload()  # idempotent shutdown
    assert our_tasks() == []
    assert not [r for r in caplog.records if r.name == "homeassistant.core"]


async def test_cache_saved_after_change(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any], freezer: FrozenDateTimeFactory
) -> None:
    assert await sim.setup()
    coordinator = sim.runtime.coordinator
    await sim.drive_until(lambda: len(coordinator.data.valves) == 2)
    assert _stored(hass_storage, sim) is None
    freezer.tick(timedelta(seconds=11))  # Store checks loop.time() against its due time
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    stored = _stored(hass_storage, sim)
    assert stored is not None
    assert set(stored.valves) == {str(v.eui) for v in sim.inst.valves}


# --- repair issues -------------------------------------------------------------------------


def _issue(hass: HomeAssistant, sim: Sim, issue: ConnectionIssue) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue(DOMAIN, issue_id(issue.value, sim.entry.entry_id))


async def test_mtu_issue_appears_and_clears(hass: HomeAssistant, sim: Sim) -> None:
    sim.inst.r0.mtu_size = 100
    assert await sim.setup()
    issue = _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL)
    assert issue is not None
    assert issue.translation_key == "mtu_too_small"
    assert issue.severity is ir.IssueSeverity.WARNING

    sim.inst.r0.mtu_size = 247
    connection = sim.runtime.connection
    gen = _current(sim)
    connection.request_rejoin(gen, "test")
    await sim.drive_until(
        lambda: connection.current is not None and connection.current.number > gen.number
    )
    assert _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL) is None


async def test_long_write_issue_appears_and_clears(hass: HomeAssistant, sim: Sim) -> None:
    r0 = sim.inst.r0
    r0.mtu_size = 70
    r0.long_write_supported = False
    assert await sim.setup()
    connection = sim.runtime.connection
    assert _issue(hass, sim, ConnectionIssue.LONG_WRITE_UNSUPPORTED) is None
    gen = _current(sim)

    async def large_read() -> None:
        await gen.node.zcl_read(0x0000, 1, 0x0201, list(range(40)))  # frame > MTU - 3

    connection.spawn(gen, large_read(), name="large read")
    await sim.drive_until(lambda: connection.state is not READY)
    assert _issue(hass, sim, ConnectionIssue.LONG_WRITE_UNSUPPORTED) is not None
    # the next session opens at the same MTU without a long write: cleared
    await sim.drive_until(lambda: connection.state is READY)
    assert _issue(hass, sim, ConnectionIssue.LONG_WRITE_UNSUPPORTED) is None
    assert _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL) is not None

    assert await sim.unload()  # unload removes the entry's issues
    assert _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL) is None
