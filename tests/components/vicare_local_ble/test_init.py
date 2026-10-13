"""Setup, unload and shutdown (spec §2.3, §3 HA rows; task T16), against the simulator."""

from __future__ import annotations

import asyncio
import json
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
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, STATE_UNAVAILABLE
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.json import json_bytes
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


# --- unload, reload and remove (supports_unload) -------------------------------------------


def _entity_ids(hass: HomeAssistant, sim: Sim) -> list[str]:
    entries = er.async_entries_for_config_entry(er.async_get(hass), sim.entry.entry_id)
    return [e.entity_id for e in entries]


async def test_entry_supports_unload(hass: HomeAssistant, sim: Sim) -> None:
    assert await sim.setup()
    entry = hass.config_entries.async_get_entry(sim.entry.entry_id)
    assert entry is not None
    assert entry.supports_unload is True
    api = json.loads(json_bytes(entry.as_json_fragment))  # what the HA frontend reads
    assert api["supports_unload"] is True


async def test_unload_makes_entities_unavailable(hass: HomeAssistant, sim: Sim) -> None:
    assert await sim.setup()
    coordinator = sim.runtime.coordinator
    euis = {v.eui for v in sim.inst.valves}
    await sim.drive_until(lambda: all(coordinator.data.available.get(e) for e in euis))
    await hass.async_block_till_done()
    live = [
        e
        for e in _entity_ids(hass, sim)
        if (state := hass.states.get(e)) is not None and state.state != STATE_UNAVAILABLE
    ]
    assert live

    assert await sim.unload()
    await hass.async_block_till_done()
    assert sim.entry.state is ConfigEntryState.NOT_LOADED
    for e in live:
        state = hass.states.get(e)
        assert state is None or state.state == STATE_UNAVAILABLE
    assert our_tasks() == []


async def test_reload_stops_old_connection_before_new_connect(
    hass: HomeAssistant, sim: Sim
) -> None:
    assert await sim.setup()
    old = sim.runtime
    assert sim.inst.r0.client is not None
    seen: list[tuple[ConnectionState, bool]] = []
    real = sim.inst.connector

    async def spy(*args: Any, **kwargs: Any) -> Any:
        # the R0 accepts one client: the old one must be gone before a new connect starts
        seen.append((old.connection.state, sim.inst.r0.client is None))
        return await real(*args, **kwargs)

    with patch(f"{INIT}.establish_connection", spy):
        assert await sim.drive(hass.config_entries.async_reload(sim.entry.entry_id))
    assert sim.entry.state is ConfigEntryState.LOADED
    assert sim.runtime is not old
    assert seen
    assert seen[0] == (ConnectionState.STOPPED, True)
    assert old.connection.state is ConnectionState.STOPPED
    assert sim.runtime.connection.state is READY
    assert sim.inst.r0.client is not None


async def test_unload_keeps_connection_when_platforms_fail(hass: HomeAssistant, sim: Sim) -> None:
    assert await sim.setup()
    runtime = sim.runtime

    async def refuse(*_args: Any, **_kwargs: Any) -> bool:
        return False

    with patch.object(type(hass.config_entries), "async_unload_platforms", refuse):
        assert not await sim.unload()
    assert sim.entry.state is ConfigEntryState.FAILED_UNLOAD
    assert runtime.connection.state is READY
    assert sim.inst.r0.client is not None
    assert our_tasks() != []

    await sim.drive(runtime.async_shutdown())  # the fixture only unloads LOADED entries
    await hass.async_block_till_done()
    assert our_tasks() == []


async def test_remove_deletes_issues_and_cache(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any]
) -> None:
    assert await sim.setup()
    key = storage_key(sim.entry.entry_id)
    assert await sim.unload()
    assert key in hass_storage  # unload saved the cache
    # an issue left behind (e.g. by an older version) goes with the entry
    ident = issue_id(ConnectionIssue.MTU_TOO_SMALL.value, sim.entry.entry_id)
    ir.async_create_issue(
        hass,
        DOMAIN,
        ident,
        is_fixable=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key=ConnectionIssue.MTU_TOO_SMALL.value,
    )

    result = await sim.drive(hass.config_entries.async_remove(sim.entry.entry_id))
    await hass.async_block_till_done()
    assert result == {"require_restart": False}
    assert ir.async_get(hass).async_get_issue(DOMAIN, ident) is None
    assert key not in hass_storage
    assert our_tasks() == []


async def test_remove_loaded_entry_releases_r0(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any]
) -> None:
    sim.inst.r0.mtu_size = 100  # raises a repair issue while loaded
    assert await sim.setup()
    connection = sim.runtime.connection
    assert _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL) is not None

    result = await sim.drive(hass.config_entries.async_remove(sim.entry.entry_id))
    await hass.async_block_till_done()
    assert result == {"require_restart": False}
    assert connection.state is ConnectionState.STOPPED
    assert sim.inst.r0.client is None
    assert _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL) is None
    assert storage_key(sim.entry.entry_id) not in hass_storage
    assert our_tasks() == []


async def test_remove_after_failed_unload_shuts_down_first(
    hass: HomeAssistant, sim: Sim, hass_storage: dict[str, Any], freezer: FrozenDateTimeFactory
) -> None:
    sim.inst.r0.mtu_size = 100  # raises a repair issue while loaded
    assert await sim.setup()
    runtime = sim.runtime
    await sim.drive_until(lambda: len(runtime.coordinator.data.valves) == 2)  # cache pending

    async def refuse(*_args: Any, **_kwargs: Any) -> bool:
        return False

    with patch.object(type(hass.config_entries), "async_unload_platforms", refuse):
        result = await sim.drive(hass.config_entries.async_remove(sim.entry.entry_id))
    assert result == {"require_restart": True}  # HA: the platforms did not unload
    assert runtime.connection.state is ConnectionState.STOPPED
    assert sim.inst.r0.client is None

    # nothing recreates the cache or the issue afterwards
    await sim.drive(runtime.async_shutdown())
    freezer.tick(timedelta(seconds=60))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert storage_key(sim.entry.entry_id) not in hass_storage
    assert _issue(hass, sim, ConnectionIssue.MTU_TOO_SMALL) is None
    assert our_tasks() == []
