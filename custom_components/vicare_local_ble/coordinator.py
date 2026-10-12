"""Coordinator and runtime data (spec §2.3, §2.4).

Polling and pushes are separate paths:

* Poll: ``DataUpdateCoordinator`` schedule (``update_interval`` = the ``scan_interval``
  option) -> ``_async_update_data`` -> ``bridge.poll()``. The first call (the config entry's
  first refresh) returns ``bridge.snapshot()`` (the cache, or empty) and never polls.
* Push: bridge ``on_update`` and connection state changes -> ``async_push`` -> ``self.data =
  snapshot`` + ``async_update_listeners()``. In HA 2026.10.1 ``async_set_updated_data`` calls
  ``_async_unsub_refresh()`` and ``_schedule_refresh()`` (it RESETS the interval), while
  ``async_update_listeners`` only calls the listeners. Valves report every few minutes, so a
  reset per push would starve the poll; the push path therefore never touches the schedule.

The schedule only runs while the coordinator has listeners. The integration adds one no-op
listener for the lifetime of the entry, so the valves are polled (misses, availability, the
all-silent rejoin rule) even when every entity is disabled.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from vicare_local_ble.bridge import BridgeSnapshot, ViCareBridge
from vicare_local_ble.zigbee_direct.connection import ConnectionState

from .const import CACHE_SAVE_DELAY, CONF_ADDRESS, DOMAIN, STOP_TIMEOUT, signal_new_valve

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.storage import Store

    from vicare_local_ble.bridge import BridgeCache
    from vicare_local_ble.valves import Valve
    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.connection import ZdConnection
    from vicare_local_ble.zigbee_direct.debug import NpduRecorder
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger(__name__)

type CacheStore = Store[dict[str, Any]]
type VicareConfigEntry = ConfigEntry[VicareRuntime]


class VicareCoordinator(DataUpdateCoordinator[BridgeSnapshot]):
    """Owns the ``ViCareBridge``; data is the latest ``BridgeSnapshot`` (module docstring)."""

    config_entry: VicareConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: VicareConfigEntry,
        connection: ZdConnection,
        *,
        clock: Clock,
        cache: BridgeCache | None,
        store: CacheStore,
        scan_interval: float,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
            always_update=False,
        )
        self.address: str = entry.data[CONF_ADDRESS]
        self.connection = connection
        #: Device registry id of the R0 device (set at setup; valves link to it).
        self.bridge_device_id: str | None = None
        self._store = store
        self._first_refresh_done = False
        self.bridge = ViCareBridge(
            connection,
            clock=clock,
            cache=cache,
            on_update=self.async_push,
            on_new_valve=self._on_new_valve,
            on_cache_changed=self._on_cache_changed,
        )

    async def _async_update_data(self) -> BridgeSnapshot:
        if not self._first_refresh_done:
            self._first_refresh_done = True
            return self.bridge.snapshot()  # cache or empty; never a sleepy poll at setup
        if self.connection.state is ConnectionState.AUTH_FAILED:
            raise ConfigEntryAuthFailed(translation_domain=DOMAIN, translation_key="auth_failed")
        if self.connection.stats.generation == 0:
            raise UpdateFailed("the R0 connection has never been ready")
        return await self.bridge.poll()

    @callback
    def async_push(self, snapshot: BridgeSnapshot) -> None:
        """Push a snapshot to the entities without moving the poll schedule."""
        self.data = snapshot
        self.async_update_listeners()

    @callback
    def async_on_connection_state(self, state: ConnectionState) -> None:
        """Connection state listener: push at once (the bridge entities flip immediately);
        AUTH_FAILED on a loaded entry starts the reauth flow."""
        self.async_push(self.bridge.snapshot())
        if (
            state is ConnectionState.AUTH_FAILED
            and self.config_entry.state is ConfigEntryState.LOADED
        ):
            self.config_entry.async_start_reauth(self.hass)

    @callback
    def _on_new_valve(self, valve: Valve) -> None:
        async_dispatcher_send(self.hass, signal_new_valve(self.config_entry.entry_id), valve)

    @callback
    def _on_cache_changed(self, _cache: BridgeCache) -> None:
        self._store.async_delay_save(self._cache_data, CACHE_SAVE_DELAY)

    def _cache_data(self) -> dict[str, Any]:
        return dict(self.bridge.export_cache().to_json())

    async def async_save_cache(self) -> None:
        """Write the cache now (replaces a pending delayed save)."""
        await self._store.async_save(self._cache_data())


@dataclass(slots=True, eq=False)
class VicareRuntime:
    """``entry.runtime_data``: everything one config entry owns.

    ``async_shutdown`` is idempotent (unload and the HA stop event may both call it): bounded
    ``connection.stop()``, then the registered cleanups (listeners, repair issues), then the
    cache is saved. ``added_valves`` lets each platform add a valve's entities once (T17).
    """

    clock: Clock
    connection: ZdConnection
    coordinator: VicareCoordinator
    recorder: NpduRecorder
    added_valves: set[Eui64] = field(default_factory=set)
    _cleanups: list[Callable[[], None]] = field(default_factory=list)
    _shutdown: asyncio.Task[None] | None = None

    @property
    def bridge(self) -> ViCareBridge:
        return self.coordinator.bridge

    def add_cleanup(self, cleanup: Callable[[], None]) -> None:
        """Run ``cleanup`` at shutdown, after the connection stopped (reverse order)."""
        self._cleanups.append(cleanup)

    async def async_shutdown(self) -> None:
        if self._shutdown is None:
            self._shutdown = asyncio.get_running_loop().create_task(
                self._async_shutdown(), name=f"{DOMAIN} shutdown"
            )
        await asyncio.shield(self._shutdown)

    async def _async_shutdown(self) -> None:
        try:
            async with self.clock.timeout(STOP_TIMEOUT):
                await self.connection.stop()
        except TimeoutError:
            _LOGGER.warning("Stopping the R0 connection took longer than %s s", STOP_TIMEOUT)
        finally:
            while self._cleanups:
                self._cleanups.pop()()
            await self.coordinator.async_save_cache()
