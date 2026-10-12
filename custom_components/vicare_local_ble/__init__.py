"""ViCare Local (Bluetooth via ubisys R0) integration: setup and unload (spec §2.3).

Setup: resolver precheck -> cache from ``Store`` -> ``ZdConnection`` + coordinator (which owns
the ``ViCareBridge``) -> ``bridge.attach()`` and the state/issue/advertisement listeners ->
``connection.start(first_ready_timeout)`` -> first refresh (cached snapshot, no poll) -> bridge
device -> platforms -> HA stop listener.

Shutdown (unload, HA stop or a failed setup): bounded ``connection.stop()``, listener cleanup
and repair issues removed, then the cache is saved (``VicareRuntime.async_shutdown``).

Test seams: ``LoopClock``, ``establish_connection`` and ``async_ble_device_from_address`` are
module attributes so the HA tests can swap in the simulator's ``VirtualClock``, its
``fake_connector`` and its ``BLEDevice`` (no real Bluetooth, deterministic time).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from bleak_retry_connector import establish_connection
from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothReachabilityIntent,
    BluetoothScanningMode,
    async_address_reachability_diagnostics,
    async_ble_device_from_address,
    async_register_callback,
)
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.storage import Store

from vicare_local_ble.bridge import BridgeCache
from vicare_local_ble.zigbee_direct.clock import LoopClock
from vicare_local_ble.zigbee_direct.connection import ConnectionIssue, ZdConnection
from vicare_local_ble.zigbee_direct.debug import NpduRecorder
from vicare_local_ble.zigbee_direct.errors import (
    ConnectionLostError,
    HandshakeRejectedError,
    TransportError,
)
from vicare_local_ble.zigbee_direct.node import NodeConfig, RouteReplyMode
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

from .const import (
    CONF_ADDRESS,
    CONF_NETWORK_KEY,
    CONF_ROUTE_REPLY_MODE,
    CONF_SCAN_INTERVAL,
    CONF_ZVD_EUI,
    DEFAULT_ROUTE_REPLY_MODE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    FIRST_READY_TIMEOUT,
    STORAGE_VERSION,
    issue_id,
    storage_key,
)
from .coordinator import VicareCoordinator, VicareRuntime
from .entity import bridge_device_info

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice
    from homeassistant.components.bluetooth import BluetoothChange, BluetoothServiceInfoBleak
    from homeassistant.core import Event, HomeAssistant

    from .coordinator import CacheStore, VicareConfigEntry

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.CLIMATE, Platform.SENSOR, Platform.BINARY_SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: VicareConfigEntry) -> bool:
    """Connect to the R0 and start the bridge (module docstring)."""
    address: str = entry.data[CONF_ADDRESS]

    def resolve() -> BLEDevice | None:
        # fresh lookup per attempt: the current best adapter or proxy
        return async_ble_device_from_address(hass, address, connectable=True)

    if resolve() is None:
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN,
            translation_key="device_not_found",
            translation_placeholders={"diagnostics": _reachability(hass, address)},
        )

    store: CacheStore = Store(hass, STORAGE_VERSION, storage_key(entry.entry_id))
    stored = await store.async_load()
    cache = BridgeCache.from_json(stored) if stored is not None else None

    clock = LoopClock()
    recorder = NpduRecorder(clock=clock)
    options = entry.options
    connection = ZdConnection(
        resolve,
        own_eui=Eui64.from_str(entry.data[CONF_ZVD_EUI]),
        network_key=SecretBytes(bytes.fromhex(entry.data[CONF_NETWORK_KEY])),
        clock=clock,
        node_config=NodeConfig(
            route_reply_mode=RouteReplyMode(
                options.get(CONF_ROUTE_REPLY_MODE, DEFAULT_ROUTE_REPLY_MODE)
            )
        ),
        name=entry.title,
        connector=establish_connection,
        recorder=recorder,
    )
    coordinator = VicareCoordinator(
        hass,
        entry,
        connection,
        clock=clock,
        cache=cache,
        store=store,
        scan_interval=float(options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)),
    )
    runtime = VicareRuntime(
        clock=clock, connection=connection, coordinator=coordinator, recorder=recorder
    )
    entry.runtime_data = runtime

    # cleanups run in reverse order: listeners go before their issues are deleted
    runtime.add_cleanup(lambda: _delete_issues(hass, entry))
    runtime.add_cleanup(coordinator.bridge.attach())
    runtime.add_cleanup(connection.add_state_listener(coordinator.async_on_connection_state))
    runtime.add_cleanup(
        connection.add_issue_listener(
            lambda issue, active: _on_issue(hass, entry, issue, active=active)
        )
    )

    @callback
    def _seen(_info: BluetoothServiceInfoBleak, _change: BluetoothChange) -> None:
        connection.notify_seen()

    # before the first connect, so an advert can shorten an early backoff wait
    runtime.add_cleanup(
        async_register_callback(
            hass,
            _seen,
            BluetoothCallbackMatcher(address=address, connectable=True),
            BluetoothScanningMode.ACTIVE,
        )
    )
    # keep the poll schedule running even without entity listeners (coordinator docstring)
    runtime.add_cleanup(coordinator.async_add_listener(_keep_polling))

    try:
        await connection.start(first_ready_timeout=FIRST_READY_TIMEOUT)
        await coordinator.async_config_entry_first_refresh()
    except HandshakeRejectedError as err:
        await runtime.async_shutdown()
        raise ConfigEntryAuthFailed(
            translation_domain=DOMAIN, translation_key="auth_failed"
        ) from err
    except (TimeoutError, TransportError, ConnectionLostError) as err:
        await runtime.async_shutdown()
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN,
            translation_key="device_not_found",
            translation_placeholders={"diagnostics": _reachability(hass, address)},
        ) from err
    except BaseException:
        await runtime.async_shutdown()
        raise

    bridge_device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, **bridge_device_info(address, entry.title)
    )
    coordinator.bridge_device_id = bridge_device.id
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def _on_hass_stop(_event: Event) -> None:
        await runtime.async_shutdown()

    # async_listen, not async_listen_once: removing a fired once-listener at unload logs an error
    entry.async_on_unload(hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, _on_hass_stop))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: VicareConfigEntry) -> bool:
    """Unload the platforms, then stop the connection and save the cache."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.async_shutdown()
    return unloaded


@callback
def _keep_polling() -> None:
    """No-op coordinator listener (see ``coordinator`` module docstring)."""


def _reachability(hass: HomeAssistant, address: str) -> str:
    return async_address_reachability_diagnostics(
        hass, address, BluetoothReachabilityIntent.CONNECTION
    )


@callback
def _on_issue(
    hass: HomeAssistant, entry: VicareConfigEntry, issue: ConnectionIssue, *, active: bool
) -> None:
    """Connection issue listener -> repair issue (created or deleted)."""
    ident = issue_id(issue.value, entry.entry_id)
    if not active:
        ir.async_delete_issue(hass, DOMAIN, ident)
        return
    ir.async_create_issue(
        hass,
        DOMAIN,
        ident,
        is_fixable=False,
        is_persistent=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key=issue.value,
    )


def _delete_issues(hass: HomeAssistant, entry: VicareConfigEntry) -> None:
    for issue in ConnectionIssue:
        ir.async_delete_issue(hass, DOMAIN, issue_id(issue.value, entry.entry_id))
