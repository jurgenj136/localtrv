"""Constants for ViCare Local (Bluetooth via ubisys R0)."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "vicare_local_ble"

# Config entry data keys.
CONF_ADDRESS: Final = "address"
CONF_NETWORK_KEY: Final = "network_key"
CONF_ZVD_EUI: Final = "zvd_eui"
CONF_ZDD_EUI: Final = "zdd_eui"
CONF_VALIDATE: Final = "validate"

# Option keys.
CONF_SCAN_INTERVAL: Final = "scan_interval"
CONF_ROUTE_REPLY_MODE: Final = "route_reply_mode"
# Options-flow section holding the advanced options (route_reply_mode).
SECTION_ADVANCED: Final = "advanced"

DEFAULT_SCAN_INTERVAL: Final = 300  # seconds
MIN_SCAN_INTERVAL: Final = 60
MAX_SCAN_INTERVAL: Final = 3600

ROUTE_REPLY_MODE_LIVE: Final = "live"
ROUTE_REPLY_MODE_SPEC: Final = "spec"
ROUTE_REPLY_MODE_OFF: Final = "off"
ROUTE_REPLY_MODES: Final = (ROUTE_REPLY_MODE_LIVE, ROUTE_REPLY_MODE_SPEC, ROUTE_REPLY_MODE_OFF)
DEFAULT_ROUTE_REPLY_MODE: Final = ROUTE_REPLY_MODE_LIVE

# ZigBee Direct service advertised by the ubisys R0 (0xFFF7).
ZIGBEE_DIRECT_SERVICE_UUID: Final = "0000fff7-0000-1000-8000-00805f9b34fb"
LOCAL_NAME_PREFIX: Final = "ubisys"

# Validation time limit for the config flow (seconds).
VALIDATE_TIMEOUT: Final = 60
# Valve is unavailable after this many consecutive missed polls.
MISSED_POLLS_UNAVAILABLE: Final = 3

# Setup and shutdown. Seconds on the library clock unless noted.
FIRST_READY_TIMEOUT: Final = 90.0
# Upper bound for connection.stop() at unload / HA stop (the teardown has its own inner bounds).
STOP_TIMEOUT: Final = 30.0
# Debounce for persisting the bridge cache after a change (HA Store.async_delay_save, seconds).
CACHE_SAVE_DELAY: Final = 10
STORAGE_VERSION: Final = 1

# Bridge (R0) device registry entry.
BRIDGE_MANUFACTURER: Final = "ubisys"
BRIDGE_MODEL: Final = "R0"


def storage_key(entry_id: str) -> str:
    """HA Store key of the bridge cache of one config entry."""
    return f"{DOMAIN}.{entry_id}"


def signal_new_valve(entry_id: str) -> str:
    """Dispatcher signal sent once per newly identified valve (payload: the ``Valve``)."""
    return f"{DOMAIN}_{entry_id}_new_valve"


def issue_id(issue: str, entry_id: str) -> str:
    """Repair issue id of a connection issue (one per config entry)."""
    return f"{issue}_{entry_id}"
