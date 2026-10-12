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
