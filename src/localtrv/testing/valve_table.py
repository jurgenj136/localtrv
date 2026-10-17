"""Raw ZK03840 simulator fixture data (protocol.md §9), written independently of ``valves``.

Values are raw wire values: centi-degrees, 0.5 % battery units, raw enums, quarter-seconds.
Nothing here is imported from ``localtrv.valves`` (CONTRIBUTING.md layering), so
a scaling or id bug there cannot pass tautologically against the simulator.
"""

from __future__ import annotations

from typing import Final

from localtrv.zigbee_direct.codec.zcl_types import ZclDataType, ZclValue

type RawKey = tuple[int, int, int | None]

#: Viessmann manufacturer code used by the mfr-specific thermostat attributes.
MFR_CODE: Final = 0x1221

CL_BASIC: Final = 0x0000
CL_POWER: Final = 0x0001
CL_IDENTIFY: Final = 0x0003
CL_TIME: Final = 0x000A
CL_POLL_CONTROL: Final = 0x0020
CL_THERMOSTAT: Final = 0x0201
CL_UI: Final = 0x0204
CL_DIAGNOSTICS: Final = 0x0B05

#: Simple descriptor of endpoint 1.
PROFILE_HA: Final = 0x0104
DEVICE_ID: Final = 0x0301
IN_CLUSTERS: Final = (
    CL_BASIC,
    CL_POWER,
    CL_IDENTIFY,
    CL_TIME,
    CL_POLL_CONTROL,
    CL_THERMOSTAT,
    CL_UI,
    CL_DIAGNOSTICS,
)
OUT_CLUSTERS: Final = (0x0000, 0x0019)

#: Thermostat attribute ids the simulator gives semantics to.
ATTR_LOCAL_TEMPERATURE: Final = 0x0000
ATTR_ABS_MIN: Final = 0x0003
ATTR_ABS_MAX: Final = 0x0004
ATTR_SETPOINT: Final = 0x0012
ATTR_MIN_LIMIT: Final = 0x0015
ATTR_MAX_LIMIT: Final = 0x0016

_DEFAULT: Final[tuple[tuple[RawKey, ZclDataType, ZclValue], ...]] = (
    # Basic (identification)
    ((CL_BASIC, 0x0004, None), ZclDataType.CHARSTR, "Viessmann"),
    ((CL_BASIC, 0x0005, None), ZclDataType.CHARSTR, "7637434"),
    ((CL_BASIC, 0x0006, None), ZclDataType.CHARSTR, "20230613"),
    ((CL_BASIC, 0x0007, None), ZclDataType.ENUM8, 3),
    ((CL_BASIC, 0x4000, None), ZclDataType.CHARSTR, "01.18.0008 02.06"),
    # Power configuration: batteryPercentageRemaining, 0.5 % units (126 = 63 %)
    ((CL_POWER, 0x0021, None), ZclDataType.UINT8, 126),
    # Poll control: check-in / long poll interval, quarter-seconds (300 s / 7 s)
    ((CL_POLL_CONTROL, 0x0000, None), ZclDataType.UINT32, 1200),
    ((CL_POLL_CONTROL, 0x0001, None), ZclDataType.UINT32, 28),
    # Thermostat
    ((CL_THERMOSTAT, ATTR_LOCAL_TEMPERATURE, None), ZclDataType.INT16, 1965),
    ((CL_THERMOSTAT, ATTR_ABS_MIN, None), ZclDataType.INT16, 800),
    ((CL_THERMOSTAT, ATTR_ABS_MAX, None), ZclDataType.INT16, 3000),
    ((CL_THERMOSTAT, 0x0008, None), ZclDataType.UINT8, 2),  # piHeatingDemand, percent
    ((CL_THERMOSTAT, ATTR_SETPOINT, None), ZclDataType.INT16, 2200),
    ((CL_THERMOSTAT, ATTR_MIN_LIMIT, None), ZclDataType.INT16, 800),
    ((CL_THERMOSTAT, ATTR_MAX_LIMIT, None), ZclDataType.INT16, 3000),
    ((CL_THERMOSTAT, 0x001B, None), ZclDataType.ENUM8, 2),  # heating only
    ((CL_THERMOSTAT, 0x001C, None), ZclDataType.ENUM8, 9),  # sleep while regulating
    # Thermostat, manufacturer specific (0x1221)
    ((CL_THERMOSTAT, 0x4000, MFR_CODE), ZclDataType.ENUM8, 1),  # window_open
    ((CL_THERMOSTAT, 0x4003, MFR_CODE), ZclDataType.BOOL, False),
    ((CL_THERMOSTAT, 0x4007, MFR_CODE), ZclDataType.BOOL, False),
    ((CL_THERMOSTAT, 0x4008, MFR_CODE), ZclDataType.UINT16, 300),
    ((CL_THERMOSTAT, 0x4012, MFR_CODE), ZclDataType.BOOL, False),
    # User interface: keypadLockout
    ((CL_UI, 0x0001, None), ZclDataType.ENUM8, 0),
    # Diagnostics: lastMessageLQI / lastMessageRSSI
    ((CL_DIAGNOSTICS, 0x011C, None), ZclDataType.UINT8, 180),
    ((CL_DIAGNOSTICS, 0x011D, None), ZclDataType.INT8, -60),
)

#: Attributes a Write Attributes may change; everything else answers READ_ONLY (0x88).
WRITABLE: Final[frozenset[RawKey]] = frozenset(
    {
        (CL_THERMOSTAT, ATTR_SETPOINT, None),
        (CL_THERMOSTAT, ATTR_MIN_LIMIT, None),
        (CL_THERMOSTAT, ATTR_MAX_LIMIT, None),
        (CL_THERMOSTAT, 0x001B, None),
        (CL_THERMOSTAT, 0x001C, None),
        (CL_THERMOSTAT, 0x4000, MFR_CODE),
        (CL_THERMOSTAT, 0x4003, MFR_CODE),
        (CL_THERMOSTAT, 0x4012, MFR_CODE),
        (CL_UI, 0x0001, None),
    }
)


def default_table() -> dict[RawKey, tuple[ZclDataType, ZclValue]]:
    """A fresh mutable copy of the default raw attribute table."""
    return {key: (dt, value) for key, dt, value in _DEFAULT}


__all__ = [
    "ATTR_ABS_MAX",
    "ATTR_ABS_MIN",
    "ATTR_LOCAL_TEMPERATURE",
    "ATTR_MAX_LIMIT",
    "ATTR_MIN_LIMIT",
    "ATTR_SETPOINT",
    "CL_BASIC",
    "CL_THERMOSTAT",
    "DEVICE_ID",
    "IN_CLUSTERS",
    "MFR_CODE",
    "OUT_CLUSTERS",
    "PROFILE_HA",
    "WRITABLE",
    "RawKey",
    "default_table",
]
