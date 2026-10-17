"""ZK03840 identification, cluster/attribute ids, validation constants, specs and read plans.

Pure data (docs/protocol.md §9).
"""

from __future__ import annotations

from typing import Final

from localtrv.valves.models import AttrSpec, ReadPlan, ReadRequest, ValueKind
from localtrv.zigbee_direct.codec.aps import HA_PROFILE_ID
from localtrv.zigbee_direct.codec.zcl_types import ZclDataType

# --- identification ----------------------------------------------------------------------

MANUFACTURER: Final = "Viessmann"
MFR_VIESSMANN: Final = 0x1221
MODEL_IDS: Final = frozenset({"7637434"})
#: Valve EUI OUIs; they only order identification, never decide it (Basic modelId does).
#: 14:2D:41 seen live; it also covers the ZK03838 floor-heating thermostat (kristian/ViLocal
#: discussion #6), so it is not valve-specific. 28:DB:A7: ZK03840 example valve EUI in the
#: zbtk README.
OUI_HINT: Final = ("14:2D:41", "28:DB:A7")
#: Display names for HA's DeviceInfo.
MODEL_NAME: Final = "ZK03840"

ENDPOINT: Final = 1
PROFILE: Final = HA_PROFILE_ID

# --- clusters and attributes ----------------------------------------------------------

CLUSTER_BASIC: Final = 0x0000
CLUSTER_POWER: Final = 0x0001
CLUSTER_POLL_CONTROL: Final = 0x0020
CLUSTER_THERMOSTAT: Final = 0x0201
CLUSTER_DIAGNOSTICS: Final = 0x0B05

ATTR_MANUFACTURER_NAME: Final = 0x0004
ATTR_MODEL_ID: Final = 0x0005
ATTR_POWER_SOURCE: Final = 0x0007
ATTR_SW_BUILD_ID: Final = 0x4000

ATTR_BATTERY_PERCENTAGE: Final = 0x0021

ATTR_LOCAL_TEMPERATURE: Final = 0x0000
ATTR_ABS_MIN_HEAT: Final = 0x0003
ATTR_ABS_MAX_HEAT: Final = 0x0004
ATTR_PI_HEATING_DEMAND: Final = 0x0008
ATTR_OCCUPIED_HEATING_SETPOINT: Final = 0x0012
ATTR_MIN_HEAT: Final = 0x0015
ATTR_MAX_HEAT: Final = 0x0016
ATTR_SYSTEM_MODE: Final = 0x001C
#: Manufacturer-specific (``MFR_VIESSMANN``): window open state, raw/diagnostic only.
ATTR_WINDOW_OPEN: Final = 0x4000
#: Manufacturer-specific assembly mode: NEVER write.
ATTR_ASSEMBLY_MODE: Final = 0x4012

ATTR_LAST_MESSAGE_LQI: Final = 0x011C
ATTR_LAST_MESSAGE_RSSI: Final = 0x011D

# --- validation constants ----------------------------------------------------------------

TEMPERATURE_SENTINEL: Final = -0x8000  # int16 0x8000 as decoded
UINT8_SENTINEL: Final = 0xFF
INT8_SENTINEL: Final = -0x80  # int8 0x80 as decoded
TEMPERATURE_RANGE_C: Final = (-50.0, 100.0)
BATTERY_RAW_MAX: Final = 200
#: piHeatingDemand ceiling: ZCL PIHeatingDemand percent (0-100). Live values 2, 5, 11 seen
#: 2026-10-13; ViLocal's 0-7 claim is disproven. Above it the value is kept and flagged
#: ``demand_scale``.
HEATING_DEMAND_MAX: Final = 100
#: Limits are accepted only inside this band (and inside valid abs limits).
LIMITS_BAND_C: Final = (5.0, 35.0)
SETPOINT_STEP_C: Final = 0.5
#: ``window_open(raw)``: 3/4 open, 1 closed (a hypothesis), anything else unknown.
WINDOW_OPEN_VALUES: Final = frozenset({3, 4})
WINDOW_CLOSED_VALUES: Final = frozenset({1})

# --- polling cadence (battery valves) ----------------------------------------------------

#: SLOW plan every n-th poll (the FAST plan runs every poll).
SLOW_EVERY_N_POLLS: Final = 6
#: STATIC plan at discovery and then at most this often.
STATIC_REFRESH_S: Final = 86_400.0

_TH, _K = CLUSTER_THERMOSTAT, ValueKind
_I16, _U8, _I8, _E8, _STR = (
    ZclDataType.INT16, ZclDataType.UINT8, ZclDataType.INT8, ZclDataType.ENUM8, ZclDataType.CHARSTR
)  # fmt: skip

# fmt: off
A_LOCAL_TEMPERATURE: Final = AttrSpec(_TH, ATTR_LOCAL_TEMPERATURE, _I16, None, _K.CENTI_CELSIUS, "local_temperature_c")  # noqa: E501
A_HEATING_DEMAND: Final = AttrSpec(_TH, ATTR_PI_HEATING_DEMAND, _U8, None, _K.DEMAND, "heating_demand")  # noqa: E501
A_SETPOINT: Final = AttrSpec(_TH, ATTR_OCCUPIED_HEATING_SETPOINT, _I16, None, _K.CENTI_CELSIUS, "setpoint_c")  # noqa: E501
A_SYSTEM_MODE: Final = AttrSpec(_TH, ATTR_SYSTEM_MODE, _E8, None, _K.ENUM8, "system_mode")
A_ABS_MIN_HEAT: Final = AttrSpec(_TH, ATTR_ABS_MIN_HEAT, _I16, None, _K.CENTI_CELSIUS)
A_ABS_MAX_HEAT: Final = AttrSpec(_TH, ATTR_ABS_MAX_HEAT, _I16, None, _K.CENTI_CELSIUS)
A_MIN_HEAT: Final = AttrSpec(_TH, ATTR_MIN_HEAT, _I16, None, _K.CENTI_CELSIUS)
A_MAX_HEAT: Final = AttrSpec(_TH, ATTR_MAX_HEAT, _I16, None, _K.CENTI_CELSIUS)
A_WINDOW_OPEN: Final = AttrSpec(_TH, ATTR_WINDOW_OPEN, _E8, MFR_VIESSMANN, _K.ENUM8, "window_open_raw")  # noqa: E501
A_BATTERY: Final = AttrSpec(CLUSTER_POWER, ATTR_BATTERY_PERCENTAGE, _U8, None, _K.HALF_PERCENT, "battery_pct")  # noqa: E501
A_LQI: Final = AttrSpec(CLUSTER_DIAGNOSTICS, ATTR_LAST_MESSAGE_LQI, _U8, None, _K.RAW_UINT8, "lqi")
A_RSSI: Final = AttrSpec(CLUSTER_DIAGNOSTICS, ATTR_LAST_MESSAGE_RSSI, _I8, None, _K.RAW_INT8, "rssi")  # noqa: E501
A_MANUFACTURER_NAME: Final = AttrSpec(CLUSTER_BASIC, ATTR_MANUFACTURER_NAME, _STR, None, _K.STRING)
A_MODEL_ID: Final = AttrSpec(CLUSTER_BASIC, ATTR_MODEL_ID, _STR, None, _K.STRING)
A_POWER_SOURCE: Final = AttrSpec(CLUSTER_BASIC, ATTR_POWER_SOURCE, _E8, None, _K.ENUM8)
#: Standard Basic attribute 0x4000 (swBuildID, ZCL r8), not manufacturer-specific.
A_SW_BUILD_ID: Final = AttrSpec(CLUSTER_BASIC, ATTR_SW_BUILD_ID, _STR, None, _K.STRING)
# fmt: on

ATTRS: Final = (
    A_LOCAL_TEMPERATURE,
    A_HEATING_DEMAND,
    A_SETPOINT,
    A_SYSTEM_MODE,
    A_ABS_MIN_HEAT,
    A_ABS_MAX_HEAT,
    A_MIN_HEAT,
    A_MAX_HEAT,
    A_WINDOW_OPEN,
    A_BATTERY,
    A_LQI,
    A_RSSI,
    A_MANUFACTURER_NAME,
    A_MODEL_ID,
    A_POWER_SOURCE,
    A_SW_BUILD_ID,
)


# --- read plans --------------------------------------------------------------------------

#: Every poll.
FAST: Final[ReadPlan] = (
    ReadRequest(
        CLUSTER_THERMOSTAT,
        (
            ATTR_LOCAL_TEMPERATURE,
            ATTR_PI_HEATING_DEMAND,
            ATTR_OCCUPIED_HEATING_SETPOINT,
            ATTR_SYSTEM_MODE,
        ),
    ),
)
#: Every ``SLOW_EVERY_N_POLLS``-th poll.
SLOW: Final[ReadPlan] = (
    ReadRequest(CLUSTER_POWER, (ATTR_BATTERY_PERCENTAGE,)),
    ReadRequest(CLUSTER_DIAGNOSTICS, (ATTR_LAST_MESSAGE_LQI, ATTR_LAST_MESSAGE_RSSI)),
    ReadRequest(CLUSTER_THERMOSTAT, (ATTR_WINDOW_OPEN,), MFR_VIESSMANN),
)
#: Identification: the Basic request of ``STATIC``; decides ``is_supported_valve``.
IDENTIFY: Final = ReadRequest(
    CLUSTER_BASIC, (ATTR_MANUFACTURER_NAME, ATTR_MODEL_ID, ATTR_POWER_SOURCE, ATTR_SW_BUILD_ID)
)
#: At discovery and every ``STATIC_REFRESH_S``.
STATIC: Final[ReadPlan] = (
    ReadRequest(
        CLUSTER_THERMOSTAT, (ATTR_ABS_MIN_HEAT, ATTR_ABS_MAX_HEAT, ATTR_MIN_HEAT, ATTR_MAX_HEAT)
    ),
    IDENTIFY,
)
#: Confirming read after a setpoint write.
CONFIRM_SETPOINT: Final = ReadRequest(CLUSTER_THERMOSTAT, (ATTR_OCCUPIED_HEATING_SETPOINT,))


__all__ = [
    "ATTRS",
    "ATTR_ABS_MAX_HEAT",
    "ATTR_ABS_MIN_HEAT",
    "ATTR_ASSEMBLY_MODE",
    "ATTR_BATTERY_PERCENTAGE",
    "ATTR_LAST_MESSAGE_LQI",
    "ATTR_LAST_MESSAGE_RSSI",
    "ATTR_LOCAL_TEMPERATURE",
    "ATTR_MANUFACTURER_NAME",
    "ATTR_MAX_HEAT",
    "ATTR_MIN_HEAT",
    "ATTR_MODEL_ID",
    "ATTR_OCCUPIED_HEATING_SETPOINT",
    "ATTR_PI_HEATING_DEMAND",
    "ATTR_POWER_SOURCE",
    "ATTR_SW_BUILD_ID",
    "ATTR_SYSTEM_MODE",
    "ATTR_WINDOW_OPEN",
    "A_ABS_MAX_HEAT",
    "A_ABS_MIN_HEAT",
    "A_BATTERY",
    "A_HEATING_DEMAND",
    "A_LOCAL_TEMPERATURE",
    "A_LQI",
    "A_MANUFACTURER_NAME",
    "A_MAX_HEAT",
    "A_MIN_HEAT",
    "A_MODEL_ID",
    "A_POWER_SOURCE",
    "A_RSSI",
    "A_SETPOINT",
    "A_SW_BUILD_ID",
    "A_SYSTEM_MODE",
    "A_WINDOW_OPEN",
    "BATTERY_RAW_MAX",
    "CLUSTER_BASIC",
    "CLUSTER_DIAGNOSTICS",
    "CLUSTER_POLL_CONTROL",
    "CLUSTER_POWER",
    "CLUSTER_THERMOSTAT",
    "CONFIRM_SETPOINT",
    "ENDPOINT",
    "FAST",
    "HEATING_DEMAND_MAX",
    "IDENTIFY",
    "INT8_SENTINEL",
    "LIMITS_BAND_C",
    "MANUFACTURER",
    "MFR_VIESSMANN",
    "MODEL_IDS",
    "MODEL_NAME",
    "OUI_HINT",
    "PROFILE",
    "SETPOINT_STEP_C",
    "SLOW",
    "SLOW_EVERY_N_POLLS",
    "STATIC",
    "STATIC_REFRESH_S",
    "TEMPERATURE_RANGE_C",
    "TEMPERATURE_SENTINEL",
    "UINT8_SENTINEL",
    "WINDOW_CLOSED_VALUES",
    "WINDOW_OPEN_VALUES",
]
