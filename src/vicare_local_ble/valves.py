"""Viessmann ZK03840 radiator valve mapping (phase-2 stub).

This is the ONLY module with Viessmann-specific knowledge; ``zigbee_direct`` stays generic.

The valve exposes endpoint 1 (profile 0x0104, Home Automation) with the Thermostat cluster
0x0201:

* 0x0000 local temperature, int16, centi-degrees Celsius
* 0x0008 PI heating demand, uint8, percent
* 0x0012 occupied heating setpoint, int16, centi-degrees Celsius (writable, persists)

Coexistence: writes must coexist with the schedules managed through ViCare; a setpoint write is
a manual override from the valve's point of view, so callers should read before writing.
"""

from __future__ import annotations

from dataclasses import dataclass

ENDPOINT = 1
PROFILE_HA = 0x0104
CLUSTER_THERMOSTAT = 0x0201
ATTR_LOCAL_TEMPERATURE = 0x0000
ATTR_PI_HEATING_DEMAND = 0x0008
ATTR_OCCUPIED_HEATING_SETPOINT = 0x0012


@dataclass(frozen=True, slots=True)
class Valve:
    """State of one valve. Temperatures in centi-degrees Celsius, demand in percent."""

    eui64: str
    local_temperature_centi_c: int | None = None
    pi_heating_demand_pct: int | None = None
    occupied_heating_setpoint_centi_c: int | None = None
