"""Valve data models: attribute specs, read requests, limits, valve and state (T4 implements).

No imports from ``constants`` (it imports this module).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Literal

if TYPE_CHECKING:
    from collections.abc import Iterable

    from vicare_local_ble.zigbee_direct.codec.zcl import ReadAttributeStatus
    from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
    from vicare_local_ble.zigbee_direct.types import Eui64

#: Fallback setpoint limits when neither min/max nor abs limits are valid.
DEFAULT_LIMITS_C: Final = (8.0, 30.0)
#: Mirror of ``constants.LIMITS_BAND_C`` (constants imports this module); a test pins equality.
_LIMITS_BAND_C: Final = (5.0, 35.0)


class ValueKind(StrEnum):
    """How a raw attribute value is validated and scaled into a ``ValveState`` field."""

    CENTI_CELSIUS = "centi_celsius"
    HALF_PERCENT = "half_percent"
    DEMAND = "demand"
    RAW_UINT8 = "raw_uint8"
    RAW_INT8 = "raw_int8"
    ENUM8 = "enum8"
    STRING = "string"


type StateField = Literal[
    "local_temperature_c",
    "setpoint_c",
    "heating_demand",
    "system_mode",
    "battery_pct",
    "lqi",
    "rssi",
    "window_open_raw",
]


@dataclass(frozen=True, slots=True)
class AttrSpec:
    """One v1 attribute: where it lives, its expected ZCL type and how it is decoded.

    ``manufacturer`` is the ZCL manufacturer code for manufacturer-specific attributes (they
    need their own request with the MS bit). ``field`` is the ``ValveState`` field it feeds, or
    ``None`` for attributes that feed ``Valve``/``SetpointLimits``/``BasicInfo`` instead.
    ``decode`` names the validation/scaling rule (``ValueKind``); T4 implements it in
    ``decode_attr``.
    """

    cluster: int
    attr: int
    zcl_type: ZclDataType
    manufacturer: int | None
    decode: ValueKind
    field: StateField | None = None


@dataclass(frozen=True, slots=True)
class ReadRequest:
    """One Read Attributes frame: one cluster, one manufacturer flag, at most 4 attributes."""

    cluster: int
    attrs: tuple[int, ...]
    manufacturer: int | None = None


type ReadPlan = tuple[ReadRequest, ...]


def _pair(low: float | None, high: float | None) -> tuple[float, float] | None:
    """``(low, high)`` if ``5 <= low < high <= 35`` (``LIMITS_BAND_C``); ``None``/NaN: invalid."""
    if low is None or high is None:
        return None
    band_low, band_high = _LIMITS_BAND_C
    return (low, high) if band_low <= low < high <= band_high else None


@dataclass(frozen=True, slots=True)
class SetpointLimits:
    """Validated setpoint limits in °C; ``source`` says which rule produced them."""

    min_c: float
    max_c: float
    source: Literal["limits", "abs", "default"] = "default"

    @classmethod
    def from_attrs(
        cls,
        *,
        min_c: float | None,
        max_c: float | None,
        abs_min_c: float | None = None,
        abs_max_c: float | None = None,
    ) -> SetpointLimits:
        """Accept min/max only if ``5 <= min < max <= 35`` and inside valid abs limits; else
        valid abs limits; else ``DEFAULT_LIMITS_C``. Invalid limits are never applied.

        A pair counts as valid only as a pair (both present, finite, ``5 <= lo < hi <= 35``);
        the abs pair is held to the same band as min/max."""
        limits = _pair(min_c, max_c)
        absolute = _pair(abs_min_c, abs_max_c)
        if absolute is None:
            return cls(*limits, "limits") if limits else DEFAULT_LIMITS
        if limits and absolute[0] <= limits[0] and limits[1] <= absolute[1]:
            return cls(*limits, "limits")
        return cls(*absolute, "abs")

    @classmethod
    def from_reads(cls, statuses: Iterable[ReadAttributeStatus]) -> SetpointLimits:
        """``from_attrs`` over a STATIC Thermostat read (validated and scaled first)."""
        from vicare_local_ble.valves import constants as c
        from vicare_local_ble.valves.decode import _decode, _entries

        by_attr: dict[int, float | None] = {}
        for spec, data_type, value in _entries(c.CLUSTER_THERMOSTAT, statuses, None):
            got = _decode(spec, data_type, value)[0]
            by_attr[spec.attr] = float(got) if isinstance(got, int | float) else None
        return cls.from_attrs(
            min_c=by_attr.get(c.ATTR_MIN_HEAT),
            max_c=by_attr.get(c.ATTR_MAX_HEAT),
            abs_min_c=by_attr.get(c.ATTR_ABS_MIN_HEAT),
            abs_max_c=by_attr.get(c.ATTR_ABS_MAX_HEAT),
        )


DEFAULT_LIMITS: Final = SetpointLimits(*DEFAULT_LIMITS_C, source="default")


@dataclass(frozen=True, slots=True)
class BasicInfo:
    """Identification values from the ``IDENTIFY`` read; ``None`` if missing or invalid."""

    manufacturer: str | None
    model: str | None
    power_source: int | None
    sw_build: str | None


@dataclass(frozen=True, slots=True)
class Valve:
    """A discovered, supported valve. ``short`` may change; ``eui`` is the identity."""

    eui: Eui64
    short: int
    endpoint: int
    manufacturer: str | None
    model: str | None
    sw_build: str | None
    limits: SetpointLimits = DEFAULT_LIMITS


@dataclass(frozen=True, slots=True)
class ValveState:
    """Last known values; every field is ``None`` until a valid value was seen.

    ``heating_demand`` is raw (0-7 scale, not percent). ``battery_pct`` is percent (raw/2).
    ``system_mode`` and ``window_open_raw`` are raw enum values. ``updated_at`` is the clock time
    of the last change applied by ``apply_reads``.
    """

    local_temperature_c: float | None = None
    setpoint_c: float | None = None
    heating_demand: int | None = None
    system_mode: int | None = None
    battery_pct: float | None = None
    lqi: int | None = None
    rssi: int | None = None
    window_open_raw: int | None = None
    updated_at: float | None = None


@dataclass(frozen=True, slots=True)
class AttrIssue:
    """A value that was rejected or is suspicious; the bridge logs each once per valve."""

    cluster: int
    attr: int
    kind: Literal["type", "sentinel", "range", "demand_scale"]


__all__ = [
    "DEFAULT_LIMITS",
    "DEFAULT_LIMITS_C",
    "AttrIssue",
    "AttrSpec",
    "BasicInfo",
    "ReadPlan",
    "ReadRequest",
    "SetpointLimits",
    "StateField",
    "ValueKind",
    "Valve",
    "ValveState",
]
