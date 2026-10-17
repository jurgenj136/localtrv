"""Validation, scaling and identification functions. Pure: no I/O, no logging."""

from __future__ import annotations

import dataclasses
import math
from typing import TYPE_CHECKING, Any, Final, Literal

from localtrv.valves.constants import (
    A_MANUFACTURER_NAME,
    A_MODEL_ID,
    A_POWER_SOURCE,
    A_SW_BUILD_ID,
    ATTR_OCCUPIED_HEATING_SETPOINT,
    ATTRS,
    BATTERY_RAW_MAX,
    CLUSTER_BASIC,
    HEATING_DEMAND_MAX,
    INT8_SENTINEL,
    MANUFACTURER,
    MODEL_IDS,
    OUI_HINT,
    TEMPERATURE_RANGE_C,
    TEMPERATURE_SENTINEL,
    UINT8_SENTINEL,
    WINDOW_CLOSED_VALUES,
    WINDOW_OPEN_VALUES,
)
from localtrv.valves.models import AttrIssue, BasicInfo, ValueKind
from localtrv.zigbee_direct.codec.zcl import AttributeRecord, ReadAttributeStatus
from localtrv.zigbee_direct.codec.zcl_types import ZclDataType

if TYPE_CHECKING:
    from collections.abc import Iterable

    from localtrv.valves.models import AttrSpec, SetpointLimits, ValveState
    from localtrv.zigbee_direct.types import Eui64

type _Value = float | int | str | None
type _IssueKind = Literal["type", "sentinel", "range", "demand_scale"]

_SPECS: Final = {(a.cluster, a.attr, a.manufacturer): a for a in ATTRS}
_ZCL_SUCCESS: Final = 0x00


def spec_for(cluster: int, attr: int, *, manufacturer: int | None) -> AttrSpec | None:
    """The ``AttrSpec`` for an attribute, or ``None`` if it is not a v1 attribute."""
    return _SPECS.get((cluster, attr, manufacturer))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _decode(
    spec: AttrSpec, data_type: int | None, value: object
) -> tuple[_Value, _IssueKind | None]:
    """Decode one value; returns ``(result, issue)``. ``result`` is ``None`` when invalid."""
    if data_type != spec.zcl_type:
        return None, "type"
    kind = spec.decode
    if kind is ValueKind.STRING:
        if not isinstance(value, str):
            return None, "type"
        return (value.strip() or None), None
    if not _is_int(value) or not isinstance(value, int):
        return None, "type"
    if kind is ValueKind.CENTI_CELSIUS:
        if value == TEMPERATURE_SENTINEL:
            return None, "sentinel"
        celsius = round(value / 100, 2)
        low, high = TEMPERATURE_RANGE_C
        return (celsius, None) if low <= celsius <= high else (None, "range")
    if kind is ValueKind.RAW_INT8:
        return (None, "sentinel") if value == INT8_SENTINEL else (value, None)
    # Remaining kinds are unsigned 8-bit with 0xFF as the sentinel.
    if value == UINT8_SENTINEL:
        return None, "sentinel"
    if kind is ValueKind.HALF_PERCENT:
        return (value / 2, None) if 0 <= value <= BATTERY_RAW_MAX else (None, "range")
    if kind is ValueKind.DEMAND and value > HEATING_DEMAND_MAX:
        return value, "demand_scale"
    return value, None


def decode_attr(spec: AttrSpec, data_type: int | None, value: object) -> float | int | str | None:
    """Validate type, sentinel and range, then scale; ``None`` if invalid."""
    return _decode(spec, data_type, value)[0]


def _entries(
    cluster: int,
    statuses: Iterable[ReadAttributeStatus | AttributeRecord],
    manufacturer: int | None,
) -> Iterable[tuple[AttrSpec, int | None, object]]:
    """``(spec, data_type, value)`` for every successful, known-attribute record."""
    for item in statuses:
        if isinstance(item, ReadAttributeStatus) and item.status != _ZCL_SUCCESS:
            continue
        spec = spec_for(cluster, item.attribute_id, manufacturer=manufacturer)
        if spec is not None:
            yield spec, item.data_type, item.value


def apply_reads(
    state: ValveState,
    cluster: int,
    statuses: Iterable[ReadAttributeStatus | AttributeRecord],
    *,
    manufacturer: int | None,
    at: float | None = None,
) -> ValveState:
    """Pure: a new state with every v1 ``field`` attribute of ``cluster`` applied.

    Accepts read records and report records alike. Invalid values set the field to ``None``;
    non-success read statuses and unknown attributes leave it unchanged. ``updated_at`` becomes
    ``at`` if any field changed.
    """
    changes: dict[str, Any] = {}
    for spec, data_type, value in _entries(cluster, statuses, manufacturer):
        if spec.field is None:
            continue
        new = _decode(spec, data_type, value)[0]
        if new != getattr(state, spec.field):
            changes[spec.field] = new
        else:
            changes.pop(spec.field, None)
    if not changes:
        return state
    if at is not None:
        changes["updated_at"] = at
    return dataclasses.replace(state, **changes)


def read_issues(
    cluster: int,
    statuses: Iterable[ReadAttributeStatus | AttributeRecord],
    *,
    manufacturer: int | None,
) -> tuple[AttrIssue, ...]:
    """Pure: the ``AttrIssue``s ``apply_reads`` would encounter (for once-per-valve logging)."""
    issues: list[AttrIssue] = []
    for spec, data_type, value in _entries(cluster, statuses, manufacturer):
        kind = _decode(spec, data_type, value)[1]
        if kind is not None:
            issues.append(AttrIssue(spec.cluster, spec.attr, kind))
    return tuple(issues)


def parse_basic(statuses: Iterable[ReadAttributeStatus]) -> BasicInfo:
    """``BasicInfo`` from an ``IDENTIFY`` read response."""
    found: dict[int, _Value] = {}
    for spec, data_type, value in _entries(CLUSTER_BASIC, statuses, None):
        found[spec.attr] = _decode(spec, data_type, value)[0]

    def text(spec: AttrSpec) -> str | None:
        got = found.get(spec.attr)
        return got if isinstance(got, str) else None

    power = found.get(A_POWER_SOURCE.attr)
    return BasicInfo(
        manufacturer=text(A_MANUFACTURER_NAME),
        model=text(A_MODEL_ID),
        power_source=power if isinstance(power, int) else None,
        sw_build=text(A_SW_BUILD_ID),
    )


def is_supported_valve(manufacturer: str | None, model: str | None) -> bool:
    """True for ``MANUFACTURER`` with a model in ``MODEL_IDS`` (exact match after strip)."""
    if manufacturer is None or model is None:
        return False
    return manufacturer.strip() == MANUFACTURER and model.strip() in MODEL_IDS


def has_oui_hint(eui: Eui64) -> bool:
    """True if ``eui`` starts with one of ``OUI_HINT`` (identification order only)."""
    return str(eui).upper().startswith(tuple(oui.upper() for oui in OUI_HINT))


def heating_active(demand: int | None) -> bool | None:
    """``demand > 0`` for a demand on the accepted scale (0..``HEATING_DEMAND_MAX``), else
    ``None`` (unknown, or flagged ``demand_scale``)."""
    if demand is None or not _is_int(demand) or not 0 <= demand <= HEATING_DEMAND_MAX:
        return None
    return demand > 0


def clamp_setpoint(celsius: float, limits: SetpointLimits) -> float:
    """Clamp to ``limits`` and round to 0.01 °C; ``ValueError`` for a non-finite input."""
    if not math.isfinite(celsius):
        raise ValueError("setpoint must be finite")
    return round(min(max(celsius, limits.min_c), limits.max_c), 2)


def setpoint_record(celsius: float, limits: SetpointLimits) -> AttributeRecord:
    """Write record for ``occupiedHeatingSetpoint``: ``clamp_setpoint`` then int16 centi-°C,
    type 0x29. ``ValueError`` for a non-finite input."""
    centi = round(clamp_setpoint(celsius, limits) * 100)
    return AttributeRecord(ATTR_OCCUPIED_HEATING_SETPOINT, ZclDataType.INT16, centi)


def window_open(raw: int | None) -> bool | None:
    """3 or 4 -> True, 1 -> False (hypothesis), anything else -> None."""
    if raw is None or not _is_int(raw):
        return None
    if raw in WINDOW_OPEN_VALUES:
        return True
    if raw in WINDOW_CLOSED_VALUES:
        return False
    return None


__all__ = [
    "apply_reads",
    "clamp_setpoint",
    "decode_attr",
    "has_oui_hint",
    "heating_active",
    "is_supported_valve",
    "parse_basic",
    "read_issues",
    "setpoint_record",
    "spec_for",
    "window_open",
]
