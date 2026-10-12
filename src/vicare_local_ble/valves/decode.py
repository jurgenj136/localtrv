"""Validation, scaling and identification functions (T4). Pure: no I/O, no logging."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from vicare_local_ble.valves.models import (
        AttrIssue,
        AttrSpec,
        BasicInfo,
        SetpointLimits,
        ValveState,
    )
    from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord, ReadAttributeStatus
    from vicare_local_ble.zigbee_direct.types import Eui64


def spec_for(cluster: int, attr: int, *, manufacturer: int | None) -> AttrSpec | None:
    """The ``AttrSpec`` for an attribute, or ``None`` if it is not a v1 attribute."""
    raise NotImplementedError("T4")


def decode_attr(spec: AttrSpec, data_type: int | None, value: object) -> float | int | str | None:
    """Validate type, sentinel and range, then scale; ``None`` if invalid."""
    raise NotImplementedError("T4")


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
    raise NotImplementedError("T4")


def read_issues(
    cluster: int,
    statuses: Iterable[ReadAttributeStatus | AttributeRecord],
    *,
    manufacturer: int | None,
) -> tuple[AttrIssue, ...]:
    """Pure: the ``AttrIssue``s ``apply_reads`` would encounter (for once-per-valve logging)."""
    raise NotImplementedError("T4")


def parse_basic(statuses: Iterable[ReadAttributeStatus]) -> BasicInfo:
    """``BasicInfo`` from an ``IDENTIFY`` read response."""
    raise NotImplementedError("T4")


def is_supported_valve(manufacturer: str | None, model: str | None) -> bool:
    """True for ``MANUFACTURER`` with a model in ``MODEL_IDS`` (exact match after strip)."""
    raise NotImplementedError("T4")


def has_oui_hint(eui: Eui64) -> bool:
    """True if ``eui`` starts with ``OUI_HINT`` (identification order only)."""
    raise NotImplementedError("T4")


def clamp_setpoint(celsius: float, limits: SetpointLimits) -> float:
    """Clamp to ``limits`` and round to 0.01 °C; ``ValueError`` for a non-finite input."""
    raise NotImplementedError("T4")


def setpoint_record(celsius: float, limits: SetpointLimits) -> AttributeRecord:
    """Write record for ``occupiedHeatingSetpoint``: ``clamp_setpoint`` then int16 centi-°C,
    type 0x29. ``ValueError`` for a non-finite input."""
    raise NotImplementedError("T4")


def window_open(raw: int | None) -> bool | None:
    """3 or 4 -> True, 1 -> False (hypothesis), anything else -> None."""
    raise NotImplementedError("T4")


__all__ = [
    "apply_reads",
    "clamp_setpoint",
    "decode_attr",
    "has_oui_hint",
    "is_supported_valve",
    "parse_basic",
    "read_issues",
    "setpoint_record",
    "spec_for",
    "window_open",
]
