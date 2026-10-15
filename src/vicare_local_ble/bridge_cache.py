"""Persisted bridge state: ``BridgeCache``/``CachedValve`` and their JSON round trip (T14).

Re-exported from ``vicare_local_ble.bridge``. No key material, ever: only shorts, EUIs (display
form), identification strings and validated limits.
"""

from __future__ import annotations

import dataclasses
import logging
import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Literal, Self

from vicare_local_ble.valves import SetpointLimits, Valve
from vicare_local_ble.zigbee_direct.types import Eui64, validate_short

if TYPE_CHECKING:
    from collections.abc import Mapping

CACHE_VERSION: Final = 1

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None
#: The ``SetpointLimits.source`` values a cache records (``"cached"`` is stored as ``None``).
type _StoredSource = Literal["limits", "abs"]

_LOGGER = logging.getLogger("vicare_local_ble.bridge")
_ENDPOINT_RANGE: Final = (1, 240)


class _BadCacheError(ValueError):
    """Internal: the persisted data does not have the expected shape."""


@dataclass(frozen=True, slots=True)
class CachedValve:
    """Persisted identity of a valve (``eui`` in display form); limits in °C.

    ``limits_source`` is the ``SetpointLimits.source`` of the limits. ``None`` (caches written
    by 0.1.0a1 and earlier have no such field) loads them as provisional ``"cached"`` limits.
    """

    eui: str
    short: int
    endpoint: int
    manufacturer: str | None
    model: str | None
    sw_build: str | None
    min_c: float | None = None
    max_c: float | None = None
    limits_source: _StoredSource | None = None

    @classmethod
    def from_valve(cls, valve: Valve) -> Self:
        limits = valve.limits
        keep = limits.source != "default"
        source: _StoredSource | None
        match limits.source:
            case "limits" | "abs":
                source = limits.source
            case _:
                source = None
        return cls(
            eui=str(valve.eui),
            short=valve.short,
            endpoint=valve.endpoint,
            manufacturer=valve.manufacturer,
            model=valve.model,
            sw_build=valve.sw_build,
            min_c=limits.min_c if keep else None,
            max_c=limits.max_c if keep else None,
            limits_source=source,
        )

    def to_valve(self) -> Valve:
        """Back to a ``Valve``; limits revalidated through ``valves.SetpointLimits``."""
        return Valve(
            eui=Eui64.from_str(self.eui),
            short=self.short,
            endpoint=self.endpoint,
            manufacturer=self.manufacturer,
            model=self.model,
            sw_build=self.sw_build,
            limits=self._limits(),
        )

    def _limits(self) -> SetpointLimits:
        if self.limits_source == "abs":
            return SetpointLimits.from_attrs(
                min_c=None, max_c=None, abs_min_c=self.min_c, abs_max_c=self.max_c
            )
        limits = SetpointLimits.from_attrs(min_c=self.min_c, max_c=self.max_c)
        if self.limits_source is None and limits.source != "default":
            return dataclasses.replace(limits, source="cached")
        return limits

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "eui": self.eui,
            "short": self.short,
            "endpoint": self.endpoint,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "sw_build": self.sw_build,
            "min_c": self.min_c,
            "max_c": self.max_c,
            "limits_source": self.limits_source,
        }

    @classmethod
    def from_json(cls, data: object) -> Self:
        """Strict inverse of ``to_json``; ``_BadCacheError`` on any deviation."""
        if not isinstance(data, dict):
            raise _BadCacheError("valve entry is not an object")
        endpoint = _int(data.get("endpoint"), *_ENDPOINT_RANGE)
        return cls(
            eui=_eui(data.get("eui")),
            short=_short(data.get("short")),
            endpoint=endpoint,
            manufacturer=_opt_str(data.get("manufacturer")),
            model=_opt_str(data.get("model")),
            sw_build=_opt_str(data.get("sw_build")),
            min_c=_opt_float(data.get("min_c")),
            max_c=_opt_float(data.get("max_c")),
            limits_source=_opt_source(data.get("limits_source")),
        )


@dataclass(frozen=True, slots=True)
class BridgeCache:
    """Everything the integration persists between restarts (HA ``Store``). No key material.

    ``own_short`` feeds ``NodeConfig.preferred_short``; valve shorts feed ``avoid_shorts``.
    ``ignored`` are EUIs identified as not supported (not re-identified every discovery).
    """

    own_short: int | None = None
    zdd_eui: str | None = None
    valves: Mapping[str, CachedValve] = field(default_factory=dict)
    ignored: frozenset[str] = frozenset()

    def to_json(self) -> dict[str, JsonValue]:
        """JSON-serialisable dict with ``"version": CACHE_VERSION``."""
        return {
            "version": CACHE_VERSION,
            "own_short": self.own_short,
            "zdd_eui": self.zdd_eui,
            "valves": {eui: v.to_json() for eui, v in sorted(self.valves.items())},
            "ignored": list[JsonValue](sorted(self.ignored)),
        }

    @classmethod
    def from_json(cls, data: object) -> Self:
        """Inverse of ``to_json``. Malformed data, or another version, yields an empty cache
        (logged at WARNING) rather than raising: a cache is never worth a failed setup."""
        try:
            return cls._parse(data)
        except (_BadCacheError, ValueError, TypeError) as exc:
            _LOGGER.warning("ignoring the stored bridge cache: %s", _reason(exc))
            return cls()

    @classmethod
    def _parse(cls, data: object) -> Self:
        if not isinstance(data, dict):
            raise _BadCacheError("not an object")
        version = data.get("version")
        if type(version) is not int or version != CACHE_VERSION:
            raise _BadCacheError("unsupported version")
        own = data.get("own_short")
        zdd = data.get("zdd_eui")
        raw_valves = data.get("valves", {})
        raw_ignored = data.get("ignored", [])
        if not isinstance(raw_valves, dict) or not isinstance(raw_ignored, list):
            raise _BadCacheError("valves or ignored have the wrong type")
        valves: dict[str, CachedValve] = {}
        for key, entry in raw_valves.items():
            valve = CachedValve.from_json(entry)
            if _eui(key) != valve.eui:
                raise _BadCacheError("valve key does not match its EUI")
            valves[valve.eui] = valve
        return cls(
            own_short=None if own is None else _short(own),
            zdd_eui=None if zdd is None else _eui(zdd),
            valves=valves,
            ignored=frozenset(_eui(item) for item in raw_ignored),
        )


def _reason(exc: BaseException) -> str:
    """A log-safe reason: our own messages only (never echo the stored values)."""
    return str(exc) if isinstance(exc, _BadCacheError) else "malformed data"


def _int(value: object, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise _BadCacheError("integer field out of range")
    return value


def _short(value: object) -> int:
    if type(value) is not int:
        raise _BadCacheError("short address has the wrong type")
    try:
        return validate_short(value)
    except ValueError as exc:
        raise _BadCacheError("short address out of range") from exc


def _opt_str(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise _BadCacheError("string field has the wrong type")


def _opt_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _BadCacheError("number field has the wrong type")
    if not math.isfinite(value):
        raise _BadCacheError("number field is not finite")
    return float(value)


def _opt_source(value: object) -> _StoredSource | None:
    if value is None:
        return None
    if value == "limits":
        return "limits"
    if value == "abs":
        return "abs"
    raise _BadCacheError("limits source is not recognised")


def _eui(value: object) -> str:
    if not isinstance(value, str):
        raise _BadCacheError("EUI is not a string")
    try:
        return str(Eui64.from_str(value))
    except ValueError as exc:
        raise _BadCacheError("invalid EUI") from exc


__all__ = ["CACHE_VERSION", "BridgeCache", "CachedValve", "JsonValue"]
