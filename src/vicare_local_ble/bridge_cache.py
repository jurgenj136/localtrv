"""Persisted bridge state: ``BridgeCache``/``CachedValve`` and their JSON round trip (T14).

Re-exported from ``vicare_local_ble.bridge``. No key material, ever: only shorts, EUIs (display
form), identification strings and validated limits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Self

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vicare_local_ble.valves import Valve

CACHE_VERSION: Final = 1

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None


@dataclass(frozen=True, slots=True)
class CachedValve:
    """Persisted identity of a valve (``eui`` in display form); limits in °C."""

    eui: str
    short: int
    endpoint: int
    manufacturer: str | None
    model: str | None
    sw_build: str | None
    min_c: float | None = None
    max_c: float | None = None

    @classmethod
    def from_valve(cls, valve: Valve) -> Self:
        raise NotImplementedError("T14")

    def to_valve(self) -> Valve:
        """Back to a ``Valve``; limits revalidated through ``valves.SetpointLimits``."""
        raise NotImplementedError("T14")


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
        raise NotImplementedError("T14")

    @classmethod
    def from_json(cls, data: object) -> Self:
        """Inverse of ``to_json``. Malformed data, or another version, yields an empty cache
        (logged at WARNING) rather than raising: a cache is never worth a failed setup."""
        raise NotImplementedError("T14")


__all__ = ["CACHE_VERSION", "BridgeCache", "CachedValve", "JsonValue"]
