"""Short ownership of the known valves: authoritative evidence and leases (internal).

One EUI per short. Only authoritative evidence moves or evicts ownership (``seen_at``): a
Device_annce, a frame whose NWK header names its source IEEE, or an IEEE_addr response from the
short asked. Walk results (router neighbor tables) are hints only and never reach this module
directly: ``bridge_verify`` confirms them with IEEE_addr_req first. Evidence for another EUI at
a short makes the valve cached there unaddressed. Restored (cached) shorts are trusted, except
a short the cache lists for two valves (neither is trusted).

A request runs under a ``Lease`` taken when it starts. A valve lease (``lease``/``holds``) needs
the valve still addressed at the lease's short; every lease (``holds_short``) needs that no
evidence changed the short's EUI since the lease began, and that no evidence placed the lease's
EUI at another short since (it moved away, so whatever answers at the lease's short may be
another device). Both use ownership epochs, so the checks never depend on clock ties.
``check``/``check_short`` raise ``ValveAddressUnknownError``; they are the node ``guard`` of
every valve and identification request (before queueing, at transmission) and run again on the
answer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from vicare_local_ble.bridge_types import ValveAddressUnknownError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vicare_local_ble.valves import Valve
    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.bridge")


@dataclass(frozen=True, slots=True)
class Lease:
    """``eui`` was at ``short`` at ownership epoch ``epoch`` (see module docstring)."""

    eui: Eui64
    short: int
    epoch: int


class Ownership:
    """The ownership state of the bridge (see module docstring). ``valves`` is the bridge's
    live valve map (read only here)."""

    def __init__(self, valves: Mapping[Eui64, Valve], clock: Clock) -> None:
        self._valves = valves
        self._clock = clock
        #: Valves without a trusted short: no ZCL request is sent to them.
        self.unaddressed: set[Eui64] = _duplicate_shorts(valves)
        #: Latest EUI evidenced at each short and when (valve or not).
        self.short_seen: dict[int, tuple[Eui64, float]] = {}
        self._epoch = 0
        self._changed: dict[int, int] = {}
        #: Per EUI: the short it was last evidenced at and the epoch of that move.
        self._moved: dict[Eui64, tuple[int, int]] = {}

    def seen_at(self, eui: Eui64, short: int, at: float | None = None) -> bool:
        """Authoritative evidence: ``eui`` is at ``short`` as of ``at`` (default now). True if
        another valve lost the short."""
        at = self._clock.now() if at is None else at
        seen = self.short_seen.get(short)
        if seen is not None and seen[1] > at:
            return False  # newer evidence exists for this short
        previous = seen[0] if seen is not None else self.owner(short)  # first record: cache
        if previous != eui:
            self._epoch += 1
            self._changed[short] = self._epoch
        if self._last_short(eui) != short:
            self._epoch += 1
            self._moved[eui] = (short, self._epoch)
        self.short_seen[short] = (eui, at)
        taken = False
        for other, valve in self._valves.items():
            if other != eui and valve.short == short and other not in self.unaddressed:
                _LOGGER.debug("valve %s: short 0x%04X taken by %s", other, short, eui)
                self.unaddressed.add(other)
                taken = True
        return taken

    def claim(self, eui: Eui64, short: int, at: float) -> None:
        """Valve ``eui`` was learned at ``short`` as of ``at``: it is addressed there."""
        self.unaddressed.discard(eui)
        self.seen_at(eui, short, at)

    def owner(self, short: int) -> Eui64 | None:
        """The addressed valve at ``short``, if any."""
        for eui, valve in self._valves.items():
            if valve.short == short and eui not in self.unaddressed:
                return eui
        return None

    def evicted(self, eui: Eui64) -> bool:
        """Unaddressed because evidence names another device at its cached short (asking that
        short again is pointless until new evidence arrives)."""
        seen = self.short_seen.get(self._valves[eui].short)
        return eui in self.unaddressed and seen is not None and seen[0] != eui

    def lease(self, eui: Eui64) -> Lease:
        """A lease on valve ``eui``'s short; ``ValveAddressUnknownError`` if it has none."""
        short = self._valves[eui].short
        if eui in self.unaddressed:
            raise ValveAddressUnknownError(short)
        return Lease(eui, short, self._epoch)

    def short_lease(self, eui: Eui64, short: int) -> Lease:
        """A lease on ``short`` for a device that is not (yet) a known valve."""
        return Lease(eui, short, self._epoch)

    def holds_short(self, lease: Lease) -> bool:
        if self._changed.get(lease.short, 0) > lease.epoch:
            return False
        moved = self._moved.get(lease.eui)
        return moved is None or moved[0] == lease.short or moved[1] <= lease.epoch

    def _last_short(self, eui: Eui64) -> int | None:
        moved = self._moved.get(eui)
        if moved is not None:
            return moved[0]
        valve = self._valves.get(eui)
        return valve.short if valve is not None else None

    def holds(self, lease: Lease) -> bool:
        return (
            lease.eui not in self.unaddressed
            and self._valves[lease.eui].short == lease.short
            and self.holds_short(lease)
        )

    def check(self, lease: Lease) -> None:
        """Raise ``ValveAddressUnknownError`` unless the valve lease still holds."""
        if not self.holds(lease):
            raise ValveAddressUnknownError(lease.short)

    def check_short(self, lease: Lease) -> None:
        """Raise ``ValveAddressUnknownError`` unless no evidence changed the short since."""
        if not self.holds_short(lease):
            raise ValveAddressUnknownError(lease.short)


def _duplicate_shorts(cached: Mapping[Eui64, Valve]) -> set[Eui64]:
    """Valves the cache lists at a shared short: none of them is trusted with it."""
    by_short: dict[int, list[Eui64]] = {}
    for eui, valve in cached.items():
        by_short.setdefault(valve.short, []).append(eui)
    return {eui for euis in by_short.values() if len(euis) > 1 for eui in euis}


__all__ = ["Lease", "Ownership"]
