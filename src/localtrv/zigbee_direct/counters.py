"""Incoming frame-counter tracking and ZDD counter-model detection (docs/protocol.md §4).

Sans-IO, pure. ``SessionCipher`` owns one ``IncomingCounters`` and feeds it every accepted
peer frame counter. Detection never rejects anything.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from localtrv.zigbee_direct.uuids import COMMISSIONING_STATUS, TUNNEL_NPDU, uuid_bytes

#: Accepted counters remembered per characteristic for cross-characteristic repeat detection.
#: Status sees one or two frames per session, so a small window covers the overlap that matters
#: while keeping memory bounded on a busy Tunnel.
_REPEAT_WINDOW: Final = 64

_STATUS: Final = uuid_bytes(COMMISSIONING_STATUS)
_TUNNEL: Final = uuid_bytes(TUNNEL_NPDU)


class CounterModel(StrEnum):
    """How the ZDD numbers its outgoing frames across characteristics (docs/protocol.md §4).

    * ``SHARED``: one counter for the whole session; Tunnel's first counter is above the Status
      counter and no value repeats across characteristics.
    * ``PER_CHARACTERISTIC``: a counter value was accepted on two characteristics (the ZDD then
      reuses CCM nonces across characteristics; detected and reported, never rejected).
    * ``UNKNOWN``: not enough evidence yet.
    """

    UNKNOWN = "unknown"
    SHARED = "shared"
    PER_CHARACTERISTIC = "per_characteristic"


class IncomingCounters:
    """Last accepted counter per characteristic plus counter-model evidence.

    Edge-case choices:

    * Only one characteristic seen, or Tunnel's first counter at or below the Status counter
      without a repeat: ``UNKNOWN``.
    * ``PER_CHARACTERISTIC`` is sticky and wins over ``SHARED``: a repeat seen later flips an
      earlier ``SHARED`` verdict (the transport logs the first verdict it sees, so a late flip is
      visible in diagnostics only).
    * Repeat detection compares against the first ``_REPEAT_WINDOW`` accepted counters of each
      other characteristic.
    """

    __slots__ = ("_first", "_highest", "_last", "_per_char", "_recent", "_shared_evidence")

    def __init__(self) -> None:
        self._last: dict[bytes, int] = {}
        self._first: dict[bytes, int] = {}
        self._recent: dict[bytes, set[int]] = {}
        self._highest = 0
        self._shared_evidence = False
        self._per_char = False

    @property
    def highest(self) -> int:
        """Highest counter accepted on any characteristic (0 before any frame)."""
        return self._highest

    def last(self, char: bytes) -> int:
        """Last accepted counter on ``char`` (0 if none)."""
        return self._last.get(char, 0)

    def is_replay(self, char: bytes, counter: int) -> bool:
        return counter <= self._last.get(char, 0)

    def accept(self, char: bytes, counter: int) -> None:
        """Record an authenticated frame counter (caller already checked ``is_replay``)."""
        first_on_char = char not in self._last
        if not self._per_char:
            for other, seen in self._recent.items():
                if other != char and counter in seen:
                    self._per_char = True
                    break
        if first_on_char:
            self._first[char] = counter
            if char == _TUNNEL and _STATUS in self._last and counter > self._last[_STATUS]:
                self._shared_evidence = True
        recent = self._recent.setdefault(char, set())
        if len(recent) < _REPEAT_WINDOW:
            recent.add(counter)
        self._last[char] = counter
        self._highest = max(self._highest, counter)

    def model(self) -> CounterModel:
        if self._per_char:
            return CounterModel.PER_CHARACTERISTIC
        if self._shared_evidence:
            return CounterModel.SHARED
        return CounterModel.UNKNOWN


__all__ = ["CounterModel", "IncomingCounters"]
