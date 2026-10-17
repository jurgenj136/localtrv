"""Fault-injection types of the simulated R0 and the pending write-fault queue.

The public names are re-exported by ``testing.gatt`` (the documented import path).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from vicare_local_ble.testing.errors import GATT_ERROR_UNLIKELY

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu

type Se3Fault = Literal["none", "gatt_error", "disconnect"]
type ReplayBehavior = Literal["silent_drop", "gatt_error"]
type OversizeBehavior = Literal["truncate", "drop", "reject"]
type WriteFault = Literal["raise", "hang", "disconnect"]
type HandshakeFault = Literal["none", "se2_silence", "se4_silence", "malformed_se2"]


class TunnelPeer(Protocol):
    """The network behind the R0 (``SimNetwork`` implements it)."""

    def on_zvd_npdu(self, npdu: TunnelNpdu) -> None:
        """A decrypted Tunnel write from the ZVD (sync; schedule replies on the clock)."""
        ...

    def on_session_reset(self) -> None:
        """The BLE session ended (disconnect or reboot): drop join and gating state."""
        ...


@dataclass(frozen=True, slots=True)
class WriteFaultSpec:
    """One pending write fault: applies to the ``after_writes``-th next write on ``char``
    (0 = the next one), then is consumed. ``code`` is the ATT code for ``"raise"``."""

    kind: WriteFault
    char: str
    after_writes: int = 0
    code: int = GATT_ERROR_UNLIKELY


class _PendingFault:
    __slots__ = ("remaining", "spec")

    def __init__(self, spec: WriteFaultSpec) -> None:
        self.spec = spec
        self.remaining = spec.after_writes


class WriteFaultQueue:
    """Pending ``WriteFaultSpec``s; each write on a characteristic counts down its specs."""

    __slots__ = ("_pending",)

    def __init__(self) -> None:
        self._pending: list[_PendingFault] = []

    def add(self, spec: WriteFaultSpec) -> None:
        self._pending.append(_PendingFault(spec))

    def take(self, char_uuid: str) -> WriteFaultSpec | None:
        """The fault due on this write to ``char_uuid`` (consumed), or ``None``.

        The first due spec fires; every other spec on that characteristic counts down.
        """
        hit: _PendingFault | None = None
        for pending in self._pending:
            if pending.spec.char.lower() != char_uuid:
                continue
            if pending.remaining == 0 and hit is None:
                hit = pending
            elif pending.remaining > 0:
                pending.remaining -= 1
        if hit is None:
            return None
        self._pending.remove(hit)
        return hit.spec


__all__ = [
    "HandshakeFault",
    "OversizeBehavior",
    "ReplayBehavior",
    "Se3Fault",
    "TunnelPeer",
    "WriteFault",
    "WriteFaultQueue",
    "WriteFaultSpec",
]
