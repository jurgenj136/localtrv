"""APS acknowledged transmission of the simulated mesh (``SimNetwork``): ack wait and retries.

Real devices (the ubisys R0's ZDO, the ZK03840 valves) send every unicast to the ZVD with the
APS ack-request bit set (APS frame control 0x40) and retransmit it when no APS ack arrives
(live: 2-3 copies, 2-3.2 s apart). This module models the sender side (Zigbee R22/R23
2.2.8.4.2 "Reliability"): after each transmission it waits ``ack_wait`` on the injected
clock; without a matching ack it hands the same APS frame (same APS counter) back to the
network for a new NWK transmission, at most ``max_retries`` times.

Constants (simulator choices, cited):

* ``SIM_APS_MAX_FRAME_RETRIES = 3``: ``apscMaxFrameRetries`` (Zigbee R22 2.2.7.1 APS
  constants; ZBOSS ``ZB_N_APS_MAX_FRAME_RETRIES`` defaults to 3 citing that table).
* ``SIM_APS_ACK_WAIT = 1.6`` s: ``apscAckWaitDuration`` = 0.05 s x (2 x ``nwkcMaxDepth`` 15)
  + 0.1 s terminal encrypt/decrypt allowance (same table; SiLabs EmberZNet documents the
  same 50 ms per hop and 100 ms ``EMBER_APSC_MAX_ACK_WAIT_TERMINAL_SECURITY_MS``). The live
  2-3 s spacing is longer because stacks add per-hop/sleepy allowances; 1.6 s keeps tests
  fast and still well above the simulator's reply delays.

Pure bookkeeping plus ``clock.call_later``; no I/O, no randomness.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from vicare_local_ble.zigbee_direct.codec.aps import ApsAckFrame, ApsFrameControl, ApsFrameType
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame

SIM_APS_ACK_WAIT: Final = 1.6
SIM_APS_MAX_FRAME_RETRIES: Final = 3

#: ``(sender short, expected ack)``.
type _Key = tuple[int, ApsAckFrame]
#: Sends one transmission of ``aps`` from ``src`` now; False if it could not be sent.
type Resend = Callable[[int, ApsDataFrame], bool]


def is_aps_ack(frame: NwkFrame) -> bool:
    """True if ``frame`` is a NWK data frame carrying an APS ack (APS frame type 0b10)."""
    payload = frame.payload
    return (
        frame.frame_type is NwkFrameType.DATA
        and bool(payload)
        and ApsFrameControl.from_byte(payload[0]).frame_type is ApsFrameType.ACK
    )


class _Waiting:
    __slots__ = ("aps", "retries")

    def __init__(self, aps: ApsDataFrame) -> None:
        self.aps = aps
        self.retries = 0


class ApsRetransmitter:
    """Frames sent with ack request that wait for the ZVD's APS ack."""

    def __init__(
        self,
        clock: VirtualClock,
        resend: Resend,
        *,
        ack_wait: float = SIM_APS_ACK_WAIT,
        max_retries: int = SIM_APS_MAX_FRAME_RETRIES,
    ) -> None:
        if not ack_wait > 0 or max_retries < 0:
            raise ValueError("need ack_wait > 0 and max_retries >= 0")
        self._clock = clock
        self._resend = resend
        self.ack_wait = ack_wait
        self.max_retries = max_retries
        self._waiting: dict[_Key, _Waiting] = {}
        self.retransmits = 0
        self.acks_received = 0
        self.unacked = 0

    def sent(self, src: int, aps: ApsDataFrame) -> None:
        """``aps`` (ack request set) was just sent from ``src`` for the first time."""
        key = (src, ApsAckFrame.for_frame(aps))
        entry = _Waiting(aps)
        self._waiting[key] = entry  # a reused counter replaces the older frame
        self._arm(key, entry)

    def _arm(self, key: _Key, entry: _Waiting) -> None:
        self._clock.call_later(self.ack_wait, lambda: self._expire(key, entry))

    def _expire(self, key: _Key, entry: _Waiting) -> None:
        if self._waiting.get(key) is not entry:
            return  # acked, replaced or cleared
        if entry.retries >= self.max_retries:
            del self._waiting[key]
            self.unacked += 1
            return
        entry.retries += 1
        if not self._resend(key[0], entry.aps):
            del self._waiting[key]
            return
        self.retransmits += 1
        self._arm(key, entry)

    def on_ack(self, dst: int, ack: ApsAckFrame) -> bool:
        """An APS ack from the ZVD to ``dst``; True if it matched a waiting frame."""
        if self._waiting.pop((dst, ack), None) is None:
            return False
        self.acks_received += 1
        return True

    def clear(self) -> None:
        """Forget every waiting frame (session reset)."""
        self._waiting.clear()

    @property
    def waiting(self) -> int:
        return len(self._waiting)


__all__ = [
    "SIM_APS_ACK_WAIT",
    "SIM_APS_MAX_FRAME_RETRIES",
    "ApsRetransmitter",
    "Resend",
    "is_aps_ack",
]
