"""``RecordingTunnelHost``: a ``TunnelHost`` stub that records what the network indicates.

Lets tests drive ``SimNetwork`` with raw NPDUs (golden fixtures) without a ``SimulatedR0``:
``send`` hands a ZVD NPDU to the attached network, ``indications`` lists every NPDU the
network sent back with its virtual time and tunnel security flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu

if TYPE_CHECKING:
    from vicare_local_ble.testing.gatt import TunnelPeer
    from vicare_local_ble.zigbee_direct.clock import VirtualClock


@dataclass(frozen=True, slots=True)
class Indication:
    """One NPDU the network indicated, at virtual time ``at``."""

    at: float
    npdu: bytes
    secure: bool

    @property
    def frame(self) -> NwkFrame:
        return NwkFrame.decode(self.npdu)


class RecordingTunnelHost:
    """Records indications; ``send`` plays the ZVD side of the tunnel."""

    def __init__(self, clock: VirtualClock) -> None:
        self._clock = clock
        self._peer: TunnelPeer | None = None
        self._indications: list[Indication] = []

    def attach_network(self, peer: TunnelPeer) -> None:
        self._peer = peer

    def indicate_npdu(self, npdu: bytes, *, secure: bool = True) -> None:
        self._indications.append(Indication(self._clock.now(), npdu, secure))

    def send(self, npdu: bytes, *, secure: bool = True) -> None:
        """Hand a ZVD NPDU to the network, as the R0 does after decrypting a Tunnel write."""
        if self._peer is None:
            raise RuntimeError("no network attached")
        self._peer.on_zvd_npdu(TunnelNpdu(npdu, secure))

    def reset_session(self) -> None:
        """What ``SimulatedR0.r0_reboot`` does to its peer."""
        if self._peer is not None:
            self._peer.on_session_reset()

    @property
    def indications(self) -> tuple[Indication, ...]:
        return tuple(self._indications)

    def take(self) -> tuple[Indication, ...]:
        """Return and forget the indications recorded so far."""
        out = tuple(self._indications)
        self._indications.clear()
        return out


__all__ = ["Indication", "RecordingTunnelHost"]
