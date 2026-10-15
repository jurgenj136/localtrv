"""Sending side of ``SimNetwork`` (T9): session generation, sequence counters, delayed frames,
the ZVD gate and APS acknowledged unicasts (``network_aps``).

``SimMeshLink`` is the base class of ``SimNetwork``; it holds no topology and decodes nothing.
Every frame goes out from a ``clock.call_later`` callback, guarded by the session generation.
"""

from __future__ import annotations

import contextlib
import dataclasses
from typing import TYPE_CHECKING, Final, Protocol

from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.testing.network_aps import ApsRetransmitter
from vicare_local_ble.zigbee_direct.codec.aps import ApsAckFrame
from vicare_local_ble.zigbee_direct.errors import DecodeError

if TYPE_CHECKING:
    import random
    from collections.abc import Callable, Mapping

    from vicare_local_ble.testing.gatt import TunnelPeer
    from vicare_local_ble.testing.network_frames import FrameVariant
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
    from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
    from vicare_local_ble.zigbee_direct.types import Eui64

type _Builder = Callable[[], bytes | None]

#: Live median delay of a parent's Network Status 0x06 after our request (1.6-12 s observed).
SIM_INDIRECT_EXPIRY_DELAY: Final = 8.8


class TunnelHost(Protocol):
    """What the network needs from the R0 (``SimulatedR0`` implements it; T9 tests may pass a
    recording stub instead)."""

    def attach_network(self, peer: TunnelPeer) -> None: ...

    def indicate_npdu(self, npdu: bytes, *, secure: bool = True) -> None: ...


class SimMeshLink:
    """Timed, generation-guarded sending into the tunnel (base of ``SimNetwork``)."""

    def __init__(
        self,
        clock: VirtualClock,
        *,
        rng: random.Random,
        zdd_short: int,
        variant_weights: Mapping[FrameVariant, float] | None,
        aps_ack_request: bool,
        aps_ack_wait: float,
        aps_max_retries: int,
    ) -> None:
        self._clock = clock
        self._rng = rng
        self._zdd_short = zdd_short
        self._weights = nf.check_variant_weights(variant_weights)
        #: Live devices request an APS ack on every unicast to the ZVD (FC 0x40).
        self.aps_ack_request = aps_ack_request
        self.aps = ApsRetransmitter(
            clock, self._send_reply, ack_wait=aps_ack_wait, max_retries=aps_max_retries
        )
        self._host: TunnelHost | None = None
        self._generation = 0
        self._joined: int | None = None
        self._annce_seen = False
        self._mtorr_seen = False
        self._nwk_seq = 0x20
        self._aps_counter = 0x10
        self._zdo_seq = 0x60
        self._indirect_drops: dict[int, list[tuple[int, float]]] = {}
        #: Scripted NWK source IEEE per replying short (tests: a frame naming its sender).
        self.reply_src_ieee: dict[int, Eui64] = {}

    def _next_seq(self) -> int:
        self._nwk_seq = (self._nwk_seq + 1) & 0xFF
        return self._nwk_seq

    def _next_aps(self) -> int:
        self._aps_counter = (self._aps_counter + 1) & 0xFF
        return self._aps_counter

    def _next_zdo_seq(self) -> int:
        self._zdo_seq = (self._zdo_seq + 1) & 0xFF
        return self._zdo_seq

    def _later(self, delay: float, build: _Builder, *, secure: bool = True) -> None:
        """Send ``build()`` after ``delay`` unless the session changed or it returns None."""
        generation = self._generation

        def fire() -> None:
            if generation != self._generation or self._host is None:
                return
            npdu = build()
            if npdu is not None:
                self._host.indicate_npdu(npdu, secure=secure)

        self._clock.call_later(delay, fire)

    def _status_later(self, dst: int, status: int, *, about: int) -> None:
        """Network Status from the R0, sent from a zero-delay clock callback."""
        self._later(
            0.0,
            lambda: nf.network_status_npdu(
                dst=dst, src=self._zdd_short, seq=self._next_seq(), status=status, about=about
            ),
        )

    def drop_indirect(
        self,
        short: int,
        *,
        count: int = 1,
        status: int = nf.NETWORK_STATUS_INDIRECT_EXPIRY,
        delay: float = SIM_INDIRECT_EXPIRY_DELAY,
    ) -> None:
        """The parent of the sleepy ``short`` drops the next ``count`` unicasts to it from its
        indirect queue (the device never sees them) and ``delay`` s later sends the ZVD a
        Network Status ``status`` about ``short`` (0x06 expiry, or 0x05 no capacity)."""
        self._indirect_drops.setdefault(short, []).extend([(status, delay)] * count)

    def _indirect_dropped(self, short: int) -> bool:
        """Consume one scripted ``drop_indirect`` for ``short``; True if the frame is dropped."""
        queue = self._indirect_drops.get(short)
        joined = self._joined
        if not queue or joined is None:
            return False
        status, delay = queue.pop(0)
        self._later(
            delay,
            lambda: nf.network_status_npdu(
                dst=joined, src=self._zdd_short, seq=self._next_seq(), status=status, about=short
            ),
        )
        return True

    def _pick_variant(self) -> FrameVariant:
        if self._weights is None:
            return "plain"
        return self._rng.choices(self._weights[0], weights=self._weights[1])[0]

    def _reply_npdu(self, src: int, aps: ApsDataFrame) -> bytes | None:
        """A unicast from ``src`` to the ZVD now; None when the gate is closed."""
        if self._joined is None or not self.gated_open:
            return None
        return nf.data_npdu(
            dst=self._joined,
            src=src,
            seq=self._next_seq(),
            aps=aps,
            variant=self._pick_variant(),
            relay=self._zdd_short,
            src_ieee=self.reply_src_ieee.get(src),
        )

    def _send_reply(self, src: int, aps: ApsDataFrame) -> bool:
        """``ApsRetransmitter`` resend: one more transmission of ``aps`` right now."""
        npdu = self._reply_npdu(src, aps)
        if npdu is None or self._host is None:
            return False
        self._host.indicate_npdu(npdu)
        return True

    def _reply_later(self, src: int, aps: ApsDataFrame, delay: float) -> None:
        """A unicast from ``src`` to the ZVD; dropped when the gate is closed at send time.
        With ``aps_ack_request`` it is sent with the ack-request bit and retransmitted until
        acked (``network_aps``)."""
        if self.aps_ack_request:
            aps = dataclasses.replace(aps, ack_request=True)

        def build() -> bytes | None:
            npdu = self._reply_npdu(src, aps)
            if npdu is not None and aps.ack_request:
                self.aps.sent(src, aps)
            return npdu

        self._later(delay, build)

    def _on_aps_ack(self, frame: NwkFrame, *, secure: bool) -> None:
        """A delivered APS ack from the ZVD (the caller checked routing and the gate): a
        matching ack ends the retransmissions of the acked frame. Without the NWK security
        bit or the tunnel's secure flag, or malformed, it is ignored."""
        if not (secure and frame.security):
            return
        with contextlib.suppress(DecodeError):
            self.aps.on_ack(frame.dst, ApsAckFrame.decode(frame.payload))

    @property
    def joined_short(self) -> int | None:
        return self._joined

    @property
    def gated_open(self) -> bool:
        """True once a Device_annce and an MTORR from the ZVD were seen this session."""
        return self._annce_seen and self._mtorr_seen


__all__ = ["SIM_INDIRECT_EXPIRY_DELAY", "SimMeshLink", "TunnelHost"]
