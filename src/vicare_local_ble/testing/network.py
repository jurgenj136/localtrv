"""Simulated Zigbee network behind the R0: TC rules, routing, Mgmt_Lqi, RREQs, noise (T9).

Frozen interface (T2); implemented by T9. Driven by the golden fixtures, never by the
production builders: frames from the ZVD are decoded with the phase-1 decoders and checked
against the live rules below; replies are assembled from fixture-shaped bytes.

All delays are ``clock.call_later`` on the shared ``VirtualClock``; randomness comes only from
the injected ``random.Random``.

Behaviours (spec §1.7) and their knobs
    Join
        * Silent drop of a Commissioning Request when FC byte1 != 0x18, radius != 1, or the
          0x48 TLV is missing (always).
        * Response after ``commissioning_delay`` (default 1.5 s).
        * Echo the placeholder, or ``assign_short`` (including invalid values such as 0xFFFD).
        * ``commissioning_status`` != 0 -> reject.
        * ``drop_commissioning_requests(n)``: silently drop the next ``n`` VALID requests (to
          test the join retry with a fresh placeholder).
        * ``unrelated_commissioning_response``: first send a response for another placeholder.
    Gating
        * No valve traffic to the ZVD until a Device_annce AND an MTORR were seen (always).
        * A unicast with ``discover_route=0`` -> Network Status ``03 02 <dst>`` (always).
    Routing
        * Frames to a short no device has (stale short) go unanswered.
        * ``emit_route_request``: RREQs with option 0x20 + dst IEEE, repeated route ids,
          other destinations, unknown originators. ``route_replies`` records every RREP.
    Quirk and noise
        * ``variant_weights``: per reply frame ``plain | source_route | garbage4``.
        * ``emit_noise``: foreign broadcasts, Network Status for others, frames for other dsts.
    Mgmt_Lqi
        * At most ``lqi_page_size`` records per page (default 2). The coordinator lists the
          valves (end devices, children, rx_on=0) and the R0 (router). Routers added with
          ``add_router`` list their own children. ``router_timeout`` shorts never answer.
        * Mgmt_Bind to the coordinator never answers (always).
    Events
        * ``add_valve_later(valve)`` (Device_annce from a new EUI), ``valve_rejoin(valve,
          new_short)``, ``address_conflict()`` (Network Status 0x0D for the ZVD short),
          ``SimulatedR0.r0_reboot()`` (via ``on_session_reset``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from vicare_local_ble.zigbee_direct.types import COORDINATOR

if TYPE_CHECKING:
    import random
    from collections.abc import Mapping

    from vicare_local_ble.testing.gatt import TunnelPeer
    from vicare_local_ble.testing.valve import SimValve
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
    from vicare_local_ble.zigbee_direct.codec.nwk_commands import RouteReply
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.types import Eui64

type FrameVariant = Literal["plain", "source_route", "garbage4"]
type NoiseKind = Literal["foreign_annce", "foreign_broadcast", "network_status_other", "other_dst"]


class TunnelHost(Protocol):
    """What the network needs from the R0 (``SimulatedR0`` implements it; T9 tests may pass a
    recording stub instead)."""

    def attach_network(self, peer: TunnelPeer) -> None: ...

    def indicate_npdu(self, npdu: bytes, *, secure: bool = True) -> None: ...


@dataclass(frozen=True, slots=True)
class SimRouter:
    """A router in the simulated mesh (the R0 itself is one, added automatically)."""

    eui: Eui64
    short: int
    parent: int = COORDINATOR


@dataclass(frozen=True, slots=True)
class RecordedRrep:
    """A Route Reply the ZVD sent, with its NWK frame (for golden comparisons)."""

    frame: NwkFrame
    reply: RouteReply
    raw: bytes


class SimNetwork:
    """The mesh behind the R0; implements ``testing.gatt.TunnelPeer`` and
    ``testing.valve.ValveUplink``."""

    def __init__(
        self,
        clock: VirtualClock,
        *,
        zdd_short: int,
        zdd_eui: Eui64,
        coordinator_eui: Eui64,
        extended_pan_id: Eui64,
        rng: random.Random,
        commissioning_delay: float = 1.5,
        assign_short: int | None = None,
        commissioning_status: int = 0,
        unrelated_commissioning_response: bool = False,
        lqi_page_size: int = 2,
        router_timeout: frozenset[int] = frozenset(),
        variant_weights: Mapping[FrameVariant, float] | None = None,
    ) -> None:
        raise NotImplementedError("T9")

    # --- topology ---

    def attach(self, host: TunnelHost) -> None:
        """Wire both directions (``host.attach_network(self)``); replies go to
        ``host.indicate_npdu``."""
        raise NotImplementedError("T9")

    def add_router(self, router: SimRouter) -> None:
        raise NotImplementedError("T9")

    def add_valve(self, valve: SimValve, *, parent: int = COORDINATOR) -> None:
        """Register ``valve`` under ``parent`` and bind its back-reference
        (``valve.bind(self)``), so ``valve.report`` and scheduled replies reach the tunnel.
        A valve belongs to at most one network; ``ValueError`` on a duplicate EUI or short."""
        raise NotImplementedError("T9")

    def drop_commissioning_requests(self, count: int) -> None:
        """Silently drop the next ``count`` valid Commissioning Requests."""
        raise NotImplementedError("T9")

    @property
    def valves(self) -> tuple[SimValve, ...]:
        raise NotImplementedError("T9")

    # --- TunnelPeer ---

    def on_zvd_npdu(self, npdu: TunnelNpdu) -> None:
        raise NotImplementedError("T9")

    def on_session_reset(self) -> None:
        raise NotImplementedError("T9")

    # --- scripted traffic and events ---

    def emit_route_request(
        self,
        src_short: int,
        *,
        route_id: int,
        dst: int | None = None,
        with_dst_ieee: bool = True,
        with_src_ieee: bool = True,
        repeat: int = 1,
        spacing: float = 1.0,
    ) -> None:
        """RREQ from ``src_short`` to ``dst`` (default: the ZVD short), as the R0 relays it."""
        raise NotImplementedError("T9")

    def emit_noise(self, kind: NoiseKind) -> None:
        raise NotImplementedError("T9")

    def add_valve_later(self, valve: SimValve, *, parent: int = COORDINATOR) -> None:
        """Add a valve and emit its Device_annce into the tunnel."""
        raise NotImplementedError("T9")

    def valve_rejoin(self, valve: SimValve, new_short: int) -> None:
        """The valve gets ``new_short`` (old short goes stale) and announces itself."""
        raise NotImplementedError("T9")

    def address_conflict(self) -> None:
        """Network Status 0x0D naming the ZVD's short."""
        raise NotImplementedError("T9")

    # --- observation ---

    @property
    def joined_short(self) -> int | None:
        raise NotImplementedError("T9")

    @property
    def gated_open(self) -> bool:
        """True once a Device_annce and an MTORR from the ZVD were seen this session."""
        raise NotImplementedError("T9")

    @property
    def route_replies(self) -> tuple[RecordedRrep, ...]:
        raise NotImplementedError("T9")

    @property
    def received(self) -> tuple[NwkFrame, ...]:
        """Every decoded NWK frame the ZVD sent this session (for assertions)."""
        raise NotImplementedError("T9")


__all__ = ["FrameVariant", "NoiseKind", "RecordedRrep", "SimNetwork", "SimRouter", "TunnelHost"]
