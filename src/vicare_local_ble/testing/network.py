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
        * ``drop_indirect(short, count, status, delay)``: the sleepy valve's parent drops the
          next ``count`` unicasts to it and sends Network Status 0x06 (or 0x05) ``delay`` s
          later (live: 0x06 after 1.6-12 s).
        * ``emit_route_request``: RREQs with option 0x20 + dst IEEE, repeated route ids,
          other destinations, unknown originators. ``route_replies`` records every RREP.
    APS reliability (``network_aps``)
        * ``aps_ack_request`` (default True, as the live devices): every unicast to the ZVD
          sets the APS ack-request bit and is retransmitted (same APS counter, new NWK seq)
          up to ``aps_max_retries`` times, ``aps_ack_wait`` apart, until the ZVD acks it.
          False sends plain frames once (the pre-hardware simulator). An ack counts only
          when it is delivered like any other unicast (gate open, discover_route=1, not a
          broadcast) and carries the NWK security bit and the tunnel's secure flag.
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

Implementation notes (T9)
    * Every frame the network sends goes out from a ``clock.call_later`` callback (scripted
      events and noise use delay 0: ``await clock.advance(0)`` delivers them).
    * A session generation guards scheduled frames: after ``on_session_reset`` nothing
      scheduled earlier reaches the tunnel. ``route_replies`` survives resets; ``received``
      is per session.
    * The extra Commissioning Request checks beyond the three live rules: dst must be the
      ZDD short and a src IEEE must be present (the response carries it as dst IEEE).
    * Device and coordinator replies (and valve reports) need an open gate when they are sent,
      so a gate closed by a session reset also stops them. Broadcasts, RREQs and Network
      Status frames do not need the gate.
    * Unicasts to the coordinator or a router are gated like valve traffic; a ZDO request
      other than Mgmt_Lqi_req (Mgmt_Bind included) is never answered by them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal

from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.testing.network_aps import (
    SIM_APS_ACK_WAIT,
    SIM_APS_MAX_FRAME_RETRIES,
    is_aps_ack,
)
from vicare_local_ble.testing.network_link import SimMeshLink, TunnelHost
from vicare_local_ble.testing.network_topology import FIRST_BROADCAST, MeshTopology
from vicare_local_ble.zigbee_direct.codec.aps import ZDO_PROFILE_ID, ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    TLV_JOINER_ENCAPSULATION,
    CommissioningRequest,
    ManyToOne,
    RouteReply,
    RouteRequest,
    decode_nwk_command,
)
from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce, ZdoCluster
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiReq
from vicare_local_ble.zigbee_direct.errors import DecodeError
from vicare_local_ble.zigbee_direct.types import (
    BROADCAST_ROUTERS,
    BROADCAST_RX_ON,
    COORDINATOR,
    Eui64,
    validate_short,
)

if TYPE_CHECKING:
    import random
    from collections.abc import Mapping

    from vicare_local_ble.testing.valve import SimValve
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import Neighbor

type FrameVariant = Literal["plain", "source_route", "garbage4"]
type NoiseKind = Literal["foreign_annce", "foreign_broadcast", "network_status_other", "other_dst"]

_FC1_COMMISSIONING: Final = 0x18
_ROUTER_REPLY_DELAY: Final = (0.2, 1.0)


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


class SimNetwork(SimMeshLink):
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
        aps_ack_request: bool = True,
        aps_ack_wait: float = SIM_APS_ACK_WAIT,
        aps_max_retries: int = SIM_APS_MAX_FRAME_RETRIES,
    ) -> None:
        if lqi_page_size < 1:
            raise ValueError("lqi_page_size must be >= 1")
        super().__init__(
            clock,
            rng=rng,
            zdd_short=validate_short(zdd_short),
            variant_weights=variant_weights,
            aps_ack_request=aps_ack_request,
            aps_ack_wait=aps_ack_wait,
            aps_max_retries=aps_max_retries,
        )
        self._zdd_eui = zdd_eui
        self._mesh = MeshTopology(coordinator_eui=coordinator_eui, extended_pan_id=extended_pan_id)
        self.commissioning_delay = commissioning_delay
        self.assign_short = assign_short
        self.commissioning_status = commissioning_status
        self.unrelated_commissioning_response = unrelated_commissioning_response
        self.lqi_page_size = lqi_page_size
        self.router_timeout = router_timeout
        self._drop_requests = 0
        self._zvd_eui: Eui64 | None = None
        self._received: list[NwkFrame] = []
        self._rreps: list[RecordedRrep] = []
        self.add_router(SimRouter(eui=zdd_eui, short=self._zdd_short))

    # --- topology ---

    def attach(self, host: TunnelHost) -> None:
        """Wire both directions (``host.attach_network(self)``); replies go to
        ``host.indicate_npdu``."""
        self._host = host
        host.attach_network(self)

    def add_router(self, router: SimRouter) -> None:
        self._mesh.add_router(router)

    def add_valve(self, valve: SimValve, *, parent: int = COORDINATOR) -> None:
        """Register ``valve`` under ``parent`` and bind its back-reference
        (``valve.bind(self)``), so ``valve.report`` and scheduled replies reach the tunnel.
        A valve belongs to at most one network; ``ValueError`` on a duplicate EUI or short."""
        self._mesh.add_valve(valve, parent)
        valve.bind(self)

    def drop_commissioning_requests(self, count: int) -> None:
        """Silently drop the next ``count`` valid Commissioning Requests."""
        if count < 0:
            raise ValueError("count must be >= 0")
        self._drop_requests = count

    @property
    def valves(self) -> tuple[SimValve, ...]:
        return self._mesh.valves

    @property
    def routers(self) -> tuple[SimRouter, ...]:
        """Every router, the R0 first."""
        return self._mesh.routers

    def neighbor_table(self, short: int) -> tuple[Neighbor, ...]:
        """The Mgmt_Lqi table of the coordinator or a router: its valves, then its routers."""
        return self._mesh.neighbor_table(short)

    def deliver_from_valve(self, valve: SimValve, aps: ApsDataFrame, *, delay: float) -> None:
        """``ValveUplink``: an unsolicited frame from ``valve`` (reports)."""
        if valve not in self.valves:
            raise ValueError(f"{valve!r} is not in this network")
        self._reply_later(valve.short, aps, delay)

    # --- TunnelPeer ---

    def on_zvd_npdu(self, npdu: TunnelNpdu) -> None:
        raw = npdu.npdu
        try:
            frame = NwkFrame.decode(raw)
        except DecodeError:
            return
        self._received.append(frame)
        if frame.frame_type is NwkFrameType.COMMAND:
            self._on_command(frame, raw)
        elif frame.frame_type is NwkFrameType.DATA:
            self._on_data(frame, secure=npdu.nwk_security)

    def on_session_reset(self) -> None:
        self._generation += 1
        self._joined = None
        self._zvd_eui = None
        self._annce_seen = False
        self._mtorr_seen = False
        self._received.clear()
        self.aps.clear()

    def _on_command(self, frame: NwkFrame, raw: bytes) -> None:
        try:
            command = decode_nwk_command(frame.payload)
        except DecodeError:
            return
        match command:
            case CommissioningRequest():
                self._on_commissioning(frame, raw, command)
            case RouteRequest():
                if (
                    command.many_to_one is not ManyToOne.NONE
                    and self._joined is not None
                    and frame.src == self._joined
                ):
                    self._mtorr_seen = True
            case RouteReply():
                self._rreps.append(RecordedRrep(frame, command, raw))
            case _:
                pass

    def _on_commissioning(self, frame: NwkFrame, raw: bytes, req: CommissioningRequest) -> None:
        if raw[1] != _FC1_COMMISSIONING or frame.radius != 1:
            return
        if not any(t.tag == TLV_JOINER_ENCAPSULATION for t in req.tlvs):
            return
        zvd = frame.src_ieee
        if frame.dst != self._zdd_short or zvd is None:
            return
        if self._drop_requests:
            self._drop_requests -= 1
            return
        placeholder = frame.src
        if self.unrelated_commissioning_response:
            other = placeholder ^ 0x444C  # 0x1234 -> 0x5678 (golden OTHER_PLACEHOLDER)
            self._later(
                self.commissioning_delay / 2,
                lambda: nf.commissioning_response_npdu(
                    placeholder=other,
                    zdd_short=self._zdd_short,
                    seq=self._next_seq(),
                    short=other,
                    status=0,
                    zvd=None,
                ),
                secure=False,
            )
        short = placeholder if self.assign_short is None else self.assign_short
        status = self.commissioning_status

        def respond() -> bytes:
            if status == 0:
                self._joined, self._zvd_eui = short, zvd
                self._annce_seen = self._mtorr_seen = False
            return nf.commissioning_response_npdu(
                placeholder=placeholder,
                zdd_short=self._zdd_short,
                seq=self._next_seq(),
                short=short,
                status=status,
                zvd=zvd,
            )

        self._later(self.commissioning_delay, respond, secure=False)

    def _on_data(self, frame: NwkFrame, *, secure: bool) -> None:
        joined = self._joined
        if joined is None or frame.src != joined:
            return
        ack = is_aps_ack(frame)  # delivered like any other unicast before it counts
        if not ack:
            try:
                aps = ApsDataFrame.decode(frame.payload)
            except DecodeError:
                return
        if frame.dst >= FIRST_BROADCAST:
            if not ack:
                self._on_broadcast(aps)
            return
        if frame.discover_route == 0:
            self._status_later(joined, nf.NETWORK_STATUS_NO_ROUTE, about=frame.dst)
            return
        if not self.gated_open:
            return
        if ack:
            self._on_aps_ack(frame, secure=secure)
            return
        if self._mesh.is_router(frame.dst):
            self._on_router_request(frame.dst, aps)
            return
        valve = self._mesh.valve_by_short(frame.dst)
        if valve is None:
            return  # stale or unknown short: unanswered
        src = valve.short
        if self._indirect_dropped(src):
            return
        for reply in valve.handle_request(aps):
            self._reply_later(src, reply.aps, reply.delay)

    def _on_broadcast(self, aps: ApsDataFrame) -> None:
        if aps.profile_id != ZDO_PROFILE_ID or aps.cluster_id != ZdoCluster.DEVICE_ANNCE:
            return  # Match_Desc and other broadcasts: the valves sleep
        try:
            annce = DeviceAnnce.decode(aps.payload)
        except DecodeError:
            return
        if annce.nwk_addr == self._joined and annce.ieee == self._zvd_eui:
            self._annce_seen = True

    def _on_router_request(self, short: int, aps: ApsDataFrame) -> None:
        if aps.profile_id != ZDO_PROFILE_ID or aps.dst_endpoint != 0:
            return
        if aps.cluster_id != ZdoCluster.MGMT_LQI_REQ or short in self.router_timeout:
            return  # Mgmt_Bind and other ZDO requests never answer
        try:
            req = MgmtLqiReq.decode(aps.payload)
        except DecodeError:
            return
        rsp = nf.lqi_page(req, self.neighbor_table(short), self.lqi_page_size)
        reply = ApsDataFrame(
            cluster_id=ZdoCluster.MGMT_LQI_RSP,
            profile_id=ZDO_PROFILE_ID,
            payload=rsp.encode(),
            dst_endpoint=0,
            src_endpoint=0,
            counter=self._next_aps(),
        )
        self._reply_later(short, reply, self._rng.uniform(*_ROUTER_REPLY_DELAY))

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
        target = self._joined if dst is None else dst
        if target is None:
            raise RuntimeError("no joined ZVD short to target")
        if repeat < 1:
            raise ValueError("repeat must be >= 1")
        target_ieee = None
        if with_dst_ieee:
            target_ieee = self._zvd_eui if target == self._joined else self._mesh.eui_of(target)
        src_ieee = self._mesh.eui_of(src_short) if with_src_ieee else None
        for i in range(repeat):
            self._later(
                i * spacing,
                lambda: nf.route_request_npdu(
                    src=src_short,
                    seq=self._next_seq(),
                    route_id=route_id,
                    target=target,
                    target_ieee=target_ieee,
                    src_ieee=src_ieee,
                    broadcast=BROADCAST_ROUTERS,
                ),
            )

    def emit_noise(self, kind: NoiseKind) -> None:
        self._later(0.0, lambda: self._noise(kind))

    def _foreign_short(self) -> int:
        while True:
            short = self._rng.randrange(0x0001, FIRST_BROADCAST)
            if short not in {self._joined, self._zdd_short} and self._mesh.eui_of(short) is None:
                return short

    def _noise(self, kind: NoiseKind) -> bytes:
        valves = self._mesh.valves
        return nf.noise_npdu(
            kind,
            seq=self._next_seq(),
            zdo_seq=self._next_zdo_seq(),
            counter=self._next_aps(),
            foreign_short=self._foreign_short(),
            valve_short=valves[0].short if valves else self._zdd_short,
            zdd_short=self._zdd_short,
        )

    def _announce(self, valve: SimValve) -> None:
        short, eui = valve.short, valve.eui

        def build() -> bytes:
            aps = nf.device_annce_aps(
                zdo_seq=self._next_zdo_seq(), short=short, eui=eui, counter=self._next_aps()
            )
            return nf.broadcast_npdu(src=short, seq=self._next_seq(), aps=aps)

        self._later(0.0, build)

    def add_valve_later(self, valve: SimValve, *, parent: int = COORDINATOR) -> None:
        """Add a valve and emit its Device_annce into the tunnel."""
        self.add_valve(valve, parent=parent)
        self._announce(valve)

    def valve_rejoin(self, valve: SimValve, new_short: int) -> None:
        """The valve gets ``new_short`` (old short goes stale) and announces itself."""
        if valve not in self.valves:
            raise ValueError(f"{valve!r} is not in this network")
        self._mesh.check_short_free(new_short)
        valve.set_short(new_short)
        self._announce(valve)

    def address_conflict(self) -> None:
        """Network Status 0x0D naming the ZVD's short."""
        joined = self._joined
        if joined is None:
            raise RuntimeError("no joined ZVD short to conflict with")
        self._status_later(BROADCAST_RX_ON, nf.NETWORK_STATUS_ADDRESS_CONFLICT, about=joined)

    # --- observation ---

    @property
    def route_replies(self) -> tuple[RecordedRrep, ...]:
        return tuple(self._rreps)

    @property
    def received(self) -> tuple[NwkFrame, ...]:
        """Every decoded NWK frame the ZVD sent this session (for assertions)."""
        return tuple(self._received)


__all__ = ["FrameVariant", "NoiseKind", "RecordedRrep", "SimNetwork", "SimRouter", "TunnelHost"]
