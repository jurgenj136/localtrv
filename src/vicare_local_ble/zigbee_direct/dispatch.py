"""Ingress dispatch: one decrypted tunnel NPDU in, routed to exactly one consumer.

``Dispatcher.handle`` is installed as the transport's NPDU handler (``transport.set_npdu_handler``)
by the node's constructor. It runs synchronously on the loop inside the BLE notify callback: it
never awaits, never sends, and never raises (every exception is caught, counted in
``decode_errors`` and logged at DEBUG).

Per NPDU:

1. ``NwkFrame.decode`` (strips multicast and source-route data); error -> ``decode_errors``.
   A ``src_ieee`` in the header is noted in ``host.neighbors`` and, unless the frame is
   our own, emitted (``host.emit_sender``) before the frame is processed. A response whose
   ``src_ieee`` differs from its envelope's ``expect_ieee`` resolves nothing (unmatched).
2. Command frames (``decode_nwk_command``). First the address filter: a command frame whose NWK
   dst is not ``host.current_short``, not the active join token's placeholder
   (``host.join_slot.active``) and not a broadcast (>= 0xFFF8) is dropped (DEBUG). Then:
   * Commissioning Response (0x0F) -> ``host.join_slot.offer(frame, rsp)``; unclaimed responses
     (no token, other placeholder including an older attempt's) are dropped with DEBUG.
   * Route Request -> ``host.router.on_route_request(frame, rreq)``.
   * Network Status -> ``host.router.on_network_status(frame, status)`` (the router decides:
     ``RouteError`` only for frames unicast to our short; 0x0D whenever the status
     destination is our short).
   * Route Record (sent to us, the concentrator, before a device's unicast) and Link Status
     (the R0's periodic 0xFFFC broadcast) are counted (``route_records``, ``link_status``).
   * Others are ignored.
3. Data frames whose dst is neither ``host.current_short`` nor a broadcast are dropped. Before the
   join completed (``current_short is None``) every data frame is dropped. Otherwise
   ``ApsDataFrame.decode``; a header that fails to decode or is implausible
   (``node_match.plausible_aps_header``: profile not ZDO/HA, or a ZDO frame with endpoints
   other than 0/0 or a cluster outside the standard ZDP table) goes to the fallback (4).
   A plausible header is final: a body that then fails to decode only counts
   ``decode_errors`` (no offset scan).
   * APS ack: a plausible unicast header with the ack-request bit, NWK dst == our short (no
     NWK multicast, a dst IEEE if present equal to our EUI) and a unicast NWK src
     (0x0000..0xFFF7) other than our short is acked first (``host.ack_aps``, scheduled, never
     awaited), whatever the body: responses, reports, duplicates of retired requests and
     undecodable bodies alike.
     Broadcasts, group frames, APS commands/acks and fallback-path frames are never acked: a
     garbled header's endpoints and counter are not trustworthy, and a wrong ack could stop
     the retransmission of a different frame.
   * ZDO profile: Device_annce -> ``host.neighbors.note`` + ``host.emit_device_annce``;
     responses resolve a pending entry only if ``Envelope.match_zdo`` passes; a retired key
     counts ``late_drops``; standard ZDO requests (to us or broadcast) and responses without
     a decoder are ignored in v1 (not counted as decode errors).
   * HA profile: ``ZclFrame.decode``. Report Attributes (0x0A,
     server->client) ALWAYS goes to ``host.emit_report`` and never touches pending; everything
     else is matched with ``Envelope.match_zcl`` against the entry for
     ``(src, "zcl", tsn)``.
4. Fallback: only for an undecodable or implausible APS header (3) AND if
   ``host.pending.for_src(src)`` is non-empty, run ``scan_for_response(nwk_payload,
   expected, src_short=src)`` (strict, ``max_trailing=0``) for each; a ``ScanMatch`` must still
   pass command, tsn/seq, direction and manufacturer checks, and a match found at offset 0
   (APS header known) must also pass the envelope's profile/cluster/endpoint checks. Counted
   in ``fallback_hits``.
5. Never reply to anything (reports, broadcasts) beyond the APS ack of step 3.

Logging (logger ``vicare_local_ble.zigbee_direct.node``): DEBUG only, and only decoded,
sanitised fields (``debug.sanitize_records`` before logging any attribute records). Never
payload bytes: the NPDU log is the recorder's job.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING, Final, Protocol

from vicare_local_ble.zigbee_direct.codec.aps import ZDO_PROFILE_ID, ApsDataFrame, ApsDeliveryMode
from vicare_local_ble.zigbee_direct.codec.fallback import (
    ZDO_RESPONSE_DECODERS,
    ExpectedZcl,
    ScanMatch,
    scan_for_response,
)
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningResponse,
    NetworkStatus,
    RouteRequest,
    UnsupportedNwkCommandError,
    decode_nwk_command,
)
from vicare_local_ble.zigbee_direct.codec.nwk_mesh import LinkStatus, RouteRecord
from vicare_local_ble.zigbee_direct.codec.zcl import (
    ReportAttributes,
    ZclCommandId,
    ZclDirection,
    ZclFrame,
    ZclFrameType,
)
from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce, ZdoCluster
from vicare_local_ble.zigbee_direct.debug import sanitize_records
from vicare_local_ble.zigbee_direct.errors import DecodeError
from vicare_local_ble.zigbee_direct.node_match import (
    MFR_HEADER_MISSING,
    NO_MATCH,
    ZDO_RESPONSE_TYPES,
    aps_header_matches,
    plausible_aps_header,
    zcl_command_verdict,
    zdo_verdict,
)
from vicare_local_ble.zigbee_direct.node_types import ReportEvent
from vicare_local_ble.zigbee_direct.requests import EnvelopeMatch, ZclResponse

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.fallback import Expected
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.node_types import NodeStats
    from vicare_local_ble.zigbee_direct.requests import (
        Envelope,
        JoinSlot,
        Pending,
        PendingKey,
        PendingMap,
        PendingResult,
    )
    from vicare_local_ble.zigbee_direct.routing import NeighborTable, Router
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.node")
#: Shorts at or above this are broadcast addresses.
_FIRST_BROADCAST: Final = 0xFFF8


class DispatchHost(Protocol):
    """What the dispatcher needs from its node (``ZigbeeDirectNode`` implements it)."""

    @property
    def current_short(self) -> int | None:
        """Validated own short, or ``None`` before the Commissioning Response was accepted.

        (The public ``ZigbeeDirectNode.own_short`` raises before the join instead.)"""
        ...

    @property
    def pending(self) -> PendingMap: ...

    @property
    def join_slot(self) -> JoinSlot: ...

    @property
    def router(self) -> Router: ...

    @property
    def neighbors(self) -> NeighborTable: ...

    @property
    def stats(self) -> NodeStats: ...

    @property
    def own_eui(self) -> Eui64:
        """Our EUI-64 (an inbound dst IEEE must match it before we ack)."""
        ...

    def emit_report(self, event: ReportEvent) -> None:
        """Call every ``on_report`` listener; listener exceptions are logged and swallowed."""
        ...

    def emit_device_annce(self, annce: DeviceAnnce, src_short: int) -> None:
        """Call every ``on_device_annce`` listener with the annce and its NWK src short."""
        ...

    def emit_sender(self, src_short: int, src_ieee: Eui64) -> None:
        """Call every ``on_sender`` listener (a NWK header named its source IEEE)."""
        ...

    def ack_aps(self, src_short: int, aps: ApsDataFrame) -> None:
        """Schedule the APS ack of ``aps`` to ``src_short`` (``node_acks.ApsAcker``); never
        awaits, never raises."""
        ...


class Dispatcher:
    """Stateless router of ingress NPDUs (all state lives in the host's collaborators)."""

    __slots__ = ("_host",)

    def __init__(self, host: DispatchHost) -> None:
        self._host = host

    def handle(self, npdu: TunnelNpdu) -> None:
        """Process one NPDU (see module docstring). Never raises."""
        try:
            self._handle(npdu.npdu)
        except Exception as exc:
            self._host.stats.decode_errors += 1
            _LOGGER.debug("NPDU dropped: %s", type(exc).__name__)

    # --- NWK ---

    def _handle(self, raw: bytes) -> None:
        host = self._host
        try:
            frame = NwkFrame.decode(raw)
        except DecodeError as exc:
            host.stats.decode_errors += 1
            _LOGGER.debug("NWK decode failed: %s", exc)
            return
        if frame.src_ieee is not None:
            host.neighbors.note(frame.src, frame.src_ieee)
            if frame.src != host.current_short:
                host.emit_sender(frame.src, frame.src_ieee)
        if frame.frame_type is NwkFrameType.COMMAND:
            self._command(frame)
        elif frame.frame_type is NwkFrameType.DATA:
            self._data(frame)

    def _command(self, frame: NwkFrame) -> None:
        host = self._host
        token = host.join_slot.active
        dst = frame.dst
        if (
            dst != host.current_short
            and (token is None or dst != token.placeholder)
            and dst < _FIRST_BROADCAST
        ):
            _LOGGER.debug("NWK command for 0x%04X dropped (not addressed to us)", dst)
            return
        try:
            command = decode_nwk_command(frame.payload)
        except UnsupportedNwkCommandError:
            return  # other NWK commands are ignored
        except DecodeError as exc:
            host.stats.decode_errors += 1
            _LOGGER.debug("NWK command decode failed: %s", exc)
            return
        match command:
            case CommissioningResponse():
                if not host.join_slot.offer(frame, command):
                    _LOGGER.debug(
                        "Commissioning Response from 0x%04X to 0x%04X matches no join token",
                        frame.src,
                        dst,
                    )
            case RouteRequest():
                host.router.on_route_request(frame, command)
            case NetworkStatus():
                host.stats.network_status += 1
                host.router.on_network_status(frame, command)
            case RouteRecord():
                host.stats.route_records += 1
            case LinkStatus():
                host.stats.link_status += 1
            case _:
                pass

    def _data(self, frame: NwkFrame) -> None:
        host = self._host
        current = host.current_short
        if current is None or (frame.dst != current and frame.dst < _FIRST_BROADCAST):
            _LOGGER.debug("data frame for 0x%04X dropped", frame.dst)
            return
        failed = False
        try:
            aps = ApsDataFrame.decode(frame.payload)
        except DecodeError:
            failed = True
        if failed or not plausible_aps_header(aps):
            self._fallback(frame)  # garbled header (quirk): the only case that is scanned
            return
        if self._ack_eligible(frame, aps, current):
            host.ack_aps(frame.src, aps)
        if aps.profile_id == ZDO_PROFILE_ID:
            self._zdo(frame, aps, current)
        else:
            self._zcl(frame, aps)

    def _ack_eligible(self, frame: NwkFrame, aps: ApsDataFrame, current: int) -> bool:
        """Step 3 APS ack rule: an ack goes only to a valid unicast source, for a unicast
        (non-multicast) frame to our short whose dst IEEE, if present, is our EUI."""
        return (
            aps.ack_request
            and aps.delivery_mode is ApsDeliveryMode.UNICAST
            and frame.dst == current
            and frame.multicast_control is None
            and (frame.dst_ieee is None or frame.dst_ieee == self._host.own_eui)
            and 0 <= frame.src < _FIRST_BROADCAST
            and frame.src != current
        )

    # --- ZDO ---

    def _zdo(self, frame: NwkFrame, aps: ApsDataFrame, current: int) -> None:
        host = self._host
        cluster = aps.cluster_id
        if cluster == ZdoCluster.DEVICE_ANNCE:
            try:
                annce = DeviceAnnce.decode(aps.payload)
            except DecodeError:
                self._undecodable(frame, "Device_annce")
                return
            if frame.src == current:
                return  # our own announcement
            host.neighbors.note(annce.nwk_addr, annce.ieee)
            host.stats.device_annces += 1
            _LOGGER.debug("Device_annce from 0x%04X", annce.nwk_addr)
            host.emit_device_annce(annce, frame.src)
            return
        decoder = ZDO_RESPONSE_DECODERS.get(cluster)
        if decoder is None:  # a standard ZDO request (to us or broadcast): ignored in v1
            _LOGGER.debug("ZDO cluster 0x%04X from 0x%04X ignored", cluster, frame.src)
            return
        try:
            response = decoder(aps.payload)
        except DecodeError:
            self._undecodable(frame, f"ZDO 0x{cluster:04X}")
            return
        key: PendingKey = (frame.src, "zdo", response.seq)
        pending = host.pending.get(key)
        if (
            pending is not None
            and pending.envelope.sender_ok(frame.src_ieee)
            and pending.envelope.match_zdo(frame.src, aps, response)
        ):
            host.pending.resolve(key, response)
            _LOGGER.debug("ZDO 0x%04X seq %d from 0x%04X resolved", cluster, key[2], frame.src)
            return
        self._unmatched(key, f"ZDO 0x{cluster:04X}")

    # --- ZCL ---

    def _zcl(self, frame: NwkFrame, aps: ApsDataFrame) -> None:
        host = self._host
        try:
            zcl = ZclFrame.decode(aps.payload)
            header = zcl.header
            if header.frame_type is not ZclFrameType.GLOBAL:
                _LOGGER.debug("cluster-specific ZCL frame from 0x%04X ignored", frame.src)
                return
            command = zcl.global_command()
        except DecodeError:
            self._undecodable(frame, f"ZCL cluster 0x{aps.cluster_id:04X}")
            return
        if header.direction is not ZclDirection.SERVER_TO_CLIENT:
            _LOGGER.debug("ZCL request from 0x%04X ignored", frame.src)
            return
        if isinstance(command, ReportAttributes):
            self._report(frame, aps, zcl, command)
            return
        key: PendingKey = (frame.src, "zcl", header.tsn)
        pending = host.pending.get(key)
        if pending is not None and pending.envelope.sender_ok(frame.src_ieee):
            verdict = pending.envelope.match_zcl(frame.src, aps, zcl)
            if verdict is not EnvelopeMatch.NO_MATCH:
                if verdict is EnvelopeMatch.MATCH_MFR_HEADER_MISSING:
                    host.stats.mfr_header_missing += 1
                host.pending.resolve(key, ZclResponse(header, command))
                _LOGGER.debug("ZCL tsn %d from 0x%04X resolved", header.tsn, frame.src)
                return
        self._unmatched(key, f"ZCL 0x{header.command_id:02X}")

    def _report(
        self, frame: NwkFrame, aps: ApsDataFrame, zcl: ZclFrame, command: ReportAttributes
    ) -> None:
        host = self._host
        event = ReportEvent(
            src_short=frame.src,
            src_ieee=frame.src_ieee,
            endpoint=aps.src_endpoint,
            cluster=aps.cluster_id,
            manufacturer_code=zcl.header.manufacturer_code,
            records=command.records,
        )
        host.stats.reports += 1
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "report from 0x%04X cluster 0x%04X: %s",
                frame.src,
                aps.cluster_id,
                sanitize_records(command.records),
            )
        host.emit_report(event)

    def _unmatched(self, key: PendingKey, what: str) -> None:
        host = self._host
        src, _, seq = key
        if host.pending.is_retired(key):
            host.stats.late_drops += 1
            _LOGGER.debug("late %s seq %d from 0x%04X dropped", what, seq, src)
            return
        host.stats.unmatched += 1
        _LOGGER.debug("unmatched %s seq %d from 0x%04X", what, seq, src)

    # --- fallback ---

    def _undecodable(self, frame: NwkFrame, what: str) -> None:
        """A plausible APS header with a body that does not decode: counted, never scanned."""
        self._host.stats.decode_errors += 1
        _LOGGER.debug("undecodable %s from 0x%04X", what, frame.src)

    def _fallback(self, frame: NwkFrame) -> None:
        host = self._host
        for pending in host.pending.for_src(frame.src):
            if pending.envelope.sender_ok(frame.src_ieee) and self._scan(frame, pending):
                return
        host.stats.decode_errors += 1
        _LOGGER.debug(
            "undecodable data frame from 0x%04X (%d B payload)", frame.src, len(frame.payload)
        )

    def _scan(self, frame: NwkFrame, pending: Pending) -> bool:
        host = self._host
        envelope = pending.envelope
        for expected in _expectations(envelope):
            match = scan_for_response(frame.payload, expected, src_short=frame.src)
            if not isinstance(match, ScanMatch):
                continue
            if match.aps is not None and not aps_header_matches(envelope, match.aps):
                continue  # found at offset 0: the decoded APS header must fit the envelope
            response = match.response
            result: PendingResult
            if isinstance(response, ZDO_RESPONSE_TYPES):
                if not zdo_verdict(envelope, response):
                    continue
                result = response
            else:
                header = match.zcl_header
                if header is None:  # pragma: no cover - a ZCL ScanMatch always has its header
                    continue
                verdict = zcl_command_verdict(envelope, header, response)
                if verdict == NO_MATCH:
                    continue
                if verdict == MFR_HEADER_MISSING:
                    host.stats.mfr_header_missing += 1
                result = ZclResponse(header, response, via_fallback=True)
            if host.pending.resolve(envelope.key, result):
                host.stats.fallback_hits += 1
                _LOGGER.debug(
                    "fallback hit: %s seq %d from 0x%04X at offset %s",
                    envelope.kind,
                    envelope.seq,
                    frame.src,
                    match.offset,
                )
                return True
        return False


def _expectations(envelope: Envelope) -> tuple[Expected, ...]:
    """The fallback expectations of ``envelope``: its response command, a Default Response for
    its request command, and (for a manufacturer request) both without the MS header."""
    base = envelope.expected()
    if not isinstance(base, ExpectedZcl):
        return (base,)
    variants = [base]
    if envelope.request_command is not None and base.command_id != ZclCommandId.DEFAULT_RESPONSE:
        variants.append(dataclasses.replace(base, command_id=ZclCommandId.DEFAULT_RESPONSE))
    if envelope.manufacturer_code is not None:
        variants += [dataclasses.replace(v, manufacturer_code=None) for v in tuple(variants)]
    return tuple(variants)


__all__ = ["DispatchHost", "Dispatcher"]
