"""Value types shared by the node, dispatcher, router and connection.

They live here, below ``node.py``, so ``dispatch.py`` and ``routing.py`` can build them at
runtime without importing the node. ``node.py`` re-exports every name; import them from there.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Self

if TYPE_CHECKING:
    from localtrv.zigbee_direct.codec.commissioning import ChannelMask, CommissioningStatus
    from localtrv.zigbee_direct.codec.zcl import AttributeRecord
    from localtrv.zigbee_direct.types import Eui64


#: Smallest enabled periodic MTORR interval (seconds); a flood of MTORRs loads the mesh.
MIN_MTORR_INTERVAL: Final = 10.0


class RouteReplyMode(StrEnum):
    """How the node answers a Route Request addressed to its own short (docs/protocol.md §6.4).

    * ``LIVE``: options byte forced to 0x20 with both EUIs appended (the live-proven bytes).
    * ``SPEC``: options derived from the present EUIs (0x30 with both).
    * ``OFF``: never send a Route Reply.
    """

    LIVE = "live"
    SPEC = "spec"
    OFF = "off"


@dataclass(frozen=True, slots=True)
class NodeConfig:
    """Tunables of one ``ZigbeeDirectNode``; immutable, replaced per join by the connection.

    Times are seconds on the injected ``Clock``.

    * ``request_timeout`` per attempt; ``request_attempts`` total attempts per request
      (retransmits reuse the ZDO seq / ZCL TSN, with a new NWK seq).
      ``indirect_extra_attempts``: further attempts allowed beyond ``request_attempts``, only
      while the previous attempt was dropped by a Network Status 0x05/0x06 (a sleepy device's
      parent dropped the frame; that error comes within seconds, a timeout takes
      ``request_timeout``). A timed-out last attempt never gets one.
    * ``late_window``: how long a retired ``(src, kind, seq)`` key stays reserved (late or
      duplicate responses for it are dropped and counted; the seq is not reallocated).
    * ``join_timeout`` per Commissioning Request attempt; ``join_attempts`` total attempts,
      each with a fresh join token.
    * ``mtorr_count`` many-to-one route requests during join, ``mtorr_spacing`` apart; then one
      every ``mtorr_interval`` while the node is open.
    * ``route_reply_mode``: see ``RouteReplyMode``. ``rreq_dedupe_ttl``: TTL of the
      ``(originator, route_id)`` dedupe set.
    * ``max_in_flight``: global cap on concurrent requests (a per-destination lock serialises
      requests to the same device on top of it).
    * ``preferred_short``: requested own short (0x0001..0xFFF7) if not in ``avoid_shorts``.

    ``__post_init__`` raises ``ValueError`` for: non-positive (or NaN/inf) ``request_timeout``,
    ``join_timeout``, ``rreq_dedupe_ttl``; ``request_attempts``, ``join_attempts``,
    ``mtorr_count``, ``max_in_flight`` below 1; negative ``indirect_extra_attempts``,
    ``late_window`` or ``mtorr_spacing``;
    a positive ``mtorr_interval`` below ``MIN_MTORR_INTERVAL`` (a value <= 0 or NaN disables
    the periodic MTORR); a ``preferred_short`` outside 0x0001..0xFFF7.
    * ``avoid_shorts``: shorts never used as the placeholder (known device shorts, a short that
      caused an address conflict).
    """

    request_timeout: float = 30.0
    request_attempts: int = 2
    indirect_extra_attempts: int = 1
    late_window: float = 120.0
    join_timeout: float = 15.0
    join_attempts: int = 2
    mtorr_count: int = 2
    mtorr_spacing: float = 1.0
    mtorr_interval: float = 900.0
    route_reply_mode: RouteReplyMode = RouteReplyMode.LIVE
    rreq_dedupe_ttl: float = 60.0
    max_in_flight: int = 4
    preferred_short: int | None = None
    avoid_shorts: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        """Range checks (``ValueError``); see the class docstring for the rules."""
        positive = {
            "request_timeout": self.request_timeout,
            "join_timeout": self.join_timeout,
            "rreq_dedupe_ttl": self.rreq_dedupe_ttl,
        }
        for name, value in positive.items():
            if not value > 0 or math.isinf(value):  # also rejects NaN
                raise ValueError(f"{name} must be a positive number of seconds: {value!r}")
        for name, count in (
            ("request_attempts", self.request_attempts),
            ("join_attempts", self.join_attempts),
            ("mtorr_count", self.mtorr_count),
            ("max_in_flight", self.max_in_flight),
        ):
            if count < 1:
                raise ValueError(f"{name} must be >= 1: {count!r}")
        if self.indirect_extra_attempts < 0:
            raise ValueError(
                f"indirect_extra_attempts must be >= 0: {self.indirect_extra_attempts!r}"
            )
        if not self.late_window >= 0 or math.isinf(self.late_window):
            raise ValueError(f"late_window must be >= 0 seconds: {self.late_window!r}")
        if not self.mtorr_spacing >= 0:
            raise ValueError(f"mtorr_spacing must be >= 0 seconds: {self.mtorr_spacing!r}")
        interval = self.mtorr_interval
        if math.isfinite(interval) and 0 < interval < MIN_MTORR_INTERVAL:
            raise ValueError(
                f"mtorr_interval must be >= {MIN_MTORR_INTERVAL} s (or <= 0 to disable): "
                f"{interval!r}"
            )
        short = self.preferred_short
        if short is not None and not 0x0001 <= short <= 0xFFF7:
            raise ValueError(f"preferred_short must be 0x0001..0xFFF7: {short!r}")


@dataclass(frozen=True, slots=True)
class NetworkSummary:
    """Allowlisted, key-free view of the ZDD's Commissioning Status.

    The full ``CommissioningStatus`` (which holds the network, link and admin keys) is reduced to
    this immediately after the read and then dropped. ``channel_masks`` is ``None`` if the TLV
    is absent or malformed (its layout is unverified live). ``extended_pan_id`` and
    ``trust_center_address`` are identifiers: diagnostics must pseudonymise them.
    ``status_deviations`` holds the ``(tag, length)`` headers of allowed non-ZD-1.0 length
    variants (``CommissioningStatus.deviations``; never a value byte), e.g.
    ``((0x05, 4),)`` on the live R0.
    """

    pan_id: int | None
    extended_pan_id: Eui64 | None
    channel_masks: tuple[ChannelMask, ...] | None
    trust_center_address: Eui64 | None
    device_type: int | None
    joined_status: int | None
    status_deviations: tuple[tuple[int, int], ...] = ()

    @classmethod
    def from_status(cls, status: CommissioningStatus) -> Self:
        """Copy only the allowlisted fields; never raises on a malformed channel TLV."""
        try:
            masks = status.channel_masks
        except ValueError, IndexError:  # DecodeError is a ValueError
            masks = None
        return cls(
            pan_id=status.pan_id,
            extended_pan_id=status.extended_pan_id,
            channel_masks=masks,
            trust_center_address=status.trust_center_address,
            device_type=status.device_type,
            joined_status=status.joined_status,
            status_deviations=status.deviations,
        )


@dataclass(frozen=True, slots=True)
class JoinInfo:
    """Result of a successful ``ZigbeeDirectNode.join()``; holds no key material.

    ``own_short`` is the validated, TC-assigned short (authoritative); ``requested_short`` the
    placeholder we asked for. ``zdd_short`` comes from Commissioning Status TLV 0x06,
    ``zdd_eui`` from SE2.
    """

    own_short: int
    own_eui: Eui64
    zdd_short: int
    zdd_eui: Eui64
    requested_short: int
    network: NetworkSummary


@dataclass(frozen=True, slots=True)
class ReportEvent:
    """One ZCL Report Attributes frame received from a device.

    ``src_ieee`` is the NWK header's source IEEE, else ``None``. Never taken from the neighbor
    table: an entry there can be stale (a walk result), and consumers treat ``src_ieee`` as
    proof that the device is at ``src_short``.
    ``manufacturer_code`` is the ZCL header's code (``None`` for a standard frame).
    """

    src_short: int
    src_ieee: Eui64 | None
    endpoint: int
    cluster: int
    manufacturer_code: int | None
    records: tuple[AttributeRecord, ...]


@dataclass(slots=True)
class NodeStats:
    """Counters for diagnostics; mutated by the node, dispatcher and router on the loop thread.

    * ``timeouts``: requests that exhausted every attempt.
    * ``retransmits``: attempts after the first.
    * ``indirect_retries``: resends after an attempt was ended by Network Status 0x05/0x06 (the
      parent of a sleepy destination dropped our frame), counted when the resend is sent (also
      in ``retransmits``).
    * ``late_drops``: responses matching a retired key (late or duplicate).
    * ``fallback_hits``: responses matched only through ``codec.fallback``.
    * ``mfr_header_missing``: manufacturer-specific requests answered without the MS header.
    * ``decode_errors``: NPDUs dropped because NWK/APS/ZCL/ZDO decoding failed (no fallback hit).
    * ``unmatched``: decodable responses matching no pending or retired key.
    * ``reports``, ``device_annces``, ``network_status``: frames handed to listeners/routing.
    * ``rreq_seen``, ``rrep_sent``, ``mtorr_sent``: routing activity. ``rreq_own_echo``: our
      own MTORRs relayed back by neighbours (not in ``rreq_seen``).
    * ``route_records``, ``link_status``: NWK Route Record / Link Status commands received
      (decoded and counted only).
    * ``aps_acks_sent``: APS acks sent for inbound unicast data frames with the ack-request bit;
      ``aps_ack_failures``: acks that could not be sent (write failed, node closing, too many
      in flight).
    """

    timeouts: int = 0
    retransmits: int = 0
    indirect_retries: int = 0
    late_drops: int = 0
    fallback_hits: int = 0
    mfr_header_missing: int = 0
    decode_errors: int = 0
    unmatched: int = 0
    reports: int = 0
    device_annces: int = 0
    network_status: int = 0
    rreq_seen: int = 0
    rrep_sent: int = 0
    mtorr_sent: int = 0
    rreq_own_echo: int = 0
    route_records: int = 0
    link_status: int = 0
    aps_acks_sent: int = 0
    aps_ack_failures: int = 0


__all__ = [
    "MIN_MTORR_INTERVAL",
    "JoinInfo",
    "NetworkSummary",
    "NodeConfig",
    "NodeStats",
    "ReportEvent",
    "RouteReplyMode",
]
