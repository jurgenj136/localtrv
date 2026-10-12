"""Value types shared by the node, dispatcher, router and connection (spec §1.3).

They live here, below ``node.py``, so ``dispatch.py`` and ``routing.py`` can build them at
runtime without importing the node. ``node.py`` re-exports every name; import them from there.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.commissioning import ChannelMask, CommissioningStatus
    from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord
    from vicare_local_ble.zigbee_direct.types import Eui64


class RouteReplyMode(StrEnum):
    """How the node answers a Route Request addressed to its own short (spec §1.3 Routing).

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
    * ``preferred_short``: requested own short if valid and not in ``avoid_shorts``.
    * ``avoid_shorts``: shorts never used as the placeholder (known device shorts, a short that
      caused an address conflict).
    """

    request_timeout: float = 30.0
    request_attempts: int = 2
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


@dataclass(frozen=True, slots=True)
class NetworkSummary:
    """Allowlisted, key-free view of the ZDD's Commissioning Status.

    The full ``CommissioningStatus`` (which holds the network, link and admin keys) is reduced to
    this immediately after the read and then dropped. ``channel_masks`` is ``None`` if the TLV
    is absent or malformed (its layout is unverified live). ``extended_pan_id`` and
    ``trust_center_address`` are identifiers: diagnostics must pseudonymise them.
    """

    pan_id: int | None
    extended_pan_id: Eui64 | None
    channel_masks: tuple[ChannelMask, ...] | None
    trust_center_address: Eui64 | None
    device_type: int | None
    joined_status: int | None

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

    ``src_ieee`` comes from the NWK header or the node's neighbor table, else ``None``.
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
    * ``late_drops``: responses matching a retired key (late or duplicate).
    * ``fallback_hits``: responses matched only through ``codec.fallback``.
    * ``mfr_header_missing``: manufacturer-specific requests answered without the MS header.
    * ``decode_errors``: NPDUs dropped because NWK/APS/ZCL/ZDO decoding failed (no fallback hit).
    * ``unmatched``: decodable responses matching no pending or retired key.
    * ``reports``, ``device_annces``, ``network_status``: frames handed to listeners/routing.
    * ``rreq_seen``, ``rrep_sent``, ``mtorr_sent``: routing activity.
    """

    timeouts: int = 0
    retransmits: int = 0
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


__all__ = [
    "JoinInfo",
    "NetworkSummary",
    "NodeConfig",
    "NodeStats",
    "ReportEvent",
    "RouteReplyMode",
]
