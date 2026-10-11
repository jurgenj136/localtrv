"""High-level Zigbee Direct virtual node (phase-2 stub, not implemented).

Design constraints for the implementation:

Join flow
    Session (SPEKE handshake) -> Commissioning Request -> Device_annce -> many-to-one Route
    Request -> answer incoming Route Requests. Route Request replies are deduplicated per
    ``(originator, route_id)`` with a TTL, for ANY originator.

Allocators
    One NWK sequence allocator, one ZDO sequence allocator, one ZCL TSN allocator and one APS
    counter allocator. They are owned by the node and are never shared module state.

Pending requests
    Keyed by ``(src_short, kind, seq)``. Default timeout 35 s; sleepy end devices may need
    2-30 s to answer. Futures are created lazily inside the running loop.

Addressing
    The ZDD short address and EUI-64 are read from the Commissioning Status / SE2 and never
    hardcoded. Devices are addressed by EUI-64; short addresses are resolved at runtime.

Own short address strategy
    Pick a random valid short address that avoids known shorts. The Trust Center-assigned short
    (from the Commissioning Response) is the truth. The caller may persist it and re-request it
    on the next join.

Connection policy
    Persistent connection preferred. Start with passive change detection (listen for reports)
    before issuing active reads, to keep sleepy end devices and battery use in check.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .transport import ZigbeeDirectTransport

DEFAULT_REQUEST_TIMEOUT_S = 35.0
SLEEPY_END_DEVICE_RESPONSE_RANGE_S = (2.0, 30.0)


class ZigbeeDirectNode:
    """Virtual Zigbee node attached to a ZDD through a transport (stub)."""

    def __init__(self, transport: ZigbeeDirectTransport) -> None:
        self._transport = transport

    async def join(self) -> None:
        """Run the join flow (stub)."""
        raise NotImplementedError("phase 2")
