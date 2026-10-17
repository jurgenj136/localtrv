"""node_types.py: ``NetworkSummary.from_status`` keeps only the allowlisted fields."""

from __future__ import annotations

from dataclasses import fields

from fixtures import golden as g
from localtrv.zigbee_direct.codec.commissioning import ChannelMask, CommissioningStatus
from localtrv.zigbee_direct.node_types import NetworkSummary
from localtrv.zigbee_direct.types import SecretBytes

KEY = SecretBytes(bytes(range(16)))  # dummy


def status(channel_raw: bytes | None) -> CommissioningStatus:
    return CommissioningStatus(
        extended_pan_id=g.EXT_PAN,
        pan_id=0x1A2B,
        network_channel_raw=channel_raw,
        network_key=KEY,
        link_key=KEY,
        admin_key=KEY,
        device_type=1,
        nwk_address=g.ZDD_SHORT,
        ieee_address=g.ZDD_EUI,
        trust_center_address=g.COORDINATOR_EUI,
        status_map=0x12,
    )


def test_from_status_copies_allowlisted_fields() -> None:
    summary = NetworkSummary.from_status(status(bytes([1, 0x00, 0x08, 0x00, 0x00])))
    assert summary == NetworkSummary(
        pan_id=0x1A2B,
        extended_pan_id=g.EXT_PAN,
        channel_masks=(ChannelMask(page=0, mask=0x0800),),
        trust_center_address=g.COORDINATOR_EUI,
        device_type=1,
        joined_status=2,
    )
    assert not any("key" in f.name for f in fields(NetworkSummary))


def test_from_status_tolerates_a_malformed_channel_tlv() -> None:
    assert NetworkSummary.from_status(status(bytes([2, 0x00]))).channel_masks is None
    assert NetworkSummary.from_status(status(None)).channel_masks is None
