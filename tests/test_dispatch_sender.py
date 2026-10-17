"""Dispatch: a NWK source IEEE is emitted as address evidence and checked against
``Envelope.expect_ieee`` (review round 4)."""

from __future__ import annotations

import dataclasses

from fixtures import golden as g
from localtrv.zigbee_direct.codec.nwk import NwkFrame
from localtrv.zigbee_direct.types import Eui64
from test_dispatch import feed, read_envelope, setup

OTHER = Eui64.from_str("02:00:00:00:00:09:00:01")


def with_src_ieee(npdu: bytes, ieee: Eui64 | None, *, src: int | None = None) -> bytes:
    frame = NwkFrame.decode(npdu)
    return dataclasses.replace(frame, src_ieee=ieee, src=frame.src if src is None else src).encode()


async def test_response_naming_another_sender_resolves_nothing() -> None:
    host, dispatcher = setup()
    pending = host.pending.register(dataclasses.replace(read_envelope(), expect_ieee=g.VALVE_EUI))
    feed(dispatcher, with_src_ieee(g.ZCL_READ_RSP, OTHER))
    assert not pending.future.done()
    assert host.stats.unmatched == 1
    assert host.senders == [(g.VALVE_SHORT, OTHER)]  # still evidence: OTHER is at the short
    feed(dispatcher, with_src_ieee(g.ZCL_READ_RSP, g.VALVE_EUI))
    assert pending.future.done()


async def test_response_without_or_with_the_expected_ieee_resolves() -> None:
    host, dispatcher = setup()
    pending = host.pending.register(dataclasses.replace(read_envelope(), expect_ieee=g.VALVE_EUI))
    feed(dispatcher, g.ZCL_READ_RSP)  # no IEEE in the header: not checked
    assert pending.future.done()
    assert host.senders == []


async def test_fallback_scan_checks_the_sender_too() -> None:
    host, dispatcher = setup()
    pending = host.pending.register(dataclasses.replace(read_envelope(), expect_ieee=g.VALVE_EUI))
    feed(dispatcher, with_src_ieee(g.QUIRK_GARBAGE4, OTHER))
    assert not pending.future.done()
    assert host.stats.fallback_hits == 0


def test_own_frames_are_not_emitted() -> None:
    host, dispatcher = setup()
    feed(dispatcher, with_src_ieee(g.ZCL_READ_RSP, g.ZVD_EUI, src=g.ZVD_SHORT))
    assert host.senders == []
