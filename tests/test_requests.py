"""requests.py (T11): allocators, retired window, pending map, envelopes, join slot."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from fixtures import golden as g
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID, ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.fallback import ExpectedZcl, ExpectedZdo
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import CommissioningResponse
from vicare_local_ble.zigbee_direct.codec.zcl import (
    DefaultResponse,
    ReadAttributesResponse,
    ZclCommandId,
    ZclDirection,
    ZclFrame,
    ZclFrameType,
    ZclHeader,
)
from vicare_local_ble.zigbee_direct.codec.zdo import ActiveEpRsp
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiRsp
from vicare_local_ble.zigbee_direct.errors import RouteError
from vicare_local_ble.zigbee_direct.requests import (
    MAX_RETIRED,
    Allocators,
    Envelope,
    EnvelopeMatch,
    JoinSlot,
    JoinToken,
    PendingMap,
    RetiredWindow,
    SeqAllocator,
    ZclResponse,
)

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.types import Eui64

VALVE = g.VALVE_SHORT
TSN = 0x2B


def zcl_envelope(**kw: object) -> Envelope:
    fields: dict[str, object] = {
        "src_short": VALVE,
        "kind": "zcl",
        "seq": TSN,
        "profile_id": HA_PROFILE_ID,
        "cluster_id": 0x0201,
        "remote_endpoint": 1,
        "local_endpoint": 1,
        "request_command": ZclCommandId.READ_ATTRIBUTES,
        "response_commands": frozenset({ZclCommandId.READ_ATTRIBUTES_RESPONSE}),
    }
    fields.update(kw)
    return Envelope(**fields)  # type: ignore[arg-type]


def zdo_envelope(**kw: object) -> Envelope:
    fields: dict[str, object] = {
        "src_short": VALVE,
        "kind": "zdo",
        "seq": 0x0B,
        "profile_id": 0,
        "cluster_id": 0x8005,
        "nwk_addr_of_interest": VALVE,
    }
    fields.update(kw)
    return Envelope(**fields)  # type: ignore[arg-type]


def golden_zcl(npdu: bytes) -> tuple[ApsDataFrame, ZclFrame]:
    aps = ApsDataFrame.decode(NwkFrame.decode(npdu).payload)
    return aps, ZclFrame.decode(aps.payload)


# --- allocators -------------------------------------------------------------------------------


def test_seq_allocator_wraps_and_skips() -> None:
    alloc = SeqAllocator(0xFE)
    assert [alloc.next(), alloc.next(), alloc.next()] == [0xFE, 0xFF, 0x00]
    assert alloc.peek() == 1
    assert alloc.next(skip=lambda v: v in {1, 2}) == 3
    with pytest.raises(RuntimeError, match="256"):
        alloc.next(skip=lambda _v: True)
    with pytest.raises(ValueError, match="range"):
        SeqAllocator(256)


def test_allocators_create() -> None:
    alloc = Allocators.create()
    assert [a.peek() for a in (alloc.nwk, alloc.zdo, alloc.tsn, alloc.aps)] == [1, 1, 1, 1]
    assert alloc.nwk is not Allocators.create().nwk
    assert Allocators.create(7).tsn.peek() == 7


# --- retired window ---------------------------------------------------------------------------


async def test_retired_window_ttl_size_and_refresh() -> None:
    clock = VirtualClock()
    window = RetiredWindow(clock, ttl=10.0, max_size=2)
    window.add((1, "zcl", 5))
    await clock.advance(5.0)
    window.add((2, "zdo", 5))
    assert window.contains((1, "zcl", 5))
    assert window.seq_in_use("zcl", 5)
    assert not window.seq_in_use("zcl", 6)
    window.add((1, "zcl", 5))  # refresh: now the newest
    window.add((3, "zcl", 7))  # evicts the oldest: (2, zdo, 5)
    assert not window.contains((2, "zdo", 5))
    assert len(window) == 2
    await clock.advance(10.0)
    assert not window.contains((1, "zcl", 5))
    assert len(window) == 0
    window.add((4, "zcl", 1))
    window.discard((4, "zcl", 1))
    assert not window.contains((4, "zcl", 1))
    assert RetiredWindow(clock, ttl=1.0).max_size == MAX_RETIRED == 512


# --- pending map ------------------------------------------------------------------------------


async def test_pending_map_lifecycle() -> None:
    clock = VirtualClock()
    pending = PendingMap(clock=clock, late_window=120.0)
    envelope = zcl_envelope()
    entry = pending.register(envelope)
    assert entry.created_at == 0.0
    assert pending.get(envelope.key) is entry
    assert pending.for_src(VALVE) == (entry,)
    assert pending.for_src(VALVE + 1) == ()
    assert pending.seq_in_use("zcl", TSN)
    assert not pending.seq_in_use("zdo", TSN)
    with pytest.raises(ValueError, match="pending"):
        pending.register(envelope)
    result = ZclResponse(ZclHeader(TSN, 1), ReadAttributesResponse(()))
    assert pending.resolve(envelope.key, result)
    assert not pending.resolve(envelope.key, result)  # already done
    assert not pending.resolve((1, "zcl", 1), result)  # unknown
    assert await entry.future is result
    assert not pending.is_retired(envelope.key)
    pending.retire(envelope.key)
    pending.retire(envelope.key)  # idempotent
    assert len(pending) == 0
    assert pending.is_retired(envelope.key)
    assert pending.seq_in_use("zcl", TSN)
    again = pending.register(envelope)  # re-registering takes the key out of the window
    assert not pending.is_retired(envelope.key)
    pending.retire(envelope.key)
    assert again.future.cancelled()
    await clock.advance(120.0)
    assert not pending.seq_in_use("zcl", TSN)


async def test_pending_fail_dst_and_fail_all() -> None:
    pending = PendingMap(clock=VirtualClock(), late_window=1.0)
    a = pending.register(zcl_envelope())
    b = pending.register(zcl_envelope(seq=TSN + 1))
    c = pending.register(zdo_envelope(src_short=0x0001))
    assert pending.fail_dst(VALVE, RouteError(VALVE, 2)) == 2
    assert pending.fail_dst(VALVE, RouteError(VALVE, 2)) == 0  # already failed
    for entry in (a, b):
        with pytest.raises(RouteError):
            await entry.future
    pending.fail_all(ConnectionError("gone"))
    with pytest.raises(ConnectionError):
        await c.future
    for entry in (a, b, c):
        pending.retire(entry.envelope.key)  # marks a failure retrieved, no warning
    assert len(pending) == 0
    d = pending.register(zcl_envelope(seq=1))
    d.future.cancel()
    pending.retire(d.envelope.key)  # an already cancelled future is fine too
    assert pending.is_retired(d.envelope.key)


# --- envelopes --------------------------------------------------------------------------------


def test_envelope_matches_golden_read_response() -> None:
    aps, frame = golden_zcl(g.ZCL_READ_RSP)
    envelope = zcl_envelope()
    assert envelope.key == (VALVE, "zcl", TSN)
    assert envelope.match_zcl(VALVE, aps, frame) is EnvelopeMatch.MATCH


@pytest.mark.parametrize(
    ("change", "src"),
    [
        ({}, VALVE + 1),  # from another device
        ({"cluster_id": 0x0000}, VALVE),
        ({"profile_id": 0x0109}, VALVE),
        ({"remote_endpoint": 2}, VALVE),
        ({"local_endpoint": 2}, VALVE),
        ({"seq": TSN + 1}, VALVE),
        ({"response_commands": frozenset({ZclCommandId.WRITE_ATTRIBUTES_RESPONSE})}, VALVE),
        ({"manufacturer_code": 0x1221}, VALVE),  # no MS header: accepted below, not here
        ({"kind": "zdo"}, VALVE),
    ],
)
def test_envelope_zcl_rejections(change: dict[str, object], src: int) -> None:
    aps, frame = golden_zcl(g.ZCL_READ_RSP)
    verdict = zcl_envelope(**change).match_zcl(src, aps, frame)
    if change == {"manufacturer_code": 0x1221}:
        assert verdict is EnvelopeMatch.MATCH_MFR_HEADER_MISSING
    else:
        assert verdict is EnvelopeMatch.NO_MATCH


def test_envelope_manufacturer_rules() -> None:
    mfr = zcl_envelope(seq=0x2C, manufacturer_code=0x1221)
    aps, with_header = golden_zcl(g.ZCL_READ_RSP_MFR)
    assert mfr.match_zcl(VALVE, aps, with_header) is EnvelopeMatch.MATCH
    aps, without = golden_zcl(g.ZCL_READ_RSP_MFR_NO_HEADER)
    assert mfr.match_zcl(VALVE, aps, without) is EnvelopeMatch.MATCH_MFR_HEADER_MISSING
    other = zcl_envelope(seq=0x2C, manufacturer_code=0x1222)
    assert other.match_zcl(VALVE, aps, with_header) is EnvelopeMatch.NO_MATCH
    standard = zcl_envelope(seq=0x2C)
    assert standard.match_zcl(VALVE, aps, with_header) is EnvelopeMatch.NO_MATCH


def test_envelope_default_response_rules() -> None:
    aps, frame = golden_zcl(g.ZCL_DEFAULT_RSP)  # Default Response to Read (0x00), status 0xC3
    read = zcl_envelope(seq=0x2E, cluster_id=0x0004)
    assert read.match_zcl(VALVE, aps, frame) is EnvelopeMatch.MATCH
    write = zcl_envelope(
        seq=0x2E,
        cluster_id=0x0004,
        request_command=ZclCommandId.WRITE_ATTRIBUTES,
        response_commands=frozenset({ZclCommandId.WRITE_ATTRIBUTES_RESPONSE}),
    )
    assert write.match_zcl(VALVE, aps, frame) is EnvelopeMatch.NO_MATCH
    broken = ZclFrame(frame.header, b"\x00")  # undecodable Default Response
    assert read.match_zcl(VALVE, aps, broken) is EnvelopeMatch.NO_MATCH
    no_request = zcl_envelope(seq=0x2E, cluster_id=0x0004, request_command=None)
    assert no_request.match_zcl(VALVE, aps, frame) is EnvelopeMatch.NO_MATCH


def test_envelope_rejects_direction_and_cluster_specific_frames() -> None:
    aps, frame = golden_zcl(g.ZCL_READ_RSP)
    envelope = zcl_envelope()
    request_dir = ZclFrame(
        ZclHeader(TSN, 1, direction=ZclDirection.CLIENT_TO_SERVER), frame.payload
    )
    assert envelope.match_zcl(VALVE, aps, request_dir) is EnvelopeMatch.NO_MATCH
    specific = ZclFrame(
        ZclHeader(
            TSN,
            1,
            frame_type=ZclFrameType.CLUSTER_SPECIFIC,
            direction=ZclDirection.SERVER_TO_CLIENT,
        ),
        frame.payload,
    )
    assert envelope.match_zcl(VALVE, aps, specific) is EnvelopeMatch.NO_MATCH


def test_envelope_zdo_matching() -> None:
    rsp = ActiveEpRsp.decode(g.ACTIVE_EP_RSP_ZDO)
    aps = ApsDataFrame(cluster_id=0x8005, profile_id=0, payload=g.ACTIVE_EP_RSP_ZDO)
    envelope = zdo_envelope()
    assert envelope.match_zdo(VALVE, aps, rsp)
    assert not envelope.match_zdo(VALVE + 1, aps, rsp)
    assert not zdo_envelope(seq=0x0C).match_zdo(VALVE, aps, rsp)
    assert not zdo_envelope(nwk_addr_of_interest=VALVE + 1).match_zdo(VALVE, aps, rsp)
    assert zdo_envelope(nwk_addr_of_interest=None).match_zdo(VALVE, aps, rsp)
    assert not zdo_envelope(cluster_id=0x8004).match_zdo(VALVE, aps, rsp)
    wrong_profile = ApsDataFrame(cluster_id=0x8005, profile_id=0x0104, payload=b"")
    assert not envelope.match_zdo(VALVE, wrong_profile, rsp)
    assert not zcl_envelope(seq=0x0B).match_zdo(VALVE, aps, rsp)
    # Mgmt_Lqi has no address of interest: the check is skipped
    lqi = MgmtLqiRsp(seq=0x0B, status=0)
    lqi_aps = ApsDataFrame(cluster_id=0x8031, profile_id=0, payload=lqi.encode())
    assert zdo_envelope(cluster_id=0x8031).match_zdo(VALVE, lqi_aps, lqi)


def test_envelope_expected() -> None:
    assert zdo_envelope().expected() == ExpectedZdo(src_short=VALVE, cluster_id=0x8005, seq=0x0B)
    assert zcl_envelope(manufacturer_code=0x1221).expected() == ExpectedZcl(
        src_short=VALVE,
        tsn=TSN,
        command_id=ZclCommandId.READ_ATTRIBUTES_RESPONSE,
        cluster_id=0x0201,
        manufacturer_code=0x1221,
    )
    bare = zcl_envelope(response_commands=frozenset())
    assert bare.expected().command_id == ZclCommandId.DEFAULT_RESPONSE  # type: ignore[union-attr]
    assert DefaultResponse(0, 0).COMMAND_ID == ZclCommandId.DEFAULT_RESPONSE


# --- join slot --------------------------------------------------------------------------------


def commissioning(dst: int, src: int, dst_ieee: Eui64 | None = g.ZVD_EUI) -> NwkFrame:
    return NwkFrame(
        frame_type=NwkFrameType.COMMAND,
        dst=dst,
        src=src,
        radius=30,
        seq=1,
        payload=CommissioningResponse(dst, 0).encode(),
        dst_ieee=dst_ieee,
    )


async def test_join_slot() -> None:
    slot = JoinSlot()
    response = CommissioningResponse(g.ZVD_SHORT, 0)
    assert slot.active is None
    assert not slot.offer(commissioning(g.ZVD_SHORT, g.ZDD_SHORT), response)  # no token
    token = JoinToken(g.ZVD_SHORT, 1, g.ZDD_SHORT, g.ZVD_EUI)
    first = slot.open(token)
    assert slot.active is token
    second = slot.open(JoinToken(g.OTHER_PLACEHOLDER, 2, g.ZDD_SHORT, g.ZVD_EUI))
    assert first.cancelled()  # replaced
    assert not slot.offer(commissioning(g.ZVD_SHORT, g.ZDD_SHORT), response)  # older placeholder
    assert not slot.offer(commissioning(g.OTHER_PLACEHOLDER, g.ZVD_SHORT), response)  # src
    assert not slot.offer(
        commissioning(g.OTHER_PLACEHOLDER, g.ZDD_SHORT, g.VALVE_EUI), response
    )  # dst IEEE is not ours
    assert slot.offer(commissioning(g.OTHER_PLACEHOLDER, g.ZDD_SHORT, None), response)
    assert await second is response
    assert not slot.offer(commissioning(g.OTHER_PLACEHOLDER, g.ZDD_SHORT), response)  # done
    slot.close()
    assert slot.active is None
    third = slot.open(token)
    slot.close()
    assert third.cancelled()
    assert asyncio.isfuture(third)
