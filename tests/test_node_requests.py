"""ZigbeeDirectNode requests (T11): envelopes, late window, races, parallelism, retries, quirks."""

from __future__ import annotations

import asyncio

import pytest

from test_node import LOCAL_TEMPERATURE, MFR, SETPOINT, THERMOSTAT, Rig, rig
from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID, ZDO_PROFILE_ID, ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
from vicare_local_ble.zigbee_direct.codec.zcl import (
    AttributeRecord,
    ReadAttributesResponse,
    ReadAttributeStatus,
    WriteAttributesResponse,
    WriteAttributeStatus,
    ZclCommandId,
    ZclDirection,
    ZclFrame,
    ZclHeader,
)
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import ActiveEpReq, ActiveEpRsp, SimpleDescRsp
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiReq, MgmtLqiRsp
from vicare_local_ble.zigbee_direct.errors import RequestTimeoutError, ZclStatusError
from vicare_local_ble.zigbee_direct.node import NodeConfig, ReportEvent
from vicare_local_ble.zigbee_direct.types import COORDINATOR

FAKE_VALUE = 1234  # never in the valve table: tells an injected frame from the real reply


def zcl_aps(
    tsn: int,
    *,
    cluster: int = THERMOSTAT,
    command: object | None = None,
    command_id: int = ZclCommandId.READ_ATTRIBUTES_RESPONSE,
    manufacturer: int | None = None,
    direction: ZclDirection = ZclDirection.SERVER_TO_CLIENT,
    src_endpoint: int = 1,
    dst_endpoint: int = 1,
    profile: int = HA_PROFILE_ID,
) -> ApsDataFrame:
    if command is None:
        command = ReadAttributesResponse(
            (ReadAttributeStatus(LOCAL_TEMPERATURE, 0, ZclDataType.INT16, FAKE_VALUE),)
        )
    header = ZclHeader(
        tsn=tsn,
        command_id=command_id,
        manufacturer_code=manufacturer,
        direction=direction,
        disable_default_response=True,
    )
    payload = header.encode() + command.encode()  # type: ignore[attr-defined]
    return ApsDataFrame(
        cluster_id=cluster,
        profile_id=profile,
        payload=payload,
        dst_endpoint=dst_endpoint,
        src_endpoint=src_endpoint,
        counter=0x99,
    )


def read(
    r: Rig, valve_index: int = 0, **kw: object
) -> asyncio.Future[tuple[ReadAttributeStatus, ...]]:
    valve = r.inst.valves[valve_index]
    attrs = kw.pop("attrs", [LOCAL_TEMPERATURE])
    return asyncio.ensure_future(
        r.node.zcl_read(valve.short, 1, kw.pop("cluster", THERMOSTAT), attrs, **kw)  # type: ignore[arg-type]
    )


def zcl_tsns(r: Rig, start: int = 4) -> list[int]:
    """TSN of every ZCL request written after the join (ZCL header byte after the APS)."""
    out = []
    for raw in r.writes()[start:]:
        aps = ApsDataFrame.decode(NwkFrame.decode(raw).payload)
        out.append(ZclFrame.decode(aps.payload).header.tsn)
    return out


# --- basic requests -------------------------------------------------------------------------


async def test_read_write_and_zdo_requests() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        records = await r.clock.run_task(r.node.zcl_read(valve.short, 1, THERMOSTAT, [SETPOINT]))
        assert records[0].attribute_id == SETPOINT
        assert records[0].status == 0
        rsp = await r.clock.run_task(
            r.node.zcl_write(
                valve.short, 1, THERMOSTAT, [AttributeRecord(SETPOINT, ZclDataType.INT16, 2150)]
            )
        )
        assert rsp.success
        assert valve.writes[-1][1] == 2150
        active = await r.clock.run_task(
            r.node.zdo_request(
                valve.short, ActiveEpReq(seq=0, nwk_addr=valve.short), response=ActiveEpRsp
            )
        )
        assert active.endpoints == (1,)
        lqi = await r.clock.run_task(
            r.node.zdo_request(COORDINATOR, MgmtLqiReq(seq=0), response=MgmtLqiRsp)
        )
        assert lqi.neighbor_table_entries >= 1
        assert r.core.pending.seq_in_use("zdo", active.seq)  # retired keys stay reserved
        assert len(r.core.pending) == 0


async def test_zdo_request_response_type_and_unicast_checks() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        with pytest.raises(TypeError):
            await r.node.zdo_request(
                valve.short, ActiveEpReq(seq=0, nwk_addr=valve.short), response=SimpleDescRsp
            )
        with pytest.raises(ValueError, match="unicast"):
            await r.node.zcl_read(0xFFFD, 1, THERMOSTAT, [0])


# --- envelope matching ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "variant",
    ["cluster", "src_endpoint", "dst_endpoint", "profile", "mfr_on_standard", "command", "source"],
)
async def test_envelope_rejects_mismatches(variant: str) -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        tsn = r.core.allocators.tsn.peek()
        src = valve.short
        match variant:
            case "cluster":
                aps = zcl_aps(tsn, cluster=0x0000)
            case "src_endpoint":
                aps = zcl_aps(tsn, src_endpoint=2)
            case "dst_endpoint":
                aps = zcl_aps(tsn, dst_endpoint=2)
            case "profile":
                aps = zcl_aps(tsn, profile=0x0109)
            case "mfr_on_standard":
                aps = zcl_aps(tsn, manufacturer=MFR)
            case "command":
                aps = zcl_aps(
                    tsn,
                    command=WriteAttributesResponse((WriteAttributeStatus(0),)),
                    command_id=ZclCommandId.WRITE_ATTRIBUTES_RESPONSE,
                )
            case _:
                src = r.inst.valves[1].short
                aps = zcl_aps(tsn)
        task = read(r)
        await r.clock.advance(1.0)
        r.inject(r.from_valve(src, aps))
        await r.clock.advance(0)
        assert not task.done()
        if variant == "profile":  # implausible header: scanned, refused by the envelope
            assert r.node.stats.decode_errors == 1
        else:
            assert r.node.stats.unmatched == 1
        records = await r.clock.run_task(task)
        assert records[0].value != FAKE_VALUE


async def test_wrong_manufacturer_code_is_rejected() -> None:
    async with rig() as r:
        tsn = r.core.allocators.tsn.peek()
        task = read(r, attrs=[0x4000], manufacturer=MFR)
        await r.clock.advance(1.0)
        r.inject(r.from_valve(r.inst.valves[0].short, zcl_aps(tsn, manufacturer=MFR + 1)))
        await r.clock.advance(0)
        assert not task.done()
        records = await r.clock.run_task(task)
        assert records[0].value == 1
        assert r.node.stats.mfr_header_missing == 0


async def test_client_to_server_frame_is_ignored() -> None:
    async with rig() as r:
        tsn = r.core.allocators.tsn.peek()
        task = read(r)
        await r.clock.advance(1.0)
        aps = zcl_aps(tsn, direction=ZclDirection.CLIENT_TO_SERVER)
        r.inject(r.from_valve(r.inst.valves[0].short, aps))
        await r.clock.advance(0)
        assert not task.done()
        assert (await r.clock.run_task(task))[0].value != FAKE_VALUE


@pytest.mark.parametrize("with_header", [True, False])
async def test_mfr_header_missing_is_accepted_and_counted(with_header: bool) -> None:
    async with rig() as r:
        r.inst.valves[0].mfr_response_header = with_header
        records = await r.clock.run_task(read(r, attrs=[0x4000], manufacturer=MFR))
        assert records[0].value == 1
        assert r.node.stats.mfr_header_missing == (0 if with_header else 1)


async def test_zdo_nwk_addr_of_interest_is_checked() -> None:
    async with rig() as r:
        valve, other = r.inst.valves[0], r.inst.valves[1]
        seq = r.core.allocators.zdo.peek()
        task = asyncio.ensure_future(
            r.node.zdo_request(
                valve.short, ActiveEpReq(seq=0, nwk_addr=valve.short), response=ActiveEpRsp
            )
        )
        await r.clock.advance(1.0)
        fake = ActiveEpRsp(seq, 0, other.short, (9,))
        aps = ApsDataFrame(
            cluster_id=0x8005, profile_id=ZDO_PROFILE_ID, payload=fake.encode(), counter=1
        )
        r.inject(r.from_valve(valve.short, aps))
        await r.clock.advance(0)
        assert not task.done()
        assert r.node.stats.unmatched == 1
        rsp = await r.clock.run_task(task)
        assert (rsp.nwk_addr, rsp.endpoints) == (valve.short, (1,))


async def test_report_with_pending_tsn_never_resolves_it() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.node.note_neighbors(r.inst.network.neighbor_table(COORDINATOR))
        events: list[ReportEvent] = []
        r.node.on_report(events.append)
        tsn = r.core.allocators.tsn.peek()
        task = read(r)
        await r.clock.advance(1.0)
        valve.report(THERMOSTAT, (LOCAL_TEMPERATURE,), tsn=tsn)
        await r.clock.advance(0)
        assert not task.done()
        (event,) = events
        assert (event.src_short, event.src_ieee, event.cluster) == (
            valve.short,
            valve.eui,
            THERMOSTAT,
        )
        assert event.records[0].attribute_id == LOCAL_TEMPERATURE
        assert r.node.stats.reports == 1
        await r.clock.run_task(task)
        assert r.clock.now() >= 14.0


async def test_default_response_for_another_command_is_rejected() -> None:
    async with rig() as r:
        r.inst.valves[0].queue_default_response(ZclCommandId.WRITE_ATTRIBUTES, 0x00)
        start = r.clock.now()
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        assert r.node.stats.unmatched == 1
        assert r.node.stats.retransmits == 1  # attempt 2 got the real answer
        assert r.clock.now() - start == pytest.approx(30.0 + 14.0)


async def test_default_response_for_the_request_raises_zcl_status() -> None:
    async with rig() as r:
        with pytest.raises(ZclStatusError) as exc:
            await r.clock.run_task(read(r, cluster=0x0004))  # unsupported cluster
        assert exc.value.status == 0xC3
        r.inst.valves[0].queue_default_response(ZclCommandId.WRITE_ATTRIBUTES, 0x87)
        record = AttributeRecord(SETPOINT, ZclDataType.INT16, 2150)
        with pytest.raises(ZclStatusError) as exc:
            await r.clock.run_task(
                r.node.zcl_write(r.inst.valves[0].short, 1, THERMOSTAT, [record])
            )
        assert exc.value.status == 0x87


async def test_default_response_success_to_a_write_means_success() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        record = AttributeRecord(SETPOINT, ZclDataType.INT16, 2150)
        valve.queue_default_response(ZclCommandId.WRITE_ATTRIBUTES, 0x00)
        rsp = await r.clock.run_task(r.node.zcl_write(valve.short, 1, THERMOSTAT, [record]))
        assert rsp == WriteAttributesResponse.decode(b"\x00")  # same as an all-success ``04 00``
        assert rsp.success


async def test_default_response_success_to_a_read_raises() -> None:
    async with rig() as r:
        r.inst.valves[0].queue_default_response(ZclCommandId.READ_ATTRIBUTES, 0x00)
        with pytest.raises(ZclStatusError) as exc:
            await r.clock.run_task(read(r))
        assert exc.value.status == 0x00


@pytest.mark.parametrize("status", [0x00, 0x87])
async def test_write_default_response_through_the_garbage4_fallback(status: int) -> None:
    weights = nf.check_variant_weights({"garbage4": 1.0})
    async with rig(network={"_weights": weights}) as r:
        valve = r.inst.valves[0]
        record = AttributeRecord(SETPOINT, ZclDataType.INT16, 2150)
        valve.queue_default_response(ZclCommandId.WRITE_ATTRIBUTES, status)
        write = r.node.zcl_write(valve.short, 1, THERMOSTAT, [record])
        if status:
            with pytest.raises(ZclStatusError) as exc:
                await r.clock.run_task(write)
            assert exc.value.status == status
        else:
            assert (await r.clock.run_task(write)).success
        assert r.node.stats.fallback_hits == 1


# --- late window ----------------------------------------------------------------------------


async def test_late_and_duplicate_responses_are_dropped() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        tsn = r.core.allocators.tsn.peek()
        await r.clock.run_task(read(r))
        r.inject(r.from_valve(valve.short, zcl_aps(tsn)))
        await r.clock.advance(0)
        assert r.node.stats.late_drops == 1
        assert r.node.stats.unmatched == 0


async def test_seq_reuse_inside_the_late_window_is_prevented() -> None:
    async with rig() as r:
        tsn = r.core.allocators.tsn.peek()
        await r.clock.run_task(read(r))
        r.core.allocators.tsn._next = tsn  # force a wrap onto the retired TSN
        await r.clock.run_task(read(r))
        assert zcl_tsns(r) == [tsn, tsn + 1]
        await r.clock.advance(r.node.config.late_window)
        r.core.allocators.tsn._next = tsn
        await r.clock.run_task(read(r))
        assert zcl_tsns(r)[-1] == tsn  # free again once the window passed
        r.inject(r.from_valve(r.inst.valves[0].short, zcl_aps(tsn)))
        await r.clock.advance(0)
        assert r.node.stats.late_drops == 1  # the third read's key is inside its window


# --- races and concurrency ------------------------------------------------------------------


async def test_response_before_the_write_returns_still_resolves() -> None:
    async with rig(latency=0.0) as r:
        r.inst.r0.write_latency = 0.5
        tsn = r.core.allocators.tsn.peek()
        key = (r.inst.valves[0].short, "zcl", tsn)
        task = read(r)
        await r.clock.advance(0)
        pending = r.core.pending.get(key)  # type: ignore[arg-type]
        assert pending is not None
        assert pending.future.done()  # the reply arrived ...
        assert not task.done()  # ... while the GATT write is still in flight
        await r.clock.advance(0.5)
        assert task.done()
        assert task.result()[0].attribute_id == LOCAL_TEMPERATURE


async def test_interleaved_parallel_requests_to_several_valves() -> None:
    async with rig() as r:
        start = r.clock.now()
        tasks = [read(r, i) for i in range(3)]
        results = await r.clock.run_task(asyncio.gather(*tasks))
        assert all(rs[0].status == 0 for rs in results)
        assert r.clock.now() - start == pytest.approx(14.0)  # in parallel, not 42 s
        assert len(set(zcl_tsns(r))) == 3


async def test_requests_to_one_destination_are_serialised() -> None:
    async with rig() as r:
        start = r.clock.now()
        done_at: list[float] = []
        tasks = [read(r, 0), read(r, 0)]
        for t in tasks:
            t.add_done_callback(lambda _t: done_at.append(r.clock.now() - start))
        await r.clock.advance(0)
        assert len(r.core.pending) == 1
        assert len(r.writes()) == 5  # the second read waits for the first
        await r.clock.run_task(asyncio.gather(*tasks))
        assert done_at == pytest.approx([14.0, 28.0])


async def test_max_in_flight_caps_concurrent_requests() -> None:
    async with rig(config=NodeConfig(max_in_flight=2)) as r:
        start = r.clock.now()
        tasks = [read(r, i) for i in range(3)]
        await r.clock.advance(0)
        assert len(r.core.pending) == 2
        await r.clock.run_task(asyncio.gather(*tasks))
        assert r.clock.now() - start == pytest.approx(28.0)


# --- timeouts and retries -------------------------------------------------------------------


async def test_timeout_and_retry_reuse_tsn_with_new_nwk_seq() -> None:
    async with rig() as r:
        r.inst.valves[0].drop_rate = 1.0
        tsn = r.core.allocators.tsn.peek()
        start = r.clock.now()
        with pytest.raises(RequestTimeoutError) as exc:
            await r.clock.run_task(read(r))
        assert (exc.value.kind, exc.value.seq) == ("zcl", tsn)
        assert r.clock.now() - start == pytest.approx(60.0)
        attempts = [NwkFrame.decode(w) for w in r.writes()[4:]]
        assert len(attempts) == 2
        assert zcl_tsns(r) == [tsn, tsn]
        assert attempts[0].seq != attempts[1].seq
        aps = [ApsDataFrame.decode(f.payload).counter for f in attempts]
        assert aps[0] != aps[1]
        assert (r.node.stats.timeouts, r.node.stats.retransmits) == (1, 1)
        assert r.core.pending.is_retired((r.inst.valves[0].short, "zcl", tsn))


async def test_zdo_retry_reuses_zdo_seq_with_aps_counter_zero() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        valve.drop_rate = 1.0
        with pytest.raises(RequestTimeoutError):
            await r.clock.run_task(
                r.node.zdo_request(valve.short, ActiveEpReq(0, valve.short), response=ActiveEpRsp)
            )
        frames = [ApsDataFrame.decode(NwkFrame.decode(w).payload) for w in r.writes()[4:]]
        assert [f.counter for f in frames] == [0, 0]
        assert frames[0].payload == frames[1].payload  # same ZDO seq


async def test_late_answer_to_attempt_one_resolves_during_attempt_two() -> None:
    async with rig(latency=35.0) as r:
        start = r.clock.now()
        records = await r.clock.run_task(read(r))
        assert records[0].status == 0
        assert r.clock.now() - start == pytest.approx(35.0)
        assert r.node.stats.retransmits == 1
        assert r.node.stats.timeouts == 0


async def test_cancelling_the_caller_retires_the_key() -> None:
    async with rig() as r:
        tsn = r.core.allocators.tsn.peek()
        task = read(r)
        await r.clock.advance(1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(r.core.pending) == 0
        assert r.core.pending.is_retired((r.inst.valves[0].short, "zcl", tsn))
        await r.clock.advance(20.0)  # the valve's reply arrives late
        assert r.node.stats.late_drops == 1


# --- quirks and noise -----------------------------------------------------------------------


@pytest.mark.parametrize(("variant", "hits"), [("source_route", 0), ("garbage4", 1)])
async def test_quirk_variants(variant: str, hits: int) -> None:
    weights = nf.check_variant_weights({variant: 1.0})  # type: ignore[dict-item]
    async with rig(network={"_weights": weights}) as r:
        records = await r.clock.run_task(read(r))
        assert records[0].attribute_id == LOCAL_TEMPERATURE
        assert r.node.stats.fallback_hits == hits
        assert r.node.stats.decode_errors == 0


async def test_garbage4_fallback_for_zdo_mfr_and_default_response() -> None:
    weights = nf.check_variant_weights({"garbage4": 1.0})
    async with rig(network={"_weights": weights}) as r:
        valve = r.inst.valves[0]
        valve.mfr_response_header = False
        rsp = await r.clock.run_task(
            r.node.zdo_request(valve.short, ActiveEpReq(0, valve.short), response=ActiveEpRsp)
        )
        assert rsp.endpoints == (1,)
        records = await r.clock.run_task(read(r, attrs=[0x4000], manufacturer=MFR))
        assert records[0].value == 1
        assert r.node.stats.mfr_header_missing == 1
        with pytest.raises(ZclStatusError):
            await r.clock.run_task(read(r, cluster=0x0004))
        assert r.node.stats.fallback_hits == 3


async def test_noise_is_ignored() -> None:
    async with rig() as r:
        annces: list[int] = []
        r.node.on_device_annce(lambda _a, src: annces.append(src))
        task = read(r)
        await r.clock.advance(1.0)
        for kind in ("foreign_annce", "foreign_broadcast", "network_status_other", "other_dst"):
            r.inst.network.emit_noise(kind)
        await r.clock.advance(0)
        assert not task.done()
        records = await r.clock.run_task(task)
        assert records[0].status == 0
        stats = r.node.stats
        assert len(annces) == stats.device_annces == 1  # foreign Device_annce: listeners only
        assert stats.network_status == 1
        assert (stats.decode_errors, stats.unmatched, stats.late_drops) == (0, 0, 0)


async def test_undecodable_frames_count_decode_errors() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        r.inject(b"\x08")  # shorter than a NWK header
        full = r.from_valve(valve.short, zcl_aps(0))
        r.inject(full[:11])  # APS truncated: neither standard nor fallback (nothing pending)
        r.inject(full[:19])  # ZCL header truncated
        garbled = ApsDataFrame(cluster_id=0x005A, profile_id=ZDO_PROFILE_ID, payload=b"\x01")
        r.inject(r.from_valve(valve.short, garbled))  # no ZDO cluster: fallback, nothing pending
        await r.clock.advance(0)
        assert r.node.stats.decode_errors == 4
