"""SimValve: ZCL semantics and sleepy timing, driven by golden bytes through SimNetwork.

The expected values are the hand-written golden fixtures and raw wire numbers (docs/protocol.md §9),
never ``vicare_local_ble.valves`` (no tautological scaling checks).
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass

import pytest

from fixtures import golden as g
from vicare_local_ble.testing.network import SimNetwork
from vicare_local_ble.testing.network_recorder import Indication, RecordingTunnelHost
from vicare_local_ble.testing.valve import SimValve, zk03840_attributes
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

h = g.h
SEQ = 7
APS_CTR = 15
NWK_TO_VALVE = "48 02 6F 5E 34 12 1E 06"
APS_THERMOSTAT = "00 01 01 02 04 01 01"
OTHER_EUI = Eui64.from_str("02:00:00:00:00:00:00:09")
OTHER_SHORT = 0x0E0E


def seeded(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 - deterministic simulator, not crypto


def masked(npdu: bytes) -> bytes:
    out = bytearray(npdu)
    out[SEQ] = out[APS_CTR] = 0
    return bytes(out)


def zcl(ind: Indication) -> bytes:
    """The ZCL frame of an indication (header included)."""
    return ApsDataFrame.decode(ind.frame.payload).payload


def request(tsn: int, body: str, *, cluster: str = "01 02", dst: str = "6F 5E") -> bytes:
    """A ZVD -> valve ZCL request in the live layout (``48 02``, APS ctr = tsn)."""
    t = f"{tsn:02X}"
    return h(f"48 02 {dst} 34 12 1E 06", f"00 01 {cluster} 04 01 01 {t}", body.replace("tt", t))


@dataclass
class Rig:
    clock: VirtualClock
    net: SimNetwork
    host: RecordingTunnelHost
    valve: SimValve

    async def collect(self, seconds: float) -> tuple[Indication, ...]:
        await self.clock.advance(seconds)
        return self.host.take()

    async def ask(self, npdu: bytes, seconds: float = 30.0) -> Indication:
        self.host.send(npdu)
        (ind,) = await self.collect(seconds)
        return ind


async def joined_rig(*, seed: int = 0, **valve_kwargs: object) -> Rig:
    clock = VirtualClock()
    rng = seeded(seed)
    net = SimNetwork(
        clock,
        zdd_short=g.ZDD_SHORT,
        zdd_eui=g.ZDD_EUI,
        coordinator_eui=g.COORDINATOR_EUI,
        extended_pan_id=g.EXT_PAN,
        rng=rng,
        aps_ack_request=False,  # golden replies are plain frames; the recording host never acks
    )
    host = RecordingTunnelHost(clock)
    net.attach(host)
    valve = SimValve(clock, eui=g.VALVE_EUI, short=g.VALVE_SHORT, rng=rng, **valve_kwargs)  # type: ignore[arg-type]
    net.add_valve(valve)
    host.send(g.COMMISSIONING_REQUEST, secure=False)
    await clock.advance(2.0)
    host.send(g.DEVICE_ANNCE)
    host.send(g.MTORR)
    host.take()
    return Rig(clock, net, host, valve)


# --- ZCL -------------------------------------------------------------------------------------


async def test_read_matches_golden_response() -> None:
    rig = await joined_rig()
    ind = await rig.ask(g.ZCL_READ)
    assert masked(ind.npdu) == masked(g.ZCL_READ_RSP)


async def test_unknown_attribute_is_0x86_per_record() -> None:
    rig = await joined_rig()
    ind = await rig.ask(request(0x30, "00 tt 00 10 00 00 00"))  # 0x0010 is not on the valve
    assert zcl(ind) == h("18 30 01", "10 00 86", "00 00 00 29 AD 07")


async def test_unsupported_cluster_gives_default_response_c3() -> None:
    rig = await joined_rig()
    ind = await rig.ask(request(0x2E, "00 tt 00 00 00", cluster="04 00"))  # Groups
    assert masked(ind.npdu)[8:] == masked(g.ZCL_DEFAULT_RSP)[8:]


async def test_write_persists_with_04_00() -> None:
    rig = await joined_rig()
    ind = await rig.ask(g.ZCL_WRITE)
    assert masked(ind.npdu) == masked(g.ZCL_WRITE_RSP)
    ind = await rig.ask(request(0x31, "00 tt 00 12 00"))
    assert zcl(ind) == h("18 31 01 12 00 00 29 66 08")  # 2150 = 21.50 C
    assert rig.valve.writes == (((0x0201, 0x0012, None), 2150),)


@pytest.mark.parametrize(
    ("record", "status"),
    [
        ("12 00 29 AC 0D", "87"),  # 3500 > absMax 3000: INVALID_VALUE
        ("12 00 29 E8 03", "87"),  # 1000 is fine for abs, see min limit below
        ("12 00 21 66 08", "8D"),  # uint16 instead of int16
        ("00 00 29 66 08", "88"),  # localTemperature is read-only
        ("10 00 29 00 00", "86"),  # unknown attribute
    ],
)
async def test_write_failures(record: str, status: str) -> None:
    rig = await joined_rig()
    rig.valve.set_attribute(0x0201, 0x0015, ZclDataType.INT16, 1200)  # minHeatSetpointLimit
    ind = await rig.ask(request(0x32, f"00 tt 02 {record}"))
    assert zcl(ind) == h("18 32 04", status, record[:5])
    assert rig.valve.writes == ()


@pytest.mark.parametrize(
    ("header", "golden"),
    [(True, g.ZCL_READ_RSP_MFR), (False, g.ZCL_READ_RSP_MFR_NO_HEADER)],
)
async def test_mfr_response_with_or_without_ms_header(header: bool, golden: bytes) -> None:
    rig = await joined_rig(mfr_response_header=header)
    ind = await rig.ask(g.ZCL_READ_MFR)
    assert masked(ind.npdu) == masked(golden)


async def test_mfr_attribute_needs_the_manufacturer_code() -> None:
    rig = await joined_rig()
    ind = await rig.ask(request(0x33, "00 tt 00 00 40"))  # 0x4000 without MS bit
    assert zcl(ind) == h("18 33 01 00 40 86")


async def test_sentinels_and_inverted_limits() -> None:
    rig = await joined_rig()
    rig.valve.set_attribute(0x0201, 0x0000, ZclDataType.INT16, -0x8000)
    rig.valve.set_attribute(0x0001, 0x0021, ZclDataType.UINT8, 0xFF)
    rig.valve.set_attribute(0x0201, 0x0015, ZclDataType.INT16, 3000)
    rig.valve.set_attribute(0x0201, 0x0016, ZclDataType.INT16, 800)
    ind = await rig.ask(request(0x34, "00 tt 00 00 00 15 00 16 00"))
    assert zcl(ind) == h("18 34 01", "00 00 00 29 00 80", "15 00 00 29 B8 0B", "16 00 00 29 20 03")
    ind = await rig.ask(request(0x35, "00 tt 00 21 00", cluster="01 00"))
    assert zcl(ind) == h("18 35 01 21 00 00 20 FF")
    ind = await rig.ask(g.ZCL_WRITE)  # 21.50 C is outside [3000, 800]
    assert zcl(ind) == h("18 2D 04 87 12 00")


async def test_key128_attribute_is_served_raw() -> None:
    rig = await joined_rig()
    key = SecretBytes(bytes(range(0xA0, 0xB0)))  # dummy, for redaction tests
    rig.valve.set_attribute(0x0000, 0x4F00, ZclDataType.KEY128, key)
    ind = await rig.ask(request(0x36, "00 tt 00 00 4F", cluster="00 00"))
    assert zcl(ind) == h("18 36 01 00 4F 00 F1") + bytes(range(0xA0, 0xB0))
    assert rig.valve.get_attribute(0x0000, 0x4F00) == (ZclDataType.KEY128, key)
    rig.valve.remove_attribute(0x0000, 0x4F00)
    assert rig.valve.get_attribute(0x0000, 0x4F00) is None


async def test_external_setpoint_change_last_writer_wins() -> None:
    rig = await joined_rig()
    await rig.ask(g.ZCL_WRITE)
    rig.valve.external_setpoint_change(23.0)
    ind = await rig.ask(request(0x37, "00 tt 00 12 00"))
    assert zcl(ind) == h("18 37 01 12 00 00 29 FC 08")  # 2300
    await rig.ask(g.ZCL_WRITE.replace(h("2D 00 2D"), h("38 00 38")))
    assert rig.valve.get_attribute(0x0201, 0x0012) == (ZclDataType.INT16, 2150)


async def test_report_reusing_a_pending_tsn_arrives_first() -> None:
    rig = await joined_rig()
    rig.host.send(g.ZCL_READ)  # tsn 0x2B pending
    rig.valve.report(0x0201, (0x0000,), tsn=0x2B)
    report, response = await rig.collect(30.0)
    assert zcl(report) == h("18 2B 0A 00 00 29 AD 07")
    assert zcl(response)[:3] == h("18 2B 01")
    assert report.at < response.at


async def test_report_errors() -> None:
    clock = VirtualClock()
    valve = SimValve(clock, eui=OTHER_EUI, short=OTHER_SHORT, rng=seeded(0))
    with pytest.raises(RuntimeError, match="not bound"):
        valve.report(0x0201, (0x0000,))
    rig = await joined_rig()
    with pytest.raises(KeyError):
        rig.valve.report(0x0201, (0x0010,))


async def test_default_response_for_a_different_command() -> None:
    rig = await joined_rig()
    rig.valve.queue_default_response(0x02, 0x00)
    ind = await rig.ask(g.ZCL_READ)
    assert zcl(ind) == h("18 2B 0B 02 00")
    ind = await rig.ask(g.ZCL_READ)  # only the next request
    assert zcl(ind)[:3] == h("18 2B 01")


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("01 tt 00", "18 tt 0B 00 81"),  # cluster-specific command
        ("00 tt 06 00", "18 tt 0B 06 81"),  # Configure Reporting: unsupported global
        ("00 tt 02 12 00", "18 tt 0B 02 80"),  # truncated write record
    ],
)
async def test_unsupported_commands(body: str, expected: str) -> None:
    rig = await joined_rig()
    ind = await rig.ask(request(0x39, body))
    assert zcl(ind) == h(expected.replace("tt", "39"))


async def test_zdo_active_ep_and_simple_desc() -> None:
    rig = await joined_rig()
    ind = await rig.ask(h(NWK_TO_VALVE, "00 00 05 00 00 00 00 00", "0B 6F 5E"))
    aps = ApsDataFrame.decode(ind.frame.payload)
    assert (aps.cluster_id, aps.payload) == (0x8005, g.ACTIVE_EP_RSP_ZDO)
    ind = await rig.ask(h(NWK_TO_VALVE, "00 00 04 00 00 00 00 00", "0C 6F 5E 01"))
    aps = ApsDataFrame.decode(ind.frame.payload)
    assert (aps.cluster_id, aps.payload) == (0x8004, g.SIMPLE_DESC_RSP_ZDO)


@pytest.mark.parametrize(
    ("zdo", "answer"),
    [
        ("05 00 00 00 00 00 0D 01 02", "0D 81 01 02 00"),  # Active_EP for someone else
        ("04 00 00 00 00 00 0E 6F 5E 02", "0E 82 6F 5E 00"),  # Simple_Desc, wrong endpoint
        ("04 00 00 00 00 00 0F 01 02 01", "0F 81 01 02 00"),  # Simple_Desc, someone else
    ],
)
async def test_zdo_failures(zdo: str, answer: str) -> None:
    rig = await joined_rig()
    ind = await rig.ask(h(NWK_TO_VALVE, "00 00", zdo))
    assert ApsDataFrame.decode(ind.frame.payload).payload == h(answer)


@pytest.mark.parametrize(
    "aps",
    [
        "00 00 33 00 00 00 00 00 10 00",  # Mgmt_Bind_req: never answers
        "00 00 05 00 00 00 00 00 11",  # truncated Active_EP_req
        "00 02 02 01 04 01 01 2B 00 2B 00 00 00",  # endpoint 2 does not exist
        "00 01 02 01 04 01 01 2B FF",  # undecodable ZCL
        "00 01 02 01 04 01 01 2B 18 2B 01 00 00 00",  # server->client frame
    ],
)
async def test_requests_never_answered(aps: str) -> None:
    rig = await joined_rig()
    rig.host.send(h(NWK_TO_VALVE, aps))
    assert await rig.collect(120.0) == ()


# --- Sleepy timing ---------------------------------------------------------------------------


async def test_latency_is_2_to_30_s_quantised_to_the_7_s_poll() -> None:
    rig = await joined_rig()
    delays = []
    for tsn in range(0x40, 0x60):
        start = rig.clock.now()
        ind = await rig.ask(request(tsn, "00 tt 00 00 00"), seconds=30.0)
        delays.append(ind.at - start)
    assert set(delays) <= {7.0, 14.0, 21.0, 28.0}
    assert len(set(delays)) > 1


def test_quantisation_edges() -> None:
    clock = VirtualClock()
    aps = ApsDataFrame.decode(g.ZCL_READ[8:])
    unquantised = SimValve(clock, eui=OTHER_EUI, short=1, rng=seeded(0), poll_interval=0.0)
    (reply,) = unquantised.handle_request(aps)
    assert 2.0 <= reply.delay <= 30.0
    assert reply.delay % 7.0 != 0.0
    late = SimValve(clock, eui=OTHER_EUI, short=1, rng=seeded(0), latency=(40.0, 40.0))
    assert late.handle_request(aps)[0].delay == 42.0
    with pytest.raises(ValueError, match="latency"):
        SimValve(clock, eui=OTHER_EUI, short=1, rng=seeded(0), latency=(5.0, 2.0))
    with pytest.raises(ValueError, match="drop_rate"):
        SimValve(clock, eui=OTHER_EUI, short=1, rng=seeded(0), drop_rate=1.5)
    with pytest.raises(ValueError, match="endpoint"):
        SimValve(clock, eui=OTHER_EUI, short=1, rng=seeded(0), endpoint=0)


async def test_drops_force_a_retry() -> None:
    rig = await joined_rig(drop_rate=1.0)
    rig.host.send(g.ZCL_READ)
    assert await rig.collect(60.0) == ()
    rig.valve.drop_rate = 0.0
    ind = await rig.ask(g.ZCL_READ)  # same-tsn retransmit
    assert zcl(ind)[:3] == h("18 2B 01")
    assert rig.valve.writes == ()


async def test_same_tsn_retransmit_coalesces_or_duplicates() -> None:
    rig = await joined_rig(latency=(29.0, 29.0))  # 35 s: both sends while the reply is pending
    rig.host.send(g.ZCL_READ)
    await rig.clock.advance(30.0)
    rig.host.send(g.ZCL_READ)
    assert len(await rig.collect(60.0)) == 1

    rig = await joined_rig(latency=(29.0, 29.0), duplicate_rate=1.0)
    rig.host.send(g.ZCL_READ)
    await rig.clock.advance(30.0)
    rig.host.send(g.ZCL_READ)
    first, second = await rig.collect(60.0)
    assert zcl(first) == zcl(second)
    assert (first.at, second.at) == (37.0, 67.0)


async def test_late_response_after_the_retry_window() -> None:
    rig = await joined_rig(latency=(65.0, 65.0))  # 2 x 30 s attempts are over at 60 s
    start = rig.clock.now()
    rig.host.send(g.ZCL_READ)
    await rig.clock.advance(30.0)
    rig.host.send(g.ZCL_READ)  # the retry is coalesced into the pending reply
    (ind,) = await rig.collect(60.0)
    assert ind.at - start == 70.0


async def test_interleaving_across_valves() -> None:
    rig = await joined_rig(seed=4)
    other = SimValve(rig.clock, eui=OTHER_EUI, short=OTHER_SHORT, rng=seeded(9))
    rig.net.add_valve(other)
    for tsn in range(0x50, 0x56):
        rig.host.send(request(tsn, "00 tt 00 00 00"))
        rig.host.send(request(tsn, "00 tt 00 00 00", dst="0E 0E"))
    srcs = [ind.frame.src for ind in await rig.collect(30.0)]
    assert sorted(srcs) == sorted([g.VALVE_SHORT, OTHER_SHORT] * 6)
    switches = sum(a != b for a, b in itertools.pairwise(srcs))
    assert switches >= 3  # responses come back interleaved, not grouped per valve


async def test_same_seed_same_traffic() -> None:
    async def run() -> list[float]:
        rig = await joined_rig(seed=11)
        for tsn in range(0x60, 0x68):
            rig.host.send(request(tsn, "00 tt 00 00 00"))
        return [i.at for i in await rig.collect(30.0)]

    assert await run() == await run()


def test_default_table_is_a_fresh_copy_with_pn_values() -> None:
    table = zk03840_attributes()
    assert table[(0x0201, 0x0000, None)] == (ZclDataType.INT16, 1965)
    assert table[(0x0001, 0x0021, None)] == (ZclDataType.UINT8, 126)
    assert table[(0x0201, 0x4000, 0x1221)] == (ZclDataType.ENUM8, 1)
    table.clear()
    assert zk03840_attributes()
    valve = SimValve(VirtualClock(), eui=OTHER_EUI, short=2, rng=seeded(0), model_id="X1")
    assert valve.get_attribute(0x0000, 0x0005) == (ZclDataType.CHARSTR, "X1")
    assert "0x0002" in repr(valve)
    valve.set_short(3)
    assert valve.short == 3
    assert valve.endpoint == 1
