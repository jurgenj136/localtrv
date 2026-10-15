"""dispatch.py (T11): golden NPDUs through the dispatcher with a recording host (unit level)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from fixtures import golden as g
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID, ApsDataFrame, ApsDeliveryMode
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningResponse,
    NetworkStatus,
    RouteReply,
    RouteRequest,
)
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
from vicare_local_ble.zigbee_direct.codec.zcl import ReadAttributesResponse, ZclCommandId
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiRsp
from vicare_local_ble.zigbee_direct.dispatch import Dispatcher
from vicare_local_ble.zigbee_direct.node_types import NodeStats, ReportEvent
from vicare_local_ble.zigbee_direct.requests import (
    Envelope,
    JoinSlot,
    JoinToken,
    PendingMap,
    ZclResponse,
)
from vicare_local_ble.zigbee_direct.routing import NeighborTable

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.types import Eui64

LOGGER = "vicare_local_ble.zigbee_direct.node"


@dataclass
class RecordingRouter:
    rreqs: list[tuple[NwkFrame, RouteRequest]] = field(default_factory=list)
    statuses: list[tuple[NwkFrame, NetworkStatus]] = field(default_factory=list)

    def on_route_request(self, frame: NwkFrame, request: RouteRequest) -> None:
        self.rreqs.append((frame, request))

    def on_network_status(self, frame: NwkFrame, status: NetworkStatus) -> None:
        self.statuses.append((frame, status))


class Host:
    """A ``DispatchHost`` with real bookkeeping and recording listeners."""

    def __init__(self, current_short: int | None = g.ZVD_SHORT) -> None:
        self.current_short = current_short
        self.pending = PendingMap(clock=VirtualClock(), late_window=120.0)
        self.join_slot = JoinSlot()
        self.router = RecordingRouter()
        self.neighbors = NeighborTable()
        self.stats = NodeStats()
        self.own_eui = g.ZVD_EUI
        self.reports: list[ReportEvent] = []
        self.annces: list[tuple[DeviceAnnce, int]] = []
        self.acks: list[tuple[int, ApsDataFrame]] = []
        self.senders: list[tuple[int, Eui64]] = []
        self.raise_on_report = False

    def emit_report(self, event: ReportEvent) -> None:
        if self.raise_on_report:
            raise RuntimeError("listener bug")
        self.reports.append(event)

    def emit_device_annce(self, annce: DeviceAnnce, src_short: int) -> None:
        self.annces.append((annce, src_short))

    def ack_aps(self, src_short: int, aps: ApsDataFrame) -> None:
        self.acks.append((src_short, aps))

    def emit_sender(self, src_short: int, src_ieee: Eui64) -> None:
        self.senders.append((src_short, src_ieee))


def setup(current_short: int | None = g.ZVD_SHORT) -> tuple[Host, Dispatcher]:
    host = Host(current_short)
    return host, Dispatcher(host)  # type: ignore[arg-type]


def feed(dispatcher: Dispatcher, *npdus: bytes) -> None:
    for npdu in npdus:
        dispatcher.handle(TunnelNpdu(npdu, True))


def read_envelope(tsn: int = 0x2B, cluster: int = 0x0201) -> Envelope:
    return Envelope(
        src_short=g.VALVE_SHORT,
        kind="zcl",
        seq=tsn,
        profile_id=HA_PROFILE_ID,
        cluster_id=cluster,
        remote_endpoint=1,
        local_endpoint=1,
        request_command=ZclCommandId.READ_ATTRIBUTES,
        response_commands=frozenset({ZclCommandId.READ_ATTRIBUTES_RESPONSE}),
    )


@pytest.mark.parametrize("golden", ["ZCL_READ_RSP", "QUIRK_SOURCE_ROUTE", "QUIRK_GARBAGE4"])
async def test_golden_read_responses_resolve(golden: str) -> None:
    host, dispatcher = setup()
    pending = host.pending.register(read_envelope())
    feed(dispatcher, g.ALL_NPDUS[golden])
    result = await pending.future
    assert isinstance(result, ZclResponse)
    assert isinstance(result.command, ReadAttributesResponse)
    assert result.command.records[0].value == 1965
    assert result.via_fallback == (golden == "QUIRK_GARBAGE4")
    assert host.stats.fallback_hits == (1 if golden == "QUIRK_GARBAGE4" else 0)
    assert host.stats.decode_errors == 0


async def test_golden_default_response_and_mgmt_lqi() -> None:
    host, dispatcher = setup()
    default = host.pending.register(read_envelope(0x2E, cluster=0x0004))
    lqi = host.pending.register(
        Envelope(src_short=0x0000, kind="zdo", seq=0x0A, profile_id=0, cluster_id=0x8031)
    )
    feed(dispatcher, g.ZCL_DEFAULT_RSP, g.MGMT_LQI_RSP)
    assert (await default.future).command.status == 0xC3  # type: ignore[union-attr]
    assert isinstance(await lqi.future, MgmtLqiRsp)


async def test_golden_report_and_unmatched() -> None:
    host, dispatcher = setup()
    # A neighbor-table entry is not proof of who sent the frame (it may be stale): only an
    # IEEE in the NWK header becomes ``src_ieee``.
    host.neighbors.note(g.VALVE_SHORT, g.VALVE_EUI)
    pending = host.pending.register(read_envelope(0x2F))  # same TSN as the report
    feed(dispatcher, g.ZCL_REPORT)
    (event,) = host.reports
    assert event == ReportEvent(
        src_short=g.VALVE_SHORT,
        src_ieee=None,
        endpoint=1,
        cluster=0x0201,
        manufacturer_code=None,
        records=event.records,
    )
    assert event.records[0].data_type is ZclDataType.INT16
    assert not pending.future.done()
    feed(dispatcher, g.ZCL_WRITE_RSP)  # nothing pending for tsn 0x2D
    assert host.stats.unmatched == 1


def test_report_listener_failure_is_contained(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    host, dispatcher = setup()
    host.raise_on_report = True
    feed(dispatcher, g.ZCL_REPORT)  # never raises out of handle()
    assert host.stats.decode_errors == 1
    assert "RuntimeError" in caplog.text
    assert "AD 07" not in caplog.text.upper()  # no payload bytes


async def test_commissioning_responses_go_to_the_join_slot() -> None:
    host, dispatcher = setup(current_short=None)
    future = host.join_slot.open(JoinToken(g.ZVD_SHORT, 1, g.ZDD_SHORT, g.ZVD_EUI))
    feed(dispatcher, g.COMMISSIONING_RESPONSE_OTHER)  # other placeholder: address filter
    assert not future.done()
    feed(dispatcher, g.COMMISSIONING_RESPONSE)
    assert await future == CommissioningResponse(g.ZVD_SHORT, 0)
    host.join_slot.close()
    feed(dispatcher, g.COMMISSIONING_RESPONSE)  # no token any more: dropped
    assert host.stats.decode_errors == 0


def test_commands_go_to_the_router() -> None:
    host, dispatcher = setup()
    feed(dispatcher, g.RREQ_FROM_VALVE, g.NETWORK_STATUS_NO_ROUTE, g.NETWORK_STATUS_CONFLICT)
    ((frame, rreq),) = host.router.rreqs
    assert (frame.src, rreq.route_id) == (g.VALVE_SHORT, 7)
    assert host.neighbors.ieee_for(g.VALVE_SHORT) == g.VALVE_EUI  # NWK src IEEE noted
    assert [s.status for _, s in host.router.statuses] == [0x02, 0x0D]
    assert host.stats.network_status == 2


def command(dst: int, payload: bytes, *, src: int = g.ZDD_SHORT) -> bytes:
    return NwkFrame(
        frame_type=NwkFrameType.COMMAND, dst=dst, src=src, radius=30, seq=1, payload=payload
    ).encode()


def data(dst: int, aps: ApsDataFrame, src: int = g.VALVE_SHORT) -> bytes:
    return NwkFrame(
        frame_type=NwkFrameType.DATA, dst=dst, src=src, radius=30, seq=1, payload=aps.encode()
    ).encode()


def test_drops_and_ignores() -> None:
    host, dispatcher = setup()
    own = g.ZVD_SHORT
    feed(
        dispatcher,
        command(0x4444, b"\x03\x02\x6f\x5e"),  # command for someone else
        command(own, b"\x04\x00"),  # Leave: unsupported, ignored
        data(0x4444, ApsDataFrame(cluster_id=0x0201, profile_id=HA_PROFILE_ID, payload=b"")),
        # a ZDO request to us (Active_EP_req) is ignored
        data(own, ApsDataFrame(cluster_id=0x0005, profile_id=0, payload=b"\x01\x34\x12")),
        # a cluster-specific ZCL frame is ignored
        data(
            own, ApsDataFrame(cluster_id=0x0201, profile_id=HA_PROFILE_ID, payload=b"\x19\x01\x00")
        ),
        NwkFrame(
            frame_type=NwkFrameType.INTER_PAN, dst=own, src=1, radius=1, seq=1, payload=b"\x00"
        ).encode(),
    )
    assert host.stats.decode_errors == 0
    assert host.stats.unmatched == 0
    assert host.router.rreqs == []
    assert host.router.statuses == []


def test_decode_errors_are_counted() -> None:
    host, dispatcher = setup()
    own = g.ZVD_SHORT
    feed(
        dispatcher,
        b"\x08\x02",  # NWK too short
        command(own, b"\x01"),  # truncated Route Request
        data(own, ApsDataFrame(cluster_id=0x0013, profile_id=0, payload=b"\x01")),  # bad annce
        data(own, ApsDataFrame(cluster_id=0x8005, profile_id=0, payload=b"\x01")),  # bad rsp
    )
    assert host.stats.decode_errors == 4


def test_data_before_join_is_dropped() -> None:
    host, dispatcher = setup(current_short=None)
    feed(dispatcher, g.ZCL_REPORT, g.DEVICE_ANNCE)
    assert host.reports == []
    assert host.annces == []


def test_device_annce_from_others_and_ourselves() -> None:
    host, dispatcher = setup()
    feed(dispatcher, g.DEVICE_ANNCE)  # our own announcement echoed back
    assert host.annces == []
    annce = DeviceAnnce(seq=1, nwk_addr=g.VALVE_SHORT, ieee=g.VALVE_EUI, capability=0x80)
    aps = ApsDataFrame(
        cluster_id=0x0013,
        profile_id=0,
        payload=annce.encode(),
        delivery_mode=ApsDeliveryMode.BROADCAST,
        counter=3,
    )
    feed(dispatcher, data(0xFFFD, aps))
    assert host.annces == [(annce, g.VALVE_SHORT)]
    assert host.neighbors.ieee_for(g.VALVE_SHORT) == g.VALVE_EUI
    assert host.stats.device_annces == 1


async def test_fallback_rejections_and_duplicates() -> None:
    host, dispatcher = setup()
    host.join_slot.open(JoinToken(0x7777, 1, g.ZDD_SHORT, g.ZVD_EUI))
    # a Commissioning Response to the placeholder, but not from the ZDD
    feed(dispatcher, command(0x7777, CommissioningResponse(0x7777, 0).encode(), src=0x0101))
    feed(dispatcher, command(g.ZVD_SHORT, RouteReply(1, 2, 3).encode()))  # decoded, ignored
    assert host.stats.decode_errors == 0
    # two pending entries for the valve: the first never matches, the second resolves once
    other = host.pending.register(read_envelope(0x10))
    pending = host.pending.register(read_envelope())
    feed(dispatcher, g.QUIRK_GARBAGE4)
    assert pending.future.done()
    assert not other.future.done()
    feed(dispatcher, g.QUIRK_GARBAGE4)  # a duplicate: matches, but the entry is already done
    assert host.stats.fallback_hits == 1
    assert host.stats.decode_errors == 1


def garbage4(aps: ApsDataFrame, *, src: int = g.VALVE_SHORT) -> bytes:
    return NwkFrame(
        frame_type=NwkFrameType.DATA,
        dst=g.ZVD_SHORT,
        src=src,
        radius=30,
        seq=1,
        payload=bytes.fromhex("005A5A00") + aps.encode(),
    ).encode()


async def test_fallback_still_checks_the_envelope() -> None:
    host, dispatcher = setup()
    zdo = host.pending.register(
        Envelope(
            src_short=g.VALVE_SHORT,
            kind="zdo",
            seq=0x0B,
            profile_id=0,
            cluster_id=0x8005,
            nwk_addr_of_interest=0x0102,  # the golden response names the valve instead
        )
    )
    rsp = ApsDataFrame(cluster_id=0x8005, profile_id=0, payload=g.ACTIVE_EP_RSP_ZDO, counter=1)
    # a "response" travelling client -> server: the scan finds it, the envelope refuses it
    zcl = host.pending.register(read_envelope(0x2C))
    request_dir = ApsDataFrame(
        cluster_id=0x0201,
        profile_id=HA_PROFILE_ID,
        payload=bytes.fromhex("10 2C 01 00 00 00 29 AD 07"),  # client -> server
        dst_endpoint=1,
        src_endpoint=1,
        counter=0x47,
    )
    feed(dispatcher, garbage4(rsp), garbage4(request_dir))
    assert not zdo.future.done()
    assert not zcl.future.done()
    assert host.stats.decode_errors == 2
    bare = host.pending.register(
        Envelope(
            src_short=g.VALVE_SHORT,
            kind="zcl",
            seq=0x2B,
            profile_id=HA_PROFILE_ID,
            cluster_id=0x0201,
        )
    )
    feed(dispatcher, g.QUIRK_GARBAGE4)  # no response command and no request command
    assert not bare.future.done()


# --- fallback scope (CP3): only implausible APS headers are offset-scanned ------------------

READ_RSP_ZCL = bytes.fromhex("18 2B 01 00 00 00 29 AD 07")  # tsn 0x2B, localTemperature 1965


@pytest.mark.parametrize(
    ("cluster", "endpoints"),
    [(0x0000, (1, 1)), (0x0201, (1, 2)), (0x0201, (1, 1))],
    ids=["other-cluster", "other-endpoint", "matching-header"],
)
async def test_clean_header_with_undecodable_body_is_never_scanned(
    cluster: int, endpoints: tuple[int, int]
) -> None:
    host, dispatcher = setup()
    pending = host.pending.register(read_envelope())
    src_ep, dst_ep = endpoints
    # ZCL FC 0x02 (reserved frame type) makes the body undecodable; the bytes after it hold a
    # coincidental "read response with our TSN" that an offset scan would find
    aps = ApsDataFrame(
        cluster_id=cluster,
        profile_id=HA_PROFILE_ID,
        payload=bytes.fromhex("02 5A 5A 5A") + READ_RSP_ZCL,
        dst_endpoint=dst_ep,
        src_endpoint=src_ep,
    )
    feed(dispatcher, data(g.ZVD_SHORT, aps))
    assert not pending.future.done()
    assert host.stats.decode_errors == 1
    assert host.stats.fallback_hits == 0


def test_standard_zdo_requests_are_ignored_not_errors() -> None:
    host, dispatcher = setup()
    permit = ApsDataFrame(cluster_id=0x0036, profile_id=0, payload=b"\x01\x3c\x00")
    node_desc_rsp = ApsDataFrame(cluster_id=0x8002, profile_id=0, payload=b"\x01\x00")
    feed(dispatcher, data(0xFFFC, permit, src=0x0000), data(g.ZVD_SHORT, node_desc_rsp))
    assert host.stats.decode_errors == 0
    assert host.stats.unmatched == 0


async def test_zdo_header_with_wrong_endpoints_goes_to_the_fallback() -> None:
    host, dispatcher = setup()
    pending = host.pending.register(
        Envelope(src_short=g.VALVE_SHORT, kind="zdo", seq=0x0B, profile_id=0, cluster_id=0x8005)
    )
    aps = ApsDataFrame(
        cluster_id=0x8005,
        profile_id=0,
        payload=g.ACTIVE_EP_RSP_ZDO,
        dst_endpoint=0x5A,  # implausible for ZDO: goes to the scan, which judges offset 0
        src_endpoint=0,
    )
    feed(dispatcher, data(g.ZVD_SHORT, aps))
    assert not pending.future.done()  # the codec refuses a ZDO header on endpoint 0x5A
    assert host.stats.decode_errors == 1
