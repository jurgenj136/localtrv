"""Simulated ZK03840 valve: raw attribute table, ZCL semantics, sleepy timing (T9).

Frozen interface (T2); implemented by T9. The attribute table here is simulator fixture data
written independently of ``vicare_local_ble.valves`` (AGENTS.md layering exception), so a
scaling or id bug in ``valves.py`` cannot pass tautologically. Values follow PN §4 (raw wire
values: centi-degrees, 0.5 % battery units, raw enums).

Behaviours (spec §1.7 "Sleepy valves" and "ZCL")
    * Reply latency drawn from ``latency`` (default 2-30 s) and quantised up to the next
      ``poll_interval`` tick (default 7 s); ``drop_rate`` drops requests (no reply).
    * ``duplicate_rate``: a same-TSN retransmit may produce two responses.
    * Unknown attribute -> per-record status 0x86; unsupported cluster -> Default Response 0xC3.
    * Writes persist and answer ``04 00``; an out-of-range setpoint answers INVALID_VALUE 0x87.
    * ``mfr_response_header``: manufacturer reads answered with or without the MS header.
    * Sentinels (0x8000 temperature, 0xFF battery), inverted limits and a KEY128-typed attribute
      are set with ``set_attribute``.
    * ``external_setpoint_change`` (an OPTO2 overwrite); optional reports (``report``),
      including a report reusing a pending TSN; ``queue_default_response`` for a Default
      Response to a different command.

Implementation notes (T9)
    * Quantisation: the drawn latency is rounded up to a whole number of polls; when that
      overshoots ``latency[1]`` and one poll fewer still reaches ``latency[0]``, one poll fewer
      is used (defaults give 7, 14, 21 or 28 s). ``poll_interval <= 0`` disables it.
    * Retransmits: a request whose (kind, cluster, tsn/seq) still has a reply in flight is
      coalesced (no second reply) unless the ``duplicate_rate`` draw says otherwise. Once the
      first reply has been delivered, a retransmit is a fresh request.
    * Writes are non-atomic (ZCL): accepted records persist, failures are listed. Status order:
      unknown 0x86, wrong type 0x8D, not writable 0x88, out of range 0x87. The setpoint must lie
      in ``[max(absMin, minLimit), min(absMax, maxLimit)]``, so inverted limits reject every
      setpoint write. ``external_setpoint_change`` bypasses all checks (last writer wins).
    * Unsupported ZDO requests (Mgmt_Bind and anything but Active_EP / Simple_Desc) and
      requests to an endpoint other than 0 / ``endpoint`` are never answered.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.zigbee_direct.codec.aps import ZDO_PROFILE_ID, ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.zcl import (
    AttributeRecord,
    DefaultResponse,
    ReadAttributes,
    ReadAttributesResponse,
    ReadAttributeStatus,
    ReportAttributes,
    WriteAttributes,
    WriteAttributesResponse,
    WriteAttributeStatus,
    ZclCommandId,
    ZclDirection,
    ZclFrame,
    ZclFrameType,
    ZclHeader,
    ZclStatus,
)
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType, ZclValue
from vicare_local_ble.zigbee_direct.codec.zdo import (
    ActiveEpReq,
    ActiveEpRsp,
    SimpleDescReq,
    SimpleDescriptor,
    SimpleDescRsp,
    ZdoCluster,
    ZdoStatus,
)
from vicare_local_ble.zigbee_direct.errors import DecodeError, UnsupportedFrameError
from vicare_local_ble.zigbee_direct.types import validate_short

if TYPE_CHECKING:
    import random

    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.types import Eui64

type AttrKey = tuple[int, int, int | None]
"""``(cluster, attribute id, manufacturer code or None)``."""

type _ReplyKey = tuple[str, int, int]

#: The ZVD's application endpoint (reports are addressed to it; golden ``_APS_THERMOSTAT``).
_ZVD_ENDPOINT: Final = 1
_ZDO_RESPONSE_BIT: Final = 0x8000


@dataclass(frozen=True, slots=True)
class ScheduledReply:
    """A reply the network must deliver ``delay`` seconds after the request arrived."""

    delay: float
    aps: ApsDataFrame


class ValveUplink(Protocol):
    """How a valve sends unsolicited frames (reports, Device_annce); ``SimNetwork`` implements
    it and binds itself in ``SimNetwork.add_valve``."""

    def deliver_from_valve(self, valve: SimValve, aps: ApsDataFrame, *, delay: float) -> None: ...


def _check_rate(name: str, value: float) -> float:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be within [0, 1]: {value!r}")
    return value


class SimValve:
    """One sleepy ZK03840 end device (endpoint 1). Request replies are returned to the network
    (``handle_request``); unsolicited frames go through the bound ``ValveUplink``."""

    def __init__(
        self,
        clock: VirtualClock,
        *,
        eui: Eui64,
        short: int,
        rng: random.Random,
        endpoint: int = 1,
        poll_interval: float = 7.0,
        latency: tuple[float, float] = (2.0, 30.0),
        drop_rate: float = 0.0,
        duplicate_rate: float = 0.0,
        mfr_response_header: bool = True,
        manufacturer_name: str = "Viessmann",
        model_id: str = "7637434",
    ) -> None:
        if not 0.0 <= latency[0] <= latency[1]:
            raise ValueError(f"latency must satisfy 0 <= low <= high: {latency!r}")
        if not 1 <= endpoint <= 240:
            raise ValueError(f"endpoint out of range 1..240: {endpoint!r}")
        self._clock = clock
        self._eui = eui
        self._short = validate_short(short)
        self._rng = rng
        self._endpoint = endpoint
        self._poll = poll_interval
        self._latency = latency
        self.drop_rate = _check_rate("drop_rate", drop_rate)
        self.duplicate_rate = _check_rate("duplicate_rate", duplicate_rate)
        self.mfr_response_header = mfr_response_header
        self._attrs = zk03840_attributes()
        self._attrs[(vt.CL_BASIC, 0x0004, None)] = (ZclDataType.CHARSTR, manufacturer_name)
        self._attrs[(vt.CL_BASIC, 0x0005, None)] = (ZclDataType.CHARSTR, model_id)
        self._uplink: ValveUplink | None = None
        self._in_flight: dict[_ReplyKey, float] = {}
        self._queued_default: tuple[int, int] | None = None
        self._writes: list[tuple[AttrKey, ZclValue]] = []
        self._aps_counter = 0x40
        self._tsn = 0x80

    def __repr__(self) -> str:
        return f"SimValve(eui={self._eui}, short=0x{self._short:04X})"

    @property
    def eui(self) -> Eui64:
        return self._eui

    @property
    def short(self) -> int:
        return self._short

    @property
    def endpoint(self) -> int:
        return self._endpoint

    def bind(self, uplink: ValveUplink) -> None:
        """Set the back-reference (called by ``SimNetwork.add_valve``); rebinding replaces it."""
        self._uplink = uplink

    def set_short(self, short: int) -> None:
        """Used by ``SimNetwork.valve_rejoin``."""
        self._short = validate_short(short)
        self._in_flight.clear()

    # --- requests ---

    def handle_request(self, aps: ApsDataFrame) -> tuple[ScheduledReply, ...]:
        """ZDO (Active_EP, Simple_Desc) or ZCL request in; replies to schedule out."""
        if self.drop_rate and self._rng.random() < self.drop_rate:
            return ()
        if aps.profile_id == ZDO_PROFILE_ID and aps.dst_endpoint == 0:
            answer = self._zdo(aps)
        elif aps.dst_endpoint == self._endpoint and aps.profile_id != ZDO_PROFILE_ID:
            answer = self._zcl(aps)
        else:
            answer = None
        if answer is None:
            return ()
        key, reply = answer
        now = self._clock.now()
        self._in_flight = {k: t for k, t in self._in_flight.items() if t > now}
        if key in self._in_flight and not (
            self.duplicate_rate and self._rng.random() < self.duplicate_rate
        ):
            return ()
        delay = self._reply_delay()
        self._in_flight[key] = max(self._in_flight.get(key, 0.0), now + delay)
        return (ScheduledReply(delay, reply),)

    def _reply_delay(self) -> float:
        low, high = self._latency
        raw = self._rng.uniform(low, high)
        if self._poll <= 0:
            return raw
        ticks = max(1, math.ceil(raw / self._poll))
        if ticks > 1 and ticks * self._poll > high and (ticks - 1) * self._poll >= low:
            ticks -= 1
        return ticks * self._poll

    def _next_aps_counter(self) -> int:
        self._aps_counter = (self._aps_counter + 1) & 0xFF
        return self._aps_counter

    def _zdo(self, aps: ApsDataFrame) -> tuple[_ReplyKey, ApsDataFrame] | None:
        payload: bytes
        try:
            if aps.cluster_id == ZdoCluster.ACTIVE_EP_REQ:
                req = ActiveEpReq.decode(aps.payload)
                seq = req.seq
                if req.nwk_addr == self._short:
                    rsp = ActiveEpRsp(seq, ZdoStatus.SUCCESS, self._short, (self._endpoint,))
                else:
                    rsp = ActiveEpRsp(seq, ZdoStatus.DEVICE_NOT_FOUND, req.nwk_addr)
                payload = rsp.encode()
            elif aps.cluster_id == ZdoCluster.SIMPLE_DESC_REQ:
                sreq = SimpleDescReq.decode(aps.payload)
                seq = sreq.seq
                payload = self._simple_desc(sreq).encode()
            else:
                return None  # Mgmt_Bind and the rest: never answered
        except DecodeError:
            return None
        reply = ApsDataFrame(
            cluster_id=aps.cluster_id | _ZDO_RESPONSE_BIT,
            profile_id=ZDO_PROFILE_ID,
            payload=payload,
            dst_endpoint=0,
            src_endpoint=0,
            counter=self._next_aps_counter(),
        )
        return ("zdo", aps.cluster_id, seq), reply

    def _simple_desc(self, req: SimpleDescReq) -> SimpleDescRsp:
        if req.nwk_addr != self._short:
            return SimpleDescRsp(req.seq, ZdoStatus.DEVICE_NOT_FOUND, req.nwk_addr)
        if req.endpoint != self._endpoint:
            return SimpleDescRsp(req.seq, ZdoStatus.INVALID_EP, self._short)
        descriptor = SimpleDescriptor(
            endpoint=self._endpoint,
            profile_id=vt.PROFILE_HA,
            device_id=vt.DEVICE_ID,
            in_clusters=vt.IN_CLUSTERS,
            out_clusters=vt.OUT_CLUSTERS,
        )
        return SimpleDescRsp(req.seq, ZdoStatus.SUCCESS, self._short, descriptor)

    def _zcl(self, aps: ApsDataFrame) -> tuple[_ReplyKey, ApsDataFrame] | None:
        try:
            frame = ZclFrame.decode(aps.payload)
        except DecodeError:
            return None
        hdr = frame.header
        if hdr.direction is not ZclDirection.CLIENT_TO_SERVER:
            return None
        command_id, payload = self._zcl_answer(aps.cluster_id, frame)
        rsp_header = ZclHeader(
            tsn=hdr.tsn,
            command_id=command_id,
            manufacturer_code=hdr.manufacturer_code if self.mfr_response_header else None,
            direction=ZclDirection.SERVER_TO_CLIENT,
            disable_default_response=True,
        )
        reply = ApsDataFrame(
            cluster_id=aps.cluster_id,
            profile_id=aps.profile_id,
            payload=rsp_header.encode() + payload,
            dst_endpoint=aps.src_endpoint,
            src_endpoint=self._endpoint,
            counter=self._next_aps_counter(),
        )
        return ("zcl", aps.cluster_id, hdr.tsn), reply

    def _zcl_answer(self, cluster: int, frame: ZclFrame) -> tuple[int, bytes]:
        hdr = frame.header
        if self._queued_default is not None:
            queued, self._queued_default = self._queued_default, None
            return ZclCommandId.DEFAULT_RESPONSE, DefaultResponse(*queued).encode()

        def default(status: int) -> tuple[int, bytes]:
            body = DefaultResponse(hdr.command_id, status).encode()
            return ZclCommandId.DEFAULT_RESPONSE, body

        if cluster not in vt.IN_CLUSTERS:
            return default(ZclStatus.UNSUPPORTED_CLUSTER)
        if hdr.frame_type is not ZclFrameType.GLOBAL:
            return default(ZclStatus.UNSUP_COMMAND)
        try:
            command = frame.global_command()
        except UnsupportedFrameError:
            return default(ZclStatus.UNSUP_COMMAND)
        except DecodeError:
            return default(ZclStatus.MALFORMED_COMMAND)
        mfr = hdr.manufacturer_code
        match command:
            case ReadAttributes():
                records = tuple(self._read_record(cluster, a, mfr) for a in command.attribute_ids)
                return ZclCommandId.READ_ATTRIBUTES_RESPONSE, ReadAttributesResponse(
                    records
                ).encode()
            case WriteAttributes():
                failures = tuple(
                    WriteAttributeStatus(status, rec.attribute_id)
                    for rec in command.records
                    if (status := self._write_record(cluster, rec, mfr)) != ZclStatus.SUCCESS
                )
                result = failures or (WriteAttributeStatus(ZclStatus.SUCCESS),)
                return ZclCommandId.WRITE_ATTRIBUTES_RESPONSE, WriteAttributesResponse(
                    result
                ).encode()
            case _:
                return default(ZclStatus.UNSUP_COMMAND)

    def _read_record(self, cluster: int, attr: int, mfr: int | None) -> ReadAttributeStatus:
        entry = self._attrs.get((cluster, attr, mfr))
        if entry is None:
            return ReadAttributeStatus(attr, ZclStatus.UNSUPPORTED_ATTRIBUTE)
        return ReadAttributeStatus(attr, ZclStatus.SUCCESS, entry[0], entry[1])

    def _write_record(self, cluster: int, rec: AttributeRecord, mfr: int | None) -> int:
        key: AttrKey = (cluster, rec.attribute_id, mfr)
        entry = self._attrs.get(key)
        if entry is None:
            return ZclStatus.UNSUPPORTED_ATTRIBUTE
        if entry[0] != rec.data_type:
            return ZclStatus.INVALID_DATA_TYPE
        if key not in vt.WRITABLE:
            return ZclStatus.READ_ONLY
        if not self._in_range(key, rec.value):
            return ZclStatus.INVALID_VALUE
        self._attrs[key] = (entry[0], rec.value)
        self._writes.append((key, rec.value))
        return ZclStatus.SUCCESS

    def _limit(self, attr: int, fallback: int) -> int:
        entry = self._attrs.get((vt.CL_THERMOSTAT, attr, None))
        value = None if entry is None else entry[1]
        if isinstance(value, bool) or not isinstance(value, int):
            return fallback
        return value

    def _in_range(self, key: AttrKey, value: ZclValue) -> bool:
        if isinstance(value, bool) or not isinstance(value, int):
            return True
        abs_min = self._limit(vt.ATTR_ABS_MIN, -0x8000)
        abs_max = self._limit(vt.ATTR_ABS_MAX, 0x7FFF)
        if key == (vt.CL_THERMOSTAT, vt.ATTR_SETPOINT, None):
            low = max(abs_min, self._limit(vt.ATTR_MIN_LIMIT, abs_min))
            high = min(abs_max, self._limit(vt.ATTR_MAX_LIMIT, abs_max))
            return low <= value <= high
        if key in {
            (vt.CL_THERMOSTAT, vt.ATTR_MIN_LIMIT, None),
            (vt.CL_THERMOSTAT, vt.ATTR_MAX_LIMIT, None),
        }:
            return abs_min <= value <= abs_max
        return True

    # --- attribute table ---

    def set_attribute(
        self,
        cluster: int,
        attr: int,
        data_type: ZclDataType,
        value: ZclValue,
        *,
        manufacturer: int | None = None,
    ) -> None:
        self._attrs[(cluster, attr, manufacturer)] = (data_type, value)

    def get_attribute(
        self, cluster: int, attr: int, *, manufacturer: int | None = None
    ) -> tuple[ZclDataType, ZclValue] | None:
        return self._attrs.get((cluster, attr, manufacturer))

    def remove_attribute(self, cluster: int, attr: int, *, manufacturer: int | None = None) -> None:
        self._attrs.pop((cluster, attr, manufacturer), None)

    def external_setpoint_change(self, celsius: float) -> None:
        """Overwrite the setpoint as the OPTO2 would (last writer wins)."""
        key: AttrKey = (vt.CL_THERMOSTAT, vt.ATTR_SETPOINT, None)
        self._attrs[key] = (ZclDataType.INT16, round(celsius * 100))

    # --- unsolicited ---

    def report(self, cluster: int, attrs: tuple[int, ...], *, tsn: int | None = None) -> None:
        """Emit Report Attributes through the bound uplink (``tsn`` may reuse a pending TSN);
        ``RuntimeError`` if unbound."""
        if self._uplink is None:
            raise RuntimeError("SimValve is not bound to a network")
        records: list[AttributeRecord] = []
        for attr in attrs:
            entry = self._attrs.get((cluster, attr, None))
            if entry is None:
                raise KeyError(f"no attribute 0x{cluster:04X}/0x{attr:04X}")
            records.append(AttributeRecord(attr, entry[0], entry[1]))
        if tsn is None:
            self._tsn = (self._tsn + 1) & 0xFF
            tsn = self._tsn
        header = ZclHeader(
            tsn=tsn,
            command_id=ZclCommandId.REPORT_ATTRIBUTES,
            direction=ZclDirection.SERVER_TO_CLIENT,
            disable_default_response=True,
        )
        aps = ApsDataFrame(
            cluster_id=cluster,
            profile_id=vt.PROFILE_HA,
            payload=header.encode() + ReportAttributes(tuple(records)).encode(),
            dst_endpoint=_ZVD_ENDPOINT,
            src_endpoint=self._endpoint,
            counter=self._next_aps_counter(),
        )
        self._uplink.deliver_from_valve(self, aps, delay=0.0)

    def queue_default_response(self, command_id: int, status: int) -> None:
        """Answer the next ZCL request with a Default Response for ``command_id``."""
        self._queued_default = (command_id, status)

    @property
    def writes(self) -> tuple[tuple[AttrKey, ZclValue], ...]:
        """Every accepted write, in order."""
        return tuple(self._writes)


def zk03840_attributes() -> dict[AttrKey, tuple[ZclDataType, ZclValue]]:
    """A fresh copy of the default raw attribute table (PN §4, per-valve inventory)."""
    return vt.default_table()


__all__ = ["AttrKey", "ScheduledReply", "SimValve", "ValveUplink", "zk03840_attributes"]
