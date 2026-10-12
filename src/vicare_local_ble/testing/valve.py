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
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import random

    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
    from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType, ZclValue
    from vicare_local_ble.zigbee_direct.types import Eui64

type AttrKey = tuple[int, int, int | None]
"""``(cluster, attribute id, manufacturer code or None)``."""


@dataclass(frozen=True, slots=True)
class ScheduledReply:
    """A reply the network must deliver ``delay`` seconds after the request arrived."""

    delay: float
    aps: ApsDataFrame


class ValveUplink(Protocol):
    """How a valve sends unsolicited frames (reports, Device_annce); ``SimNetwork`` implements
    it and binds itself in ``SimNetwork.add_valve``."""

    def deliver_from_valve(self, valve: SimValve, aps: ApsDataFrame, *, delay: float) -> None: ...


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
        raise NotImplementedError("T9")

    @property
    def eui(self) -> Eui64:
        raise NotImplementedError("T9")

    @property
    def short(self) -> int:
        raise NotImplementedError("T9")

    def bind(self, uplink: ValveUplink) -> None:
        """Set the back-reference (called by ``SimNetwork.add_valve``); rebinding replaces it."""
        raise NotImplementedError("T9")

    def set_short(self, short: int) -> None:
        """Used by ``SimNetwork.valve_rejoin``."""
        raise NotImplementedError("T9")

    def handle_request(self, aps: ApsDataFrame) -> tuple[ScheduledReply, ...]:
        """ZDO (Active_EP, Simple_Desc) or ZCL request in; replies to schedule out."""
        raise NotImplementedError("T9")

    def set_attribute(
        self,
        cluster: int,
        attr: int,
        data_type: ZclDataType,
        value: ZclValue,
        *,
        manufacturer: int | None = None,
    ) -> None:
        raise NotImplementedError("T9")

    def get_attribute(
        self, cluster: int, attr: int, *, manufacturer: int | None = None
    ) -> tuple[ZclDataType, ZclValue] | None:
        raise NotImplementedError("T9")

    def remove_attribute(self, cluster: int, attr: int, *, manufacturer: int | None = None) -> None:
        raise NotImplementedError("T9")

    def external_setpoint_change(self, celsius: float) -> None:
        """Overwrite the setpoint as the OPTO2 would (last writer wins)."""
        raise NotImplementedError("T9")

    def report(self, cluster: int, attrs: tuple[int, ...], *, tsn: int | None = None) -> None:
        """Emit Report Attributes through the bound uplink (``tsn`` may reuse a pending TSN);
        ``RuntimeError`` if unbound."""
        raise NotImplementedError("T9")

    def queue_default_response(self, command_id: int, status: int) -> None:
        """Answer the next ZCL request with a Default Response for ``command_id``."""
        raise NotImplementedError("T9")

    @property
    def writes(self) -> tuple[tuple[AttrKey, ZclValue], ...]:
        """Every accepted write, in order."""
        raise NotImplementedError("T9")


def zk03840_attributes() -> dict[AttrKey, tuple[ZclDataType, ZclValue]]:
    """A fresh copy of the default raw attribute table (PN §4, per-valve inventory)."""
    raise NotImplementedError("T9")


__all__ = ["AttrKey", "ScheduledReply", "SimValve", "ValveUplink", "zk03840_attributes"]
