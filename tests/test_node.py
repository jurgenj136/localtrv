"""ZigbeeDirectNode (T11): join, gating and golden post-join bytes, against the simulator.

Shared helpers live here (``test_node_*.py`` import them). Everything runs on ``VirtualClock``
with production ``NodeConfig`` timeouts; keys and EUIs are dummies from ``default_installation``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any

import pytest

from fixtures import golden as g
from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.testing.scenario import default_installation
from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningRequest,
    RouteRequest,
    decode_nwk_command,
)
from vicare_local_ble.zigbee_direct.crypto import derive_basic_authorization_key
from vicare_local_ble.zigbee_direct.errors import (
    CommissioningDecodeError,
    JoinError,
    JoinRejectedError,
)
from vicare_local_ble.zigbee_direct.node import NetworkSummary, NodeConfig, ZigbeeDirectNode
from vicare_local_ble.zigbee_direct.transport import ZigbeeDirectTransport

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from vicare_local_ble.testing.scenario import Installation
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.node_core import NodeCore

LOGGER = "vicare_local_ble.zigbee_direct.node"
THERMOSTAT = 0x0201
LOCAL_TEMPERATURE = 0x0000
SETPOINT = 0x0012
MFR = 0x1221  # the valve fixture's manufacturer code (test data, not library knowledge)


@dataclass
class Rig:
    inst: Installation
    transport: ZigbeeDirectTransport
    node: ZigbeeDirectNode

    @property
    def clock(self) -> VirtualClock:
        return self.inst.clock

    @property
    def core(self) -> NodeCore:
        return self.node._core

    def writes(self) -> list[bytes]:
        """Every NPDU the node wrote to the tunnel this session."""
        return [w.npdu for w in self.inst.r0.tunnel_writes]

    def inject(self, npdu: bytes, *, secure: bool = True) -> None:
        """Indicate a raw NPDU to the node through the simulated R0."""
        self.inst.r0.indicate_npdu(npdu, secure=secure)

    def from_valve(self, src: int, aps: ApsDataFrame, *, seq: int = 0x70) -> bytes:
        return nf.data_npdu(
            dst=self.node.own_short, src=src, seq=seq, aps=aps, variant="plain", relay=0
        )


def fast_valves(inst: Installation, latency: float = 14.0) -> None:
    """Make every valve answer after exactly ``latency`` seconds."""
    for valve in inst.valves:
        valve._latency = (latency, latency)
        valve._poll = 0.0


@contextlib.asynccontextmanager
async def rig(
    *,
    config: NodeConfig | None = None,
    n_valves: int = 3,
    seed: int = 0,
    join: bool = True,
    network: dict[str, Any] | None = None,
    r0: dict[str, Any] | None = None,
    latency: float | None = 14.0,
) -> AsyncIterator[Rig]:
    inst = default_installation(n_valves=n_valves, behind_router=0, seed=seed)
    for name, value in (network or {}).items():
        setattr(inst.network, name, value)
    for name, value in (r0 or {}).items():
        setattr(inst.r0, name, value)
    if latency is not None:
        fast_valves(inst, latency)
    client = inst.r0.connect(inst.r0.ble_device(), None)
    psk = derive_basic_authorization_key(inst.zvd_eui, inst.network_key)
    transport = ZigbeeDirectTransport(client, own_eui=inst.zvd_eui, psk=psk, clock=inst.clock)
    await inst.clock.run_task(transport.open())
    node = ZigbeeDirectNode(
        transport,
        clock=inst.clock,
        config=config,
        rng=random.Random(seed),  # noqa: S311
    )
    the_rig = Rig(inst, transport, node)
    try:
        if join:
            await inst.clock.run_task(node.join())
        yield the_rig
    finally:
        await node.close()
        await transport.close()


def decoded_commands(npdus: list[bytes]) -> list[object]:
    out: list[object] = []
    for raw in npdus:
        frame = NwkFrame.decode(raw)
        if frame.frame_type is NwkFrameType.COMMAND:
            out.append(decode_nwk_command(frame.payload))
        else:
            out.append(ApsDataFrame.decode(frame.payload))
    return out


def mask(data: bytes, *offsets: int) -> bytes:
    out = bytearray(data)
    for offset in offsets:
        out[offset] = 0
    return bytes(out)


def patch_short(golden: bytes, old: int, new: int) -> bytes:
    return golden.replace(old.to_bytes(2, "little"), new.to_bytes(2, "little"))


# --- join -----------------------------------------------------------------------------------


async def test_join_happy_path(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    async with rig() as r:
        info = r.node.join_info
        assert info is not None
        inst = r.inst
        assert info.own_short == r.node.own_short == inst.network.joined_short
        assert info.own_short == info.requested_short  # the TC echoed the placeholder
        assert info.own_eui == r.node.own_eui == inst.zvd_eui
        assert (info.zdd_short, info.zdd_eui) == (inst.r0.zdd_short, inst.zdd_eui)
        network = info.network
        assert network.pan_id == 0x1A2B
        assert network.extended_pan_id is not None
        assert {f.name for f in fields(NetworkSummary)} == {
            "pan_id",
            "extended_pan_id",
            "channel_masks",
            "trust_center_address",
            "device_type",
            "joined_status",
        }
        assert "key" not in repr(info).lower()
        assert inst.network.gated_open
        assert r.node.stats.mtorr_sent == 2
        for key in (inst.network_key, inst.r0._link_key, inst.r0._admin_key):
            assert key is not None
            assert key.reveal().hex() not in caplog.text
            assert key.reveal().hex().upper() not in caplog.text
        (line,) = [
            rec for rec in caplog.records if rec.levelno == logging.INFO and rec.name == LOGGER
        ]
        assert f"0x{info.own_short:04X}" in line.getMessage()


async def test_join_sends_status_commission_annce_mtorr_in_order() -> None:
    async with rig() as r:
        commands = decoded_commands(r.writes())
        assert isinstance(commands[0], CommissioningRequest)
        annce = commands[1]
        assert isinstance(annce, ApsDataFrame)
        assert annce.cluster_id == 0x0013
        assert all(isinstance(c, RouteRequest) for c in commands[2:4])
        assert len(commands) == 4
        mtorr_ids = [c.route_id for c in commands[2:4] if isinstance(c, RouteRequest)]
        assert len(set(mtorr_ids)) == 2
        assert r.inst.r0.tunnel_writes[0].nwk_security is False
        assert all(w.nwk_security for w in r.inst.r0.tunnel_writes[1:])


async def test_join_adopts_valid_reassigned_short() -> None:
    async with rig(network={"assign_short": 0x4321}) as r:
        info = r.node.join_info
        assert info is not None
        assert info.own_short == 0x4321 == r.node.own_short
        assert info.requested_short != 0x4321
        annce = NwkFrame.decode(r.writes()[1])
        assert annce.src == 0x4321  # Device_annce uses the assigned short


@pytest.mark.parametrize("assigned", [0x0000, 0xFFFD, 0xFFF8, "zdd"])
async def test_join_rejects_invalid_assigned_short(assigned: int | str) -> None:
    async with rig(join=False) as r:
        r.inst.network.assign_short = r.inst.r0.zdd_short if isinstance(assigned, str) else assigned
        with pytest.raises(JoinError, match="invalid assigned short") as exc:
            await r.clock.run_task(r.node.join())
        assert not isinstance(exc.value, JoinRejectedError)
        assert r.node.join_info is None
        with pytest.raises(RuntimeError):
            _ = r.node.own_short
        assert len(r.writes()) == 1  # no Device_annce, no MTORR


async def test_join_rejected_status() -> None:
    async with rig(join=False, network={"commissioning_status": 0x9A}) as r:
        with pytest.raises(JoinRejectedError) as exc:
            await r.clock.run_task(r.node.join())
        assert exc.value.status == 0x9A


async def test_join_ignores_unrelated_commissioning_response() -> None:
    async with rig(join=False, network={"unrelated_commissioning_response": True}) as r:
        info = await r.clock.run_task(r.node.join())
        assert info.own_short == info.requested_short
        assert r.clock.now() >= 1.5  # resolved by the real response, not the early one


async def test_join_retries_with_new_placeholder_then_succeeds() -> None:
    async with rig(join=False) as r:
        r.inst.network.drop_commissioning_requests(1)
        start = r.clock.now()
        info = await r.clock.run_task(r.node.join())
        requests = [NwkFrame.decode(w) for w in r.writes()[:2]]
        assert all(
            isinstance(decode_nwk_command(f.payload), CommissioningRequest) for f in requests
        )
        assert requests[0].src != requests[1].src  # a NEW placeholder per attempt
        assert requests[0].seq != requests[1].seq
        assert info.requested_short == requests[1].src
        assert r.clock.now() - start >= r.node.config.join_timeout


async def test_join_silent_drop_gives_join_error_after_attempts() -> None:
    async with rig(join=False) as r:
        r.inst.network.drop_commissioning_requests(5)
        start = r.clock.now()
        with pytest.raises(JoinError, match="no Commissioning Response after 2"):
            await r.clock.run_task(r.node.join())
        assert r.clock.now() - start == pytest.approx(2 * r.node.config.join_timeout, abs=0.1)
        placeholders = {NwkFrame.decode(w).src for w in r.writes()}
        assert len(placeholders) == 2
        assert r.core.join_slot.active is None


async def test_late_response_to_older_placeholder_is_dropped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # attempt 1 (t=0) is answered at t=20, during attempt 2 (sent at t=15, answered at t=23)
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    async with rig(join=False, network={"commissioning_delay": 20.0}) as r:
        t0 = r.clock.now()
        join = asyncio.ensure_future(r.node.join())
        await r.clock.advance(1.0)
        r.inst.network.commissioning_delay = 8.0
        await r.clock.advance(20.0)
        assert not join.done()  # the late answer to placeholder 1 resolved nothing
        info = await r.clock.run_task(join)
        first, second = (NwkFrame.decode(w).src for w in r.writes()[:2])
        assert first != second
        assert info.requested_short == info.own_short == second
        assert r.clock.now() - t0 == pytest.approx(23.0 + r.node.config.mtorr_spacing)
        assert f"0x{first:04X}" in caplog.text  # the dropped response was logged


async def test_join_uses_preferred_short_and_avoids_shorts() -> None:
    config = NodeConfig(preferred_short=0x0BAD, avoid_shorts=frozenset({0x0BAD}))
    async with rig(config=config) as r:
        info = r.node.join_info
        assert info is not None
        assert info.requested_short != 0x0BAD
    async with rig(config=NodeConfig(preferred_short=0x0BAD)) as r:
        info = r.node.join_info
        assert info is not None
        assert info.requested_short == 0x0BAD


async def test_join_malformed_status_is_a_join_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def malformed(_self: ZigbeeDirectTransport) -> None:
        raise CommissioningDecodeError("duplicate TLV")

    async with rig(join=False) as r:
        monkeypatch.setattr(ZigbeeDirectTransport, "read_commissioning_status", malformed)
        with pytest.raises(JoinError, match="malformed") as exc:
            await r.clock.run_task(r.node.join())
        assert exc.value.__cause__ is None


async def test_join_missing_zdd_short_tlv() -> None:
    async with rig(join=False, r0={"status_omit_short": True}) as r:
        with pytest.raises(JoinError, match="TLV 0x06"):
            await r.clock.run_task(r.node.join())
        assert r.writes() == []


async def test_join_tlv_0x08_mismatch_warns_and_trusts_se2(
    caplog: pytest.LogCaptureFixture,
) -> None:
    other = g.VALVE_EUI
    async with rig(join=False, r0={"status_ieee_override": other}) as r:
        caplog.set_level(logging.WARNING, logger=LOGGER)
        info = await r.clock.run_task(r.node.join())
        assert info.zdd_eui == r.inst.zdd_eui != other
        (warning,) = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
        assert "SE2" in warning.getMessage()
        assert str(other) not in caplog.text


async def test_join_twice_is_an_error() -> None:
    async with rig() as r:
        with pytest.raises(RuntimeError, match="once"):
            await r.clock.run_task(r.node.join())


# --- gating and golden bytes ----------------------------------------------------------------


async def test_device_annce_and_mtorr_golden_bytes() -> None:
    config = NodeConfig(preferred_short=g.ZVD_SHORT)
    async with rig(config=config) as r:
        writes = r.writes()
        own_eui = r.inst.zvd_eui
        assert own_eui == g.ZVD_EUI
        # golden NWK seq 02 / ZDO seq 01 match our allocators; APS counter (offset 15) masked
        assert mask(writes[1], 15) == mask(g.DEVICE_ANNCE, 15)
        assert writes[2] == g.MTORR  # NWK seq 03, route id 01
        assert mask(writes[3], 7, 18) == mask(g.MTORR, 7, 18)  # NWK seq and route id differ
        assert (writes[3][7], writes[3][18]) == (4, 2)


async def test_no_valve_request_before_join_returns() -> None:
    async with rig(join=False) as r:
        valve = r.inst.valves[0]
        with pytest.raises(RuntimeError, match="join"):
            await r.node.zcl_read(valve.short, 1, THERMOSTAT, [LOCAL_TEMPERATURE])
        with pytest.raises(RuntimeError, match="join"):
            await r.node.send_mtorr()
        assert r.writes() == []
        await r.clock.run_task(r.node.join())
        records = await r.clock.run_task(
            r.node.zcl_read(valve.short, 1, THERMOSTAT, [LOCAL_TEMPERATURE])
        )
        assert records[0].attribute_id == LOCAL_TEMPERATURE
        kinds = [NwkFrame.decode(w) for w in r.writes()]
        assert [f.dst for f in kinds[4:]] == [valve.short]  # the read came after annce + MTORRs
