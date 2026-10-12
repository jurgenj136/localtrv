"""ZigbeeDirectTransport (T10): ingress counters, Commissioning Status read, counter-model log."""

from __future__ import annotations

import logging

import pytest

from test_sim_gatt import ADMIN_KEY, LINK_KEY, NETWORK_KEY, ZDD_SHORT, RecordingPeer, make_r0
from test_transport import LOGGER, SpyClient, make_transport, opened
from vicare_local_ble.testing import ZddCounterModel
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.tlv import Tlv, TunnelNpdu
from vicare_local_ble.zigbee_direct.debug import NpduRecorder
from vicare_local_ble.zigbee_direct.errors import TransportError
from vicare_local_ble.zigbee_direct.session import CounterModel
from vicare_local_ble.zigbee_direct.transport import MIC_WARNING_STREAK
from vicare_local_ble.zigbee_direct.uuids import (
    COMMISSIONING_SERVICE,
    COMMISSIONING_STATUS,
    TUNNEL_NPDU,
    TUNNEL_SERVICE,
)

SECRETS = [k.reveal().hex() for k in (NETWORK_KEY, LINK_KEY, ADMIN_KEY)]


def mic_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and r.levelno == logging.WARNING and "MIC" in r.getMessage()
    ]


def model_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and r.getMessage().startswith("counter_model=")
    ]


async def test_indications_reach_handler_and_recorder() -> None:
    clock = VirtualClock()
    recorder = NpduRecorder(clock=clock)
    r0 = make_r0(clock)
    RecordingPeer(r0)
    transport, _ = make_transport(r0, recorder=recorder)
    await clock.run_task(transport.open())
    received: list[TunnelNpdu] = []
    r0.indicate_npdu(b"\x01")  # before a handler: recorded, then dropped
    transport.set_npdu_handler(received.append)
    r0.indicate_npdu(b"\x02", secure=False)
    await clock.run_task(transport.send_npdu(b"\x03"))
    assert received == [TunnelNpdu(b"\x02", False)]
    assert [r.direction for r in recorder.records()] == ["rx", "rx", "tx"]
    assert transport.stats.frames_rx == 2
    assert transport.stats.frames_tx == 1
    await transport.close()
    r0.indicate_npdu(b"\x04")  # after close: unsubscribed, nothing delivered
    assert len(received) == 1


async def test_replay_vs_mic_counters(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    received: list[TunnelNpdu] = []
    transport.set_npdu_handler(received.append)
    r0.indicate_npdu(b"\x01")
    r0.inject_replayed_indication()
    r0.inject_replayed_indication()
    stats = transport.stats
    assert (stats.replay_drops, stats.mic_failures) == (2, 0)
    assert mic_warnings(caplog) == []  # replays are not MTU evidence
    for _ in range(MIC_WARNING_STREAK - 1):
        r0.inject_bad_mic_indication()
        r0.indicate_npdu(b"\x02")
    assert stats.mic_failures == MIC_WARNING_STREAK - 1
    assert mic_warnings(caplog) == []
    r0.inject_bad_mic_indication()
    r0.indicate_npdu(b"\x02")
    r0.inject_bad_mic_indication()
    r0.indicate_npdu(b"\x02")  # a fourth in the same streak: still one WARNING
    (warning,) = mic_warnings(caplog)
    assert "mtu=247" in warning
    r0.indicate_npdu(b"\x03")  # resets the streak
    for _ in range(MIC_WARNING_STREAK):
        r0.inject_bad_mic_indication()
        r0.indicate_npdu(b"\x02")
    assert len(mic_warnings(caplog)) == 2
    assert stats.mic_failures == 2 * MIC_WARNING_STREAK + 1
    assert stats.replay_drops == 2
    assert [n.npdu for n in received] == [b"\x01", b"\x03"]
    assert stats.frames_rx == 2
    assert not transport.broken
    await transport.close()


async def test_tlv_errors_and_short_frames_are_counted() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    received: list[TunnelNpdu] = []
    transport.set_npdu_handler(received.append)
    client = r0.client
    zdd = r0._zdd
    assert client is not None
    assert zdd is not None
    client._deliver(TUNNEL_NPDU, zdd.seal(TUNNEL_SERVICE, TUNNEL_NPDU, b"\x00\x05\x00"))
    client._deliver(TUNNEL_NPDU, b"\x01\x02")  # shorter than counter + MIC
    other = Tlv(0x7E, b"\x01").encode() + TunnelNpdu(b"\x09", True).encode()
    client._deliver(TUNNEL_NPDU, zdd.seal(TUNNEL_SERVICE, TUNNEL_NPDU, other))
    assert transport.stats.tlv_errors == 2
    assert received == [TunnelNpdu(b"\x09", True)]  # unknown TLVs are skipped
    await transport.close()


async def test_handler_and_recorder_failures_are_contained(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class BadRecorder(NpduRecorder):
        def rx(self, npdu: TunnelNpdu) -> None:
            raise RuntimeError("rx bug")

        def tx(self, npdu: TunnelNpdu) -> None:
            raise RuntimeError("tx bug")

    caplog.set_level(logging.DEBUG, logger=LOGGER)
    clock = VirtualClock()
    r0 = make_r0(clock)
    peer = RecordingPeer(r0)
    transport, _ = make_transport(r0, recorder=BadRecorder())
    await clock.run_task(transport.open())

    def explode(_npdu: TunnelNpdu) -> None:
        raise ValueError("handler bug")

    transport.set_npdu_handler(explode)
    r0.indicate_npdu(b"\x01")
    await clock.run_task(transport.send_npdu(b"\x02"))
    assert [n.npdu for n in peer.npdus] == [b"\x02"]
    assert transport.stats.frames_rx == 1
    assert not transport.broken
    assert any("handler raised" in r.getMessage() for r in caplog.records)
    assert any("recorder rx failed" in r.getMessage() for r in caplog.records)
    assert any("recorder tx failed" in r.getMessage() for r in caplog.records)
    await transport.close()


# --- Commissioning Status ----------------------------------------------------------------------


async def test_status_read_is_never_recorded_or_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    clock = VirtualClock()
    recorder = NpduRecorder(clock=clock)
    r0 = make_r0(clock)
    RecordingPeer(r0)
    transport, _ = make_transport(r0, recorder=recorder)
    await clock.run_task(transport.open())
    status = await clock.run_task(transport.read_commissioning_status())
    assert status.network_key == NETWORK_KEY
    assert status.nwk_address == ZDD_SHORT
    r0.indicate_npdu(b"\x01")
    await clock.run_task(transport.send_npdu(b"\x02"))
    await transport.close()
    records = recorder.records()
    assert [r.direction for r in records] == ["rx", "tx"]  # the status read added nothing
    dumped = caplog.text + "".join(r.to_json() for r in records) + repr(transport)
    dumped += repr(transport.stats) + repr(status)
    for secret in SECRETS:
        assert secret not in dumped
        assert secret.upper() not in dumped


async def test_status_read_timeout() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    r0.write_latency = 20.0  # reads take longer than the 10 s bound
    with pytest.raises(TransportError) as exc:
        await clock.run_task(transport.read_commissioning_status())
    assert exc.value.reason == "timeout"
    await transport.close()


@pytest.mark.parametrize("case", ["replay", "mic"])
async def test_status_read_rejected_frame_is_protocol(case: str) -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, client = make_transport(r0, spy=True)
    await clock.run_task(transport.open())
    zdd = r0._zdd
    assert zdd is not None
    if case == "replay":
        frame = bytes(12)  # counter 0 is never acceptable
    else:
        sealed = zdd.seal(COMMISSIONING_SERVICE, COMMISSIONING_STATUS, b"\x00\x00")
        frame = sealed[:-1] + bytes([sealed[-1] ^ 0xFF])

    async def read(_char: str) -> bytearray:
        return bytearray(frame)

    client.read_gatt_char = read  # type: ignore[method-assign,assignment]
    with pytest.raises(TransportError) as exc:
        await clock.run_task(transport.read_commissioning_status())
    assert exc.value.reason == "protocol"
    assert frame.hex() not in str(exc.value)
    await transport.close()


async def test_status_read_after_disconnect_is_write() -> None:
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    r0.disconnect()
    with pytest.raises(TransportError) as exc:
        await clock.run_task(transport.read_commissioning_status())
    assert exc.value.reason == "write"
    await transport.close()


# --- counter model ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        (ZddCounterModel.SHARED, CounterModel.SHARED),
        (ZddCounterModel.PER_CHARACTERISTIC, CounterModel.PER_CHARACTERISTIC),
    ],
)
async def test_counter_model_logged_once(
    caplog: pytest.LogCaptureFixture, model: ZddCounterModel, expected: CounterModel
) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    clock = VirtualClock()
    r0, _, transport = await opened(clock, counter_model=model)
    await clock.run_task(transport.read_commissioning_status())
    assert model_lines(caplog) == []
    for i in range(3):
        r0.indicate_npdu(bytes([i]))
    await clock.run_task(transport.read_commissioning_status())
    await transport.close()
    await transport.close()
    assert model_lines(caplog) == [f"counter_model={expected.value}"]
    assert transport.stats.counter_model is expected


async def test_counter_model_unknown_logged_at_close(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    clock = VirtualClock()
    r0, _, transport = await opened(clock)
    r0.indicate_npdu(b"\x01")  # Tunnel only: not enough evidence
    assert model_lines(caplog) == []
    await transport.close()
    await transport.close()
    assert model_lines(caplog) == ["counter_model=unknown"]
    assert transport.stats.counter_model is CounterModel.UNKNOWN


async def test_failed_open_logs_no_counter_model(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    clock = VirtualClock()
    r0 = make_r0(clock, handshake_fault="se2_silence")
    transport, _ = make_transport(r0)
    with pytest.raises(TransportError):
        await clock.run_task(transport.open())
    assert model_lines(caplog) == []


async def test_indication_after_close_is_ignored_even_if_still_subscribed() -> None:
    clock = VirtualClock()
    r0 = make_r0(clock)
    transport, client = make_transport(r0, spy=True)
    await clock.run_task(transport.open())
    received: list[TunnelNpdu] = []
    transport.set_npdu_handler(received.append)
    assert isinstance(client, SpyClient)
    client.fail["stop_notify"] = RuntimeError("backend refused")  # Tunnel stays subscribed
    await transport.close()
    r0.indicate_npdu(b"\x01")
    assert received == []
    assert transport.stats.frames_rx == 0
