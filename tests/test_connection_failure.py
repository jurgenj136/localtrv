"""ZdConnection: the failure log line and ``last_failure_detail`` name the cause, key-free."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import pytest
from custom_components.localtrv.diagnostics import _connection

from localtrv.testing.gatt import SimulatedR0
from localtrv.zigbee_direct.codec.commissioning import StatusTag
from localtrv.zigbee_direct.codec.tlv import Tlv, decode_tlvs, encode_tlvs
from localtrv.zigbee_direct.connection_failure import describe_failure
from localtrv.zigbee_direct.errors import (
    ConnectionLostError,
    JoinError,
    TransportError,
)
from localtrv.zigbee_direct.node import ZigbeeDirectNode
from test_connection import make_rig, start, stop

if TYPE_CHECKING:
    from collections.abc import Callable

    from localtrv.zigbee_direct.node import JoinInfo
    from test_connection import Rig

SECRET_HEX = "deadbeef" * 4  # dummy, secret-looking
DUMMY_KEY = bytes(range(0xA0, 0xB0))  # stands in for decrypted key material


def assert_key_free(r: Rig, text: str) -> None:
    """Neither the log nor the stats hold the (dummy) network key in any common rendering."""
    key = r.inst.network_key.reveal()
    stats = f"{r.conn.stats!r} {r.conn.stats!s}"
    for rendering in (key.hex(), key.hex().upper(), repr(key)[2:-1], key.hex(" ")):
        assert rendering not in text
        assert rendering not in stats


def fail_first_join(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    original = ZigbeeDirectNode.join
    calls: list[int] = []

    async def flaky_join(self: ZigbeeDirectNode) -> JoinInfo:
        calls.append(1)
        if len(calls) == 1:
            raise exc
        return await original(self)

    monkeypatch.setattr(ZigbeeDirectNode, "join", flaky_join)


def replace_first_status(
    monkeypatch: pytest.MonkeyPatch, rewrite: Callable[[bytes], bytes]
) -> None:
    """The simulator's first Commissioning Status read returns ``rewrite(plaintext)``."""
    original = SimulatedR0._status_plaintext
    reads: list[int] = []

    def first_rewritten(self: SimulatedR0) -> bytes:
        plaintext = original(self)
        reads.append(1)
        return rewrite(plaintext) if len(reads) == 1 else plaintext

    monkeypatch.setattr(SimulatedR0, "_status_plaintext", first_rewritten)


def wide_nwk_address(plaintext: bytes) -> bytes:
    """A 4-byte NWK_ADDRESS TLV: a join anchor, so its wrong length stays fatal."""
    return encode_tlvs(
        Tlv(t.tag, t.value + b"\x00\x00") if t.tag == StatusTag.NWK_ADDRESS else t
        for t in decode_tlvs(plaintext)
    )


async def test_malformed_status_logs_the_safe_layout(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    r = make_rig()
    replace_first_status(monkeypatch, wide_nwk_address)
    gen = await start(r)
    assert gen.number == 1
    prefix = "JoinError: malformed Commissioning Status (length mismatch on NWK_ADDRESS; layout "
    detail = r.conn.stats.last_failure_detail
    assert detail is not None
    assert detail.startswith(prefix)
    assert " 03/16 " in detail  # the network key TLV is shown by its header only
    assert detail.endswith(" 06/4, 45 B withheld)")  # nothing past the first unverified header
    assert f"ZDD: connection failed (join: {detail})" in caplog.text
    assert r.conn.stats.last_failure == "join"
    assert_key_free(r, caplog.text)
    await stop(r)


async def test_lying_key_length_withholds_the_structure(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex's reproduction: NETWORK_KEY declares 1 byte; key bytes would be read as headers."""
    caplog.set_level(logging.DEBUG)
    r = make_rig()
    replace_first_status(monkeypatch, lambda _plaintext: b"\x03\x00" + DUMMY_KEY)
    await start(r)
    detail = (
        "JoinError: malformed Commissioning Status "
        "(length mismatch on NETWORK_KEY; layout 18 B: 03/1, 16 B withheld)"
    )
    assert r.conn.stats.last_failure_detail == detail
    assert f"ZDD: connection failed (join: {detail})" in caplog.text
    diagnostics = json.dumps(_connection(r.conn))
    assert detail in diagnostics
    for text in (caplog.text, repr(r.conn.stats), diagnostics):
        for leak in ("A1", "a1", "163", "0xA1", DUMMY_KEY.hex()):
            assert leak not in text
    await stop(r)


async def test_foreign_exception_logs_only_its_type(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    r = make_rig()
    fail_first_join(monkeypatch, ValueError(SECRET_HEX))
    await start(r)
    assert "ZDD: connection failed (join: ValueError)" in caplog.text
    assert r.conn.stats.last_failure_detail == "ValueError"
    assert SECRET_HEX not in caplog.text
    assert SECRET_HEX not in repr(r.conn.stats)
    assert_key_free(r, caplog.text)
    await stop(r)


async def test_transport_error_in_the_chain_logs_its_reason(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    r = make_rig()
    cause = TransportError("Commissioning Status read timed out", reason="timeout")
    outer = ConnectionLostError("transport failed (timeout)")
    outer.__cause__ = cause
    fail_first_join(monkeypatch, outer)
    await start(r)
    detail = (
        "ConnectionLostError: transport failed (timeout) <- "
        "TransportError(reason=timeout): Commissioning Status read timed out"
    )
    assert f"ZDD: connection failed (join: {detail})" in caplog.text
    assert r.conn.stats.last_failure_detail == detail
    await stop(r)


async def test_connect_failure_detail_is_the_type_only(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    r = make_rig()
    r.inst.connector.fail_next(1, exc=OSError(SECRET_HEX))
    await start(r)
    assert "ZDD: connection failed (connect: OSError)" in caplog.text
    assert SECRET_HEX not in caplog.text
    await stop(r)


async def test_bleak_connect_failure_detail() -> None:
    r = make_rig()
    r.inst.connector.fail_next(1)
    await start(r)
    assert r.conn.stats.last_failure_detail == "BleakError"
    await stop(r)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (ValueError(SECRET_HEX), "ValueError"),
        (JoinError("commissioning rejected"), "JoinError: commissioning rejected"),
        (
            TransportError("SE2 timed out", reason="timeout"),
            "TransportError(reason=timeout): SE2 timed out",
        ),
    ],
)
def test_describe_failure(exc: BaseException, expected: str) -> None:
    assert describe_failure(exc) == expected


def test_describe_failure_foreign_outer_with_transport_cause() -> None:
    outer = RuntimeError(SECRET_HEX)
    try:
        try:
            raise TransportError("write failed: BleakError", reason="write")
        except TransportError:
            raise outer  # noqa: B904 - an implicit __context__ chain on purpose
    except RuntimeError:
        pass
    assert describe_failure(outer) == (
        "RuntimeError <- TransportError(reason=write): write failed: BleakError"
    )
