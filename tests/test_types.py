"""Tests for Eui64, SecretBytes, short-address helpers and the error hierarchy."""

from __future__ import annotations

import logging

import pytest

from localtrv.zigbee_direct import (
    BROADCAST_ALL,
    BROADCAST_ROUTERS,
    BROADCAST_RX_ON,
    COORDINATOR,
    ApsDecodeError,
    AuthenticationError,
    CommissioningDecodeError,
    CounterExhaustedError,
    DecodeError,
    EncodeError,
    Eui64,
    HandshakeError,
    NwkDecodeError,
    ReplayError,
    SecretBytes,
    TlvDecodeError,
    UnsupportedFrameError,
    ZclDecodeError,
    ZdoDecodeError,
    ZigbeeDirectError,
    generate_zvd_eui,
    validate_short,
)

DISPLAY = "02:00:00:00:00:00:00:01"
WIRE = bytes.fromhex("0100000000000002")


def test_eui_from_str_and_wire_order() -> None:
    eui = Eui64.from_str(DISPLAY)
    assert eui.wire == WIRE
    assert bytes(eui) == WIRE
    assert str(eui) == DISPLAY
    assert eui.as_int() == 0x0200000000000001


def test_eui_round_trips() -> None:
    eui = Eui64.from_wire(WIRE)
    assert Eui64.from_str(str(eui)) == eui
    assert Eui64.from_wire(bytes(eui)) == eui


@pytest.mark.parametrize("text", ["0200000000000001", "02-00-00-00-00-00-00-01", f" {DISPLAY} "])
def test_eui_from_str_variants(text: str) -> None:
    assert Eui64.from_str(text) == Eui64.from_wire(WIRE)


def test_eui_hashable_and_ordered_by_int() -> None:
    a = Eui64.from_str("02:00:00:00:00:00:00:01")
    b = Eui64.from_str("02:00:00:00:00:00:01:00")
    assert len({a, b, a}) == 2
    assert a.as_int() < b.as_int()


@pytest.mark.parametrize("bad", ["", "02:00", "zz:00:00:00:00:00:00:01", DISPLAY + ":00"])
def test_eui_from_str_invalid(bad: str) -> None:
    with pytest.raises(ValueError, match="EUI-64"):
        Eui64.from_str(bad)


@pytest.mark.parametrize("bad", [b"", b"\x00" * 7, b"\x00" * 9])
def test_eui_wire_length_validated(bad: bytes) -> None:
    with pytest.raises(ValueError, match="8 bytes"):
        Eui64.from_wire(bad)


def test_eui_is_immutable() -> None:
    eui = Eui64.from_wire(WIRE)
    with pytest.raises(AttributeError):
        eui.wire = b"\x00" * 8  # type: ignore[misc]


def test_generate_sets_local_bit_clears_multicast() -> None:
    eui = generate_zvd_eui(lambda n: b"\xff" * n)
    assert eui.wire[7] == 0xFE
    assert eui.wire[:7] == b"\xff" * 7
    eui = generate_zvd_eui(lambda n: b"\x00" * n)
    assert eui.wire[7] == 0x02
    assert str(eui).startswith("02:")


def test_generate_uses_rng_and_default_is_valid() -> None:
    calls: list[int] = []

    def rng(n: int) -> bytes:
        calls.append(n)
        return bytes(range(1, n + 1))

    eui = generate_zvd_eui(rng)
    assert calls == [8]
    assert eui.wire == bytes([1, 2, 3, 4, 5, 6, 7, 8 | 0x02])
    random_eui = generate_zvd_eui()
    assert random_eui.wire[7] & 0x03 == 0x02


def test_generate_rejects_bad_rng() -> None:
    with pytest.raises(ValueError, match="rng returned"):
        generate_zvd_eui(lambda _n: b"\x00" * 4)


def test_secret_redaction_everywhere(caplog: pytest.LogCaptureFixture) -> None:
    secret = SecretBytes(bytes.fromhex("aabbccddeeff00112233445566778899"))  # secret-scan: allow
    marker = "SecretBytes(<redacted>)"
    assert repr(secret) == marker
    assert str(secret) == marker
    assert f"{secret}" == marker
    assert f"{secret!r}" == marker
    assert f"{secret:>40}" == marker
    assert f"{[secret]}" == f"[{marker}]"
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("test").debug("key=%s repr=%r", secret, secret)
    assert "aabbcc" not in caplog.text.lower()
    assert marker in caplog.text


def test_secret_reveal_len_from_hex() -> None:
    secret = SecretBytes.from_hex(" 00112233 ")
    assert secret.reveal() == bytes.fromhex("00112233")
    assert len(secret) == 4


def test_secret_equality_and_unhashable() -> None:
    a = SecretBytes(b"\x01\x02")
    assert a == SecretBytes(b"\x01\x02")
    assert a != SecretBytes(b"\x01\x03")
    assert a != SecretBytes(b"\x01")
    assert a != b"\x01\x02"
    with pytest.raises(TypeError):
        hash(a)


def test_secret_requires_bytes() -> None:
    with pytest.raises(TypeError):
        SecretBytes("text")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-hexadecimal"):
        SecretBytes.from_hex("xyz")


def test_validate_short() -> None:
    assert validate_short(0) == 0
    assert validate_short(0xFFFF) == 0xFFFF
    for bad in (-1, 0x10000):
        with pytest.raises(ValueError, match="short address"):
            validate_short(bad)
    with pytest.raises(ValueError, match="short address"):
        validate_short(True)


def test_short_constants() -> None:
    assert (COORDINATOR, BROADCAST_ROUTERS, BROADCAST_RX_ON, BROADCAST_ALL) == (
        0x0000,
        0xFFFC,
        0xFFFD,
        0xFFFF,
    )


def test_error_hierarchy() -> None:
    decode_subs = (
        TlvDecodeError,
        NwkDecodeError,
        ApsDecodeError,
        ZdoDecodeError,
        ZclDecodeError,
        CommissioningDecodeError,
        UnsupportedFrameError,
    )
    for exc in decode_subs:
        assert issubclass(exc, DecodeError)
        assert issubclass(exc, ValueError)
        assert issubclass(exc, ZigbeeDirectError)
    plain: tuple[type[ZigbeeDirectError], ...] = (
        HandshakeError,
        AuthenticationError,
        ReplayError,
        CounterExhaustedError,
    )
    for plain_exc in plain:
        assert not issubclass(plain_exc, ValueError)
    assert issubclass(EncodeError, ZigbeeDirectError)
    assert issubclass(EncodeError, ValueError)
