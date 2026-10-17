"""Tests for Zigbee Direct GATT UUID constants and canonical UUID bytes."""

from __future__ import annotations

import pytest

from localtrv.zigbee_direct import uuids


def test_uuid16_expansion() -> None:
    expected = "0000fff700001000800000805f9b34fb"  # secret-scan: allow
    assert uuids.uuid_bytes(0xFFF7).hex() == expected
    assert uuids.uuid_bytes("0xFFF7").hex() == expected
    assert uuids.uuid_bytes("fff7").hex() == expected
    assert uuids.COMMISSIONING_SERVICE == "0000fff7-0000-1000-8000-00805f9b34fb"


def test_uuid128_canonical_order() -> None:
    expected = "7072377d0001421cb163491c27333a61"  # secret-scan: allow
    assert uuids.uuid_bytes(uuids.COMMISSIONING_FORM_NETWORK).hex() == expected
    assert uuids.uuid_bytes("{7072377D-0001-421C-B163-491C27333A61}").hex() == expected


@pytest.mark.parametrize("bad", ["zzzz", "0x12345", "not-a-uuid", ""])
def test_uuid_bytes_rejects_garbage(bad: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - stdlib message varies
        uuids.uuid_bytes(bad)


@pytest.mark.parametrize("bad", [-1, 0x10000, True])
def test_uuid16_range(bad: int) -> None:
    with pytest.raises(ValueError, match="16-bit"):
        uuids.expand_uuid16(bad)


def test_service_and_characteristic_constants() -> None:
    assert uuids.SECURITY_SERVICE == "29144af4-0000-4481-bfe9-6d0299b429e3"
    assert uuids.SECURITY_AUTHENTICATE_C25519 == "29144af4-0001-4481-bfe9-6d0299b429e3"
    assert uuids.TUNNEL_SERVICE == "8bd178fd-0000-45f4-8120-b2378bd5313f"
    assert uuids.TUNNEL_NPDU == "8bd178fd-0001-45f4-8120-b2378bd5313f"
    chars = [
        uuids.COMMISSIONING_FORM_NETWORK,
        uuids.COMMISSIONING_JOIN_NETWORK,
        uuids.COMMISSIONING_PERMIT_JOINING,
        uuids.COMMISSIONING_LEAVE_NETWORK,
        uuids.COMMISSIONING_STATUS,
        uuids.COMMISSIONING_MANAGE_JOINERS,
        uuids.COMMISSIONING_IDENTIFY,
        uuids.COMMISSIONING_FINDING_BINDING,
    ]
    for index, value in enumerate(chars, start=1):
        assert value == f"7072377d-{index:04x}-421c-b163-491c27333a61"
        assert len(uuids.uuid_bytes(value)) == 16
