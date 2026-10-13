"""Key-free failure details: the Commissioning Status layout rule and the GATT ATT code."""

from __future__ import annotations

import random
import re

import pytest
from bleak.exc import BleakError, BleakGATTProtocolError

from vicare_local_ble.zigbee_direct.codec.commissioning import (
    CommissioningStatus,
    safe_status_layout,
)
from vicare_local_ble.zigbee_direct.codec.tlv import Tlv
from vicare_local_ble.zigbee_direct.errors import CommissioningDecodeError
from vicare_local_ble.zigbee_direct.transport_handshake import gatt_failure

DUMMY_KEY = bytes(range(0xA0, 0xB0))  # stands in for decrypted key material
#: The live R0 tag order (60 B) with its 4-byte DEVICE_TYPE: schema-matching, so fully shown.
LIVE_LAYOUT = "60 B: 08/8 0A/1 00/8 01/2 02/5 05/4 06/2 09/8 0B/1 0C/1"
#: Fixed-length tags without key material, with their lengths (0x02 is variable).
NON_KEY_FIXED = {0x00: 8, 0x01: 2, 0x05: 1, 0x06: 2, 0x07: 1, 0x08: 8, 0x09: 8, 0x0A: 1}
#: Further allowed lengths (schema variants): the ubisys R0's 4-byte DEVICE_TYPE.
VARIANT_LENGTHS = {0x05: {4}}
_HEADER = re.compile(r"\b([0-9A-F]{2})/(\d+)\b")


def _tlv(tag: int, value: bytes) -> bytes:
    return Tlv(tag, value).encode()


def _channel() -> bytes:
    return _tlv(0x02, b"\x01" + (1 << 15).to_bytes(4, "little"))


def live_like_status() -> bytes:
    return b"".join(
        (
            _tlv(0x08, b"\x02" * 8),
            _tlv(0x0A, b"\x12"),
            _tlv(0x00, b"\xdd" * 8),
            _tlv(0x01, b"\xcd\xab"),
            _channel(),
            _tlv(0x05, b"\x01\x00\x00\x00"),
            _tlv(0x06, b"\x5a\x5a"),
            _tlv(0x09, b"\x01" * 8),
            _tlv(0x0B, b"\x00"),
            _tlv(0x0C, b"\x00"),
        )
    )


def assert_key_free(text: str) -> None:
    """No key byte appears as a token: 2-digit hex (both cases, with or without ``0x``) or
    decimal (also +1: a TLV length octet shows as value + 1); nor the key as one hex run."""
    assert DUMMY_KEY.hex() not in text.lower()
    banned: set[str] = set()
    for b in DUMMY_KEY:
        banned |= {f"{b:02x}", f"{b:02X}", f"0x{b:02x}", f"0x{b:02X}", str(b), str(b + 1)}
    leaked = banned.intersection(re.findall(r"\w+", text))
    assert not leaked, leaked


def decode_error(data: bytes) -> CommissioningDecodeError:
    with pytest.raises(CommissioningDecodeError) as exc:
        CommissioningStatus.decode(data)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    assert str(exc.value) == f"commissioning status: {exc.value.safe_detail}"
    return exc.value


# --- Commissioning Status layout --------------------------------------------------------------


def shown_headers(detail: str) -> list[tuple[int, int]]:
    """The ``(tag, length octet)`` byte pairs a detail shows."""
    return [(int(tag, 16), int(length) - 1) for tag, length in _HEADER.findall(detail)]


def test_lying_network_key_length_withholds_the_key() -> None:
    """Codex's first reproduction: NETWORK_KEY declares 1 byte; only its own header shows."""
    data = b"\x03\x00" + DUMMY_KEY
    error = decode_error(data)
    assert error.safe_detail == "length mismatch on NETWORK_KEY; layout 18 B: 03/1, 16 B withheld"
    assert_key_free(str(error))
    for leak in ("A1", "a1", "163", "0xA1"):
        assert leak not in str(error)


def test_wide_device_type_swallowing_the_key_header_withholds_the_rest() -> None:
    """Codex's counterexample: 0x05 declares 16 bytes, swallows ``03 0F`` and 13 key bytes;
    the leftover key bytes ``0A 00 AF`` would parse as a NETWORK_STATUS_MAP TLV."""
    data = bytes.fromhex("050F01030FA0A1A2A3A4A5A6A7A8A9AAAB" + "AC0A00AF")  # secret-scan: allow
    assert len(data) == 21
    error = decode_error(data)
    assert error.safe_detail == "length mismatch on DEVICE_TYPE; layout 21 B: 05/16, 19 B withheld"
    for leak in ("0A/1", "0a", "AF", "af"):
        assert leak not in str(error)
    assert shown_headers(str(error)) == [(0x05, 0x0F)]


def test_channel_length_swallowing_the_key_header_withholds_the_rest() -> None:
    channel = bytearray(_channel())
    channel[1] += 2 + 3  # swallow "03 0F" and 3 key bytes: the rest of the key would be headers
    data = bytes(channel) + _tlv(0x03, DUMMY_KEY) + _tlv(0x05, b"\x01\x00\x00\x00")
    error = decode_error(data)
    assert error.safe_detail == "unverified channel layout; layout 31 B: 02/10, 29 B withheld"
    assert_key_free(str(error))


def test_channel_count_agreeing_with_a_lying_length_withholds_the_rest() -> None:
    """Codex's second counterexample: 0x02 claims 17 B with count 4 (they agree), but only one
    mask is on the wire; ``0A 00`` and ``AD AE`` are key bytes that would parse as headers."""
    data = bytes.fromhex(  # secret-scan: allow
        "0210040080000003" + "0FA0A1A2A3A4A5A6A7A8A9" + "0A00ACADAEAF"  # secret-scan: allow
    )
    assert len(data) == 25
    error = decode_error(data)
    assert error.safe_detail == "unverified channel layout; layout 25 B: 02/17, 23 B withheld"
    for leak in ("0A/1", "AD/175", "0A", "AD", "ad"):
        assert leak not in str(error)
    assert shown_headers(str(error)) == [(0x02, 0x10)]


@pytest.mark.parametrize(
    ("value", "layout"),
    [
        (b"\x02" + b"\x00" * 8, "14 B: 02/9"),  # two masks: consistent, still unverified
        (b"\x04" + b"\x00" * 16, "22 B: 02/17"),
        (b"\x02" + b"\x00" * 4, "10 B: 02/5"),  # right length, wrong count
    ],
)
def test_non_single_page_channel_is_unverified(value: bytes, layout: str) -> None:
    fault, shown = safe_status_layout(_tlv(0x02, value) + _tlv(0x05, b"\x01"))
    assert fault == "unverified channel layout"
    assert shown == f"{layout}, {len(value) + 3} B withheld"


def test_live_status_layout_is_fully_verified() -> None:
    """The R0's 4-byte 0x05 is in the schema: the whole live chain verifies and decodes."""
    data = live_like_status()
    assert len(data) == 60
    assert safe_status_layout(data) == (None, LIVE_LAYOUT)
    assert CommissioningStatus.decode(data).deviations == ((0x05, 4),)


def test_live_status_with_an_unknown_tag_decodes_and_stops_the_layout() -> None:
    data = live_like_status() + _tlv(0x42, b"\x01")
    assert CommissioningStatus.decode(data).unknown == (Tlv(0x42, b"\x01"),)
    assert safe_status_layout(data) == (
        "unknown tag 0x42",
        f"63 B: {LIVE_LAYOUT[6:]} 42/1, 1 B withheld",
    )


def test_correct_key_tlvs_before_a_wide_device_type_show_their_headers() -> None:
    data = b"".join(
        (
            _tlv(0x03, DUMMY_KEY),
            _tlv(0x04, b"\x01" + DUMMY_KEY),
            _tlv(0x05, b"\x01\x00"),
            _tlv(0x0D, DUMMY_KEY),
        )
    )
    error = decode_error(data)
    assert error.safe_detail == (
        "length mismatch on DEVICE_TYPE; layout 59 B: 03/16 04/17 05/2, 20 B withheld"
    )
    assert_key_free(str(error))


@pytest.mark.parametrize(
    ("data", "detail"),
    [
        (
            _tlv(0x05, b"\x01\x00") + _tlv(0x06, b"\x01"),
            "length mismatch on DEVICE_TYPE; layout 7 B: 05/2, 5 B withheld",
        ),
        (
            _tlv(0x05, b"\x01") + _tlv(0x05, b"\x01"),
            "duplicate DEVICE_TYPE; layout 6 B: 05/1 05/1, 1 B withheld",
        ),
        (
            _tlv(0x03, DUMMY_KEY[:15]),
            "length mismatch on NETWORK_KEY; layout 17 B: 03/15, 15 B withheld",
        ),
        (_tlv(0x05, b"\x01") + b"\x06", "truncated TLV header; layout 4 B: 05/1, 1 B withheld"),
        (b"\x06\x01\x5a", "truncated NWK_ADDRESS; layout 3 B: 06/2, 1 B withheld"),
        (
            _tlv(0x42, b"\x01") + _tlv(0x05, b"\x01\x00"),
            "unknown tag 0x42; layout 7 B: 42/1, 5 B withheld",
        ),
    ],
)
def test_first_unverified_header_cuts_the_layout(data: bytes, detail: str) -> None:
    assert decode_error(data).safe_detail == detail


def test_unknown_tag_alone_decodes_but_stops_the_layout() -> None:
    """Unknown tags decode (kept raw); its length is unverifiable, so nothing after it shows."""
    data = _tlv(0x05, b"\x01") + _tlv(0x42, b"\x01") + _tlv(0x06, b"\x01\x02")
    CommissioningStatus.decode(data)
    assert safe_status_layout(data) == ("unknown tag 0x42", "10 B: 05/1 42/1, 5 B withheld")


def test_well_formed_status_layout() -> None:
    data = _tlv(0x05, b"\x01") + _channel()
    assert safe_status_layout(data) == (None, "10 B: 05/1 02/5")


def test_lying_lengths_before_a_key_never_show_key_byte_pairs() -> None:
    """Property: a lying length on a random non-key tag (incl. 0x02 with an agreeing count)
    before NETWORK_KEY, for random keys, never shows a header ``(tag, len-1)`` equal to an
    adjacent byte pair of the key."""
    rng = random.Random(0x5EED)  # noqa: S311 - deterministic test data
    tail = _tlv(0x0A, b"\x12") + _tlv(0x0C, b"\x00")
    for _ in range(2000):
        prefix_tags = [(0x01, 2), (0x06, 2)][: rng.randint(0, 2)]
        prefix = b"".join(_tlv(t, rng.randbytes(n)) for t, n in prefix_tags)
        if rng.random() < 0.4:
            # a 0x02 lie: one real mask (5 B) on the wire, but a header claiming more; often the
            # count byte agrees with the claimed length (len 9 / count 2, len 17 / count 4, ...)
            tag = 0x02
            count = rng.randint(2, 63)
            value = bytes((count,)) + rng.randbytes(4)
            declared = 1 + 4 * count if rng.random() < 0.6 else rng.randint(6, 256)
        else:
            tag = rng.choice(sorted(NON_KEY_FIXED))
            value = rng.randbytes(NON_KEY_FIXED[tag])
            allowed = {len(value)} | VARIANT_LENGTHS.get(tag, set())
            declared = rng.choice([n for n in range(1, 257) if n not in allowed])
        real = [(t, n - 1) for t, n in prefix_tags] + [(tag, declared - 1)]
        key = rng.randbytes(16)
        while {(key[i], key[i + 1]) for i in range(15)} & set(real):  # a coincidence, not a leak
            key = rng.randbytes(16)
        data = prefix + bytes((tag, declared - 1)) + value + _tlv(0x03, key) + tail
        # decode may even succeed (a 0x02 lie swallowing to the end); the layout rule must hold
        _fault, detail = safe_status_layout(data)
        headers = shown_headers(detail)
        assert headers == real  # only real headers, nothing past the lying one
        assert not {(key[i], key[i + 1]) for i in range(15)} & set(headers)
        assert key.hex() not in detail.lower()


# --- GATT failure ATT code --------------------------------------------------------------------


class FakeBluetoothGATTError:
    """Shape of aioesphomeapi ``BluetoothGATTError``: an int ``error``."""

    def __init__(self, error: int) -> None:
        self.address = 0x112233445566
        self.handle = 12
        self.error = error


class FakeBluetoothGATTAPIError(Exception):
    """Shape of aioesphomeapi ``BluetoothGATTAPIError``: ``.error.error`` is the ATT code."""

    def __init__(self, error: int) -> None:
        super().__init__(f"Bluetooth GATT Error address=11:22 secret={DUMMY_KEY.hex()}")
        self.error = FakeBluetoothGATTError(error)


def esphome_failure(code: int) -> BleakError:
    """bleak-esphome: ``raise BleakError(str(ex)) from ex``."""
    inner = FakeBluetoothGATTAPIError(code)
    outer = BleakError(str(inner))
    outer.__cause__ = inner
    return outer


@pytest.mark.parametrize("code", [0x02, 0x05, 0x0E])
def test_esphome_gatt_failure_names_the_att_code(code: int) -> None:
    error = gatt_failure(esphome_failure(code), "Commissioning Status read")
    assert str(error) == f"Commissioning Status read failed: BleakError (ATT 0x{code:02X})"
    assert error.reason == "write"
    assert_key_free(str(error))


def test_bleak_protocol_error_names_the_att_code() -> None:
    error = gatt_failure(BleakGATTProtocolError(0x05), "SE3 write")
    assert str(error) == "SE3 write failed: BleakGATTProtocolError (ATT 0x05)"


def test_gatt_failure_without_a_code_names_only_the_type() -> None:
    error = gatt_failure(BleakError(f"Not connected {DUMMY_KEY.hex()}"), "read")
    assert str(error) == "read failed: BleakError"


def test_gatt_failure_code_out_of_range_is_dropped() -> None:
    error = gatt_failure(esphome_failure(0x1FF), "read")
    assert str(error) == "read failed: BleakError"


def test_gatt_failure_chain_walk_is_bounded() -> None:
    inner: BaseException = FakeBluetoothGATTAPIError(0x05)
    for _ in range(6):
        outer = BleakError("wrapped")
        outer.__cause__ = inner
        inner = outer
    assert str(gatt_failure(inner, "read")) == "read failed: BleakError"
