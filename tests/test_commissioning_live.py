"""The live ubisys R0 Commissioning Status layout: 0x05 is 4 bytes, tag order is not spec order.

Hardware (2026-10): ``08/8 0A/1 00/8 01/2 02/5 05/4 06/2 09/8 0B/1 0C/1`` = 60 B, no key TLVs.
"""

from __future__ import annotations

import logging

import pytest

from localtrv.testing.gatt_services import status_value
from localtrv.zigbee_direct.codec.commissioning import (
    ChannelMask,
    CommissioningStatus,
    JoinedStatus,
    safe_status_layout,
)
from localtrv.zigbee_direct.codec.tlv import Tlv
from localtrv.zigbee_direct.errors import CommissioningDecodeError
from localtrv.zigbee_direct.node_types import NetworkSummary
from localtrv.zigbee_direct.types import Eui64, SecretBytes
from test_connection import make_rig, start, stop

ZDD_EUI = Eui64.from_str("02:00:00:00:00:00:00:02")
EXT_PAN = Eui64.from_str("DD:DD:DD:DD:DD:DD:DD:01")
TC_EUI = Eui64.from_str("02:00:00:00:00:00:00:00")
NETWORK_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")  # secret-scan: allow
ADMIN_KEY = bytes.fromhex("ffeeddccbbaa99887766554433221100")  # secret-scan: allow
#: The hardware error's layout prefix: everything up to and including the 4-byte 0x05.
LIVE_PREFIX = "08/8 0A/1 00/8 01/2 02/5 05/4"
#: The full live layout: with 0x05/4 in the schema, every header verifies.
LIVE_LAYOUT = f"{LIVE_PREFIX} 06/2 09/8 0B/1 0C/1"


def _tlv(tag: int, value: bytes) -> bytes:
    return Tlv(tag, value).encode()


def assert_fatal(data: bytes, detail: str) -> None:
    with pytest.raises(CommissioningDecodeError) as exc:
        CommissioningStatus.decode(data)
    assert exc.value.safe_detail == detail
    assert str(exc.value) == f"commissioning status: {detail}"
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


def _live_head() -> bytes:
    """08/8 0A/1 00/8 01/2 02/5 05/4: what the hardware error showed before the withheld part."""
    return b"".join(
        (
            _tlv(0x08, ZDD_EUI.wire),
            _tlv(0x0A, b"\x12"),
            _tlv(0x00, EXT_PAN.wire),
            _tlv(0x01, b"\xcd\xab"),
            _tlv(0x02, b"\x01" + (1 << 15).to_bytes(4, "little")),
            _tlv(0x05, b"\x01\x00\x00\x00"),
        )
    )


def live_status() -> bytes:
    tail = _tlv(0x06, b"\x5a\x5a") + _tlv(0x09, TC_EUI.wire) + _tlv(0x0B, b"\x03")
    return _live_head() + tail + _tlv(0x0C, b"\x00")


def test_live_layout_decodes() -> None:
    data = live_status()
    assert len(data) == 60
    status = CommissioningStatus.decode(data)
    assert status.ieee_address == ZDD_EUI
    assert status.nwk_address == 0x5A5A
    assert status.pan_id == 0xABCD
    assert status.extended_pan_id == EXT_PAN
    assert status.trust_center_address == TC_EUI
    assert status.joined_status == JoinedStatus.JOINED
    assert status.centralized is True
    assert status.nwk_update_id == 3
    assert status.active_key_seq == 0
    assert status.channel_masks == (ChannelMask(page=0, mask=1 << 15),)
    assert status.device_type is None
    assert status.deviations == ((0x05, 4),)
    assert status.network_key is None
    assert status.link_key is None
    assert status.admin_key is None
    summary = NetworkSummary.from_status(status)
    assert summary.status_deviations == ((0x05, 4),)
    assert summary.device_type is None
    assert summary.pan_id == 0xABCD
    assert summary.joined_status == JoinedStatus.JOINED
    # 05/4 is schema-matching: the whole chain verifies (the hardware error stopped there)
    assert safe_status_layout(data) == (None, f"60 B: {LIVE_LAYOUT}")


def test_simulator_live_layout_matches_the_hardware_bytes_shape() -> None:
    data = status_value(
        extended_pan_id=EXT_PAN,
        pan_id=0xABCD,
        network_key=SecretBytes(NETWORK_KEY),
        link_key=None,
        admin_key=None,
        zdd_short=0x5A5A,
        ieee=ZDD_EUI,
        trust_center_eui=TC_EUI,
        layout="r0_live",
    )
    assert len(data) == 60
    assert NETWORK_KEY not in data
    _fault, layout = safe_status_layout(data)
    assert layout == f"60 B: {LIVE_LAYOUT}"
    assert CommissioningStatus.decode(data).deviations == ((0x05, 4),)


def test_live_head_with_dummy_key_tlvs_decodes() -> None:
    """The live head + 06/2 + 03/16 + 0D/16 (24 B of key TLVs would not fit exactly)."""
    data = _live_head() + _tlv(0x06, b"\x5a\x5a") + _tlv(0x03, NETWORK_KEY) + _tlv(0x0D, ADMIN_KEY)
    status = CommissioningStatus.decode(data)
    assert isinstance(status.network_key, SecretBytes)
    assert isinstance(status.admin_key, SecretBytes)
    assert status.network_key.reveal() == NETWORK_KEY
    assert status.admin_key.reveal() == ADMIN_KEY
    assert status.deviations == ((0x05, 4),)
    assert status.nwk_address == 0x5A5A
    assert NETWORK_KEY.hex() not in repr(status)
    assert ADMIN_KEY.hex() not in repr(status)
    summary = NetworkSummary.from_status(status)
    assert NETWORK_KEY.hex() not in repr(summary)


@pytest.mark.parametrize(
    ("data", "detail"),
    [
        (
            _tlv(0x06, b"\x5a\x5a") + _tlv(0x03, NETWORK_KEY[:15]),
            "length mismatch on NETWORK_KEY; layout 21 B: 06/2 03/15, 15 B withheld",
        ),
        (
            _tlv(0x04, b"\x01" + NETWORK_KEY[:15]),
            "length mismatch on LINK_KEY; layout 18 B: 04/16, 16 B withheld",
        ),
        (
            _tlv(0x0D, NETWORK_KEY + b"\x00"),
            "length mismatch on ADMIN_KEY; layout 19 B: 0D/17, 17 B withheld",
        ),
        (
            _tlv(0x08, ZDD_EUI.wire) + _tlv(0x06, b"\x5a\x5a\x00"),
            "length mismatch on NWK_ADDRESS; layout 15 B: 08/8 06/3, 3 B withheld",
        ),
        (
            _tlv(0x06, b"\x5a\x5a") + _tlv(0x08, ZDD_EUI.wire[:7]),
            "length mismatch on IEEE_ADDRESS; layout 13 B: 06/2 08/7, 7 B withheld",
        ),
        (
            _tlv(0x0A, b"\x12") + _tlv(0x0A, b"\x12"),
            "duplicate NETWORK_STATUS_MAP; layout 6 B: 0A/1 0A/1, 1 B withheld",
        ),
        (
            _tlv(0x05, b"\x01\x00\x00\x00") + _tlv(0x05, b"\x01"),
            "duplicate DEVICE_TYPE; layout 9 B: 05/4 05/1, 1 B withheld",
        ),
        (b"\x06\x01\x5a", "truncated NWK_ADDRESS; layout 3 B: 06/2, 1 B withheld"),
        (
            live_status()[:-1],
            "truncated ACTIVE_KEY_SEQ; layout 59 B: " + LIVE_LAYOUT,
        ),
    ],
    ids=[
        "network-key",
        "link-key",
        "admin-key",
        "nwk-address",
        "ieee-address",
        "duplicate",
        "duplicate-device-type-variants",
        "truncated",
        "truncated-live",
    ],
)
def test_strict_cases_stay_fatal(data: bytes, detail: str) -> None:
    assert_fatal(data, detail)


@pytest.mark.parametrize(
    ("data", "detail"),
    [
        (
            _live_head()[:-6] + _tlv(0x05, b"\x01\x00"),
            "length mismatch on DEVICE_TYPE; layout 38 B: 08/8 0A/1 00/8 01/2 02/5 05/2, "
            "2 B withheld",
        ),
        (_tlv(0x05, bytes(3)), "length mismatch on DEVICE_TYPE; layout 5 B: 05/3, 3 B withheld"),
        (
            _tlv(0x05, bytes(16)),
            "length mismatch on DEVICE_TYPE; layout 18 B: 05/16, 16 B withheld",
        ),
    ],
    ids=["len-2", "len-3", "len-16"],
)
def test_device_type_outside_its_allowed_lengths_is_fatal(data: bytes, detail: str) -> None:
    assert_fatal(data, detail)


@pytest.mark.parametrize(
    ("tag", "length", "name"),
    [
        (0x00, 7, "EXTENDED_PAN_ID"),
        (0x01, 3, "PAN_ID"),
        (0x07, 2, "JOINING_METHOD"),
        (0x09, 9, "TRUST_CENTER_ADDRESS"),
        (0x0A, 2, "NETWORK_STATUS_MAP"),
        (0x0B, 2, "NWK_UPDATE_ID"),
        (0x0C, 4, "ACTIVE_KEY_SEQ"),
        (0x0E, 1, "STATUS_CODE"),
    ],
)
def test_informational_tag_with_a_wrong_length_is_fatal(tag: int, length: int, name: str) -> None:
    """Only 0x05 has a second allowed length; every other tag keeps exactly one."""
    assert_fatal(
        _tlv(tag, bytes(length)),
        f"length mismatch on {name}; layout {length + 2} B: {tag:02X}/{length}, "
        f"{length} B withheld",
    )


def test_schema_matching_header_with_a_short_value_is_out_of_scope() -> None:
    """Codex's counterexample, decoded honestly: 0x05 declares the allowed 4 bytes but the
    encoder wrote 1, so ``03 0F A0`` (a NETWORK_KEY header and a key byte) is swallowed and the
    remaining (dummy) key bytes parse as a schema-matching 06/2, 01/2 and 02/5. Nothing can
    detect this: a schema-matching header with a value of another size is the documented
    out-of-scope class (``safe_status_layout``), the same one that already existed for every
    single-length tag. It decodes, and key bytes land in typed fields."""
    data = bytes.fromhex(  # secret-scan: allow
        "08070200000000000002" + "050301" + "030fa0" + "06013412" + "01017856" + "02040100800000"
    )
    status = CommissioningStatus.decode(data)
    assert status.deviations == ((0x05, 4),)
    assert status.network_key is None  # its header was swallowed into the 0x05 value
    assert status.nwk_address == 0x1234  # key bytes
    assert status.pan_id == 0x5678  # key bytes
    assert status.channel_masks == (ChannelMask(page=0, mask=1 << 15),)  # key bytes
    assert safe_status_layout(data) == (None, "31 B: 08/8 05/4 06/2 01/2 02/5")


async def test_full_join_with_the_live_layout(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    r = make_rig()
    r.inst.r0.status_layout = "r0_live"
    gen = await start(r)
    assert gen.number == 1
    network = gen.join.network
    assert network.status_deviations == ((0x05, 4),)
    assert network.device_type is None
    assert network.pan_id is not None
    assert network.channel_masks == (ChannelMask(page=0, mask=1 << 15),)
    assert gen.join.zdd_short == r.inst.r0.zdd_short
    lines = [rec.getMessage() for rec in caplog.records if "deviates" in rec.getMessage()]
    assert lines == ["Commissioning Status deviates from ZD 1.0: tag 0x05 len 4"]
    assert [rec.levelno for rec in caplog.records if "deviates" in rec.getMessage()] == [
        logging.INFO
    ]
    assert r.inst.network_key.reveal().hex() not in caplog.text
    await stop(r)
