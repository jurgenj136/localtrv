"""NPDU recorder: log line, ring buffer, secret suppression, header-only frames, no raising.

Dummy keys and EUIs only (spec §1.8, §6 T5).
"""

from __future__ import annotations

import json
import logging

import pytest

from fixtures import golden as g
from vicare_local_ble.zigbee_direct import debug, redact
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord, ReadAttributeStatus
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.debug import (
    NPDU_LOGGER,
    SECURITY_TYPES,
    EuiPseudonymizer,
    NpduRecord,
    NpduRecorder,
    RedactedNpdu,
    format_log_line,
    is_security_type,
    redact_npdu,
    sanitize_records,
)
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

h = g.h

#: Distinct dummy key used only to prove it never reaches a log line or the ring buffer.
DUMMY_KEY = bytes.fromhex("D15C0DE0112233445566778899AABBCC")  # secret-scan: allow
KEY = DUMMY_KEY.hex()
EUI_A = Eui64.from_str("AC:DE:48:00:00:00:00:0A")
A = EUI_A.wire.hex()

NWK_DATA = "08 00 34 12 6F 5E 1E 40"
APS_HA = "00 01 01 02 04 01 01 2B"

#: APS command frame (FC 0x01): counter, Transport Key (0x05), key type, key, EUIs.
APS_COMMAND = h("08 00 34 12 00 00 1E 10", "01 22 05 01", KEY, A, A)
#: ZCL Read Attributes Response carrying a KEY128 (0xF1) value.
ZCL_KEY_RSP = h(NWK_DATA, APS_HA, "18 2B 01", "00 00 00 F1", KEY)
#: ZCL Write Attributes (tx direction) with a KEY128 value next to a harmless record.
ZCL_KEY_WRITE = h(NWK_DATA, APS_HA, "00 2D 02", "12 00 29 66 08", "00 00 F1", KEY)
#: Cluster-specific ZCL command (FC 0x01) with the key in its opaque payload.
ZCL_CLUSTER_SPECIFIC_KEY = h(NWK_DATA, APS_HA, "01 2B 00", KEY)
#: Commissioning Response with a TLV outside the allowlist (0x45 symmetric passphrase).
COMMISSIONING_RSP_PASSPHRASE = h("09 08 34 12 1B 2A 1E 05", A, "0F 34 12 00", "45 0F", KEY)
#: Route commands followed by the same 0x45 TLV: the tail is never decoded by the codecs.
NWK_CMD = "09 00 34 12 6F 5E 1E 41"
NETWORK_STATUS_TLV = h(NWK_CMD, "03 0B 34 12", "45 0F", KEY)
RREQ_TLV = h(NWK_CMD, "01 20 07 34 12 00", A, "45 0F", KEY)
RREP_LIVE_TLV = h(NWK_CMD, "02 20 07 6F 5E 34 12 00", A, "45 0F", KEY)
RREP_LIVE_KEY_AS_EUIS = h(NWK_CMD, "02 20 07 6F 5E 34 12 00", A, KEY)  # 16-byte tail
ROUTE_RECORD_TLV = h(NWK_CMD, "05 01 6F 5E", "45 0F", KEY)
LINK_STATUS_TLV = h(NWK_CMD, "08 61 6F 5E 11", "45 0F", KEY)
#: A data-frame APS ack must decode exactly: a key behind it is never logged.
APS_ACK_TAIL = h(NWK_DATA, "02 01 01 02 04 01 01 2B", KEY)

SECRET_FRAMES = {
    "aps_command": APS_COMMAND,
    "zcl_secret_rsp": ZCL_KEY_RSP,
    "zcl_secret_write": ZCL_KEY_WRITE,
    "commissioning_unknown_tlv": COMMISSIONING_RSP_PASSPHRASE,
    "zcl_cluster_specific": ZCL_CLUSTER_SPECIFIC_KEY,
    "network_status_tail": NETWORK_STATUS_TLV,
    "rreq_tail": RREQ_TLV,
    "rrep_tail": RREP_LIVE_TLV,
    "rrep_tail_multiple_of_8": RREP_LIVE_KEY_AS_EUIS,
    "route_record_tail": ROUTE_RECORD_TLV,
    "link_status_tail": LINK_STATUS_TLV,
    "aps_ack_tail": APS_ACK_TAIL,
}


def key_forms() -> list[str]:
    out = []
    for raw in (DUMMY_KEY, DUMMY_KEY[::-1]):
        out += [raw.hex(), raw.hex().upper(), raw.hex(" "), raw.hex(":").upper()]
    # Any 8-byte window of the key is already too much.
    out += [DUMMY_KEY[i : i + 8].hex() for i in range(len(DUMMY_KEY) - 7)]
    return out


@pytest.fixture
def npdu_debug(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG, logger=NPDU_LOGGER)
    return caplog


def tunnel(frame: bytes, *, secure: bool = True) -> TunnelNpdu:
    return TunnelNpdu(frame, nwk_security=secure)


# --- log line and ring buffer ------------------------------------------------------------------


def test_log_line_format(npdu_debug: pytest.LogCaptureFixture) -> None:
    clock = VirtualClock(start=12.3456)
    rec = NpduRecorder(clock=clock)
    rec.rx(tunnel(g.ZCL_READ_RSP))
    rec.tx(tunnel(g.ZCL_READ, secure=False))
    lines = [r.getMessage() for r in npdu_debug.records if r.name == NPDU_LOGGER]
    assert lines == [
        f'NPDU {{"dir":"rx","flags":1,"hex":"{g.ZCL_READ_RSP.hex()}","t":12.346}}',
        f'NPDU {{"dir":"tx","flags":0,"hex":"{g.ZCL_READ.hex()}","t":12.346}}',
    ]
    assert all(r.levelno == logging.DEBUG for r in npdu_debug.records)
    assert [format_log_line(r) for r in rec.records()] == lines


def test_not_logged_above_debug_but_still_recorded(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=NPDU_LOGGER)
    rec = NpduRecorder()
    rec.rx(tunnel(g.ZCL_READ_RSP))
    assert not [r for r in caplog.records if r.name == NPDU_LOGGER]
    assert len(rec.records()) == 1
    assert rec.records()[0].t > 0  # time.monotonic() without a clock


def test_ring_buffer_is_bounded_oldest_first_and_clear_keeps_pseudonyms() -> None:
    rec = NpduRecorder(maxlen=3)
    for seq in range(5):
        frame = bytearray(g.ZCL_READ)
        frame[7] = seq
        rec.tx(tunnel(bytes(frame)))
    assert [r.npdu.hex[14:16] for r in rec.records() if r.npdu.hex] == ["02", "03", "04"]
    rec.rx(tunnel(g.DEVICE_ANNCE))
    before = rec.pseudonyms.eui(g.ZVD_EUI)
    rec.clear()
    assert rec.records() == ()
    assert rec.pseudonyms.eui(g.ZVD_EUI) == before


@pytest.mark.parametrize("bad", [-1, True, 1.5])
def test_maxlen_validated(bad: object) -> None:
    with pytest.raises(ValueError, match="maxlen"):
        NpduRecorder(maxlen=bad)  # type: ignore[arg-type]


def test_custom_logger() -> None:
    seen: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    logger = logging.getLogger("test.npdu.custom")
    logger.setLevel(logging.DEBUG)
    handler = Capture()
    logger.addHandler(handler)
    try:
        NpduRecorder(logger=logger).rx(tunnel(g.MTORR))
    finally:
        logger.removeHandler(handler)
    assert len(seen) == 1
    assert seen[0].startswith('NPDU {"dir":"rx"')


def test_record_json_for_suppressed_frames() -> None:
    header = RedactedNpdu(length=12, redacted="undecodable", nwk_header_hex="0900")
    rec = NpduRecord("rx", 0, float("nan"), header)
    assert rec.to_json() == (
        '{"dir":"rx","flags":0,"len":12,"nwk_header":"0900","redacted":"undecodable","t":0.0}'
    )
    cmd = NpduRecord("tx", 1, 1.0, RedactedNpdu(length=9, redacted="aps_command"))
    assert json.loads(cmd.to_json()) == {
        "dir": "tx",
        "flags": 1,
        "len": 9,
        "redacted": "aps_command",
        "t": 1.0,
    }


# --- secret sanitising -----------------------------------------------------------------------


def test_security_types() -> None:
    assert ZclDataType.KEY128 in SECURITY_TYPES
    assert is_security_type(0xF1)
    assert is_security_type(ZclDataType.KEY128)
    assert not is_security_type(ZclDataType.EUI64)
    assert not is_security_type(None)


def test_sanitize_records_replaces_only_security_values() -> None:
    plain = AttributeRecord(0x0012, ZclDataType.INT16, 2150)
    secret = AttributeRecord(0x0000, ZclDataType.KEY128, SecretBytes(DUMMY_KEY))
    out = sanitize_records([plain, secret])
    assert out[0] is plain
    assert isinstance(out[1].value, SecretBytes)
    assert out[1].value.reveal() == bytes(16)
    assert out[1].attribute_id == 0x0000
    assert KEY not in repr(out)

    status = (
        ReadAttributeStatus(0x0000, 0x86),
        ReadAttributeStatus(0x0001, 0x00, ZclDataType.KEY128, SecretBytes(DUMMY_KEY)),
        ReadAttributeStatus(0x0002, 0x00, ZclDataType.KEY128, None),
    )
    out2 = sanitize_records(status)
    assert out2[0] is status[0]
    assert out2[1].value == SecretBytes(bytes(16))
    assert out2[2].value == SecretBytes(bytes(16))
    assert sanitize_records(()) == ()


@pytest.mark.parametrize("name", sorted(SECRET_FRAMES))
def test_secret_frames_never_reach_log_or_ring(
    name: str, npdu_debug: pytest.LogCaptureFixture
) -> None:
    rec = NpduRecorder()
    frame = SECRET_FRAMES[name]
    rec.rx(tunnel(frame))
    rec.tx(tunnel(frame))
    ring = "\n".join(r.to_json() + repr(r) for r in rec.records())
    text = npdu_debug.text + "\n".join(r.getMessage() for r in npdu_debug.records)
    for form in key_forms():
        assert form not in ring, form
        assert form.lower() not in text.lower(), form
    assert all(r.npdu.hex is None for r in rec.records())


def test_aps_command_suppressed() -> None:
    out = redact_npdu(APS_COMMAND, EuiPseudonymizer())
    assert out == RedactedNpdu(length=len(APS_COMMAND), redacted="aps_command")


def test_key128_suppressed() -> None:
    for frame in (ZCL_KEY_RSP, ZCL_KEY_WRITE):
        assert redact_npdu(frame, EuiPseudonymizer()) == RedactedNpdu(
            length=len(frame), redacted="zcl_secret"
        )


def test_fallback_scan_never_accepts_cluster_specific_candidate() -> None:
    # Garbled header (profile 0x0100); the only frame at the scan offsets is cluster-specific
    # (FC 0x01 at offset 12). Without the GLOBAL rule this would be logged with the key.
    garbled = h("08 02 34 12 6F 5E 1E 38", "00 5A 5A 00", APS_HA, "01 2B 00", KEY)
    assert redact.inspect_npdu(garbled).verdict == "undecodable"
    out = redact_npdu(garbled, EuiPseudonymizer())
    assert out.hex is None
    assert out.nwk_header_hex == h("08 02 34 12 6F 5E 1E 38").hex()
    assert KEY not in repr(out)


def test_key128_found_through_fallback_scan_is_suppressed() -> None:
    garbled = h("08 02 34 12 6F 5E 1E 38", "00 5A 5A 00", APS_HA, "18 2B 01 00 00 00 F1", KEY)
    assert redact_npdu(garbled, EuiPseudonymizer()).redacted == "zcl_secret"


# --- undecodable frames: NWK header only -------------------------------------------------------

HEADER_ONLY = {
    # unsupported NWK command (Leave) with a src IEEE in the header
    "nwk_leave": (h("09 10 FD FF 34 12 1E 07", A, "04 00"), 16),
    # APS-secured data frame (payload is ciphertext)
    "aps_secured": (h(NWK_DATA, "20 01 01 02 04 01 01 2B", KEY), 8),
    # APS command ack (ack format 1: frame control + counter); data acks are logged (ok)
    "aps_command_ack": (h(NWK_DATA, "12 2B"), 8),
    # plausible ZDO frame with a cluster the decoders do not know (Bind_req, carries EUIs)
    "zdo_bind_req": (h(NWK_DATA, "00 00 21 00 00 00 00 07", "01", A, "01 01 02 03", A, "01"), 8),
    # IEEE_addr_rsp extended form (associated device list) is not decoded
    "ieee_addr_rsp_extended": (
        h(NWK_DATA, "00 00 01 80 00 00 00 07", "07 00", A, "6F 5E 01 00 34 12"),
        8,
    ),
    # unknown ZCL global command (Configure Reporting)
    "zcl_unknown_global": (h(NWK_DATA, APS_HA, "00 2B 06 00 00 00 29 01 00 10 0E 0A 00"), 8),
    # garbled APS header, nothing decodes at the scan offsets
    "quirk_no_candidate": (h(NWK_DATA, "00 5A 5A 00", APS_HA, "FF FF FF"), 8),
    # NWK data frame without payload, and a truncated APS header
    "empty_payload": (h(NWK_DATA), 8),
    "aps_truncated": (h(NWK_DATA, "00 01 01"), 8),
    # cluster-specific ZCL command: opaque payload (may hold key material)
    "zcl_cluster_specific": (ZCL_CLUSTER_SPECIFIC_KEY, 8),
    "zcl_cluster_specific_mfr": (h(NWK_DATA, APS_HA, "1D 21 12 2B 00", KEY), 8),
    # inter-PAN NWK frame type
    "inter_pan": (h("0B 00 34 12 6F 5E 1E 40", "00 11 22"), 8),
}


@pytest.mark.parametrize("name", sorted(HEADER_ONLY))
def test_undecodable_frames_logged_as_header_only(name: str) -> None:
    frame, header_len = HEADER_ONLY[name]
    p = EuiPseudonymizer()
    out = redact_npdu(frame, p)
    assert out.hex is None
    assert out.redacted == "undecodable"
    assert out.length == len(frame)
    assert out.nwk_header_hex is not None
    header = frame[:header_len]
    if EUI_A.wire in header:
        header = header.replace(EUI_A.wire, p.eui(EUI_A).wire)
    assert out.nwk_header_hex == header.hex()
    assert A not in repr(out)
    assert KEY not in repr(out)


def test_commissioning_unknown_tlv_is_header_only() -> None:
    p = EuiPseudonymizer()
    out = redact_npdu(COMMISSIONING_RSP_PASSPHRASE, p)
    assert out.redacted == "undecodable"
    assert out.nwk_header_hex == h("09 08 34 12 1B 2A 1E 05").hex() + p.eui(EUI_A).wire.hex()


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        h("08"),
        h("0A 00 34 12 6F 5E 1E 40 00"),  # reserved NWK frame type
        h("08 18 34 12 6F 5E 1E 40", A),  # truncated src IEEE
    ],
)
def test_nwk_undecodable_is_length_only(frame: bytes) -> None:
    assert redact_npdu(frame, EuiPseudonymizer()) == RedactedNpdu(
        length=len(frame), redacted="undecodable"
    )


@pytest.mark.parametrize(
    "frame",
    [NETWORK_STATUS_TLV, RREQ_TLV, RREP_LIVE_TLV, RREP_LIVE_KEY_AS_EUIS],
    ids=["network_status", "rreq", "rrep_live", "rrep_live_16"],
)
def test_route_command_tail_is_header_only(frame: bytes) -> None:
    p = EuiPseudonymizer()
    out = redact_npdu(frame, p)
    assert out == RedactedNpdu(
        length=len(frame), redacted="undecodable", nwk_header_hex=h(NWK_CMD).hex()
    )


def test_commissioning_malformed_tlvs_are_header_only() -> None:
    cases = [
        h("09 00 1B 2A 34 12 01 01", "0E 00 8E", "48 01 41 FF"),  # bad nested TLV
        h("09 00 1B 2A 34 12 01 01", "0E 00 8E", "41 03 01 00 02 03"),  # odd 0x41 length
        h("09 00 1B 2A 34 12 01 01", "0E 00 8E", "48 01 48 00"),  # nested, bad inner
    ]
    for frame in cases:
        assert redact_npdu(frame, EuiPseudonymizer()).redacted == "undecodable"
    ok = h("09 00 1B 2A 34 12 01 01", "0E 00 8E", "41 01 01 00", "46 01 00 00")
    assert redact_npdu(ok, EuiPseudonymizer()).hex == ok.hex()


def test_deeply_nested_encapsulation_is_header_only() -> None:
    inner = h("4C 01 01 00")
    for _ in range(12):
        inner = bytes((0x48, len(inner) - 1)) + inner
    frame = h("09 00 1B 2A 34 12 01 01", "0E 00 8E") + inner
    assert redact_npdu(frame, EuiPseudonymizer()).redacted == "undecodable"


# --- never raises ------------------------------------------------------------------------------


def test_redact_npdu_internal_error_is_length_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(npdu: bytes) -> redact.Inspection:
        raise RuntimeError(npdu.hex())

    monkeypatch.setattr(debug, "inspect_npdu", boom)
    out = redact_npdu(g.DEVICE_ANNCE, EuiPseudonymizer())
    assert out == RedactedNpdu(length=len(g.DEVICE_ANNCE), redacted="undecodable")


def test_redact_npdu_bad_input_is_length_only() -> None:
    assert redact_npdu(object(), EuiPseudonymizer()) == RedactedNpdu(  # type: ignore[arg-type]
        length=0, redacted="undecodable"
    )
    assert redact_npdu("zz", EuiPseudonymizer()) == RedactedNpdu(  # type: ignore[arg-type]
        length=2, redacted="undecodable"
    )


def test_walk_depth_guard() -> None:
    collector = redact._Collector()
    nested: object = EUI_A
    for _ in range(20):
        nested = (nested,)
    with pytest.raises(RecursionError):
        collector.walk(nested)


def test_recorder_never_raises(caplog: pytest.LogCaptureFixture) -> None:
    class BadClock(VirtualClock):
        def now(self) -> float:
            raise RuntimeError("clock")

    class BadLogger(logging.Logger):
        def isEnabledFor(self, level: int) -> bool:  # noqa: N802 - logging API name
            raise RuntimeError("logger")

    rec = NpduRecorder(clock=BadClock())
    rec.rx(tunnel(g.ZCL_READ_RSP))
    assert rec.records()[0].t == 0.0
    rec = NpduRecorder(logger=BadLogger("bad"))
    rec.rx(tunnel(g.ZCL_READ_RSP))
    rec.tx(object())  # type: ignore[arg-type]
    assert len(rec.records()) == 1
    assert not [r for r in caplog.records if r.levelno > logging.DEBUG]
