"""Tests for scripts/extract_npdu_fixtures.py (synthetic log text only)."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType


def _load() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "scripts" / "extract_npdu_fixtures.py"
    spec = importlib.util.spec_from_file_location("extract_npdu_fixtures", path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ex = _load()

KEY_LIKE = "00112233445566778899aabbccddeeff"  # secret-scan: allow
LOG = f"""Gevonden: Dummy @ 00:00:00:00:00:00
Commissioning Status ontsleuteld (20 bytes):
  tag 0x00 trust-center-eui64 (?): 00:00:00:00:00:00:00:01
  tag 0x0c status-flags-c (?): {KEY_LIKE}
  [tunnel] onparseerbaar NWK-frame: 0102030405
  [tunnel] NWK frame: type=1 src=0x0000 dst=0x1234 cmd=0x01
  resterende bytes: aabb
  [zdo] APS cluster 0x8005 van 0xABCD (3 bytes)
  [zdo] APS cluster 0x8031 van 0xABCD: 00cdab01
  [dbg] NWK cmd van 0x0000: 0108ff
  [dbg] frame van 0xABCD (dst 0x0000, 4B): 11223344
random {KEY_LIKE} noise
"""


def run(
    text: str, euis: tuple[str, ...] = (), shorts: tuple[str, ...] = ()
) -> tuple[list[dict[str, str | None]], int]:
    pairs = ex.build_replacements(
        [ex.parse_eui(e) for e in euis], [ex.parse_short(s) for s in shorts]
    )
    return ex.extract(text.splitlines(), pairs)  # type: ignore[no-any-return]


def test_extracts_known_patterns() -> None:
    recs, _ = run(LOG)
    assert [(r["kind"], r["src_short"], r["hex"]) for r in recs] == [
        ("nwk_frame_unparsed", None, "0102030405"),
        ("commissioning_response_rest", None, "aabb"),
        ("aps_payload", "0xABCD", "00cdab01"),
        ("nwk_command", "0x0000", "0108ff"),
        ("nwk_payload", "0xABCD", "11223344"),
    ]


def test_commissioning_status_dump_excluded_and_16_byte_dropped() -> None:
    recs, dropped = run(LOG)
    assert all(KEY_LIKE not in str(r["hex"]) for r in recs)
    assert all("tag" not in str(r) for r in recs)
    assert dropped == 2  # the key-like status line and the noise line


def test_redact_eui_both_endiannesses() -> None:
    eui = "AA:BB:CC:DD:EE:FF:00:11"
    be = bytes.fromhex("aabbccddeeff0011")
    text = f"  [dbg] NWK cmd van 0x0001: 01{be.hex()}02{be[::-1].hex()}\n"
    recs, _ = run(text, euis=(eui,))
    out = str(recs[0]["hex"])
    assert be.hex() not in out
    assert be[::-1].hex() not in out
    assert out == "01" + "0200000000000001" + "02" + "0100000000000002"


def test_redact_short_le() -> None:
    recs, _ = run(LOG, shorts=("0xABCD",))
    assert recs[2]["hex"] == "00" + "015a" + "01"
    assert recs[2]["src_short"] == "0x5A01"


def test_parse_eui_rejects_bad() -> None:
    with pytest.raises(ValueError, match="8 colon"):
        ex.parse_eui("01:02")


def test_refuses_viessmann_local(tmp_path: Path) -> None:
    d = tmp_path / ".Viessmann-Local"
    d.mkdir()
    f = d / "log.txt"
    f.write_text("x")
    with pytest.raises(PermissionError):
        ex.read_input(str(f))
    assert ex.main([str(f)]) == 2


def test_refuses_large_file(tmp_path: Path) -> None:
    f = tmp_path / "big.txt"
    f.write_bytes(b"a" * (ex.MAX_BYTES + 1))
    assert ex.main([str(f)]) == 2


def test_main_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "log.txt"
    f.write_text(LOG)
    assert ex.main([str(f)]) == 0
    cap = capsys.readouterr()
    rows = [json.loads(line) for line in cap.out.splitlines()]
    assert len(rows) == 5
    assert set(rows[0]) == {"kind", "src_short", "hex"}
    assert "best-effort" in cap.err


def test_stdin() -> None:
    lines = ex.read_input("-", io.StringIO("a\nb\n"))
    assert lines == ["a", "b"]
