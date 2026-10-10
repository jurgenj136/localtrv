"""Tests for scripts/check_secrets.py. Key-like inputs are built at runtime so this
file itself stays clean for the scanner."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType


def _load() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "scripts" / "check_secrets.py"
    spec = importlib.util.spec_from_file_location("check_secrets", path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cs = _load()

PAIRS = [f"{0xA0 + i:02x}" for i in range(16)]  # 16 dummy bytes a0..af
MARK = "# " + "secret-scan: allow"


def spaced(n: int = 16, sep: str = " ") -> str:
    return sep.join(PAIRS[:n])


@pytest.mark.parametrize(
    "line",
    [
        "".join(PAIRS),
        "".join(PAIRS).upper(),
        spaced(),
        spaced().upper(),
        spaced(sep=":"),
        f'KEY = "{spaced()}"',
        # two 16-byte values glued together (no separator between halves)
        f'"{spaced(15)} {PAIRS[15]}{PAIRS[0]} {spaced(15)}"',
        f'k = bytes.fromhex("{spaced()}")',
        # irregular spacing / grouping inside a fromhex literal
        'k = bytes.fromhex("'
        + "  ".join("".join(PAIRS[i : i + 2]) for i in range(0, 16, 2))
        + '")',
        "k = unhex('" + "".join(PAIRS[:8]) + "   " + "".join(PAIRS[8:]) + "')",
    ],
)
def test_flags_key_like(line: str) -> None:
    assert cs.suspicious(line)
    assert not cs.suspicious(f"{line}  {MARK}")


@pytest.mark.parametrize(
    "line",
    [
        spaced(15),  # 15 bytes
        "".join(PAIRS)[:31],
        f'bytes.fromhex("{spaced(15)}")',
        # mixed separators are not one consistent run
        " ".join(PAIRS[:8]) + ":" + ":".join(PAIRS[8:]),
        # grouped frame layouts outside fromhex/unhex are not flagged
        'h("' + " ".join("".join(PAIRS[i : i + 2]) for i in range(0, 16, 2)) + '")',
        "uuid = 7072377d-0005-421c-b163-491c27333a61",
    ],
)
def test_ignores_non_key(line: str) -> None:
    assert not cs.suspicious(line)


def test_scan_and_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n")
    dirty = tmp_path / "dirty.py"
    dirty.write_text(f"ok = 1\nk = '{spaced()}'\nv = '{spaced()}'  {MARK}\n")
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\xff\xfe\x00")
    lock = tmp_path / "uv.lock"
    lock.write_text("".join(PAIRS) + "\n")

    assert cs.scan(dirty) == [2]
    assert cs.scan(binary) == []
    assert cs.main([str(clean), str(binary), str(lock), str(tmp_path / "missing")]) == 0
    assert cs.main([str(dirty)]) == 1
    assert "dirty.py:2" in capsys.readouterr().out
