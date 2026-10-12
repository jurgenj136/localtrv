"""Fail if a file contains what looks like key material.

Flags (case-insensitive):

- a run of 32+ hex characters;
- 16 hex byte pairs with one consistent single-space or colon separator
  (``aa bb cc ...``, ``aa:bb:cc:...``); a trailing hex digit does not prevent
  a match, so two keys glued together are still caught;
- a ``fromhex("...")`` / ``unhex("...")`` literal holding 32+ hex digits once
  whitespace is removed (catches irregular spacing).

Best-effort heuristics, not a guarantee. A line containing ``# secret-scan: allow``
is skipped (for public spec test vectors and obvious dummies); the marker must be
on the flagged line itself.
Usage: ``check_secrets.py FILE...``; binary and unreadable files are skipped.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOW_MARKER = "secret-scan: allow"
MIN_HEX_DIGITS = 32  # 16 bytes / 128-bit key
HEX_RUN = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32,}(?![0-9a-f])")
SEPARATED_16 = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{2}([ :])(?:[0-9a-f]{2}\1){14}[0-9a-f]{2}")
HEX_LITERAL = re.compile(r"""(?i)\b(?:fromhex|unhex)\(\s*[rb]?(["'])([0-9a-f\s:]*)\1""")
WHITESPACE = re.compile(r"[\s:]")
SELF = Path(__file__).resolve()


def suspicious(line: str) -> bool:
    """True if ``line`` looks like it holds 16+ bytes of hex key material."""
    if ALLOW_MARKER in line:
        return False
    if HEX_RUN.search(line) or SEPARATED_16.search(line):
        return True
    return any(
        len(WHITESPACE.sub("", m.group(2))) >= MIN_HEX_DIGITS for m in HEX_LITERAL.finditer(line)
    )


def scan(path: Path) -> list[int]:
    """Return 1-based line numbers with suspicious content."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError, UnicodeDecodeError:
        return []
    return [n for n, line in enumerate(text.splitlines(), start=1) if suspicious(line)]


def main(argv: list[str]) -> int:
    failed = False
    for name in argv:
        path = Path(name)
        if not path.is_file() or path.resolve() == SELF or path.name == "uv.lock":
            continue
        for lineno in scan(path):
            print(f"{path}:{lineno}: possible key material (add '# {ALLOW_MARKER}' if public)")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
