"""Fail if a file contains what looks like key material.

Flags a run of 32+ hex characters, or a 16-byte colon-separated hex string.
A line containing ``# secret-scan: allow`` is skipped (for public spec test vectors).
Usage: ``check_secrets.py FILE...``; binary and unreadable files are skipped.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOW_MARKER = "secret-scan: allow"
HEX_RUN = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32,}(?![0-9a-f])")
COLON_16 = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{2}:){15}[0-9a-f]{2}(?![0-9a-f:])")
SELF = Path(__file__).resolve()


def scan(path: Path) -> list[int]:
    """Return 1-based line numbers with suspicious content."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return [
        n
        for n, line in enumerate(text.splitlines(), start=1)
        if ALLOW_MARKER not in line and (HEX_RUN.search(line) or COLON_16.search(line))
    ]


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
