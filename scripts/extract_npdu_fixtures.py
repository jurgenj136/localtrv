#!/usr/bin/env python3
"""Extract NPDU/payload hex from saved prototype-client output or a Home Assistant log.

Input is an explicit text file (or ``-`` for stdin) holding the stdout of the
earlier prototype client (not part of this repository). Only hex printed by these
known, Dutch-language line formats is extracted:

* ``[tunnel] onparseerbaar NWK-frame: <hex>``        nwk_frame_unparsed
* ``resterende bytes: <hex>``                         commissioning_response_rest
* ``[zdo] APS cluster 0xCCCC van 0xSSSS: <hex>``      aps_payload
* ``[dbg] NWK cmd van 0xSSSS: <hex>``                 nwk_command
* ``[dbg] frame van 0xSSSS (dst 0xDDDD, NB): <hex>``  nwk_payload

DELIBERATELY EXCLUDED: the Commissioning Status dump (``tag 0x.. name: <hex>``).
It prints raw TLV values, including unknown tags, and may carry network
key material. Lines of that shape are never matched.

Defensive: unrecognised lines containing a bare 16-byte (32 hex chars) blob are
dropped and counted, never emitted.

``--from-ha-log PATH`` instead reads the library's NPDU debug log (logger
``localtrv.npdu``): every line holding ``NPDU {json}`` after any HA log
prefix, or a bare JSON object (the ``grep NPDU home-assistant.log | cut -d' '
-f2-`` form). Records are already redacted by the recorder; suppressed ones
(``"redacted"``: APS command, ZCL secret, undecodable header-only) carry no
payload and are skipped and counted, as are malformed lines. Kind is
``npdu_rx`` / ``npdu_tx``; ``src_short`` is the NWK source from the header.

Output: JSON lines ``{"kind", "src_short", "hex"}`` on stdout, summary on
stderr. Refuses paths containing ``.viessmann-local`` and files over 5 MB.

REDACTION IS BEST-EFFORT, NOT A GUARANTEE. ``--redact-eui`` / ``--redact-short``
do byte-sequence replacement and can miss encodings or hit coincidental bytes.
Review the output manually before committing anything.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Final, TextIO

MAX_BYTES: Final = 5 * 1024 * 1024
FORBIDDEN_PART: Final = ".viessmann-local"
_HEX: Final = r"(?P<hex>(?:[0-9a-fA-F]{2})+)"

# (kind, regex). Group names: hex (required), src (optional short).
PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "nwk_frame_unparsed",
        re.compile(rf"\[tunnel\] onparseerbaar NWK-frame: {_HEX}\s*$"),
    ),
    (
        "commissioning_response_rest",
        re.compile(rf"^\s*resterende bytes: {_HEX}\s*$"),
    ),
    (
        "aps_payload",
        re.compile(
            rf"\[zdo\] APS cluster 0x[0-9A-Fa-f]{{4}} van 0x(?P<src>[0-9A-Fa-f]{{4}}): {_HEX}\s*$"
        ),
    ),
    (
        "nwk_command",
        re.compile(rf"\[dbg\] NWK cmd van 0x(?P<src>[0-9A-Fa-f]{{4}}): {_HEX}\s*$"),
    ),
    (
        "nwk_payload",
        re.compile(
            r"\[dbg\] frame van 0x(?P<src>[0-9A-Fa-f]{4}) "
            rf"\(dst 0x[0-9A-Fa-f]{{4}}, \d+B\): {_HEX}\s*$"
        ),
    ),
)
_NPDU_LINE: Final = re.compile(r"(?:^|\s)NPDU (?P<json>\{.*\})\s*$")
_BARE_JSON: Final = re.compile(r"^\s*(?P<json>\{.*\})\s*$")
_HEX_ONLY: Final = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
NWK_HEADER_MIN_LEN: Final = 8
_BARE_16: Final = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16}(?![0-9A-Fa-f])")


def parse_eui(text: str) -> bytes:
    """Parse ``XX:XX:...`` (big-endian display form) into 8 bytes."""
    parts = text.replace("-", ":").split(":")
    if len(parts) != 8 or any(len(p) != 2 for p in parts):
        raise ValueError(f"EUI must be 8 colon-separated bytes: {text!r}")
    return bytes(int(p, 16) for p in parts)


def parse_short(text: str) -> int:
    value = int(text, 16)
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"short address out of range: {text!r}")
    return value


def build_replacements(euis: list[bytes], shorts: list[int]) -> list[tuple[bytes, bytes]]:
    """Byte-sequence replacement pairs; EUIs first (longer), then shorts."""
    pairs: list[tuple[bytes, bytes]] = []
    for n, eui in enumerate(euis, start=1):
        dummy = bytes([0x02, 0, 0, 0, 0, 0, 0, n])
        pairs.append((eui, dummy))  # big-endian display order
        pairs.append((eui[::-1], dummy[::-1]))  # little-endian wire order
    for n, short in enumerate(shorts, start=1):
        pairs.append(((short).to_bytes(2, "little"), (0x5A00 + n).to_bytes(2, "little")))
    return pairs


def redact(data: bytes, pairs: list[tuple[bytes, bytes]]) -> bytes:
    """Best-effort replacement. Not a guarantee."""
    for old, new in pairs:
        data = data.replace(old, new)
    return data


def extract(
    lines: list[str], pairs: list[tuple[bytes, bytes]]
) -> tuple[list[dict[str, str | None]], int]:
    """Return (records, count of unrecognised lines dropped for a bare 16-byte blob)."""
    records: list[dict[str, str | None]] = []
    dropped = 0
    for line in lines:
        for kind, pattern in PATTERNS:
            m = pattern.search(line)
            if m is None:
                continue
            raw = redact(bytes.fromhex(m.group("hex")), pairs)
            src = m.groupdict().get("src")
            src_text: str | None = None
            if src is not None:
                src_val = int.from_bytes(
                    redact(int(src, 16).to_bytes(2, "little"), pairs), "little"
                )
                src_text = f"0x{src_val:04X}"
            records.append({"kind": kind, "src_short": src_text, "hex": raw.hex()})
            break
        else:
            if _BARE_16.search(line):
                dropped += 1
    return records, dropped


def _parse_npdu_json(line: str) -> dict[str, object] | None:
    m = _NPDU_LINE.search(line) or _BARE_JSON.match(line)
    if m is None:
        return None
    try:
        obj = json.loads(m.group("json"))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def extract_ha_log(
    lines: list[str], pairs: list[tuple[bytes, bytes]]
) -> tuple[list[dict[str, str | None]], dict[str, int]]:
    """Parse recorder lines; return (records, skip counts by reason)."""
    records: list[dict[str, str | None]] = []
    skipped: dict[str, int] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for line in lines:
        if "NPDU" not in line and not line.lstrip().startswith("{"):
            continue
        obj = _parse_npdu_json(line)
        if obj is None:
            if "NPDU" in line:
                skip("malformed")
            continue
        direction, hex_text = obj.get("dir"), obj.get("hex")
        if "redacted" in obj:
            skip(f"redacted:{obj['redacted']}")
            continue
        if (
            direction not in ("rx", "tx")
            or not isinstance(hex_text, str)
            or not _HEX_ONLY.match(hex_text)
        ):
            skip("malformed")
            continue
        raw = redact(bytes.fromhex(hex_text), pairs)
        src_text: str | None = None
        if len(raw) >= NWK_HEADER_MIN_LEN:
            src_text = f"0x{int.from_bytes(raw[4:6], 'little'):04X}"
        records.append({"kind": f"npdu_{direction}", "src_short": src_text, "hex": raw.hex()})
    return records, skipped


def read_input(path: str, stdin: TextIO | None = None) -> list[str]:
    if path == "-":
        return (stdin or sys.stdin).read().splitlines()
    resolved = Path(path).resolve()
    if FORBIDDEN_PART in str(resolved).lower():
        raise PermissionError(f"refusing to read from {FORBIDDEN_PART}")
    size = resolved.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"input is {size} bytes; limit is {MAX_BYTES}")
    return resolved.read_text(encoding="utf-8", errors="replace").splitlines()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n")[0],
        epilog="REDACTION IS BEST-EFFORT, NOT A GUARANTEE: review output before sharing. "
        "Commissioning Status dumps (may hold key material) are never extracted.",
    )
    parser.add_argument("input", nargs="?", help="saved terminal-output text file, or - for stdin")
    parser.add_argument(
        "--from-ha-log",
        metavar="PATH",
        help="Home Assistant log (or - for stdin) with NPDU debug lines, instead of INPUT",
    )
    parser.add_argument(
        "--redact-eui",
        action="append",
        default=[],
        metavar="XX:XX:XX:XX:XX:XX:XX:XX",
        help="EUI-64 (big-endian display form) to replace, LE and BE, with 02:00:..:NN",
    )
    parser.add_argument(
        "--redact-short",
        action="append",
        default=[],
        metavar="0xABCD",
        help="short address to replace (LE occurrences) with 0x5A01, 0x5A02, ...",
    )
    args = parser.parse_args(argv)
    if (args.input is None) == (args.from_ha_log is None):
        print("error: give exactly one of INPUT or --from-ha-log PATH", file=sys.stderr)
        return 2
    try:
        euis = [parse_eui(e) for e in args.redact_eui]
        shorts = [parse_short(s) for s in args.redact_short]
        lines = read_input(args.from_ha_log if args.from_ha_log is not None else args.input)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    pairs = build_replacements(euis, shorts)
    print(
        "# NOTE: redaction is best-effort, not a guarantee; review before sharing.",
        file=sys.stderr,
    )
    if args.from_ha_log is not None:
        ha_records, skipped = extract_ha_log(lines, pairs)
        for rec in ha_records:
            print(json.dumps(rec))
        print(
            f"# extracted {len(ha_records)} NPDU record(s); skipped {skipped}",
            file=sys.stderr,
        )
        return 0
    records, dropped = extract(lines, pairs)
    for rec in records:
        print(json.dumps(rec))
    kinds: dict[str, int] = {}
    for rec in records:
        kinds[str(rec["kind"])] = kinds.get(str(rec["kind"]), 0) + 1
    print(
        f"# extracted {len(records)} record(s) {kinds}; dropped {dropped} unrecognised "
        f"line(s) with a bare 16-byte blob; redactions: {len(euis)} EUI, {len(shorts)} short",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
