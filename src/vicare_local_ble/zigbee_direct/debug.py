"""NPDU debug log, ring buffer, structural redaction and secret sanitising (spec §1.8).

Implemented by T5; frozen interface (T2). This module is the secret surface: everything that
leaves the process as a log line or a diagnostics record passes through it.

NPDU log
    Logger ``vicare_local_ble.npdu`` (``NPDU_LOGGER``), DEBUG only, one JSON line per tunnel
    NPDU: ``NPDU {"dir":"rx|tx","flags":1,"hex":"...","t":12.345}`` (keys sorted, compact
    separators), so ``grep NPDU home-assistant.log | cut -d' ' -f2-`` yields a fixture file.
    ``NpduRecorder(maxlen=200)`` keeps the same records in a ring buffer for diagnostics.
    Suppressed frames carry ``"redacted"`` and ``"len"`` instead of ``"hex"`` (plus
    ``"nwk_header"`` for undecodable frames whose NWK header decoded).

Structural redaction (always on, log and ring buffer alike) - ``redact_npdu``
    1. Decode with the production decoders (NWK, then APS/ZDO/ZCL/NWK commands; the generic
       offset scan of ``codec.fallback`` may be used to locate a quirk payload).
    2. Collect EVERY EUI and extended PAN the decoders expose, known devices or not: NWK
       dst/src IEEE, Device_annce, IEEE/NWK_addr responses, Mgmt_Lqi records (ext PAN + IEEE),
       RREQ dst IEEE, RREP EUIs (including the live 0x20 layout's trailing EUI), Commissioning
       Request/Response TLV EUIs, ZCL values of type EUI64.
    3. Map each to a deterministic fixed-width dummy from ``EuiPseudonymizer``.
    4. Replace the exact 8-byte wire sequences in place: length and byte order unchanged,
       short addresses kept, so a redacted frame still decodes.

    Step 4 replaces every occurrence, anywhere in the frame, of every EUI / extended PAN the
    recorder has seen so far in this session (not only the fields of the current frame), in
    wire order and reversed (display) order, and as 16-digit / colon-separated ASCII hex in
    either case. All matches are located on the original bytes before any is written, so
    overlapping matches cannot leave original bytes behind. Field discovery lives in
    ``zigbee_direct.redact`` (design notes there).

Secret sanitising (before anything is logged or recorded)
    * APS command frames -> ``{"redacted":"aps_command","len":N}``.
    * A ZCL frame with any security-typed attribute value (``SECURITY_TYPES``, KEY128 0xF1) ->
      ``{"redacted":"zcl_secret","len":N}``.
    * Frames that decode neither through the standard path nor the fallback -> NWK header
      (itself EUI-redacted) plus length only: ``{"redacted":"undecodable","nwk_header":...}``.
    * ``sanitize_records`` replaces security-typed values in decoded records; every DEBUG log of
      attribute records elsewhere in the library goes through it.

Never handled here (never passed in, never logged anywhere): Commissioning Status values,
handshake messages, the BAK, session key or network key. The recorder has no API that accepts
them: ``rx``/``tx`` take a ``TunnelNpdu`` (a plaintext NWK frame from the tunnel
characteristic) and nothing else; the transport calls them for Tunnel NPDUs only.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import deque
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Final, Literal, cast, overload

from vicare_local_ble.zigbee_direct.redact import SECURITY_TYPES, inspect_npdu, is_security_code
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

if TYPE_CHECKING:
    from collections.abc import Iterable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord, ReadAttributeStatus

NPDU_LOGGER: Final = "vicare_local_ble.npdu"
#: Prefix of every NPDU log line, followed by one space and the JSON object.
NPDU_LOG_PREFIX: Final = "NPDU"
DEFAULT_RING_SIZE: Final = 200

type Direction = Literal["rx", "tx"]
type RedactionKind = Literal["aps_command", "zcl_secret", "undecodable"]

_EUI_LEN: Final = 8
_KEY128_LEN: Final = 16
_EUI_PREFIX: Final = 0x02  # locally administered, unicast
_PAN_FILL: Final = 0xDD


def is_security_type(data_type: int | None) -> bool:
    """True if values of ``data_type`` must never be logged (``SECURITY_TYPES``)."""
    return is_security_code(data_type)


@overload
def sanitize_records(records: Iterable[AttributeRecord]) -> tuple[AttributeRecord, ...]: ...


@overload
def sanitize_records(
    records: Iterable[ReadAttributeStatus],
) -> tuple[ReadAttributeStatus, ...]: ...


def sanitize_records(
    records: Iterable[AttributeRecord] | Iterable[ReadAttributeStatus],
) -> tuple[AttributeRecord, ...] | tuple[ReadAttributeStatus, ...]:
    """Copy of ``records`` with every security-typed value replaced by ``SecretBytes`` of the
    same length (repr ``<redacted>``); other records are returned unchanged (same objects)."""
    out: list[AttributeRecord | ReadAttributeStatus] = []
    for record in records:
        if not is_security_type(record.data_type):
            out.append(record)
            continue
        value = record.value
        size = len(value) if isinstance(value, SecretBytes | bytes) else _KEY128_LEN
        out.append(replace(record, value=SecretBytes(bytes(size))))
    return cast("tuple[AttributeRecord, ...] | tuple[ReadAttributeStatus, ...]", tuple(out))


class EuiPseudonymizer:
    """Deterministic, per-recorder EUI and extended-PAN pseudonyms.

    The n-th distinct EUI (1-based) maps to ``02:00:00:00:00:00:00:NN`` (locally administered;
    n above 255 continues into the next octets), the n-th distinct extended PAN to
    ``DD:DD:DD:DD:DD:DD:DD:NN``. A pseudonym is never re-mapped, and a value already equal to an
    issued pseudonym maps to itself. The mapping lives as long as the recorder (one session).

    One table serves both kinds, so equal 8-byte values always get one pseudonym (an extended
    PAN equal to the coordinator EUI keeps whichever pseudonym it was given first). A candidate
    pseudonym equal to a real value already seen is skipped, so two real values never share one.
    The real values are never exposed: there is no public accessor for the table.
    """

    __slots__ = ("_issued", "_map", "_next_eui", "_next_pan")

    def __init__(self) -> None:
        self._map: dict[bytes, bytes] = {}  # real wire bytes -> pseudonym wire bytes
        self._issued: set[bytes] = set()
        self._next_eui = 1
        self._next_pan = 1

    def eui(self, value: Eui64) -> Eui64:
        return Eui64(self._lookup(value.wire, pan=False))

    def extended_pan(self, value: Eui64) -> Eui64:
        """Extended PAN ids are EUI-shaped (8 bytes, ``Eui64`` in the codecs)."""
        return Eui64(self._lookup(value.wire, pan=True))

    def __len__(self) -> int:
        """Number of distinct real values mapped so far."""
        return sum(1 for real, fake in self._map.items() if real != fake)

    def __repr__(self) -> str:
        return f"EuiPseudonymizer(<{len(self)} mapped>)"

    def _lookup(self, wire: bytes, *, pan: bool) -> bytes:
        if wire in self._issued:
            return wire
        known = self._map.get(wire)
        if known is not None:
            return known
        candidate = self._issue(pan=pan)
        while candidate in self._map:  # a real value already seen has this shape
            candidate = self._issue(pan=pan)
        self._map[wire] = candidate
        self._issued.add(candidate)
        return candidate

    def _issue(self, *, pan: bool) -> bytes:
        if pan:
            n, self._next_pan = self._next_pan, self._next_pan + 1
            display = (
                bytes([_PAN_FILL] * 7 + [n])
                if n <= 0xFF
                else bytes([_PAN_FILL]) + (n.to_bytes(7, "big"))
            )
        else:
            n, self._next_eui = self._next_eui, self._next_eui + 1
            display = bytes([_EUI_PREFIX]) + n.to_bytes(7, "big")
        return display[::-1]  # wire order

    def _replacements(self) -> list[tuple[bytes, bytes]]:
        """Every (original, replacement) encoding of every mapped real value."""
        pairs: list[tuple[bytes, bytes]] = []
        for real, fake in self._map.items():
            if real == fake:
                continue
            for r, f in ((real, fake), (real[::-1], fake[::-1])):
                pairs.append((r, f))
                for rh, fh in ((r.hex(), f.hex()), (r.hex(":"), f.hex(":"))):
                    pairs.append((rh.encode(), fh.encode()))
                    pairs.append((rh.upper().encode(), fh.upper().encode()))
        return pairs

    def scrub(self, data: bytes) -> bytes:
        """``data`` with every encoding of every mapped value replaced (same length)."""
        out = bytearray(data)
        for old, new in self._replacements():
            start = data.find(old)
            while start != -1:
                out[start : start + len(old)] = new
                start = data.find(old, start + 1)
        return bytes(out)


@dataclass(frozen=True, slots=True)
class RedactedNpdu:
    """Output of ``redact_npdu``: exactly one of ``hex`` or ``redacted`` is set.

    ``hex`` is the full EUI-redacted NPDU (same length as the input). For ``redacted``,
    ``nwk_header_hex`` is the EUI-redacted NWK header for ``"undecodable"`` frames and ``None``
    otherwise. ``length`` is the original NPDU length.
    """

    length: int
    hex: str | None = None
    redacted: RedactionKind | None = None
    nwk_header_hex: str | None = None


def _redact(data: bytes, pseudonyms: EuiPseudonymizer) -> RedactedNpdu:
    info = inspect_npdu(data)
    if info.verdict == "aps_command" or info.verdict == "zcl_secret":
        return RedactedNpdu(length=len(data), redacted=info.verdict)
    for kind, value in info.fields:
        if kind == "pan":
            pseudonyms.extended_pan(value)
        else:
            pseudonyms.eui(value)
    clean = pseudonyms.scrub(data)
    if len(clean) != len(data):  # pragma: no cover - scrub preserves length by construction
        raise AssertionError("redaction changed the frame length")
    if info.verdict == "ok":
        return RedactedNpdu(length=len(data), hex=clean.hex())
    header = None if info.header_len is None else clean[: info.header_len].hex()
    return RedactedNpdu(length=len(data), redacted="undecodable", nwk_header_hex=header)


def redact_npdu(npdu: bytes, pseudonyms: EuiPseudonymizer) -> RedactedNpdu:
    """Apply structural redaction and secret sanitising (module docstring) to one NPDU.

    Never raises: on any internal error it returns a length-only record
    (``RedactedNpdu(length=len(npdu), redacted="undecodable")`` with ``nwk_header_hex=None``),
    never raw hex."""
    try:
        length = len(npdu)
    except Exception:
        length = 0
    try:
        return _redact(bytes(npdu), pseudonyms)
    except Exception:
        return RedactedNpdu(length=length, redacted="undecodable")


@dataclass(frozen=True, slots=True)
class NpduRecord:
    """One recorded NPDU, already redacted. ``t`` is ``clock.now()`` at recording."""

    direction: Direction
    flags: int
    t: float
    npdu: RedactedNpdu

    def to_json(self) -> str:
        """The JSON object of the log line (without the ``NPDU`` prefix)."""
        obj: dict[str, object] = {
            "dir": self.direction,
            "flags": self.flags,
            "t": round(self.t, 3) if math.isfinite(self.t) else 0.0,
        }
        if self.npdu.hex is not None:
            obj["hex"] = self.npdu.hex
        else:
            obj["redacted"] = self.npdu.redacted or "undecodable"
            obj["len"] = self.npdu.length
            if self.npdu.nwk_header_hex is not None:
                obj["nwk_header"] = self.npdu.nwk_header_hex
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class NpduRecorder:
    """Ring buffer plus DEBUG log of redacted tunnel NPDUs.

    Called by the transport only: ``rx`` for every decrypted Tunnel NPDU, ``tx`` just before
    every Tunnel write. Cheap when the logger is not at DEBUG (the ring buffer still records).
    One recorder may outlive several transports (the connection owns it), so pseudonyms stay
    consistent across reconnects of one ``ZdConnection``. Loop thread only.

    ``t`` comes from ``clock.now()``; without a clock, ``time.monotonic()``. Keys, handshake
    messages and Commissioning Status values have no way in: the only inputs are tunnel NPDUs.
    """

    __slots__ = ("_clock", "_logger", "_pseudonyms", "_ring")

    def __init__(
        self,
        maxlen: int = DEFAULT_RING_SIZE,
        *,
        clock: Clock | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if isinstance(maxlen, bool) or not isinstance(maxlen, int) or maxlen < 0:
            raise ValueError(f"maxlen must be a non-negative int: {maxlen!r}")
        self._ring: deque[NpduRecord] = deque(maxlen=maxlen)
        self._clock = clock
        self._logger = logger if logger is not None else logging.getLogger(NPDU_LOGGER)
        self._pseudonyms = EuiPseudonymizer()

    @property
    def pseudonyms(self) -> EuiPseudonymizer:
        """This session's pseudonym table, for consistent EUIs in diagnostics."""
        return self._pseudonyms

    def rx(self, npdu: TunnelNpdu) -> None:
        """Record and log one received NPDU. Must not raise (the transport guards it anyway)."""
        self._record("rx", npdu)

    def tx(self, npdu: TunnelNpdu) -> None:
        self._record("tx", npdu)

    def records(self) -> tuple[NpduRecord, ...]:
        """Snapshot of the ring buffer, oldest first."""
        return tuple(self._ring)

    def clear(self) -> None:
        """Empty the ring buffer; the pseudonym table is kept (one session, one mapping)."""
        self._ring.clear()

    def _now(self) -> float:
        try:
            now = self._clock.now() if self._clock is not None else time.monotonic()
            return float(now)
        except Exception:
            return 0.0

    def _record(self, direction: Direction, npdu: TunnelNpdu) -> None:
        try:
            raw = npdu.npdu
            flags = 1 if npdu.nwk_security else 0
            record = NpduRecord(direction, flags, self._now(), redact_npdu(raw, self._pseudonyms))
            self._ring.append(record)
            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug("%s", format_log_line(record))
        except Exception:  # never let debugging break the tunnel; never log the payload
            return


def format_log_line(record: NpduRecord) -> str:
    """``NPDU <json>``: the exact line emitted on ``NPDU_LOGGER``."""
    return f"{NPDU_LOG_PREFIX} {record.to_json()}"


__all__ = [
    "DEFAULT_RING_SIZE",
    "NPDU_LOGGER",
    "NPDU_LOG_PREFIX",
    "SECURITY_TYPES",
    "Direction",
    "EuiPseudonymizer",
    "NpduRecord",
    "NpduRecorder",
    "RedactedNpdu",
    "RedactionKind",
    "format_log_line",
    "is_security_type",
    "redact_npdu",
    "sanitize_records",
]
