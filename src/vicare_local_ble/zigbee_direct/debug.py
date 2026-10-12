"""NPDU debug log, ring buffer, structural redaction and secret sanitising (spec §1.8).

Implemented by T5; frozen interface (T2). This module is the secret surface: everything that
leaves the process as a log line or a diagnostics record passes through it.

NPDU log
    Logger ``vicare_local_ble.npdu`` (``NPDU_LOGGER``), DEBUG only, one JSON line per tunnel
    NPDU: ``NPDU {"dir":"rx|tx","flags":1,"hex":"...","t":12.345}`` (keys sorted, compact
    separators), so ``grep NPDU home-assistant.log | cut -d' ' -f2-`` yields a fixture file.
    ``NpduRecorder(maxlen=200)`` keeps the same records in a ring buffer for diagnostics.

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

Secret sanitising (before anything is logged or recorded)
    * APS command frames -> ``{"redacted":"aps_command","len":N}``.
    * A ZCL frame with any security-typed attribute value (``SECURITY_TYPES``, KEY128 0xF1) ->
      ``{"redacted":"zcl_secret","len":N}``.
    * Frames that decode neither through the standard path nor the fallback -> NWK header
      (itself EUI-redacted) plus length only: ``{"redacted":"undecodable","nwk_header":...}``.
    * ``sanitize_records`` replaces security-typed values in decoded records; every DEBUG log of
      attribute records elsewhere in the library goes through it.

Never handled here (never passed in, never logged anywhere): Commissioning Status values,
handshake messages, the BAK, session key or network key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, overload

from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType

if TYPE_CHECKING:
    import logging
    from collections.abc import Iterable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord, ReadAttributeStatus
    from vicare_local_ble.zigbee_direct.types import Eui64

NPDU_LOGGER: Final = "vicare_local_ble.npdu"
#: Prefix of every NPDU log line, followed by one space and the JSON object.
NPDU_LOG_PREFIX: Final = "NPDU"
DEFAULT_RING_SIZE: Final = 200
#: ZCL data types whose values are secrets and never logged or recorded.
SECURITY_TYPES: Final = frozenset({ZclDataType.KEY128})

type Direction = Literal["rx", "tx"]
type RedactionKind = Literal["aps_command", "zcl_secret", "undecodable"]


def is_security_type(data_type: int | None) -> bool:
    """True if values of ``data_type`` must never be logged (``SECURITY_TYPES``)."""
    raise NotImplementedError("T5")


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
    raise NotImplementedError("T5")


class EuiPseudonymizer:
    """Deterministic, per-recorder EUI and extended-PAN pseudonyms.

    The n-th distinct EUI (1-based) maps to ``02:00:00:00:00:00:00:NN`` (locally administered;
    n above 255 continues into the next octets), the n-th distinct extended PAN to
    ``DD:DD:DD:DD:DD:DD:DD:NN``. A pseudonym is never re-mapped, and a value already equal to an
    issued pseudonym maps to itself. The mapping lives as long as the recorder (one session).
    """

    def __init__(self) -> None:
        raise NotImplementedError("T5")

    def eui(self, value: Eui64) -> Eui64:
        raise NotImplementedError("T5")

    def extended_pan(self, value: Eui64) -> Eui64:
        """Extended PAN ids are EUI-shaped (8 bytes, ``Eui64`` in the codecs)."""
        raise NotImplementedError("T5")


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


def redact_npdu(npdu: bytes, pseudonyms: EuiPseudonymizer) -> RedactedNpdu:
    """Apply structural redaction and secret sanitising (module docstring) to one NPDU.

    Never raises: on any internal error it returns a length-only record
    (``RedactedNpdu(length=len(npdu), redacted="undecodable")`` with ``nwk_header_hex=None``),
    never raw hex."""
    raise NotImplementedError("T5")


@dataclass(frozen=True, slots=True)
class NpduRecord:
    """One recorded NPDU, already redacted. ``t`` is ``clock.now()`` at recording."""

    direction: Direction
    flags: int
    t: float
    npdu: RedactedNpdu

    def to_json(self) -> str:
        """The JSON object of the log line (without the ``NPDU`` prefix)."""
        raise NotImplementedError("T5")


class NpduRecorder:
    """Ring buffer plus DEBUG log of redacted tunnel NPDUs.

    Called by the transport only: ``rx`` for every decrypted Tunnel NPDU, ``tx`` just before
    every Tunnel write. Cheap when the logger is not at DEBUG (the ring buffer still records).
    One recorder may outlive several transports (the connection owns it), so pseudonyms stay
    consistent across reconnects of one ``ZdConnection``. Loop thread only.
    """

    def __init__(
        self,
        maxlen: int = DEFAULT_RING_SIZE,
        *,
        clock: Clock | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        raise NotImplementedError("T5")

    def rx(self, npdu: TunnelNpdu) -> None:
        """Record and log one received NPDU. Must not raise (the transport guards it anyway)."""
        raise NotImplementedError("T5")

    def tx(self, npdu: TunnelNpdu) -> None:
        raise NotImplementedError("T5")

    def records(self) -> tuple[NpduRecord, ...]:
        """Snapshot of the ring buffer, oldest first."""
        raise NotImplementedError("T5")

    def clear(self) -> None:
        raise NotImplementedError("T5")


def format_log_line(record: NpduRecord) -> str:
    """``NPDU <json>``: the exact line emitted on ``NPDU_LOGGER``."""
    raise NotImplementedError("T5")


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
