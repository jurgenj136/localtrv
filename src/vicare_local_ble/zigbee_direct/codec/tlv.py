"""Generic Zigbee TLVs and the Zigbee Direct tunnel NPDU TLV.

Zigbee TLV encoding (R23 3.4.14 / Annex I, also used by Zigbee Direct 1.0):
``tag(1) ‖ length(1) ‖ value(length + 1)`` — the length octet is the value
length minus one, so a value is 1..256 bytes and never empty.

The tunnel characteristic carries NPDU TLVs (ZD 1.0, tag 0x00)::

    0x00 ‖ len-1 ‖ flags(1) ‖ npdu_len(1) ‖ npdu(npdu_len)

``flags`` bit0 = NWK security requested (ZVD->ZDD) / applied (ZDD->ZVD).
Since the whole value must fit in 256 bytes, an NPDU is at most 254 bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from vicare_local_ble.zigbee_direct.errors import EncodeError, TlvDecodeError

if TYPE_CHECKING:
    from collections.abc import Iterable

TLV_MAX_VALUE_LEN = 256
TUNNEL_NPDU_TAG = 0x00
MAX_NPDU_LEN = TLV_MAX_VALUE_LEN - 2
_TUNNEL_FLAG_NWK_SECURITY = 0x01


@dataclass(frozen=True, slots=True)
class Tlv:
    """One Zigbee TLV; ``value`` is 1..256 bytes."""

    tag: int
    value: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.tag <= 0xFF:
            raise EncodeError(f"TLV tag out of range 0..0xFF: {self.tag!r}")
        if not 1 <= len(self.value) <= TLV_MAX_VALUE_LEN:
            raise EncodeError(f"TLV value must be 1..256 bytes, got {len(self.value)}")

    def encode(self) -> bytes:
        return bytes((self.tag, len(self.value) - 1)) + self.value

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Decode exactly one TLV; trailing bytes are an error."""
        tlv, end = _read_tlv(data, 0)
        if end != len(data):
            raise TlvDecodeError(f"{len(data) - end} trailing byte(s) after TLV")
        return cls(tlv.tag, tlv.value)


def _read_tlv(data: bytes, offset: int) -> tuple[Tlv, int]:
    if offset + 2 > len(data):
        raise TlvDecodeError(f"truncated TLV header at offset {offset}")
    tag = data[offset]
    length = data[offset + 1] + 1
    end = offset + 2 + length
    if end > len(data):
        raise TlvDecodeError(
            f"truncated TLV tag 0x{tag:02X} at offset {offset}: "
            f"need {length} value bytes, have {len(data) - offset - 2}"
        )
    return Tlv(tag, bytes(data[offset + 2 : end])), end


def encode_tlvs(tlvs: Iterable[Tlv]) -> bytes:
    """Concatenate encoded TLVs."""
    return b"".join(t.encode() for t in tlvs)


def decode_tlvs(data: bytes) -> tuple[Tlv, ...]:
    """Decode a back-to-back TLV list; any truncation raises ``TlvDecodeError``."""
    out: list[Tlv] = []
    offset = 0
    while offset < len(data):
        tlv, offset = _read_tlv(data, offset)
        out.append(tlv)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class TunnelNpdu:
    """Tunnel NPDU TLV (ZD 1.0 tunnel service, tag 0x00)."""

    npdu: bytes
    nwk_security: bool

    def __post_init__(self) -> None:
        if len(self.npdu) > MAX_NPDU_LEN:
            raise EncodeError(f"NPDU too long for tunnel TLV: {len(self.npdu)} > {MAX_NPDU_LEN}")

    def to_tlv(self) -> Tlv:
        flags = _TUNNEL_FLAG_NWK_SECURITY if self.nwk_security else 0
        return Tlv(TUNNEL_NPDU_TAG, bytes((flags, len(self.npdu))) + self.npdu)

    def encode(self) -> bytes:
        return self.to_tlv().encode()

    @classmethod
    def from_tlv(cls, tlv: Tlv) -> Self:
        """Interpret a raw TLV as an NPDU TLV; reserved flag bits are ignored."""
        if tlv.tag != TUNNEL_NPDU_TAG:
            raise TlvDecodeError(f"not a tunnel NPDU TLV (tag 0x{tlv.tag:02X})")
        value = tlv.value
        if len(value) < 2:
            raise TlvDecodeError("tunnel NPDU TLV shorter than flags + npdu_len")
        npdu_len = value[1]
        if len(value) != 2 + npdu_len:
            raise TlvDecodeError(
                f"tunnel npdu_len {npdu_len} does not match TLV value length {len(value) - 2}"
            )
        return cls(bytes(value[2:]), bool(value[0] & _TUNNEL_FLAG_NWK_SECURITY))

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Decode exactly one NPDU TLV."""
        return cls.from_tlv(Tlv.decode(data))


def parse_tunnel_tlvs(data: bytes) -> tuple[TunnelNpdu | Tlv, ...]:
    """Decode a tunnel indication: NPDU TLVs become ``TunnelNpdu``, other tags stay raw ``Tlv``.

    Unlike the research parser (research tools/zvd_tunnel.py ``parse_tunnel_tlvs``),
    unknown tags do not stop parsing, and truncation / npdu_len mismatch raise.
    """
    return tuple(
        TunnelNpdu.from_tlv(t) if t.tag == TUNNEL_NPDU_TAG else t for t in decode_tlvs(data)
    )
