"""Small shared value types: EUI-64, secret bytes, short-address helpers."""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Self

if TYPE_CHECKING:
    from collections.abc import Callable

COORDINATOR = 0x0000
BROADCAST_ROUTERS = 0xFFFC
BROADCAST_RX_ON = 0xFFFD
BROADCAST_ALL = 0xFFFF

_EUI_LEN = 8


def validate_short(x: int) -> int:
    """Return ``x`` if it is a valid 16-bit short address, else raise ``ValueError``."""
    if isinstance(x, bool) or not isinstance(x, int) or not 0 <= x <= 0xFFFF:
        raise ValueError(f"short address out of range 0..0xFFFF: {x!r}")
    return x


@dataclass(frozen=True, slots=True)
class Eui64:
    """IEEE EUI-64 stored in little-endian wire order.

    ``str()`` shows the conventional big-endian colon form.
    """

    wire: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.wire, bytes) or len(self.wire) != _EUI_LEN:
            raise ValueError(f"EUI-64 needs exactly {_EUI_LEN} bytes")

    @classmethod
    def from_wire(cls, data: bytes) -> Self:
        """Build from 8 bytes in little-endian wire order."""
        return cls(bytes(data))

    @classmethod
    def from_str(cls, text: str) -> Self:
        """Parse big-endian display form, with or without ``:``/``-`` separators."""
        cleaned = text.strip().replace(":", "").replace("-", "")
        if len(cleaned) != _EUI_LEN * 2:
            raise ValueError(f"EUI-64 needs 16 hex digits: {text!r}")
        try:
            display = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"invalid EUI-64 hex: {text!r}") from exc
        return cls(display[::-1])

    def __str__(self) -> str:
        return ":".join(f"{b:02X}" for b in reversed(self.wire))

    def __bytes__(self) -> bytes:
        return self.wire

    def as_int(self) -> int:
        """Numeric value (wire bytes read as little-endian)."""
        return int.from_bytes(self.wire, "little")


def generate_zvd_eui(rng: Callable[[int], bytes] = os.urandom) -> Eui64:
    """Random EUI-64 with the locally-administered bit set and multicast bit cleared.

    Bits apply to the most significant octet of the display form (``wire[7]``).
    """
    raw = bytearray(rng(_EUI_LEN))
    if len(raw) != _EUI_LEN:
        raise ValueError(f"rng returned {len(raw)} bytes, expected {_EUI_LEN}")
    raw[7] = (raw[7] | 0x02) & ~0x01 & 0xFF
    return Eui64(bytes(raw))


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class SecretBytes:
    """Bytes that never show up in repr/str/logs; use ``reveal()`` explicitly."""

    _value: bytes
    __hash__: ClassVar[None]  # type: ignore[assignment]  # unhashable on purpose

    def __post_init__(self) -> None:
        if not isinstance(self._value, bytes):
            raise TypeError("SecretBytes wraps bytes")

    @classmethod
    def from_hex(cls, text: str) -> Self:
        return cls(bytes.fromhex(text.strip()))

    def reveal(self) -> bytes:
        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretBytes):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __repr__(self) -> str:
        return "SecretBytes(<redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return repr(self)
