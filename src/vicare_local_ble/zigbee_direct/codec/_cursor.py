"""Bounds-checked little-endian byte reader shared by the APS/ZDO/ZCL codecs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from vicare_local_ble.zigbee_direct.errors import EncodeError
from vicare_local_ble.zigbee_direct.types import Eui64

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.errors import DecodeError


class Cursor:
    """Sequential reader that raises ``error`` (a DecodeError subclass) on truncation."""

    __slots__ = ("_data", "_error", "_pos", "_what")

    def __init__(self, data: bytes, error: type[DecodeError], what: str) -> None:
        self._data = bytes(data)
        self._error = error
        self._what = what
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def fail(self, message: str) -> DecodeError:
        """Build (not raise) an error of the configured type, prefixed with the frame name."""
        return self._error(f"{self._what}: {message}")

    def take(self, n: int, field: str = "field") -> bytes:
        if n < 0 or self._pos + n > len(self._data):
            raise self.fail(
                f"truncated {field}: need {n} byte(s) at offset {self._pos}, "
                f"have {self.remaining()}"
            )
        out = self._data[self._pos : self._pos + n]
        self._pos += n
        return out

    def u8(self, field: str = "field") -> int:
        return self.take(1, field)[0]

    def u16(self, field: str = "field") -> int:
        return int.from_bytes(self.take(2, field), "little")

    def u64(self, field: str = "field") -> int:
        return int.from_bytes(self.take(8, field), "little")

    def eui(self, field: str = "EUI-64") -> Eui64:
        return Eui64.from_wire(self.take(8, field))

    def rest(self) -> bytes:
        out = self._data[self._pos :]
        self._pos = len(self._data)
        return out

    def expect_end(self) -> None:
        if self._pos != len(self._data):
            raise self.fail(f"{self.remaining()} unexpected trailing byte(s)")


def check_uint(value: int, bits: int, name: str) -> int:
    """Return ``value`` if it fits an unsigned ``bits``-wide field, else raise EncodeError."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise EncodeError(f"{name} out of range for {bits}-bit field: {value!r}")
    return value
