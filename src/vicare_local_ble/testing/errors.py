"""GATT error emulation shared by ``zdd.py`` and ``gatt.py``.

Lives in its own module so ``FakeZdd`` (``zdd.py``) and the GATT layer (``gatt.py``, which
re-exports these names) do not import each other.
"""

from __future__ import annotations

from typing import Final

#: ATT error the live ZDD returned for a rejected SE3 and for reads before the session (PN §6).
GATT_ERROR_REJECTED: Final = 0x80
#: A generic non-auth ATT error ("unlikely error"), for SE3 faults that must NOT count as auth.
GATT_ERROR_UNLIKELY: Final = 0x0E


class FakeGattError(Exception):
    """Emulates a GATT error response from the ZDD; ``code`` is the ATT error code.

    The transport's ``_att_error_code`` reads ``code`` directly (spec §1.2).
    """

    def __init__(self, message: str, *, code: int = GATT_ERROR_REJECTED) -> None:
        super().__init__(f"{message} (GATT error 0x{code:02x})")
        self.code = code


__all__ = ["GATT_ERROR_REJECTED", "GATT_ERROR_UNLIKELY", "FakeGattError"]
