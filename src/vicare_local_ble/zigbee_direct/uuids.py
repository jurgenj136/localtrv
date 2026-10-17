"""Zigbee Direct 1.0 GATT service/characteristic UUIDs and canonical UUID bytes.

String constants are full 128-bit lowercase UUIDs (usable with BLE stacks such as
bleak); ``uuid_bytes`` gives the canonical 16-byte form used in the session-frame
CCM AAD (handover section 3.3).

Sources: the research client (Security, Tunnel, Commissioning Status) and the research
notes (roles of commissioning characteristics 0001-0008).
"""

from __future__ import annotations

import uuid
from typing import Final

#: Bluetooth Base UUID; 16/32-bit UUIDs expand into its first 32 bits.
BLUETOOTH_BASE_UUID: Final = "00000000-0000-1000-8000-00805f9b34fb"


def expand_uuid16(value: int) -> str:
    """Expand a 16-bit SIG UUID (e.g. ``0xFFF7``) to its full 128-bit string form."""
    if isinstance(value, bool) or not 0 <= value <= 0xFFFF:
        raise ValueError(f"16-bit UUID out of range: {value!r}")
    return f"0000{value:04x}{BLUETOOTH_BASE_UUID[8:]}"


def uuid_bytes(value: str | int) -> bytes:
    """Canonical big-endian (text-order) 16 bytes of a UUID.

    Accepts a 16-bit int, a 4-hex-digit string (optionally ``0x``-prefixed), or
    any 128-bit UUID string form accepted by ``uuid.UUID``.
    """
    if isinstance(value, int):
        return uuid.UUID(expand_uuid16(value)).bytes
    text = value.strip().lower()
    short = text.removeprefix("0x")
    if len(short) == 4:
        try:
            return uuid.UUID(expand_uuid16(int(short, 16))).bytes
        except ValueError as exc:
            raise ValueError(f"invalid 16-bit UUID: {value!r}") from exc
    return uuid.UUID(text).bytes


# --- Security Service ---------------------------------------------------------------------
SECURITY_SERVICE: Final = "29144af4-0000-4481-bfe9-6d0299b429e3"
#: Authenticate (SPEKE / Curve25519 / AES-MMO-128 / HMAC-AES-MMO-128); SE1-SE4 run here.
SECURITY_AUTHENTICATE_C25519: Final = "29144af4-0001-4481-bfe9-6d0299b429e3"

# --- Tunnel Service -----------------------------------------------------------------------
TUNNEL_SERVICE: Final = "8bd178fd-0000-45f4-8120-b2378bd5313f"
#: ZDTS NPDU (write + indicate).
TUNNEL_NPDU: Final = "8bd178fd-0001-45f4-8120-b2378bd5313f"

# --- Commissioning Service ------------------------------------------------------------------
COMMISSIONING_SERVICE_UUID16: Final = 0xFFF7
COMMISSIONING_SERVICE: Final = expand_uuid16(COMMISSIONING_SERVICE_UUID16)
COMMISSIONING_FORM_NETWORK: Final = "7072377d-0001-421c-b163-491c27333a61"
COMMISSIONING_JOIN_NETWORK: Final = "7072377d-0002-421c-b163-491c27333a61"
COMMISSIONING_PERMIT_JOINING: Final = "7072377d-0003-421c-b163-491c27333a61"
COMMISSIONING_LEAVE_NETWORK: Final = "7072377d-0004-421c-b163-491c27333a61"
#: Commissioning Status (read + notify).
COMMISSIONING_STATUS: Final = "7072377d-0005-421c-b163-491c27333a61"
# Roles of 0006-0008 come from the research notes (inferred, unused).
COMMISSIONING_MANAGE_JOINERS: Final = "7072377d-0006-421c-b163-491c27333a61"
COMMISSIONING_IDENTIFY: Final = "7072377d-0007-421c-b163-491c27333a61"
COMMISSIONING_FINDING_BINDING: Final = "7072377d-0008-421c-b163-491c27333a61"
