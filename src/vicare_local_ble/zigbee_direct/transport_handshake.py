"""Private helpers of ``transport``: SE1-SE4 driving, strict failure classification (spec §1.2).

Nothing here logs or formats handshake messages, the PSK or the session key. Public names stay in
``transport``; this module is an implementation detail of ``ZigbeeDirectTransport.open``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from bleak.exc import BleakCharacteristicNotFoundError

from vicare_local_ble.zigbee_direct.crypto import TAG_SIZE, SecretType
from vicare_local_ble.zigbee_direct.errors import (
    HandshakeError,
    HandshakeRejectedError,
    TransportError,
)
from vicare_local_ble.zigbee_direct.session import (
    OPCODE_SE4,
    TLV_MAC_TAG,
    Established,
    HandshakeInitiator,
    SendSe3,
    parse_handshake_message,
)
from vicare_local_ble.zigbee_direct.uuids import SECURITY_AUTHENTICATE_C25519

if TYPE_CHECKING:
    import asyncio
    from collections.abc import Awaitable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.transport import GattClient
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

#: ATT error code the ZDD answers a rejected SE3 with (wrong key; PN §6).
ATT_ERROR_REJECTED: Final = 0x80
#: How deep ``_att_error_code`` follows ``__cause__``/``__context__``.
_CHAIN_DEPTH: Final = 4
_ATT_MAX: Final = 0xFF

#: Backend message patterns carrying an ATT code. Exact texts are a hardware-checklist item.
_MESSAGE_PATTERNS: Final = (
    # BlueZ (D-Bus): "Operation failed with ATT error: 0x80"
    (re.compile(r"ATT error: 0x([0-9a-f]{1,2})\b", re.IGNORECASE), 16),
    # WinRT: "Protocol Error 0x80: Unknown"
    (re.compile(r"Protocol Error 0x([0-9a-f]{1,2})\b", re.IGNORECASE), 16),
    # CoreBluetooth: "Error Domain=CBATTErrorDomain Code=128 ..."
    (re.compile(r"CBATTErrorDomain Code=(\d{1,3})\b"), 10),
    # ESPHome proxy (aioesphomeapi BluetoothGATTAPIError): "... error=128 description=..."
    (re.compile(r"\berror=(\d{1,3}) description="), 10),
)


def _int_code(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return int(value) if 0 <= value <= _ATT_MAX else None


def _typed_code(exc: BaseException) -> int | None:
    # FakeGattError.code, bleak 3 BleakGATTProtocolError.code (an IntEnum).
    code = _int_code(getattr(exc, "code", None))
    if code is not None:
        return code
    # aioesphomeapi BluetoothGATTAPIError.error is a BluetoothGATTError with an int ``error``.
    nested = getattr(exc, "error", None)
    if nested is not None and not isinstance(nested, (int, str, bytes)):
        return _int_code(getattr(nested, "error", None))
    return None


def _chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(seen) < _CHAIN_DEPTH and current not in seen:
        seen.append(current)
        current = current.__cause__ or current.__context__
    return seen


def att_error_code(exc: BaseException) -> int | None:
    """See ``transport._att_error_code`` (the frozen name re-exports this function)."""
    chain = _chain(exc)
    for item in chain:
        code = _typed_code(item)
        if code is not None:
            return code
    for item in chain:
        text = str(item)
        for pattern, base in _MESSAGE_PATTERNS:
            match = pattern.search(text)
            if match is not None:
                return _int_code(int(match.group(1), base))
    return None


def gatt_failure(exc: BaseException, what: str) -> TransportError:
    """Map a GATT/backend exception to a retryable ``TransportError`` (never auth).

    The message names the exception type and, when one is found in the (bounded) cause chain,
    the integer ATT error code, e.g. ``"Commissioning Status read failed: BleakError (ATT
    0x05)"`` behind an ESPHome proxy (bleak-esphome wraps ``BluetoothGATTAPIError``).
    """
    if isinstance(exc, BleakCharacteristicNotFoundError):
        return TransportError(f"{what}: characteristic not found", reason="missing_characteristic")
    if isinstance(exc, TimeoutError):
        return TransportError(f"{what} timed out", reason="timeout")
    code = att_error_code(exc)  # only an int 0..0xFF survives, never the foreign message
    att = "" if code is None else f" (ATT 0x{code:02X})"
    return TransportError(f"{what} failed: {type(exc).__name__}{att}", reason="write")


async def guarded[T](clock: Clock, timeout: float, what: str, call: Awaitable[T]) -> T:
    """Await one GATT call within ``timeout``; failures become ``TransportError``."""
    try:
        async with clock.timeout(timeout):
            return await call
    except Exception as exc:
        raise gatt_failure(exc, what) from exc


async def _next_indication(clock: Clock, timeout: float, queue: asyncio.Queue[bytes]) -> bytes:
    try:
        async with clock.timeout(timeout):
            return await queue.get()
    except TimeoutError:
        raise TransportError("no handshake indication in time", reason="timeout") from None


def _se4_well_formed(data: bytes) -> bool:
    try:
        tlvs = parse_handshake_message(data, opcode=OPCODE_SE4, known={TLV_MAC_TAG: TAG_SIZE})
    except HandshakeError:
        return False
    return TLV_MAC_TAG in tlvs


async def run_handshake(
    client: GattClient,
    *,
    own_eui: Eui64,
    psk: SecretBytes,
    clock: Clock,
    timeout: float,
    indications: asyncio.Queue[bytes],
) -> Established:
    """Drive SE1..SE4 over Authenticate (already subscribed into ``indications``).

    Raises ``HandshakeRejectedError`` only for ATT 0x80 on the SE3 write or an SE4 tag mismatch;
    every other failure is a ``TransportError`` with the matching reason.
    """
    initiator = HandshakeInitiator(
        own_eui=own_eui, psk=psk, secret_type=SecretType.BASIC_AUTHORIZATION_KEY
    )
    auth = SECURITY_AUTHENTICATE_C25519
    await guarded(
        clock,
        timeout,
        "SE1 write",
        client.write_gatt_char(auth, initiator.start(), response=True),
    )
    se2 = await _next_indication(clock, timeout, indications)
    try:
        step = initiator.feed(se2)
    except HandshakeError:
        raise TransportError("malformed SE2", reason="protocol") from None
    if not isinstance(step, SendSe3):  # pragma: no cover - feed() in AWAIT_SE2 returns SendSe3
        raise TransportError("unexpected handshake step", reason="protocol")
    try:
        async with clock.timeout(timeout):
            await client.write_gatt_char(auth, step.payload, response=True)
    except Exception as exc:
        if att_error_code(exc) == ATT_ERROR_REJECTED:
            raise HandshakeRejectedError("ZDD rejected SE3 (ATT 0x80): wrong key") from exc
        raise gatt_failure(exc, "SE3 write") from exc
    se4 = await _next_indication(clock, timeout, indications)
    if not _se4_well_formed(se4):
        raise TransportError("malformed SE4", reason="protocol")
    try:
        final = initiator.feed(se4)
    except HandshakeError:  # structure was checked above: only the tag can mismatch
        raise HandshakeRejectedError("SE4 confirmation tag mismatch: wrong key") from None
    if not isinstance(final, Established):  # pragma: no cover - feed() in AWAIT_SE4
        raise TransportError("unexpected handshake step", reason="protocol")
    return final


__all__ = ["ATT_ERROR_REJECTED", "att_error_code", "gatt_failure", "guarded", "run_handshake"]
