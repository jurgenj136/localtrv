"""Exception hierarchy for the Zigbee Direct library."""

from __future__ import annotations

from typing import Literal


class ZigbeeDirectError(Exception):
    """Base class for all errors raised by this library."""


class DecodeError(ZigbeeDirectError, ValueError):
    """A frame or TLV could not be decoded."""


class TlvDecodeError(DecodeError):
    """Malformed TLV data."""


class NwkDecodeError(DecodeError):
    """Malformed NWK frame."""


class ApsDecodeError(DecodeError):
    """Malformed APS frame."""


class ZdoDecodeError(DecodeError):
    """Malformed ZDO payload."""


class ZclDecodeError(DecodeError):
    """Malformed ZCL payload."""


class CommissioningDecodeError(DecodeError):
    """Malformed commissioning payload."""


class UnsupportedFrameError(DecodeError):
    """Well-formed frame that this library deliberately does not decode."""


class HandshakeError(ZigbeeDirectError):
    """The SPEKE handshake failed or was misused."""


class AuthenticationError(ZigbeeDirectError):
    """Message integrity check (MIC) failed."""


class ReplayError(ZigbeeDirectError):
    """A frame counter was not strictly increasing."""


class CounterExhaustedError(ZigbeeDirectError):
    """The outgoing frame counter reached its maximum; a new session is required."""


class EncodeError(ZigbeeDirectError, ValueError):
    """A frame could not be encoded from the given values."""


# --- phase 2: runtime errors (spec §1.1) --------------------------------------------------

type TransportErrorReason = Literal[
    "write",
    "timeout",
    "long_write_unsupported",
    "closed",
    "protocol",
    "not_found",
    "missing_characteristic",
]
"""Why a transport operation failed.

* ``write``: a GATT write or read raised (backend error, disconnect, counter exhausted).
* ``timeout``: a GATT write, SE2 or SE4 did not complete within its bound.
* ``long_write_unsupported``: a write of a frame above ``MTU - 3`` failed (GATT long write).
* ``closed``: the transport is closed or broken; nothing was sent.
* ``protocol``: the handshake peer sent a malformed or unexpected message (not a key problem).
* ``not_found``: the device resolver returned no device (``validate_connection``).
* ``missing_characteristic``: a required GATT characteristic is absent (bleak's
  ``BleakCharacteristicNotFoundError``), typically a stale GATT cache; the connection clears
  the client cache once and reconnects.

``protocol``, ``not_found`` and ``missing_characteristic`` extend the four reasons listed in the
spec; callers that map reasons to repair issues only special-case ``long_write_unsupported``.
"""

type RequestKind = Literal["zdo", "zcl"]
"""Correlation namespace of a pending request: ZDO sequence number or ZCL TSN."""


class TransportError(ZigbeeDirectError):
    """A GATT operation failed or the session is in doubt; retryable after a reconnect.

    ``reason`` classifies the failure (see ``TransportErrorReason``). The message never contains
    key material or raw characteristic values.
    """

    def __init__(self, message: str, *, reason: TransportErrorReason = "write") -> None:
        super().__init__(message)
        self.reason: TransportErrorReason = reason


class ConnectionLostError(ZigbeeDirectError):
    """The node, generation or connection is gone; the operation cannot complete.

    Raised by every ``ZigbeeDirectNode`` API after ``close()``, used to fail pending requests at
    teardown, and raised by node APIs when the transport is broken (the ``TransportError`` is
    chained as ``__cause__``).
    """


class HandshakeRejectedError(HandshakeError):
    """The ZDD rejected our credentials: wrong network key (or wrong ZVD EUI for the BAK).

    Only two signals qualify: an ATT error with code exactly 0x80 on the SE3 write, or an SE4
    confirmation tag mismatch. Everything else is a retryable ``TransportError``.
    """


class JoinError(ZigbeeDirectError):
    """The NWK join (Commissioning Request/Response) failed or produced an invalid result."""


class JoinRejectedError(JoinError):
    """The Commissioning Response carried a non-zero status."""

    def __init__(self, status: int) -> None:
        super().__init__(f"commissioning rejected with status 0x{status:02X}")
        self.status = status


class RequestTimeoutError(ZigbeeDirectError, TimeoutError):
    """No matching response arrived for a ZDO/ZCL request after every attempt.

    ``dst`` is the NWK destination short, ``kind`` the correlation namespace and ``seq`` the ZDO
    sequence number or ZCL TSN that was used for every attempt.
    """

    def __init__(self, dst: int, kind: RequestKind, seq: int) -> None:
        super().__init__(f"no {kind} response from 0x{dst:04X} for seq {seq}")
        self.dst = dst
        self.kind: RequestKind = kind
        self.seq = seq


class RouteError(ZigbeeDirectError):
    """A NWK Network Status command reported a routing failure for ``dst``."""

    def __init__(self, dst: int, status: int) -> None:
        super().__init__(f"network status 0x{status:02X} for 0x{dst:04X}")
        self.dst = dst
        self.status = status


class ZclStatusError(ZigbeeDirectError):
    """A ZCL request failed with a status (Default Response, or a failed write record).

    ``attribute_id`` is set when the status belongs to one attribute (write response record).
    """

    def __init__(self, status: int, *, attribute_id: int | None = None) -> None:
        where = "" if attribute_id is None else f" for attribute 0x{attribute_id:04X}"
        super().__init__(f"ZCL status 0x{status:02X}{where}")
        self.status = status
        self.attribute_id = attribute_id


__all__ = [
    "ApsDecodeError",
    "AuthenticationError",
    "CommissioningDecodeError",
    "ConnectionLostError",
    "CounterExhaustedError",
    "DecodeError",
    "EncodeError",
    "HandshakeError",
    "HandshakeRejectedError",
    "JoinError",
    "JoinRejectedError",
    "NwkDecodeError",
    "ReplayError",
    "RequestKind",
    "RequestTimeoutError",
    "RouteError",
    "TlvDecodeError",
    "TransportError",
    "TransportErrorReason",
    "UnsupportedFrameError",
    "ZclDecodeError",
    "ZclStatusError",
    "ZdoDecodeError",
    "ZigbeeDirectError",
]
