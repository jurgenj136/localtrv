"""Exception hierarchy for the Zigbee Direct library."""

from __future__ import annotations


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
