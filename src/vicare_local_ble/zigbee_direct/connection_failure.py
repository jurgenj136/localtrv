"""Attempt failures of the connection supervisor and their safe, loggable description.

Private helper of ``connection_supervisor.py``. ``describe_failure`` turns the exception behind
a failed attempt into a short detail for the failure log line and ``last_failure_detail``:

* a ``TransportError`` (the exception itself or in its cause chain): its type, ``reason`` and
  message; transport messages never hold key material or raw characteristic values.
* any other library exception (``ZigbeeDirectError``): ``"<Type>: <message>"``; library
  messages carry only tag names, lengths, offsets, counters and status codes.
* anything else (bleak, backend, ``ValueError`` ...): the type name ONLY, since its message
  could hold anything.

Never a traceback, a ``repr`` or ``exc_info``.
"""

from __future__ import annotations

from vicare_local_ble.zigbee_direct.errors import TransportError, ZigbeeDirectError


class AttemptFailedError(Exception):
    """A connection attempt failed: ``reason`` is the short token, ``detail`` its description."""

    def __init__(self, reason: str, *, detail: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class CacheClearedError(Exception):
    """Stale GATT cache: clear it and reconnect at once."""


def transport_error(exc: BaseException) -> TransportError | None:
    """The ``TransportError`` that ``exc`` is or was caused by (node APIs chain it)."""
    seen: BaseException | None = exc
    for _ in range(8):  # bounded walk of the cause chain
        if seen is None:
            return None
        if isinstance(seen, TransportError):
            return seen
        seen = seen.__cause__ or seen.__context__
    return None  # pragma: no cover - absurdly long chain


def _own(exc: BaseException) -> str:
    if isinstance(exc, ZigbeeDirectError):
        return f"{type(exc).__name__}: {exc}"
    return type(exc).__name__


def describe_failure(exc: BaseException) -> str:
    """A key-free description of ``exc`` (see module docstring)."""
    transport = transport_error(exc)
    if transport is None:
        return _own(exc)
    inner = f"{type(transport).__name__}(reason={transport.reason}): {transport}"
    if transport is exc:
        return inner
    return f"{_own(exc)} <- {inner}"


__all__ = ["AttemptFailedError", "CacheClearedError", "describe_failure", "transport_error"]
