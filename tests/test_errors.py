"""Runtime error classes."""

from __future__ import annotations

from vicare_local_ble.zigbee_direct.errors import (
    ConnectionLostError,
    HandshakeError,
    HandshakeRejectedError,
    JoinError,
    JoinRejectedError,
    RequestTimeoutError,
    RouteError,
    TransportError,
    ZclStatusError,
    ZigbeeDirectError,
)


def test_transport_error_reason() -> None:
    assert TransportError("x").reason == "write"
    err = TransportError("too big", reason="long_write_unsupported")
    assert err.reason == "long_write_unsupported"
    assert str(err) == "too big"
    assert isinstance(err, ZigbeeDirectError)


def test_hierarchy() -> None:
    assert issubclass(HandshakeRejectedError, HandshakeError)
    assert issubclass(JoinRejectedError, JoinError)
    assert issubclass(ConnectionLostError, ZigbeeDirectError)
    assert issubclass(RequestTimeoutError, TimeoutError)
    assert not issubclass(ConnectionLostError, TransportError)


def test_fields_and_messages() -> None:
    rejected = JoinRejectedError(0x05)
    assert rejected.status == 0x05
    assert "0x05" in str(rejected)
    timeout = RequestTimeoutError(0x5E6F, "zcl", 0x2B)
    assert (timeout.dst, timeout.kind, timeout.seq) == (0x5E6F, "zcl", 0x2B)
    assert "0x5E6F" in str(timeout)
    route = RouteError(0x5E6F, 0x02)
    assert (route.dst, route.status) == (0x5E6F, 0x02)
    status = ZclStatusError(0x87, attribute_id=0x0012)
    assert (status.status, status.attribute_id) == (0x87, 0x0012)
    assert "0x0012" in str(status)
    assert ZclStatusError(0xC3).attribute_id is None
    assert str(ZclStatusError(0xC3)) == "ZCL status 0xC3"
