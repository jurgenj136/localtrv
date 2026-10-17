"""Per-characteristic incoming tracking and ZDD counter-model detection (docs/protocol.md §4)."""

from __future__ import annotations

import pytest

from vicare_local_ble.zigbee_direct.errors import AuthenticationError, ReplayError
from vicare_local_ble.zigbee_direct.session import CounterModel, SessionCipher
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes
from vicare_local_ble.zigbee_direct.uuids import (
    COMMISSIONING_SERVICE,
    COMMISSIONING_STATUS,
    TUNNEL_NPDU,
    TUNNEL_SERVICE,
)

KEY = SecretBytes(bytes(range(16)))  # secret-scan: allow
ZVD = Eui64.from_str("02:00:00:00:00:00:00:01")
ZDD = Eui64.from_str("02:00:00:00:00:00:00:02")

STATUS = (COMMISSIONING_SERVICE, COMMISSIONING_STATUS)
TUNNEL = (TUNNEL_SERVICE, TUNNEL_NPDU)


def zvd() -> SessionCipher:
    return SessionCipher(session_key=KEY, own_eui=ZVD, peer_eui=ZDD)


def zdd_sender(start: int = 1) -> SessionCipher:
    return SessionCipher(
        session_key=KEY, own_eui=ZDD, peer_eui=ZVD, _initial_outgoing_counter=start
    )


class SharedZdd:
    """One counter across characteristics."""

    def __init__(self) -> None:
        self._c = zdd_sender()

    def seal(self, which: tuple[str, str], data: bytes = b"x") -> bytes:
        return self._c.encrypt(*which, data)


class PerCharZdd:
    """One counter per characteristic (nonce reuse across characteristics)."""

    def __init__(self) -> None:
        self._c: dict[str, SessionCipher] = {}

    def seal(self, which: tuple[str, str], data: bytes = b"x") -> bytes:
        return self._c.setdefault(which[1], zdd_sender()).encrypt(*which, data)


def test_shared_model_detected() -> None:
    z, rx = SharedZdd(), zvd()
    assert rx.counter_model() is CounterModel.UNKNOWN
    rx.decrypt(*STATUS, z.seal(STATUS))
    assert rx.counter_model() is CounterModel.UNKNOWN  # only one characteristic seen
    rx.decrypt(*TUNNEL, z.seal(TUNNEL))
    assert rx.counter_model() is CounterModel.SHARED
    for _ in range(3):
        rx.decrypt(*TUNNEL, z.seal(TUNNEL))
    assert rx.counter_model() is CounterModel.SHARED


def test_per_characteristic_model_detected() -> None:
    z, rx = PerCharZdd(), zvd()
    rx.decrypt(*STATUS, z.seal(STATUS))
    assert rx.counter_model() is CounterModel.UNKNOWN
    rx.decrypt(*TUNNEL, z.seal(TUNNEL))  # counter 1 again, on another characteristic
    assert rx.counter_model() is CounterModel.PER_CHARACTERISTIC


def test_per_characteristic_accepts_lower_counter_on_other_characteristic() -> None:
    z, rx = PerCharZdd(), zvd()
    for _ in range(3):
        rx.decrypt(*TUNNEL, z.seal(TUNNEL))
    f = z.seal(STATUS)  # counter 1 < Tunnel's last 3, but fresh on Status
    assert rx.decrypt(*STATUS, f) == b"x"
    assert rx.incoming_counter == 3
    assert rx.counter_model() is CounterModel.PER_CHARACTERISTIC


def test_shared_model_accepts_tunnel_before_status_rise_only_per_characteristic() -> None:
    z, rx = SharedZdd(), zvd()
    rx.decrypt(*TUNNEL, z.seal(TUNNEL))  # counter 1
    rx.decrypt(*STATUS, z.seal(STATUS))  # counter 2, later than Tunnel's first
    assert rx.counter_model() is CounterModel.UNKNOWN  # tunnel first is not above status


def test_late_repeat_flips_shared_to_per_characteristic() -> None:
    z, rx = SharedZdd(), zvd()
    rx.decrypt(*STATUS, z.seal(STATUS))  # 1
    rx.decrypt(*TUNNEL, z.seal(TUNNEL))  # 2
    assert rx.counter_model() is CounterModel.SHARED
    rx.decrypt(*STATUS, zdd_sender(start=2).encrypt(*STATUS, b"s"))  # 2 repeats on Status
    assert rx.counter_model() is CounterModel.PER_CHARACTERISTIC


def test_per_characteristic_is_sticky() -> None:
    z, rx = PerCharZdd(), zvd()
    rx.decrypt(*STATUS, z.seal(STATUS))
    rx.decrypt(*TUNNEL, z.seal(TUNNEL))
    rx.decrypt(*TUNNEL, z.seal(TUNNEL))
    assert rx.counter_model() is CounterModel.PER_CHARACTERISTIC


def test_failed_frames_do_not_feed_detection() -> None:
    z, rx = SharedZdd(), zvd()
    bad = z.seal(STATUS)
    bad = bad[:-1] + bytes([bad[-1] ^ 0xFF])
    with pytest.raises(AuthenticationError):
        rx.decrypt(*STATUS, bad)
    assert rx.counter_model() is CounterModel.UNKNOWN
    assert rx.incoming_counter == 0


@pytest.mark.parametrize("zdd_cls", [SharedZdd, PerCharZdd])
def test_replay_still_rejected_per_characteristic(zdd_cls: type[SharedZdd | PerCharZdd]) -> None:
    z, rx = zdd_cls(), zvd()
    s1, t1 = z.seal(STATUS), z.seal(TUNNEL)
    rx.decrypt(*STATUS, s1)
    rx.decrypt(*TUNNEL, t1)
    with pytest.raises(ReplayError):
        rx.decrypt(*STATUS, s1)
    with pytest.raises(ReplayError):
        rx.decrypt(*TUNNEL, t1)
    t2 = z.seal(TUNNEL)
    rx.decrypt(*TUNNEL, t2)
    with pytest.raises(ReplayError):
        rx.decrypt(*TUNNEL, t1)  # out of order on the same characteristic


def test_replay_on_one_characteristic_does_not_block_another() -> None:
    z, rx = SharedZdd(), zvd()
    s1 = z.seal(STATUS)
    for _ in range(5):
        rx.decrypt(*TUNNEL, z.seal(TUNNEL))  # Tunnel counters 2..6 first
    # Status frame (counter 1) arrives late but is fresh on its own characteristic.
    assert rx.decrypt(*STATUS, s1) == b"x"


def test_repr_mentions_highest_counter() -> None:
    z, rx = SharedZdd(), zvd()
    rx.decrypt(*TUNNEL, z.seal(TUNNEL))
    assert "incoming_counter=1" in repr(rx)
