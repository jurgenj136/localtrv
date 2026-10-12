"""ZdConnection (T13): auth, handshake faults, stale GATT cache, address conflicts, issues."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from test_connection import S, assert_no_tasks, make_rig, ready_again, run_until, start, stop
from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.testing.errors import GATT_ERROR_REJECTED
from vicare_local_ble.testing.gatt_client import FakeBleakClient
from vicare_local_ble.zigbee_direct.connection import ConnectionIssue
from vicare_local_ble.zigbee_direct.errors import HandshakeRejectedError
from vicare_local_ble.zigbee_direct.node import NodeConfig
from vicare_local_ble.zigbee_direct.transport import ZigbeeDirectTransport
from vicare_local_ble.zigbee_direct.types import BROADCAST_RX_ON, SecretBytes

if TYPE_CHECKING:
    from collections.abc import Callable

    from test_connection import Rig
    from vicare_local_ble.zigbee_direct.connection import ConnectionState, Generation
    from vicare_local_ble.zigbee_direct.transport import SessionInfo

WRONG_KEY = SecretBytes(b"\x99" * 16)  # dummy


def on_attempt(r: Rig, actions: dict[int, Callable[[], None]]) -> None:
    """Run ``actions[n]`` when attempt ``n`` (1-based) enters CONNECTING."""
    count = [0]

    def listener(state: ConnectionState) -> None:
        if state is S.CONNECTING:
            count[0] += 1
            action = actions.get(count[0])
            if action is not None:
                action()

    r.conn.add_state_listener(listener)


# --- auth -------------------------------------------------------------------------------------


async def test_auth_twice_stops_and_start_raises() -> None:
    r = make_rig(network_key=WRONG_KEY)
    with pytest.raises(HandshakeRejectedError):
        await start(r)
    assert r.conn.state is S.AUTH_FAILED
    assert r.conn.stats.auth_failures == 2
    assert r.conn.stats.last_failure == "auth"
    assert r.inst.r0.connect_count == 2
    assert r.inst.r0.client is None
    await r.clock.advance(3600.0)
    assert r.inst.r0.connect_count == 2  # the supervisor stopped
    await stop(r)
    assert r.sequence()[-1] is S.STOPPED
    assert_no_tasks()


async def test_single_rejection_is_retried() -> None:
    r = make_rig()
    r.inst.r0.se3_fault = "gatt_error"
    r.inst.r0.se3_error_code = GATT_ERROR_REJECTED  # ATT 0x80: a rejection
    on_attempt(r, {2: lambda: setattr(r.inst.r0, "se3_fault", "none")})
    gen = await start(r)
    assert gen.number == 1
    assert r.conn.stats.auth_failures == 1
    assert r.conn.state is S.READY
    await stop(r)


async def test_non_0x80_se3_failure_retries_without_auth() -> None:
    r = make_rig()
    r.inst.r0.se3_fault = "gatt_error"  # ATT 0x0E: retryable
    on_attempt(r, {4: lambda: setattr(r.inst.r0, "se3_fault", "none")})
    await start(r, timeout=10_000.0)
    assert r.conn.stats.auth_failures == 0
    assert r.conn.stats.attempts == 4
    assert r.conn.stats.last_failure == "transport:write"
    assert r.conn.stats.last_transport_error == "write"
    await stop(r)


async def test_other_failure_resets_auth_counter() -> None:
    r = make_rig()
    r0 = r.inst.r0
    r0.se3_error_code = GATT_ERROR_REJECTED

    def reject() -> None:
        r0.se3_fault = "gatt_error"

    def connect_fails() -> None:
        r0.se3_fault = "none"
        r.inst.connector.fail_next(1)

    on_attempt(
        r, {1: reject, 2: connect_fails, 3: reject, 4: lambda: setattr(r0, "se3_fault", "none")}
    )
    await start(r, timeout=10_000.0)
    assert r.conn.stats.auth_failures == 2
    assert r.conn.state is S.READY
    await stop(r)


async def test_handshake_timeout_is_retryable() -> None:
    r = make_rig()
    r.inst.r0.handshake_fault = "se2_silence"
    on_attempt(r, {2: lambda: setattr(r.inst.r0, "handshake_fault", "none")})
    await start(r)
    assert r.conn.stats.last_failure == "transport:timeout"
    await stop(r)


async def test_join_failure_backs_off() -> None:
    r = make_rig()
    r.inst.r0.status_omit_short = True  # the join cannot complete
    on_attempt(r, {2: lambda: setattr(r.inst.r0, "status_omit_short", False)})
    await start(r)
    assert r.conn.stats.last_failure == "join"
    assert r.entered(S.BACKOFF)
    await stop(r)


# --- stale GATT cache -------------------------------------------------------------------------


async def test_missing_characteristic_clears_cache_once_and_reconnects() -> None:
    r = make_rig()
    r.inst.r0.stale_services = True
    gen = await start(r)
    assert gen.number == 1
    assert r.conn.stats.cache_clears == 1
    assert r.conn.stats.attempts == 2
    assert S.BACKOFF not in r.sequence()  # immediate reconnect
    assert r.conn.stats.last_transport_error == "missing_characteristic"
    await stop(r)


async def test_second_missing_characteristic_backs_off(monkeypatch: pytest.MonkeyPatch) -> None:
    r = make_rig()
    r0 = r.inst.r0
    r0.stale_services = True

    async def useless_clear(self: FakeBleakClient) -> bool:
        return True  # the cache stays stale

    monkeypatch.setattr(FakeBleakClient, "clear_cache", useless_clear)
    unsubscribe = r.conn.add_state_listener(
        lambda state: setattr(r0, "stale_services", False) if state is S.BACKOFF else None
    )
    await start(r)
    assert r.conn.stats.cache_clears == 1
    assert r.conn.stats.attempts == 3
    assert r.sequence().count(S.BACKOFF) == 1
    assert r.conn.stats.last_failure == "transport:missing_characteristic"
    # the once-flag resets after READY
    monkeypatch.undo()
    unsubscribe()
    r0.stale_services = True
    r0.disconnect()
    await ready_again(r, 1)
    assert r.conn.stats.cache_clears == 2
    await stop(r)


# --- address conflict -------------------------------------------------------------------------


async def test_address_conflict_rejoins_avoiding_old_short() -> None:
    r = make_rig(node_config=NodeConfig(preferred_short=0x1234))
    gen1 = await start(r)
    assert gen1.join.own_short == 0x1234
    r.inst.network.address_conflict()
    gen2 = await ready_again(r, gen1.number)
    assert r.conn.stats.address_conflicts == 1
    assert r.conn.stats.last_failure == "address_conflict"
    assert gen2.join.own_short != 0x1234
    assert 0x1234 in gen2.node.config.avoid_shorts
    assert gen2.node.config.preferred_short is None
    assert r.conn.node_config.preferred_short is None
    await stop(r)


async def test_address_conflict_deduplicated_per_generation() -> None:
    r = make_rig()
    gen1 = await start(r)
    own = gen1.join.own_short
    for seq in (0x41, 0x42, 0x43):  # several 0x0D frames in one burst
        r.inst.r0.indicate_npdu(
            nf.network_status_npdu(
                dst=BROADCAST_RX_ON,
                src=r.inst.r0.zdd_short,
                seq=seq,
                status=nf.NETWORK_STATUS_ADDRESS_CONFLICT,
                about=own,
            )
        )
    await ready_again(r, gen1.number)
    await r.clock.advance(60.0)
    assert r.conn.stats.address_conflicts == 1
    assert r.conn.stats.generation == 2
    assert r.conn.state is S.READY
    await stop(r)


async def test_update_node_config_cannot_erase_conflict_set() -> None:
    r = make_rig()
    gen1 = await start(r)
    old = gen1.join.own_short
    r.inst.network.address_conflict()
    gen2 = await ready_again(r, gen1.number)
    r.conn.update_node_config(avoid_shorts=frozenset({0x0BAD}), preferred_short=old)
    assert gen2.node.config.avoid_shorts == frozenset({old})  # the current node keeps its config
    assert r.conn.node_config.avoid_shorts == frozenset({0x0BAD, old})
    assert r.conn.node_config.preferred_short == old  # stored, but avoided by the node
    r.conn.request_rejoin(gen2, "test")
    gen3 = await ready_again(r, gen2.number)
    assert gen3.node.config.avoid_shorts == frozenset({0x0BAD, old})
    assert gen3.join.own_short not in {0x0BAD, old}
    with pytest.raises(TypeError):
        r.conn.update_node_config(no_such_field=1)
    await stop(r)


# --- repair issues ----------------------------------------------------------------------------


async def test_mtu_issue_raised_and_cleared() -> None:
    r = make_rig()
    issues: list[tuple[ConnectionIssue, bool]] = []
    r.conn.add_issue_listener(lambda issue, active: issues.append((issue, active)))
    r.inst.r0.mtu_size = 100
    gen1 = await start(r)
    assert issues == [(ConnectionIssue.MTU_TOO_SMALL, True)]
    assert r.conn.stats.mtu_low
    r.conn.request_rejoin(gen1, "same")
    gen2 = await ready_again(r, gen1.number)
    assert issues == [(ConnectionIssue.MTU_TOO_SMALL, True)]  # still low: no repeat
    r.inst.r0.mtu_size = 247
    r.conn.request_rejoin(gen2, "bigger")
    await ready_again(r, gen2.number)
    assert issues == [(ConnectionIssue.MTU_TOO_SMALL, True), (ConnectionIssue.MTU_TOO_SMALL, False)]
    assert not r.conn.stats.mtu_low
    await stop(r)


async def _large_read(r: Rig, gen: Generation) -> None:
    valve = r.inst.valves[0].short
    await gen.node.zcl_read(valve, 1, 0x0201, list(range(40)))  # frame > MTU - 3


async def test_long_write_issue_raised_and_cleared() -> None:
    r = make_rig()
    issues: list[tuple[ConnectionIssue, bool]] = []
    r.conn.add_issue_listener(lambda issue, active: issues.append((issue, active)))
    r.inst.r0.mtu_size = 70
    r.inst.r0.long_write_supported = False
    gen1 = await start(r)
    task = r.conn.spawn(gen1, _large_read(r, gen1), name="large read")
    gen2 = await ready_again(r, gen1.number)
    assert task.done()
    assert (ConnectionIssue.LONG_WRITE_UNSUPPORTED, True) in issues
    assert r.conn.stats.last_failure == "transport:long_write_unsupported"
    assert r.conn.stats.last_transport_error == "long_write_unsupported"
    r.conn.request_rejoin(gen2, "same mtu")
    gen3 = await ready_again(r, gen2.number)
    assert (ConnectionIssue.LONG_WRITE_UNSUPPORTED, False) not in issues
    r.inst.r0.mtu_size = 247
    r.conn.request_rejoin(gen3, "bigger mtu")
    await ready_again(r, gen3.number)
    assert issues[-2:] == [
        (ConnectionIssue.MTU_TOO_SMALL, False),
        (ConnectionIssue.LONG_WRITE_UNSUPPORTED, False),
    ]
    await stop(r)


async def test_disconnect_during_join_aborts_attempt() -> None:
    r = make_rig()
    task = asyncio.ensure_future(r.conn.start())
    await run_until(r.clock, lambda: r.conn.state is S.JOINING)
    r.inst.r0.disconnect()
    await r.clock.run_task(task)
    assert r.conn.stats.last_failure == "disconnect"
    assert r.conn.stats.disconnects == 1
    assert r.conn.stats.generation == 1
    await stop(r)
    assert_no_tasks()


async def test_clear_cache_failure_still_reconnects(monkeypatch: pytest.MonkeyPatch) -> None:
    r = make_rig()
    r0 = r.inst.r0
    r0.stale_services = True

    async def broken_clear(self: FakeBleakClient) -> bool:
        r0.stale_services = False
        raise OSError("cache file locked")

    monkeypatch.setattr(FakeBleakClient, "clear_cache", broken_clear)
    await start(r)
    assert r.conn.stats.cache_clears == 1
    assert S.BACKOFF not in r.sequence()
    await stop(r)


async def test_unexpected_open_error_is_a_handshake_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = make_rig()
    original = ZigbeeDirectTransport.open
    calls: list[int] = []

    async def flaky_open(self: ZigbeeDirectTransport) -> SessionInfo:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("backend bug")
        return await original(self)

    monkeypatch.setattr(ZigbeeDirectTransport, "open", flaky_open)
    await start(r)
    assert r.conn.stats.last_failure == "handshake"
    await stop(r)
