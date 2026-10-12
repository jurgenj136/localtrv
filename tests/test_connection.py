"""ZdConnection (T13): READY, resolver, backoff and lifecycle, against the simulator.

Shared helpers live here (``test_connection_*.py`` import them). Everything runs on
``VirtualClock`` with production constants; keys and EUIs are dummies from
``default_installation``.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest

from vicare_local_ble.testing.scenario import default_installation
from vicare_local_ble.zigbee_direct.connection import (
    BACKOFF_JITTER,
    BACKOFF_SCHEDULE,
    ConnectionState,
    Generation,
    ZdConnection,
)
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError
from vicare_local_ble.zigbee_direct.types import SecretBytes

if TYPE_CHECKING:
    from collections.abc import Callable

    from bleak.backends.device import BLEDevice

    from vicare_local_ble.testing.scenario import Installation
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.connection import DeviceResolver

LOGGER = "vicare_local_ble.zigbee_direct.connection"
S = ConnectionState


@dataclass
class Rig:
    inst: Installation
    conn: ZdConnection
    states: list[tuple[ConnectionState, float]] = field(default_factory=list)

    @property
    def clock(self) -> VirtualClock:
        return self.inst.clock

    def entered(self, state: ConnectionState) -> list[float]:
        """Virtual times at which ``state`` was entered."""
        return [t for s, t in self.states if s is state]

    def sequence(self) -> list[ConnectionState]:
        return [s for s, _ in self.states]

    def backoffs(self) -> list[float]:
        """Wait before each attempt after the first: time from BACKOFF to the next CONNECTING."""
        out: list[float] = []
        backoff: float | None = None
        for state, t in self.states:
            if state is S.BACKOFF:
                backoff = t
            elif state is S.CONNECTING and backoff is not None:
                out.append(t - backoff)
                backoff = None
        return out


def make_rig(
    *,
    seed: int = 0,
    network_key: SecretBytes | None = None,
    resolver: DeviceResolver | None = None,
    **kwargs: Any,
) -> Rig:
    inst = default_installation(n_valves=2, behind_router=0, seed=seed)
    conn = ZdConnection(
        resolver if resolver is not None else inst.resolver,
        own_eui=inst.zvd_eui,
        network_key=network_key if network_key is not None else inst.network_key,
        clock=inst.clock,
        connector=inst.connector,
        rng=random.Random(seed),  # noqa: S311
        **kwargs,
    )
    rig = Rig(inst, conn)
    conn.add_state_listener(lambda state: rig.states.append((state, inst.clock.now())))
    return rig


async def start(r: Rig, *, timeout: float = 90.0, limit: float = 86_400.0) -> Generation:
    return await r.clock.run_task(r.conn.start(first_ready_timeout=timeout), limit=limit)


async def stop(r: Rig) -> None:
    await r.clock.run_task(r.conn.stop())


async def run_until(clock: VirtualClock, done: Callable[[], bool], limit: float = 3600.0) -> None:
    """Advance timer by timer until ``done()``; fails after ``limit`` virtual seconds."""
    deadline = clock.now() + limit
    await clock.run_until_idle()
    while not done():
        when = clock.next_deadline()
        assert when is not None, "blocked with no timer"
        assert when <= deadline, "condition not reached in time"
        await clock.advance_to(when)


def assert_no_tasks() -> None:
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def ready_again(r: Rig, after: int) -> Generation:
    """Run until a generation newer than ``after`` is READY."""
    await run_until(r.clock, lambda: r.conn.current is not None and r.conn.current.number > after)
    gen = r.conn.current
    assert gen is not None
    return gen


# --- READY ------------------------------------------------------------------------------------


async def test_ready_right_after_join() -> None:
    r = make_rig()
    seen: list[tuple[Generation, ConnectionState, bool]] = []
    r.conn.add_ready_listener(lambda gen: seen.append((gen, r.conn.state, r.conn.current is gen)))
    assert r.conn.state is S.IDLE
    assert r.conn.current is None
    gen = await start(r)
    assert seen == [(gen, S.READY, True)]
    assert gen.number == 1
    assert gen.join == gen.node.join_info == r.conn.last_join
    assert gen.join.zdd_eui == r.inst.zdd_eui
    assert r.inst.network.gated_open  # joined and routed
    assert r.sequence() == [S.CONNECTING, S.JOINING, S.READY]
    stats = r.conn.stats
    assert (stats.attempts, stats.connects, stats.generation) == (1, 1, 1)
    assert stats.ready_since == r.clock.now()
    assert stats.mtu == 247
    assert not stats.mtu_low
    assert r.conn.last_node_stats is gen.node.stats  # live while READY
    assert "ZdConnection" in repr(r.conn)
    await stop(r)
    assert_no_tasks()


async def test_listener_unsubscribe_and_listener_errors_are_swallowed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    r = make_rig()
    calls: list[str] = []

    def boom(_gen: Generation) -> None:
        raise RuntimeError("listener bug")

    r.conn.add_ready_listener(boom)
    unsubscribe = r.conn.add_ready_listener(lambda _gen: calls.append("x"))
    unsubscribe()
    unsubscribe()  # idempotent
    await start(r)
    assert calls == []
    assert "connection listener raised" in caplog.text
    await stop(r)


async def test_resolver_called_before_each_attempt_and_proxy_switch() -> None:
    inst_holder: list[Installation] = []
    sources = iter(["hci0", None, "proxy-1", "proxy-2"])
    calls: list[str | None] = []

    def resolver() -> BLEDevice | None:
        source = next(sources)
        calls.append(source)
        return None if source is None else inst_holder[0].r0.ble_device(source=source)

    r = make_rig(resolver=resolver)
    inst_holder.append(r.inst)
    gen1 = await start(r)
    assert calls == ["hci0"]
    r.inst.r0.disconnect()  # the adapter goes away
    gen2 = await ready_again(r, gen1.number)
    assert calls == ["hci0", None, "proxy-1"]  # not_found, then the other proxy
    assert r.conn.stats.last_failure == "not_found"
    assert [d.details["source"] for d in r.inst.connector.devices] == ["hci0", "proxy-1"]
    assert gen2.number == 2
    assert r.conn.stats.attempts == 3
    await stop(r)
    assert_no_tasks()


async def test_resolver_exception_counts_as_not_found() -> None:
    attempts: list[int] = []

    def resolver() -> BLEDevice | None:
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("bluetooth stack hiccup")
        return r.inst.r0.ble_device()

    r = make_rig(resolver=resolver)
    await start(r)
    assert r.conn.stats.last_failure == "not_found"
    assert len(attempts) == 2
    await stop(r)


# --- backoff ----------------------------------------------------------------------------------


@pytest.mark.parametrize("seed", [0, 1, 2])
async def test_backoff_sequence_with_jitter_and_cap(seed: int) -> None:
    r = make_rig(seed=seed)
    failures = len(BACKOFF_SCHEDULE) + 2
    r.inst.connector.fail_next(failures)
    await start(r, timeout=10_000.0)
    waits = r.backoffs()
    expected = [*BACKOFF_SCHEDULE, BACKOFF_SCHEDULE[-1], BACKOFF_SCHEDULE[-1]]
    assert len(waits) == failures
    for wait, base in zip(waits, expected, strict=True):
        assert base * (1 - BACKOFF_JITTER) <= wait <= base * (1 + BACKOFF_JITTER)
    assert len({round(w / b, 6) for w, b in zip(waits, expected, strict=True)}) > 1  # jittered
    assert r.conn.stats.connect_failures == failures
    assert r.conn.stats.backoff is None  # cleared at READY
    await stop(r)


async def test_backoff_is_deterministic_for_a_seed() -> None:
    runs: list[list[float]] = []
    for _ in range(2):
        r = make_rig(seed=7)
        r.inst.connector.fail_next(4)
        await start(r, timeout=10_000.0)
        runs.append(r.backoffs())
        await stop(r)
    assert runs[0] == runs[1]


async def test_start_timeout_keeps_retrying_in_background() -> None:
    r = make_rig()
    r.inst.connector.fail_next(6)  # 2+5+10+30+60 s of waits > 30 s
    with pytest.raises(TimeoutError):
        await start(r, timeout=30.0)
    assert r.conn.state in {S.BACKOFF, S.CONNECTING}
    await ready_again(r, 0)
    assert r.conn.stats.connect_failures == 6
    await stop(r)
    assert_no_tasks()


async def _wait_for_backoff(r: Rig, count: int) -> None:
    await run_until(r.clock, lambda: len(r.entered(S.BACKOFF)) >= count)


async def test_notify_seen_shortens_a_long_wait() -> None:
    r = make_rig()
    r.inst.connector.fail_next(5)
    task = asyncio.ensure_future(r.conn.start(first_ready_timeout=10_000.0))
    await _wait_for_backoff(r, 1)
    r.conn.notify_seen()  # a 2 s wait is not shortened
    await _wait_for_backoff(r, 5)  # the 60 s step (48..72 s)
    wait = r.conn.stats.backoff
    assert wait is not None
    assert wait >= 48.0
    t0 = r.clock.now()
    await r.clock.advance(10.0)
    r.conn.notify_seen()
    r.conn.notify_seen()  # once per wait
    await run_until(r.clock, lambda: len(r.entered(S.CONNECTING)) == 6)
    assert r.entered(S.CONNECTING)[-1] - t0 == pytest.approx(12.0)
    assert r.backoffs()[0] == pytest.approx(BACKOFF_SCHEDULE[0], rel=BACKOFF_JITTER)
    await r.clock.run_task(task)
    r.conn.notify_seen()  # READY: no-op
    await stop(r)
    assert_no_tasks()


async def test_notify_seen_ignores_wait_nearly_over() -> None:
    r = make_rig()
    r.inst.connector.fail_next(5)
    task = asyncio.ensure_future(r.conn.start(first_ready_timeout=10_000.0))
    await _wait_for_backoff(r, 5)  # 60 s step: 48..72 s
    wait = r.conn.stats.backoff
    assert wait is not None
    t0 = r.entered(S.BACKOFF)[-1]
    await r.clock.advance_to(t0 + wait - 1.0)
    r.conn.notify_seen()  # 1 s left: unchanged
    await run_until(r.clock, lambda: len(r.entered(S.CONNECTING)) == 6)
    assert r.entered(S.CONNECTING)[-1] - t0 == pytest.approx(wait)
    await r.clock.run_task(task)
    await stop(r)


@pytest.mark.parametrize(("ready_for", "expected_base"), [(60.0, 30.0), (600.0, 2.0)])
async def test_backoff_resets_after_ten_minutes_ready(
    ready_for: float, expected_base: float
) -> None:
    r = make_rig()
    r.inst.connector.fail_next(3)  # waits 2, 5, 10: next step is 30
    gen = await start(r, timeout=10_000.0)
    await r.clock.advance(ready_for)
    r.inst.r0.disconnect()
    await _wait_for_backoff(r, 4)
    wait = r.conn.stats.backoff
    assert wait is not None
    assert expected_base * (1 - BACKOFF_JITTER) <= wait <= expected_base * (1 + BACKOFF_JITTER)
    assert r.conn.stats.last_failure == "disconnect"
    assert r.conn.stats.disconnects == 1
    await ready_again(r, gen.number)
    await stop(r)


async def test_warning_after_three_connect_failures(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    r = make_rig()
    r.inst.connector.fail_next(2)
    await start(r, timeout=10_000.0)
    assert not [rec for rec in caplog.records if rec.levelno >= logging.WARNING]
    r.inst.connector.fail_next(4)
    r.inst.r0.disconnect()
    await ready_again(r, 1)
    warnings = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
    assert len(warnings) == 1  # one per streak, at the third failure
    assert "vendor app" in warnings[0].getMessage()
    assert "3 connection attempts" in warnings[0].getMessage()
    await stop(r)


# --- lifecycle --------------------------------------------------------------------------------


async def test_start_twice_raises() -> None:
    r = make_rig()
    await start(r)
    with pytest.raises(RuntimeError):
        await r.conn.start()
    await stop(r)
    with pytest.raises(RuntimeError):
        await r.conn.start()


async def test_stop_is_idempotent_and_leaves_no_tasks() -> None:
    r = make_rig()
    gen = await start(r)
    assert gen.node.stats.mtorr_sent >= 1
    first = asyncio.ensure_future(r.conn.stop())
    second = asyncio.ensure_future(r.conn.stop())  # concurrent: waits for the first
    await r.clock.run_task(asyncio.gather(first, second))
    await stop(r)  # and again afterwards
    assert r.conn.state is S.STOPPED
    assert r.sequence()[-2:] == [S.IDLE, S.STOPPED]  # left READY first
    assert r.conn.current is None
    assert gen.node.closed
    assert r.inst.r0.client is None  # disconnected
    assert_no_tasks()


async def test_stop_before_start() -> None:
    r = make_rig()
    await stop(r)
    assert r.conn.state is S.STOPPED
    assert_no_tasks()


async def test_stop_during_start_raises_connection_lost() -> None:
    r = make_rig()
    r.inst.connector.hang_next()
    task = asyncio.ensure_future(r.conn.start())
    await r.clock.advance(1.0)
    assert r.conn.state is S.CONNECTING
    await stop(r)
    with pytest.raises(ConnectionLostError):
        await task
    assert r.sequence()[-1] is S.STOPPED
    assert_no_tasks()


@pytest.mark.parametrize("phase", [S.JOINING, S.BACKOFF])
async def test_stop_in_any_phase(phase: ConnectionState) -> None:
    r = make_rig()
    if phase is S.BACKOFF:
        r.inst.connector.fail_next(1)
    task = asyncio.ensure_future(r.conn.start())
    await run_until(r.clock, lambda: r.conn.state is phase)
    await stop(r)
    with pytest.raises(ConnectionLostError):
        await task
    assert r.conn.state is S.STOPPED
    assert r.inst.r0.client is None
    assert_no_tasks()


async def test_default_rng_and_config() -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    conn = ZdConnection(
        inst.resolver,
        own_eui=inst.zvd_eui,
        network_key=inst.network_key,
        clock=inst.clock,
        connector=inst.connector,
    )
    assert conn.node_config.avoid_shorts == frozenset()
    assert conn.recorder is None
    assert conn.transport_stats is None
    assert conn.last_join is None
    assert conn.last_node_stats is None
    gen = await inst.clock.run_task(conn.start())
    assert gen.number == 1
    await inst.clock.run_task(conn.stop())


def test_network_key_is_not_retained() -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    conn = ZdConnection(
        inst.resolver,
        own_eui=inst.zvd_eui,
        network_key=inst.network_key,
        clock=inst.clock,
        connector=inst.connector,
    )
    secret = inst.network_key.reveal()
    for value in vars(conn).values():
        assert value is not inst.network_key
        if isinstance(value, SecretBytes):
            assert value.reveal() != secret
