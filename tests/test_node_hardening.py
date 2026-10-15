"""ZigbeeDirectNode CP3 hardening (T11): secret lifetime, close races, timeout races, config,
per-destination allocation."""

from __future__ import annotations

import asyncio
import contextlib
import gc
import warnings
from typing import TYPE_CHECKING, Any

import pytest

from test_node import LOCAL_TEMPERATURE, THERMOSTAT, Rig, rig
from test_node_requests import read, zcl_aps, zcl_tsns
from vicare_local_ble.testing import network_frames as nf
from vicare_local_ble.zigbee_direct.codec.aps import HA_PROFILE_ID
from vicare_local_ble.zigbee_direct.codec.commissioning import CommissioningStatus
from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame, NwkFrameType
from vicare_local_ble.zigbee_direct.codec.nwk_commands import (
    CommissioningRequest,
    decode_nwk_command,
)
from vicare_local_ble.zigbee_direct.errors import (
    CommissioningDecodeError,
    ConnectionLostError,
    JoinError,
    SequenceExhaustedError,
    TransportError,
)
from vicare_local_ble.zigbee_direct.node import NetworkSummary, NodeConfig
from vicare_local_ble.zigbee_direct.node_types import MIN_MTORR_INTERVAL
from vicare_local_ble.zigbee_direct.requests import Envelope
from vicare_local_ble.zigbee_direct.transport import ZigbeeDirectTransport
from vicare_local_ble.zigbee_direct.types import SecretBytes

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from types import TracebackType

    from vicare_local_ble.zigbee_direct.clock import VirtualClock

DUMMY_KEY = bytes(range(0xA0, 0xB0))  # stands in for decrypted key material


class RaceClock:
    """Wraps a ``VirtualClock``; when a ``timeout`` expires, ``on_timeout`` runs first, in the
    same loop iteration (a response racing the timeout)."""

    def __init__(self, inner: VirtualClock) -> None:
        self.inner = inner
        self.on_timeout: Callable[[int], None] | None = None
        self.expired = 0

    def now(self) -> float:
        return self.inner.now()

    async def sleep(self, seconds: float) -> None:
        await self.inner.sleep(seconds)

    def call_later(self, delay: float, callback: Callable[[], object]) -> Any:
        return self.inner.call_later(delay, callback)

    @contextlib.asynccontextmanager
    async def timeout(self, delay: float | None) -> AsyncIterator[None]:
        try:
            async with self.inner.timeout(delay):
                yield
        except TimeoutError:
            self.expired += 1
            if self.on_timeout is not None:
                self.on_timeout(self.expired)
            raise


def race_clock(r: Rig) -> RaceClock:
    clock = RaceClock(r.clock)
    r.core._clock = clock
    return clock


def _holds_secret(value: object) -> bool:
    if isinstance(value, CommissioningStatus):
        return True
    if isinstance(value, bytes | bytearray):
        return DUMMY_KEY in value
    return isinstance(value, SecretBytes) and value.reveal() == DUMMY_KEY


def secrets_in_frames(tb: TracebackType | None) -> list[str]:
    """Names of traceback-frame locals that hold the dummy key or a full status."""
    found = []
    while tb is not None:
        found += [name for name, value in tb.tb_frame.f_locals.items() if _holds_secret(value)]
        tb = tb.tb_next
    return found


# --- 1. secret lifetime ----------------------------------------------------------------------


async def test_malformed_status_join_error_has_no_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def malformed(_self: ZigbeeDirectTransport) -> CommissioningStatus:
        plaintext = b"\x03\x0f" + DUMMY_KEY  # a decrypted network key TLV as a local
        raise CommissioningDecodeError(f"bad status ({len(plaintext)} B)")

    async with rig(join=False) as r:
        monkeypatch.setattr(ZigbeeDirectTransport, "read_commissioning_status", malformed)
        with pytest.raises(JoinError, match="malformed") as exc:
            await r.clock.run_task(r.node.join())
        # a codec message is never used, only its safe_detail (unset here) or its type
        assert str(exc.value) == "malformed Commissioning Status (CommissioningDecodeError)"
        assert exc.value.__cause__ is None
        assert exc.value.__context__ is None
        assert secrets_in_frames(exc.value.__traceback__) == []


async def test_summary_failure_join_error_has_no_context(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_cls: type[NetworkSummary], status: CommissioningStatus) -> NetworkSummary:
        key = SecretBytes(DUMMY_KEY)
        raise RuntimeError(f"unexpected {key!r} in {type(status).__name__}")

    async with rig(join=False) as r:
        monkeypatch.setattr(NetworkSummary, "from_status", classmethod(broken))
        with pytest.raises(JoinError, match="unusable") as exc:
            await r.clock.run_task(r.node.join())
        assert str(exc.value) == "unusable Commissioning Status: RuntimeError"  # type only
        assert exc.value.__cause__ is None
        assert exc.value.__context__ is None
        assert secrets_in_frames(exc.value.__traceback__) == []
        assert r.writes() == []


# --- 2./3./guard: close races ----------------------------------------------------------------


async def test_close_during_commissioning_send_leaves_nothing_unretrieved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contexts: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: contexts.append(ctx))
    try:
        async with rig(join=False) as r:

            async def slow_send(
                _self: ZigbeeDirectTransport, npdu: bytes, *, secure: bool, check: object = None
            ) -> None:
                await r.clock.sleep(5.0)
                raise TransportError("gone", reason="closed")

            monkeypatch.setattr(ZigbeeDirectTransport, "send_npdu", slow_send)
            join = asyncio.ensure_future(r.node.join())
            await r.clock.advance(1.0)  # the Commissioning Request write is in flight
            await r.node.close()
            await r.clock.advance(5.0)
            with pytest.raises(ConnectionLostError):
                await join
            del join
        gc.collect()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous)
    assert [c for c in contexts if "never retrieved" in str(c.get("message"))] == []


async def test_concurrent_closes_both_wait_for_the_tasks() -> None:
    async with rig() as r:
        nested: list[str] = []

        async def stubborn() -> None:
            try:
                await r.clock.sleep(1000.0)
            except asyncio.CancelledError:
                await r.node.close()  # from a node task: returns at once, no self-deadlock
                nested.append("returned")
                await r.clock.sleep(1.0)  # slow cleanup
                raise

        r.core.start_task(stubborn(), name="stubborn")
        await r.clock.advance(0)
        first = asyncio.ensure_future(r.node.close())
        second = asyncio.ensure_future(r.node.close())
        await r.clock.advance(0)
        assert nested == ["returned"]
        assert not first.done()
        assert not second.done()  # waits for the first close, not just the closed flag
        assert r.core.task_count == 1
        await r.clock.advance(1.0)
        assert first.done()
        assert second.done()
        assert r.core.task_count == 0


async def test_task_cancelled_before_start_is_not_a_never_awaited_coroutine() -> None:
    async with rig() as r:

        async def quick() -> None:
            await r.clock.sleep(0)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            r.core.start_task(quick(), name="never-started")
            await r.node.close()  # cancels it before its first step
            gc.collect()
        assert [w for w in caught if issubclass(w.category, RuntimeWarning)] == []
        assert r.core.task_count == 0


# --- 4. timeout races ------------------------------------------------------------------------


@pytest.mark.parametrize("racing_attempt", [1, 2])
async def test_answer_racing_a_timeout_wins(racing_attempt: int) -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        valve.drop_rate = 1.0
        tsn = r.core.allocators.tsn.peek()
        clock = race_clock(r)

        def answer(expired: int) -> None:
            if expired == racing_attempt:
                r.inject(r.from_valve(valve.short, zcl_aps(tsn)))

        clock.on_timeout = answer
        records = await r.clock.run_task(
            r.node.zcl_read(valve.short, 1, THERMOSTAT, [LOCAL_TEMPERATURE])
        )
        assert records[0].attribute_id == LOCAL_TEMPERATURE
        assert r.node.stats.timeouts == 0
        assert len(zcl_tsns(r)) == racing_attempt  # no retransmit after an early answer


async def test_commissioning_response_racing_the_join_timeout_is_used() -> None:
    async with rig(join=False, network={"commissioning_delay": 100.0}) as r:
        clock = race_clock(r)

        def answer(expired: int) -> None:
            token = r.core.join_slot.active
            assert token is not None
            r.inject(
                nf.commissioning_response_npdu(
                    placeholder=token.placeholder,
                    zdd_short=token.zdd_short,
                    seq=9,
                    short=token.placeholder,
                    status=0,
                    zvd=token.own_eui,
                ),
                secure=False,
            )

        clock.on_timeout = answer
        info = await r.clock.run_task(r.node.join())
        frames = [NwkFrame.decode(w) for w in r.writes()]
        requests = [
            f
            for f in frames
            if f.frame_type is NwkFrameType.COMMAND
            and isinstance(decode_nwk_command(f.payload), CommissioningRequest)
        ]
        assert len(requests) == 1  # no second attempt
        assert info.own_short == info.requested_short == requests[0].src


# --- 8. NodeConfig validation ----------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_in_flight": 0},
        {"request_attempts": 0},
        {"join_attempts": 0},
        {"mtorr_count": 0},
        {"request_timeout": 0.0},
        {"request_timeout": float("nan")},
        {"join_timeout": -1.0},
        {"join_timeout": float("inf")},
        {"rreq_dedupe_ttl": 0.0},
        {"late_window": -1.0},
        {"mtorr_spacing": -0.5},
        {"mtorr_interval": MIN_MTORR_INTERVAL / 2},
        {"preferred_short": 0x0000},
        {"preferred_short": 0xFFF8},
    ],
)
def test_node_config_rejects_out_of_range_values(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=next(iter(kwargs))):
        NodeConfig(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"late_window": 0.0},
        {"mtorr_spacing": 0.0},
        {"mtorr_interval": MIN_MTORR_INTERVAL},
        {"mtorr_interval": 0.0},  # disabled (T12)
        {"mtorr_interval": float("nan")},  # disabled (T12)
        {"preferred_short": 0x0001},
        {"preferred_short": 0xFFF7},
    ],
)
def test_node_config_accepts_edge_values(kwargs: dict[str, Any]) -> None:
    NodeConfig(**kwargs)


# --- 9. per-destination allocation -----------------------------------------------------------


async def test_tsn_collisions_are_per_destination() -> None:
    async with rig() as r:
        tsn = r.core.allocators.tsn.peek()
        await r.clock.run_task(read(r, 0))
        r.core.allocators.tsn._next = tsn  # the same TSN, for another valve
        await r.clock.run_task(read(r, 1))
        assert zcl_tsns(r) == [tsn, tsn]
        r.core.allocators.tsn._next = tsn  # but not again for valve 0 inside the window
        await r.clock.run_task(read(r, 0))
        assert zcl_tsns(r)[-1] == tsn + 1


async def test_sequence_exhaustion_is_a_library_error() -> None:
    async with rig() as r:
        valve = r.inst.valves[0]
        for seq in range(256):
            envelope = Envelope(
                src_short=valve.short,
                kind="zcl",
                seq=seq,
                profile_id=HA_PROFILE_ID,
                cluster_id=THERMOSTAT,
            )
            r.core.pending.register(envelope)
            r.core.pending.retire(envelope.key)
        with pytest.raises(SequenceExhaustedError):
            await r.clock.run_task(read(r, 0))
        records = await r.clock.run_task(read(r, 1))  # other destinations are unaffected
        assert records[0].status == 0
