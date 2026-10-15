"""Bridge poll cycle, valve reads and topology re-walks (T14; internal, see ``bridge``).

Per valve: ``try_acquire`` the transaction lock (busy -> skipped), then the plan
``FAST`` (+ ``SLOW`` every ``SLOW_EVERY_N_POLLS``-th poll, + ``STATIC`` when due), one request
at a time. The first request without any response (timeout, route error) ends the valve's
cycle: its remaining requests would only wait out the same timeouts. A ZCL Default Response
with an error status is still a response. A setpoint waiting for the lock ends the valve's
cycle early (between requests): the lock passes to it at once, and the valve counts as answered
if any response arrived this cycle, else as busy (never a miss).

A ``STATIC`` refresh replaces the limits only with limits from an at least as good source
(``limits`` > ``abs`` > ``default``).

All-silent rejoin backoff: the first rejoin follows ``SILENT_POLLS_REJOIN`` silent polls. If no
valve answered since the last all-silent rejoin, the next one also waits
``SILENT_REJOIN_BACKOFF`` x 2^(n-1) after it (1 h, 2 h, 4 h, capped at
``SILENT_REJOIN_BACKOFF_MAX`` = 6 h), so one dead valve cannot cause a rejoin loop. Any valve
answering resets the backoff. Valves never expire.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import TYPE_CHECKING, Final, Literal

from vicare_local_ble import valves
from vicare_local_ble.bridge_types import (
    NO_RESPONSE,
    SILENT_POLLS_REJOIN,
    SILENT_REJOIN_BACKOFF,
    SILENT_REJOIN_BACKOFF_MAX,
)
from vicare_local_ble.bridge_verify import adopt_walk
from vicare_local_ble.zigbee_direct.connection import ConnectionState
from vicare_local_ble.zigbee_direct.discovery import walk_topology
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, ZclStatusError

if TYPE_CHECKING:
    from vicare_local_ble.bridge_state import BridgeCore
    from vicare_local_ble.bridge_types import BridgeSnapshot
    from vicare_local_ble.valves import ReadPlan, ReadRequest
    from vicare_local_ble.zigbee_direct.codec.zcl import ReadAttributeStatus
    from vicare_local_ble.zigbee_direct.connection import Generation
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.bridge")

type _Outcome = Literal["ok", "miss", "busy", "stale"]

#: The limits request of ``STATIC`` (everything in it except the Basic identification).
_LIMIT_REQUESTS = tuple(r for r in valves.STATIC if r != valves.IDENTIFY)
#: ``SetpointLimits.source`` quality: a refresh never downgrades. ``"cached"`` (a legacy cache
#: without a source) ranks lowest, so any fresh read replaces it.
_LIMIT_RANK: Final = {"cached": 0, "default": 0, "abs": 1, "limits": 2}


class StaleGenerationError(Exception):
    """Internal: the generation ended while a request was in flight."""


async def read(
    core: BridgeCore, gen: Generation, eui: Eui64, req: ReadRequest
) -> tuple[ReadAttributeStatus, ...] | None:
    """One read of a valve's ``req``; ``None`` for a Default Response error (a response).

    Raises ``StaleGenerationError`` if ``gen`` ended, ``NO_RESPONSE`` errors as they come;
    ``ValveAddressUnknownError`` (a ``RouteError``) if the valve's lease on its short does not
    hold before an attempt or at the answer (``bridge_owner``).
    """
    lease = core.owner.lease(eui)
    try:
        statuses = await gen.node.zcl_read(
            lease.short,
            core.valves[eui].endpoint,
            req.cluster,
            req.attrs,
            profile=valves.PROFILE,
            manufacturer=req.manufacturer,
            expect_ieee=eui,
            guard=lambda: core.owner.check(lease),
        )
    except ZclStatusError as exc:
        _LOGGER.debug(
            "valve %s: read of 0x%04X answered status 0x%02X", eui, req.cluster, exc.status
        )
        statuses = None
    except ConnectionLostError as exc:
        raise StaleGenerationError from exc
    if not core.is_current(gen):
        raise StaleGenerationError
    core.owner.check(lease)
    return statuses


def apply_result(
    core: BridgeCore, eui: Eui64, req: ReadRequest, statuses: tuple[ReadAttributeStatus, ...]
) -> bool:
    """Apply one read response to the valve's identity, limits or state; True if changed."""
    if req == valves.IDENTIFY:
        core.log_issues(eui, req.cluster, statuses, req.manufacturer)
        info = valves.parse_basic(statuses)
        valve = core.valves[eui]
        updated = dataclasses.replace(
            valve,
            manufacturer=info.manufacturer or valve.manufacturer,
            model=info.model or valve.model,
            sw_build=info.sw_build or valve.sw_build,
        )
    elif req in _LIMIT_REQUESTS:
        core.log_issues(eui, req.cluster, statuses, req.manufacturer)
        valve = core.valves[eui]
        limits = valves.SetpointLimits.from_reads(statuses)
        if _LIMIT_RANK[limits.source] < _LIMIT_RANK[valve.limits.source]:
            _LOGGER.debug("valve %s: refreshed limits (%s) kept out", eui, limits.source)
            return False
        updated = dataclasses.replace(valve, limits=limits)
    else:
        return core.apply(eui, req.cluster, statuses, req.manufacturer)
    if updated == valve:
        return False
    core.valves[eui] = updated
    return True


def plan_for(core: BridgeCore, eui: Eui64, *, slow: bool) -> tuple[ReadPlan, bool]:
    """The read plan of this cycle and whether it includes the (due) ``STATIC`` plan."""
    plan: ReadPlan = valves.FAST
    if slow:
        plan += valves.SLOW
    last = core.static_at.get(eui)
    static_due = last is None or core.clock.now() - last >= valves.STATIC_REFRESH_S
    if static_due:
        plan += valves.STATIC
    return plan, static_due


async def poll_valve(core: BridgeCore, gen: Generation, eui: Eui64, *, slow: bool) -> _Outcome:
    tx = core.tx[eui]
    if not tx.lock.try_acquire():
        _LOGGER.debug("valve %s busy: skipped this cycle", eui)
        return "busy"
    try:
        plan, static_due = plan_for(core, eui, slow=slow)
        answered = False
        static_ok = static_due
        changed = False
        for req in plan:
            if tx.lock.has_waiters():
                _LOGGER.debug("valve %s: cycle ended early for a setpoint", eui)
                if not answered:
                    return "busy"
                static_ok = False
                break
            try:
                statuses = await read(core, gen, eui, req)
            except NO_RESPONSE as exc:
                _LOGGER.debug("valve %s: no response (%s)", eui, type(exc).__name__)
                static_ok = False
                break
            answered = True
            if statuses is None:
                static_ok = static_ok and req not in valves.STATIC
                continue
            changed = apply_result(core, eui, req, statuses) or changed
        if answered:
            changed = core.responded(eui) or changed
            if static_ok:
                core.static_at[eui] = core.clock.now()
        else:
            changed = True
            if core.missed(eui):
                spawn_rewalk(core, gen)
        if changed:
            core.changed()
        return "ok" if answered else "miss"
    except StaleGenerationError:
        return "stale"
    finally:
        tx.lock.release()


async def poll(core: BridgeCore) -> BridgeSnapshot:
    """One poll cycle (``bridge`` module docstring); never raises for valve failures."""
    conn = core.connection
    gen = conn.current
    if gen is None or conn.state is not ConnectionState.READY:
        core.silent_streak = 0
        if core.valves:
            for eui in list(core.valves):
                core.missed(eui)
            core.changed()
        return core.snapshot()
    slow = core.polls % valves.SLOW_EVERY_N_POLLS == 0
    core.polls += 1
    euis = list(core.valves)
    outcomes = await asyncio.gather(*(poll_valve(core, gen, e, slow=slow) for e in euis))
    if not core.is_current(gen) or "stale" in outcomes:
        return core.snapshot()
    if euis and all(o == "miss" for o in outcomes):
        core.silent_streak += 1
    else:
        core.silent_streak = 0
    if core.silent_streak >= SILENT_POLLS_REJOIN and _rejoin_allowed(core):
        core.silent_streak = 0
        core.silent_rejoins += 1
        core.last_silent_rejoin = core.clock.now()
        _LOGGER.warning("all %d known valves silent: requesting a rejoin", len(euis))
        conn.request_rejoin(gen, "all_valves_silent")
    return core.snapshot()


def _rejoin_allowed(core: BridgeCore) -> bool:
    """The all-silent rejoin backoff (module docstring)."""
    last = core.last_silent_rejoin
    if core.silent_rejoins == 0 or last is None:
        return True
    gap: float = min(
        SILENT_REJOIN_BACKOFF * 2.0 ** (core.silent_rejoins - 1), SILENT_REJOIN_BACKOFF_MAX
    )
    return core.clock.now() - last >= gap


def spawn_rewalk(core: BridgeCore, gen: Generation) -> None:
    """Spawn one topology re-walk on ``gen`` unless one is already running."""
    if core.walking:
        return
    try:
        task = core.connection.spawn(gen, rewalk(core, gen), name="vicare topology re-walk")
    except ConnectionLostError:
        _LOGGER.debug("generation %d gone: re-walk not started", gen.number)
        return
    core.walking = True

    def done(_task: asyncio.Task[None]) -> None:
        # A done callback, not ``finally``: it also runs if the task is cancelled before it
        # started, so the flag can never stick.
        core.walking = False

    task.add_done_callback(done)


async def rewalk(core: BridgeCore, gen: Generation) -> None:
    started = core.clock.now()
    try:
        topology = await walk_topology(gen.node)
    except ConnectionLostError:
        _LOGGER.debug("generation %d lost: re-walk ends", gen.number)
        return
    if core.is_current(gen):
        await adopt_walk(core, gen, topology, started=started)
        if core.is_current(gen):
            core.push_avoid_shorts()
            core.changed()


__all__ = [
    "NO_RESPONSE",
    "StaleGenerationError",
    "apply_result",
    "plan_for",
    "poll",
    "poll_valve",
    "read",
    "rewalk",
    "spawn_rewalk",
]
