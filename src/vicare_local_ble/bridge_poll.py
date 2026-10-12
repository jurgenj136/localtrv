"""Bridge poll cycle, valve reads and topology re-walks (T14; internal, see ``bridge``).

Per valve: ``try_acquire`` the transaction lock (busy -> skipped), then the plan
``FAST`` (+ ``SLOW`` every ``SLOW_EVERY_N_POLLS``-th poll, + ``STATIC`` when due), one request
at a time. The first request without any response (timeout, route error) ends the valve's
cycle: its remaining requests would only wait out the same timeouts. A ZCL Default Response
with an error status is still a response.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import TYPE_CHECKING, Literal

from vicare_local_ble import valves
from vicare_local_ble.bridge_types import SILENT_POLLS_REJOIN
from vicare_local_ble.zigbee_direct.connection import ConnectionState
from vicare_local_ble.zigbee_direct.discovery import walk_topology
from vicare_local_ble.zigbee_direct.errors import (
    ConnectionLostError,
    RequestTimeoutError,
    RouteError,
    SequenceExhaustedError,
    ZclStatusError,
)

if TYPE_CHECKING:
    from vicare_local_ble.bridge_state import BridgeCore
    from vicare_local_ble.bridge_types import BridgeSnapshot
    from vicare_local_ble.valves import ReadPlan, ReadRequest
    from vicare_local_ble.zigbee_direct.codec.zcl import ReadAttributeStatus
    from vicare_local_ble.zigbee_direct.connection import Generation
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.bridge")

type _Outcome = Literal["ok", "miss", "busy", "stale"]

#: Errors meaning "no response from the device" for one request.
NO_RESPONSE = (RequestTimeoutError, RouteError, SequenceExhaustedError)
#: The limits request of ``STATIC`` (everything in it except the Basic identification).
_LIMIT_REQUESTS = tuple(r for r in valves.STATIC if r != valves.IDENTIFY)


class StaleGenerationError(Exception):
    """Internal: the generation ended while a request was in flight."""


async def read(
    core: BridgeCore, gen: Generation, eui: Eui64, req: ReadRequest
) -> tuple[ReadAttributeStatus, ...] | None:
    """One read of a valve's ``req``; ``None`` for a Default Response error (a response).

    Raises ``StaleGenerationError`` if ``gen`` ended, ``NO_RESPONSE`` errors as they come.
    """
    valve = core.valves[eui]
    try:
        statuses = await gen.node.zcl_read(
            valve.short,
            valve.endpoint,
            req.cluster,
            req.attrs,
            profile=valves.PROFILE,
            manufacturer=req.manufacturer,
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
        updated = dataclasses.replace(valve, limits=valves.SetpointLimits.from_reads(statuses))
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
    if core.silent_streak >= SILENT_POLLS_REJOIN:
        core.silent_streak = 0
        _LOGGER.warning("all %d known valves silent: requesting a rejoin", len(euis))
        conn.request_rejoin(gen, "all_valves_silent")
    return core.snapshot()


def spawn_rewalk(core: BridgeCore, gen: Generation) -> None:
    """Spawn one topology re-walk on ``gen`` unless one is already running."""
    if core.walking:
        return
    try:
        core.connection.spawn(gen, rewalk(core, gen), name="vicare topology re-walk")
    except ConnectionLostError:
        _LOGGER.debug("generation %d gone: re-walk not started", gen.number)
        return
    core.walking = True


async def rewalk(core: BridgeCore, gen: Generation) -> None:
    try:
        topology = await walk_topology(gen.node)
        if core.is_current(gen):
            core.set_topology(topology)
            core.push_avoid_shorts()
            core.changed()
    except ConnectionLostError:
        _LOGGER.debug("generation %d lost: re-walk ends", gen.number)
    finally:
        core.walking = False


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
