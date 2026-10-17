"""Bridge discovery: topology walk, identification, retries, Device_annce (internal).

One discovery task is spawned per generation (from the READY listener). It runs an attempt,
spawns the initial poll after the first one, then sleeps until the next attempt: the retry
delays ``DISCOVERY_RETRY_DELAYS`` while attempts stay incomplete (topology incomplete, an
identification timed out, or no valve known), ``TOPOLOGY_REFRESH`` after a complete attempt or
once the retries are used up. A complete attempt resets the retry series. The sleeping task is
owned by the generation, so teardown cancels the whole schedule.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import TYPE_CHECKING, Any, Literal

from localtrv import valves
from localtrv.bridge_poll import NO_RESPONSE, poll
from localtrv.bridge_types import (
    ANNCE_IDENTIFY_DEBOUNCE,
    ANNCE_IDENTIFY_RETRY,
    DISCOVERY_RETRY_DELAYS,
    IDENTIFY_DIAGNOSTIC_AFTER,
    TOPOLOGY_REFRESH,
    ValveAddressUnknownError,
)
from localtrv.bridge_verify import adopt_walk, ask_ieee
from localtrv.zigbee_direct.codec.zdo import (
    ActiveEpReq,
    ActiveEpRsp,
    SimpleDescReq,
    SimpleDescRsp,
    ZdoStatus,
)
from localtrv.zigbee_direct.codec.zdo_mgmt import DeviceType
from localtrv.zigbee_direct.discovery import walk_topology
from localtrv.zigbee_direct.errors import ConnectionLostError, ZclStatusError

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from localtrv.bridge_state import BridgeCore
    from localtrv.valves import SetpointLimits
    from localtrv.zigbee_direct.codec.zdo import DeviceAnnce
    from localtrv.zigbee_direct.connection import Generation
    from localtrv.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("localtrv.bridge")

type _Identified = Literal["valve", "ignored", "retry", "stale"]

_LIMIT_REQUESTS = tuple(r for r in valves.STATIC if r != valves.IDENTIFY)


def spawn_safely(
    core: BridgeCore, gen: Generation, coro: Coroutine[Any, Any, object], name: str
) -> bool:
    """``connection.spawn``; a lost generation (``ConnectionLostError``) is normal: DEBUG."""
    try:
        core.connection.spawn(gen, coro, name=name)
    except ConnectionLostError:
        _LOGGER.debug("generation %d gone: %s not started", gen.number, name)
        return False
    return True


async def discovery_task(core: BridgeCore, gen: Generation) -> None:
    """The per-generation discovery schedule (module docstring)."""
    try:
        await _schedule(core, gen)
    except ConnectionLostError:
        _LOGGER.debug("generation %d lost: discovery ends", gen.number)


async def _schedule(core: BridgeCore, gen: Generation) -> None:
    failures = 0
    first = True
    while True:
        complete = await discovery_run(core, gen)
        if not core.is_current(gen):
            return
        if complete:
            failures = 0
            delay = TOPOLOGY_REFRESH
        elif failures < len(DISCOVERY_RETRY_DELAYS):
            delay = DISCOVERY_RETRY_DELAYS[failures]
            failures += 1
        else:
            delay = TOPOLOGY_REFRESH
        core.discovery = dataclasses.replace(
            core.discovery, attempts=failures, next_retry=core.clock.now() + delay
        )
        core.changed()
        if first:
            first = False
            spawn_safely(core, gen, _initial_poll(core), "vicare initial poll")
        await core.clock.sleep(delay)


async def _initial_poll(core: BridgeCore) -> None:
    await poll(core)


async def discovery_run(core: BridgeCore, gen: Generation) -> bool:
    """One attempt; True if complete. Does not mutate state once ``gen`` is stale."""
    core.discovery = dataclasses.replace(core.discovery, running=True)
    core.changed()
    try:
        started = core.clock.now()
        topology = await walk_topology(gen.node)
        if not core.is_current(gen):
            return False
        await adopt_walk(core, gen, topology, started=started)
        if not core.is_current(gen):
            return False
        candidates = [
            (eui, n.nwk_addr)
            for eui, n in topology.neighbors.items()
            if n.device_type is DeviceType.END_DEVICE
            and eui not in core.valves
            and str(eui) not in core.ignored
        ]
        candidates.sort(key=lambda item: not valves.has_oui_hint(item[0]))
        results = await _identify_all(core, gen, candidates, started)
        if not core.is_current(gen):
            return False
        core.summarize()
        found = len(core.valves)
        complete = topology.complete and "retry" not in results and found > 0
        core.discovery = dataclasses.replace(
            core.discovery,
            running=False,
            last_run=core.clock.now(),
            complete=complete,
            valves_found=found,
            next_retry=None,
        )
        core.push_avoid_shorts()
        _LOGGER.info(
            "discovery: %d valves, %d ignored, topology %s, %s",
            found,
            len(core.ignored),
            "complete" if topology.complete else "incomplete",
            "complete" if complete else "will retry",
        )
        core.changed()
        return complete
    finally:
        if core.discovery.running:
            core.discovery = dataclasses.replace(core.discovery, running=False)


async def _identify_all(
    core: BridgeCore, gen: Generation, candidates: list[tuple[Eui64, int]], learned_at: float
) -> list[_Identified]:
    return list(
        await asyncio.gather(
            *(_identify_guarded(core, gen, e, s, learned_at, verified=False) for e, s in candidates)
        )
    )


async def _identify_guarded(
    core: BridgeCore,
    gen: Generation,
    eui: Eui64,
    short: int,
    learned_at: float,
    *,
    verified: bool,
) -> _Identified:
    async with core.identify_sem:
        return await identify(core, gen, eui, short, learned_at=learned_at, verified=verified)


async def identify(
    core: BridgeCore,
    gen: Generation,
    eui: Eui64,
    short: int,
    *,
    learned_at: float | None = None,
    verified: bool = True,
) -> _Identified:
    """Basic read; a supported valve also gets its limits read and is added.

    ``verified=False`` (a walk candidate, hearsay): an IEEE_addr_req to ``short`` must name
    ``eui`` first. Then the latest evidence at ``short`` must be ``eui``, and the whole
    identification runs under an epoch lease on ``short`` (checked before every attempt, at
    transmission and before any result is applied); answers must not name another source
    IEEE. If the lease breaks, the result is discarded: no valve added, nothing ignored
    ("retry"). ``learned_at`` is when ``short`` was learned (default: now); a Device_annce of
    ``eui`` learned at or after it wins when the valve is added (it may have rejoined).
    """
    if not core.is_current(gen):
        return "stale"
    if learned_at is None:
        learned_at = core.clock.now()
    if not verified:
        answer = await ask_ieee(core, gen, eui, short)
        if not core.is_current(gen):
            return "stale"
        if answer != eui:
            _LOGGER.debug("identify %s: 0x%04X not confirmed (%s)", eui, short, answer)
            if isinstance(answer, str) and answer.startswith("no answer"):
                await _no_response(core, gen, eui, short, answer)
            return "retry"
    seen = core.short_seen.get(short)
    if seen is None or seen[0] != eui:
        _LOGGER.debug("identify %s: 0x%04X evidenced for another device, discarded", eui, short)
        return "retry"
    lease = core.owner.short_lease(eui, short)

    def guard() -> None:
        core.owner.check_short(lease)

    req = valves.IDENTIFY
    try:
        statuses = await gen.node.zcl_read(
            short,
            valves.ENDPOINT,
            req.cluster,
            req.attrs,
            profile=valves.PROFILE,
            manufacturer=req.manufacturer,
            expect_ieee=eui,
            guard=guard,
        )
    except ValveAddressUnknownError:
        _LOGGER.debug("identify %s: 0x%04X evidence changed, discarded", eui, short)
        return "retry"
    except NO_RESPONSE as exc:
        await _no_response(core, gen, eui, short, type(exc).__name__)
        return "retry"
    except ZclStatusError as exc:
        # An error status is no proof the device is not a valve: retry later.
        _LOGGER.debug("identify %s: status 0x%02X, will retry", eui, exc.status)
        return "retry"
    except ConnectionLostError:
        return "stale"
    if not core.is_current(gen):
        return "stale"
    if not core.owner.holds_short(lease):
        _LOGGER.debug("identify %s: 0x%04X evidence changed, discarded", eui, short)
        return "retry"  # the answer may be another device's
    info = valves.parse_basic(statuses)
    if not valves.is_supported_valve(info.manufacturer, info.model):
        if not _mismatch(info):
            _LOGGER.debug("identify %s: identification incomplete, will retry", eui)
            return "retry"
        _LOGGER.debug("device %s (0x%04X) is not a supported valve: ignored", eui, short)
        core.ignored.add(str(eui))
        core.changed()
        return "ignored"
    limits, limits_ok = await _read_limits(gen, short, eui, guard)
    if not core.is_current(gen):
        return "stale"
    if eui in core.valves:  # identified meanwhile (Device_annce)
        return "valve"
    if not core.owner.holds_short(lease):
        return "retry"
    announced = core.annce_short.get(eui)
    if announced is not None and announced[1] >= learned_at:
        if announced[0] != short:
            _LOGGER.debug("identify %s: re-announced 0x%04X -> 0x%04X", eui, short, announced[0])
        short, learned_at = announced
        seen = core.short_seen.get(short)
        if seen is not None and seen[0] != eui:
            return "retry"
    valve = valves.Valve(
        eui=eui,
        short=short,
        endpoint=valves.ENDPOINT,
        manufacturer=info.manufacturer,
        model=info.model,
        sw_build=info.sw_build,
        limits=limits,
    )
    core.add_valve(valve, learned_at=learned_at)
    core.log_issues(eui, req.cluster, statuses, req.manufacturer)
    if limits_ok:
        core.static_at[eui] = core.clock.now()
    core.responded(eui)
    _LOGGER.debug("valve %s identified at 0x%04X", eui, short)
    core.changed()
    core.new_valve(valve)
    return "valve"


def _mismatch(info: valves.BasicInfo) -> bool:
    """True only on positive evidence: a manufacturer or model that was read and differs."""
    maker, model = info.manufacturer, info.model
    return (maker is not None and maker.strip() != valves.MANUFACTURER) or (
        model is not None and model.strip() not in valves.MODEL_IDS
    )


async def _no_response(core: BridgeCore, gen: Generation, eui: Eui64, short: int, why: str) -> None:
    """Count an unanswered identification; the diagnostic after repeated ones."""
    count = core.basic_timeouts.get(eui, 0) + 1
    core.basic_timeouts[eui] = count
    _LOGGER.debug("identify %s: no response (%s, %d)", eui, why, count)
    if count == IDENTIFY_DIAGNOSTIC_AFTER:
        await _diagnose(gen, eui, short)


async def _read_limits(
    gen: Generation, short: int, eui: Eui64, guard: Callable[[], None]
) -> tuple[SetpointLimits, bool]:
    limits = valves.DEFAULT_LIMITS
    for req in _LIMIT_REQUESTS:
        try:
            statuses = await gen.node.zcl_read(
                short,
                valves.ENDPOINT,
                req.cluster,
                req.attrs,
                profile=valves.PROFILE,
                manufacturer=req.manufacturer,
                expect_ieee=eui,
                guard=guard,
            )
        except (*NO_RESPONSE, ZclStatusError, ConnectionLostError):
            return valves.DEFAULT_LIMITS, False
        limits = valves.SetpointLimits.from_reads(statuses)
    return limits, True


async def _diagnose(gen: Generation, eui: Eui64, short: int) -> None:
    """Active_EP / Simple_Desc after repeated Basic timeouts: DEBUG logging only."""
    try:
        eps = await gen.node.zdo_request(
            short, ActiveEpReq(seq=0, nwk_addr=short), response=ActiveEpRsp
        )
        _LOGGER.debug("identify %s: Active_EP status 0x%02X %s", eui, eps.status, eps.endpoints)
        if eps.status != ZdoStatus.SUCCESS:
            return
        for ep in eps.endpoints:
            desc = await gen.node.zdo_request(
                short, SimpleDescReq(seq=0, nwk_addr=short, endpoint=ep), response=SimpleDescRsp
            )
            _LOGGER.debug("identify %s: Simple_Desc ep %d: %s", eui, ep, desc.descriptor)
    except (*NO_RESPONSE, ConnectionLostError) as exc:
        _LOGGER.debug("identify %s: diagnostic failed (%s)", eui, type(exc).__name__)


# --- Device_annce ---


def on_device_annce(core: BridgeCore, gen: Generation, annce: DeviceAnnce) -> None:
    """Known EUI -> update its short; unknown -> identification after the debounce."""
    if not core.is_current(gen):
        return
    on_address(core, gen, annce.ieee, annce.nwk_addr)


def on_sender_ieee(core: BridgeCore, gen: Generation, eui: Eui64, short: int) -> None:
    """A frame with an explicit source IEEE: handled like a Device_annce of the sender."""
    if eui not in core.valves and str(eui) not in core.ignored:
        _LOGGER.debug("frame from unknown %s at 0x%04X", eui, short)
    on_address(core, gen, eui, short)


def on_address(
    core: BridgeCore, gen: Generation, eui: Eui64, short: int, *, identify: bool = True
) -> None:
    """Authoritative ``eui`` at ``short`` (Device_annce, or a frame with a source IEEE).

    Address evidence on its own: any other valve cached at ``short`` loses it at once, whether
    ``eui`` is a known valve, unknown or ignored. An unknown, not ignored ``eui`` is identified
    after the debounce if ``identify`` (Device_annce and reports; not every NWK header)."""
    if not core.is_current(gen):
        return
    if eui in core.valves:
        if core.set_short(eui, short):
            core.push_avoid_shorts()
            core.changed()
        return
    if core.owner.seen_at(eui, short):
        core.changed()
    if identify and str(eui) not in core.ignored:
        _schedule_identify(core, gen, eui, short)


def _schedule_identify(core: BridgeCore, gen: Generation, eui: Eui64, short: int) -> None:
    """At most one identification per sender at a time (``annce_seen``). After a failed one,
    the next announcement retries, but no earlier than ``ANNCE_IDENTIFY_RETRY`` after the
    failure, so a flapping device cannot cause a request storm."""
    now = core.clock.now()
    core.annce_short[eui] = (short, now)
    if eui in core.annce_seen:
        return
    delay = max(ANNCE_IDENTIFY_DEBOUNCE, core.annce_retry_at.get(eui, now) - now)
    if spawn_safely(core, gen, _identify_later(core, gen, eui, delay), "vicare identify"):
        core.annce_seen.add(eui)


async def _identify_later(core: BridgeCore, gen: Generation, eui: Eui64, delay: float) -> None:
    result: _Identified | None = None
    short: int | None = None
    moved = False
    try:
        await core.clock.sleep(delay)
        if not core.is_current(gen) or eui in core.valves or str(eui) in core.ignored:
            return
        short, learned_at = core.annce_short[eui]  # set before the task is spawned
        result = await _identify_guarded(core, gen, eui, short, learned_at, verified=True)
    finally:
        if core.is_current(gen):
            core.annce_seen.discard(eui)
            # Announced elsewhere meanwhile: the discarded result is no failure of the device.
            moved = short is not None and core.annce_short[eui][0] != short
            if result != "valve" and not moved:
                core.annce_retry_at[eui] = core.clock.now() + ANNCE_IDENTIFY_RETRY
    if moved and result != "valve":
        _schedule_identify(core, gen, eui, core.annce_short[eui][0])
        return
    if result == "valve":
        core.push_avoid_shorts()
        if core.topology is not None:
            core.summarize()
        core.discovery = dataclasses.replace(core.discovery, valves_found=len(core.valves))
        core.changed()


__all__ = [
    "discovery_run",
    "discovery_task",
    "identify",
    "on_address",
    "on_device_annce",
    "on_sender_ieee",
    "spawn_safely",
]
