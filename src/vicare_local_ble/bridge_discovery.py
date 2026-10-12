"""Bridge discovery: topology walk, identification, retries, Device_annce (T14; internal).

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

from vicare_local_ble import valves
from vicare_local_ble.bridge_poll import NO_RESPONSE, poll
from vicare_local_ble.bridge_types import (
    ANNCE_IDENTIFY_DEBOUNCE,
    DISCOVERY_RETRY_DELAYS,
    IDENTIFY_DIAGNOSTIC_AFTER,
    TOPOLOGY_REFRESH,
)
from vicare_local_ble.zigbee_direct.codec.zdo import (
    ActiveEpReq,
    ActiveEpRsp,
    SimpleDescReq,
    SimpleDescRsp,
    ZdoStatus,
)
from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import DeviceType
from vicare_local_ble.zigbee_direct.discovery import walk_topology
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, ZclStatusError

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from vicare_local_ble.bridge_state import BridgeCore
    from vicare_local_ble.valves import SetpointLimits
    from vicare_local_ble.zigbee_direct.codec.zdo import DeviceAnnce
    from vicare_local_ble.zigbee_direct.connection import Generation
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.bridge")

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
        core.set_topology(topology, started=started)
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
            *(_identify_guarded(core, gen, e, s, learned_at) for e, s in candidates)
        )
    )


async def _identify_guarded(
    core: BridgeCore, gen: Generation, eui: Eui64, short: int, learned_at: float
) -> _Identified:
    async with core.identify_sem:
        return await identify(core, gen, eui, short, learned_at=learned_at)


async def identify(
    core: BridgeCore, gen: Generation, eui: Eui64, short: int, *, learned_at: float | None = None
) -> _Identified:
    """Basic read; a supported valve also gets its limits read and is added.

    ``learned_at`` is when ``short`` was learned (default: now). A Device_annce of ``eui``
    learned at or after it wins when the valve is added (same freshness rule as
    ``BridgeCore.set_topology``): the valve may have rejoined while it was being identified.
    """
    if learned_at is None:
        learned_at = core.clock.now()
    req = valves.IDENTIFY
    try:
        statuses = await gen.node.zcl_read(
            short,
            valves.ENDPOINT,
            req.cluster,
            req.attrs,
            profile=valves.PROFILE,
            manufacturer=req.manufacturer,
        )
    except NO_RESPONSE as exc:
        count = core.basic_timeouts.get(eui, 0) + 1
        core.basic_timeouts[eui] = count
        _LOGGER.debug("identify %s: no response (%s, %d)", eui, type(exc).__name__, count)
        if count == IDENTIFY_DIAGNOSTIC_AFTER:
            await _diagnose(gen, eui, short)
        return "retry"
    except ZclStatusError as exc:
        # An error status is no proof the device is not a valve: retry later.
        _LOGGER.debug("identify %s: status 0x%02X, will retry", eui, exc.status)
        return "retry"
    except ConnectionLostError:
        return "stale"
    if not core.is_current(gen):
        return "stale"
    info = valves.parse_basic(statuses)
    if not valves.is_supported_valve(info.manufacturer, info.model):
        if not _mismatch(info):
            _LOGGER.debug("identify %s: identification incomplete, will retry", eui)
            return "retry"
        _LOGGER.debug("device %s (0x%04X) is not a supported valve: ignored", eui, short)
        core.ignored.add(str(eui))
        core.changed()
        return "ignored"
    limits, limits_ok = await _read_limits(gen, short)
    if not core.is_current(gen):
        return "stale"
    if eui in core.valves:  # identified meanwhile (Device_annce)
        return "valve"
    announced = core.annce_short.get(eui)
    if announced is not None and announced[1] >= learned_at:
        if announced[0] != short:
            _LOGGER.debug("identify %s: re-announced 0x%04X -> 0x%04X", eui, short, announced[0])
        short, learned_at = announced
    valve = valves.Valve(
        eui=eui,
        short=short,
        endpoint=valves.ENDPOINT,
        manufacturer=info.manufacturer,
        model=info.model,
        sw_build=info.sw_build,
        limits=limits,
    )
    core.add_valve(valve)
    core.short_at[eui] = learned_at
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


async def _read_limits(gen: Generation, short: int) -> tuple[SetpointLimits, bool]:
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
    eui, short = annce.ieee, annce.nwk_addr
    if eui in core.valves:
        if core.set_short(eui, short):
            core.push_avoid_shorts()
            core.changed()
        return
    if str(eui) in core.ignored:
        return
    _schedule_identify(core, gen, eui, short)


def on_unknown_sender(core: BridgeCore, gen: Generation, eui: Eui64, short: int) -> None:
    """A frame with an explicit, unknown source IEEE: handled like its Device_annce."""
    if not core.is_current(gen) or eui in core.valves or str(eui) in core.ignored:
        return
    _LOGGER.debug("frame from unknown %s at 0x%04X: identification scheduled", eui, short)
    _schedule_identify(core, gen, eui, short)


def _schedule_identify(core: BridgeCore, gen: Generation, eui: Eui64, short: int) -> None:
    core.annce_short[eui] = (short, core.clock.now())
    if eui in core.annce_seen:
        return
    core.annce_seen.add(eui)
    spawn_safely(core, gen, _identify_later(core, gen, eui), "vicare identify")


async def _identify_later(core: BridgeCore, gen: Generation, eui: Eui64) -> None:
    await core.clock.sleep(ANNCE_IDENTIFY_DEBOUNCE)
    if not core.is_current(gen) or eui in core.valves or str(eui) in core.ignored:
        return
    announced = core.annce_short.get(eui)
    if announced is None:  # pragma: no cover - set before the task is spawned
        return
    short, learned_at = announced
    if await _identify_guarded(core, gen, eui, short, learned_at) == "valve":
        core.push_avoid_shorts()
        if core.topology is not None:
            core.summarize()
        core.discovery = dataclasses.replace(core.discovery, valves_found=len(core.valves))
        core.changed()


__all__ = [
    "discovery_run",
    "discovery_task",
    "identify",
    "on_device_annce",
    "on_unknown_sender",
    "spawn_safely",
]
