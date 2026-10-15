"""IEEE_addr verification of shorts: setpoints and walk hints (internal).

``ask_ieee`` sends one IEEE_addr_req (ZDO, unicast to the short asked; a sleepy valve gets it
via its parent's indirect queue like any unicast) and treats the reply as authoritative
evidence: it must come from that short (the pending key) and name that short as its address of
interest (``Envelope.nwk_addr_of_interest``). ``verify_address`` adopts a valve at a short only
if the device there answers with the valve's own IEEE. ``adopt_walk`` stores a walk and verifies
each of its hints once (``BridgeCore.set_topology``).

DEBUG lines (logger ``vicare_local_ble.bridge``), one per verification:
``valve <eui>: short 0x.... verified`` or ``valve <eui>: short 0x.... verification failed
(<reason>)`` with reason ``no answer (<error>)``, ``status 0x..``, ``generation ended`` or
``answered by <eui>``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from vicare_local_ble.bridge_types import NO_RESPONSE
from vicare_local_ble.zigbee_direct.codec.zdo import IeeeAddrReq, IeeeAddrRsp, ZdoStatus
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError

if TYPE_CHECKING:
    from vicare_local_ble.bridge_owner import Lease
    from vicare_local_ble.bridge_state import BridgeCore
    from vicare_local_ble.zigbee_direct.connection import Generation
    from vicare_local_ble.zigbee_direct.discovery import Topology
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.bridge")


async def ask_ieee(core: BridgeCore, gen: Generation, eui: Eui64, short: int) -> Eui64 | str:
    """The IEEE of the device at ``short`` (recorded as evidence), else why not (a reason).

    An epoch lease on ``short`` is taken before the request. A reply is used only if no
    evidence changed the short's device since (e.g. an announcement processed between the
    reply resolving and this coroutine resuming): an older reply never overwrites newer
    evidence. The reply's own NWK source IEEE, if it names ``eui`` already at ``short``,
    changes nothing and so does not count. Returns synchronously after the check, so a
    caller's next lease chains from it."""
    lease = core.owner.short_lease(eui, short)
    try:
        rsp = await gen.node.zdo_request(
            short, IeeeAddrReq(seq=0, nwk_addr=short), response=IeeeAddrRsp
        )
    except (*NO_RESPONSE, ConnectionLostError) as exc:
        return f"no answer ({type(exc).__name__})"
    if not core.is_current(gen):
        return "generation ended"
    if not core.owner.holds_short(lease):
        return "evidence changed meanwhile"
    if rsp.status != ZdoStatus.SUCCESS:
        return f"status 0x{rsp.status:02X}"
    if core.owner.seen_at(rsp.ieee, short):
        core.changed()
    return rsp.ieee


async def verify_address(core: BridgeCore, gen: Generation, eui: Eui64, short: int) -> Lease | None:
    """Ask ``short`` for its IEEE; adopt valve ``eui`` there only if it answers itself.

    Returns the valve lease, taken in the same step as the check (it chains from the
    verification: anything after it breaks the lease), or ``None``. A cancellation (the
    setpoint's ack deadline, the caller) is logged and propagates."""
    try:
        answer = await ask_ieee(core, gen, eui, short)
    except asyncio.CancelledError:
        _LOGGER.debug(
            "valve %s: short 0x%04X verification failed (interrupted: deadline or cancel)",
            eui,
            short,
        )
        raise
    if answer != eui:
        reason = answer if isinstance(answer, str) else f"answered by {answer}"
        _LOGGER.debug("valve %s: short 0x%04X verification failed (%s)", eui, short, reason)
        return None
    _LOGGER.debug("valve %s: short 0x%04X verified", eui, short)
    if core.set_short(eui, short):
        core.push_avoid_shorts()
    lease = core.owner.lease(eui)
    core.changed()
    return lease


async def adopt_walk(
    core: BridgeCore, gen: Generation, topology: Topology, *, started: float
) -> None:
    """Store a walk result, then verify each hint once (sequentially)."""
    for eui, short in core.set_topology(topology, started=started):
        if not core.is_current(gen):
            return
        await verify_address(core, gen, eui, short)


__all__ = ["adopt_walk", "ask_ieee", "verify_address"]
