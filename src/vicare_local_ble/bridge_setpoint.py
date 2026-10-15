"""Bridge setpoint transaction: version, lock, write, background confirm (T14; internal).

Implements steps 1-6 of the ``bridge`` module docstring. Lock ownership moves from the HA
call to the confirm task at the acknowledgement. The HA call releases it in its ``finally``;
the confirm task's cleanup (release, ``tx.confirm`` reset, ``pending`` clear) is a done
callback, so it also runs for a task cancelled before its first step. Only the latest version
touches ``pending``/``requested_c``/``acknowledged_c``/``confirmed_c``. An older version that is
acknowledged after a newer one arrived spawns no confirm: the newer write follows it under the
lock and confirms itself; if that newer write then fails before its acknowledgement,
``acknowledged_c`` shows the older acknowledged value (what the valve holds).
"""

from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING

from vicare_local_ble import valves
from vicare_local_ble.bridge_poll import NO_RESPONSE, StaleGenerationError, read
from vicare_local_ble.bridge_types import (
    SETPOINT_ACK_DEADLINE,
    SETPOINT_TOTAL_DEADLINE,
    ValveAddressUnknownError,
)
from vicare_local_ble.bridge_verify import verify_address
from vicare_local_ble.zigbee_direct.codec.zcl import ZclStatus
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, ZclStatusError

if TYPE_CHECKING:
    import asyncio

    from vicare_local_ble.bridge_state import BridgeCore
    from vicare_local_ble.bridge_types import SetpointStatus
    from vicare_local_ble.zigbee_direct.codec.zcl import ReadAttributeStatus
    from vicare_local_ble.zigbee_direct.connection import Generation
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.bridge")


def _latest(core: BridgeCore, eui: Eui64, version: int) -> bool:
    return core.setpoints[eui].version == version


def _update(core: BridgeCore, eui: Eui64, **changes: float | bool | None) -> None:
    core.setpoints[eui] = dataclasses.replace(core.setpoints[eui], **changes)  # type: ignore[arg-type]
    core.changed()


async def set_setpoint(core: BridgeCore, eui: Eui64, celsius: float) -> SetpointStatus:
    """See ``ViCareBridge.set_setpoint``."""
    valve = core.valves[eui]  # KeyError: unknown valve
    clamped = valves.clamp_setpoint(celsius, valve.limits)  # ValueError: non-finite
    record = valves.setpoint_record(clamped, valve.limits)
    if core.connection.current is None:
        raise ConnectionLostError("not connected")
    tx = core.tx[eui]
    start = core.clock.now()
    version = core.setpoints[eui].version + 1
    core.setpoints[eui] = dataclasses.replace(
        core.setpoints[eui], version=version, requested_c=clamped, pending=True
    )
    core.changed()
    confirm = tx.confirm
    if confirm is not None and not confirm.done():
        confirm.cancel()  # preempt the older confirm; its done callback releases the lock
    held = acked = handed = False
    try:
        async with core.clock.timeout(SETPOINT_ACK_DEADLINE - (core.clock.now() - start)):
            await tx.lock.acquire()
            held = True
            gen = core.connection.current  # a reconnect may have happened while waiting
            if gen is None:
                raise ConnectionLostError("not connected")
            # Verified write: the device at the valve's short (which may have changed while
            # waiting) must name itself in an IEEE_addr response first, inside the ack
            # deadline. Otherwise ``ValveAddressUnknownError`` (a ``RouteError``), nothing
            # written. The lease chains from the verification and is checked before queueing
            # and at transmission of every attempt, and on the acknowledgement.
            short = core.valves[eui].short
            lease = None if core.owner.evicted(eui) else await verify_address(core, gen, eui, short)
            if lease is None:
                raise ValveAddressUnknownError(short)
            rsp = await gen.node.zcl_write(
                lease.short,
                core.valves[eui].endpoint,
                valves.A_SETPOINT.cluster,
                (record,),
                manufacturer=valves.A_SETPOINT.manufacturer,
                expect_ieee=eui,
                guard=lambda: core.owner.check(lease),
            )
        core.owner.check(lease)  # an ack from a short that changed owner is not ours
        if not rsp.success:
            bad = next(r for r in rsp.records if r.status)
            raise ZclStatusError(bad.status, attribute_id=bad.attribute_id)
        acked = True
        tx.acked_c = clamped
        if core.is_current(gen) and core.responded(eui):
            core.changed()
        if _latest(core, eui, version):
            handed = True  # from here the lock belongs to the confirm (or is released below)
            _start_confirm(core, gen, eui, version, start)
        return core.setpoints[eui]
    finally:
        if not handed:
            if held:
                tx.lock.release()
            # Acknowledged here means an older version (the newer one owns the fields).
            if not acked and _latest(core, eui, version):
                # The valve keeps the last acknowledged write (e.g. an older version's).
                _update(core, eui, pending=False, requested_c=None, acknowledged_c=tx.acked_c)


def _start_confirm(
    core: BridgeCore, gen: Generation, eui: Eui64, version: int, start: float
) -> None:
    """Hand the lock to a confirm task; its cleanup is a done callback, so it also runs when
    the task is cancelled before its first step (preemption, teardown)."""
    tx = core.tx[eui]
    try:
        task = core.connection.spawn(
            gen, _confirm(core, gen, eui, version, start), name="vicare setpoint confirm"
        )
    except ConnectionLostError:
        _LOGGER.debug("valve %s: acknowledged, generation gone before confirm", eui)
        tx.lock.release()
        _update(core, eui, acknowledged_c=tx.acked_c, pending=False)
        return
    tx.confirm = task  # before any callback: a re-entrant set_setpoint must see it
    task.add_done_callback(lambda t: _confirm_done(core, eui, version, t))
    _update(core, eui, acknowledged_c=tx.acked_c)


def _confirm_done(core: BridgeCore, eui: Eui64, version: int, task: asyncio.Task[None]) -> None:
    tx = core.tx[eui]
    tx.lock.release()
    if tx.confirm is task:
        tx.confirm = None
    if _latest(core, eui, version):
        _update(core, eui, pending=False)


def confirmed_value(statuses: tuple[ReadAttributeStatus, ...]) -> float | None:
    """The setpoint in the confirm response itself: a success record with a valid value."""
    spec = valves.A_SETPOINT
    for item in statuses:
        if item.attribute_id == spec.attr and item.status == ZclStatus.SUCCESS:
            value = valves.decode_attr(spec, item.data_type, item.value)
            return float(value) if isinstance(value, int | float) else None
    return None


async def _confirm(
    core: BridgeCore, gen: Generation, eui: Eui64, version: int, start: float
) -> None:
    """Step 6: the confirming read, bounded by ``SETPOINT_TOTAL_DEADLINE`` from ``start``."""
    req = valves.CONFIRM_SETPOINT
    try:
        async with core.clock.timeout(SETPOINT_TOTAL_DEADLINE - (core.clock.now() - start)):
            statuses = await read(core, gen, eui, req)
    except (TimeoutError, *NO_RESPONSE) as exc:
        _LOGGER.debug("valve %s: setpoint acknowledged, unconfirmed (%s)", eui, type(exc).__name__)
        return
    except StaleGenerationError:
        return
    if statuses is None:
        return
    core.apply(eui, req.cluster, statuses, req.manufacturer)
    core.responded(eui)
    value = confirmed_value(statuses)
    if _latest(core, eui, version) and value is not None:
        _update(core, eui, confirmed_c=value, confirmed_at=core.clock.now())
    else:
        core.changed()


__all__ = ["set_setpoint"]
