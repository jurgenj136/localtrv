"""Bridge setpoint transaction: version, lock, write, background confirm (T14; internal).

Implements steps 1-6 of the ``bridge`` module docstring. Lock ownership moves from the HA
call to the confirm task at the acknowledgement; whichever holds it releases it in its
``finally``. Only the latest version touches ``pending``/``requested_c``/``acknowledged_c``/
``confirmed_c``. An older version that is acknowledged after a newer one arrived spawns no
confirm: the newer write follows it under the lock and confirms itself.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import TYPE_CHECKING

from vicare_local_ble import valves
from vicare_local_ble.bridge_poll import NO_RESPONSE, StaleGenerationError, read
from vicare_local_ble.bridge_types import SETPOINT_ACK_DEADLINE, SETPOINT_TOTAL_DEADLINE
from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, ZclStatusError

if TYPE_CHECKING:
    from vicare_local_ble.bridge_state import BridgeCore
    from vicare_local_ble.bridge_types import SetpointStatus
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
    gen = core.connection.current
    if gen is None:
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
        confirm.cancel()  # preempt the older confirm; its finally releases the lock
    held = acked = handed = False
    try:
        async with core.clock.timeout(SETPOINT_ACK_DEADLINE - (core.clock.now() - start)):
            await tx.lock.acquire()
            held = True
            target = core.valves[eui]  # the short may have changed while waiting
            rsp = await gen.node.zcl_write(
                target.short,
                target.endpoint,
                valves.A_SETPOINT.cluster,
                (record,),
                manufacturer=valves.A_SETPOINT.manufacturer,
            )
        if not rsp.success:
            bad = next(r for r in rsp.records if r.status)
            raise ZclStatusError(bad.status, attribute_id=bad.attribute_id)
        acked = True
        if core.is_current(gen) and core.responded(eui):
            core.changed()
        if _latest(core, eui, version):
            _update(core, eui, acknowledged_c=clamped)
            try:
                tx.confirm = core.connection.spawn(
                    gen, _confirm(core, gen, eui, version, start), name="vicare setpoint confirm"
                )
                handed = True
            except ConnectionLostError:
                _LOGGER.debug("valve %s: acknowledged, generation gone before confirm", eui)
                handed = True  # cleanup done here, so the returned status shows it
                tx.lock.release()
                _update(core, eui, pending=False)
        return core.setpoints[eui]
    finally:
        if not handed:
            if held:
                tx.lock.release()
            # Acknowledged here means an older version (the newer one owns the fields).
            if not acked and _latest(core, eui, version):
                _update(core, eui, pending=False, requested_c=None)


async def _confirm(
    core: BridgeCore, gen: Generation, eui: Eui64, version: int, start: float
) -> None:
    """Step 6: the confirming read, bounded by ``SETPOINT_TOTAL_DEADLINE`` from ``start``."""
    tx = core.tx[eui]
    try:
        req = valves.CONFIRM_SETPOINT
        try:
            async with core.clock.timeout(SETPOINT_TOTAL_DEADLINE - (core.clock.now() - start)):
                statuses = await read(core, gen, eui, req)
        except (TimeoutError, *NO_RESPONSE) as exc:
            _LOGGER.debug(
                "valve %s: setpoint acknowledged, unconfirmed (%s)", eui, type(exc).__name__
            )
            return
        except StaleGenerationError:
            return
        if statuses is None:
            return
        core.apply(eui, req.cluster, statuses, req.manufacturer)
        core.responded(eui)
        value = core.states[eui].setpoint_c
        if _latest(core, eui, version) and value is not None:
            _update(core, eui, confirmed_c=value, confirmed_at=core.clock.now())
        else:
            core.changed()
    finally:
        tx.lock.release()
        if tx.confirm is asyncio.current_task():
            tx.confirm = None
        if _latest(core, eui, version):
            _update(core, eui, pending=False)


__all__ = ["set_setpoint"]
