"""Request engine of a ``ZigbeeDirectNode``: locks, allocation, pending lifecycle, retries (T11).

Private helper of ``node.py`` (see the ``ZigbeeDirectNode`` docstring "Requests"):

1. per-destination lock, then the global ``max_in_flight`` semaphore;
2. allocate the ZDO seq / ZCL TSN, skipping values whose ``(dst, kind, seq)`` key is pending
   or retired within the late window (per destination: matching is per source);
3. register the pending entry BEFORE the first send (a response racing the write still
   matches);
4. up to ``request_attempts`` attempts, each a new NWK seq (and APS counter for ZCL) with the
   same ZDO seq / TSN, awaiting ``asyncio.shield(future)`` inside ``clock.timeout``: an attempt
   timeout never cancels the future, so a late answer to attempt 1 resolves attempt 2;
5. an answer that arrived in the same loop iteration as the last attempt's timeout still
   wins over ``RequestTimeoutError``;
6. ``PendingMap.retire`` in a ``finally`` exactly once (success, timeout, error, cancel).
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import TYPE_CHECKING, Final

from vicare_local_ble.zigbee_direct.codec.aps import ZDO_PROFILE_ID
from vicare_local_ble.zigbee_direct.codec.zcl import (
    DefaultResponse,
    ReadAttributes,
    ReadAttributesResponse,
    WriteAttributes,
    WriteAttributesResponse,
    WriteAttributeStatus,
    ZclCommandId,
    ZclFrame,
    ZclStatus,
)
from vicare_local_ble.zigbee_direct.errors import RequestTimeoutError, ZclStatusError
from vicare_local_ble.zigbee_direct.frames import LOCAL_ENDPOINT, zcl_unicast_npdu, zdo_unicast_npdu
from vicare_local_ble.zigbee_direct.node_match import ADDRESS_OF_INTEREST_REQUESTS
from vicare_local_ble.zigbee_direct.requests import Envelope, ZclResponse

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from vicare_local_ble.zigbee_direct.codec.fallback import ZdoResponse
    from vicare_local_ble.zigbee_direct.codec.zcl import (
        AttributeRecord,
        ReadAttributeStatus,
        ZclGlobalCommand,
    )
    from vicare_local_ble.zigbee_direct.errors import RequestKind
    from vicare_local_ble.zigbee_direct.node_core import NodeCore
    from vicare_local_ble.zigbee_direct.requests import PendingResult, ZdoRequest

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.node")
_ZDO_RESPONSE_BIT: Final = 0x8000
_FIRST_BROADCAST: Final = 0xFFF8

#: ``build(seq, nwk_seq) -> npdu`` for one attempt.
type Builder = Callable[[int, int], bytes]


def _check_dst(dst: int) -> None:
    if not 0 <= dst < _FIRST_BROADCAST:
        raise ValueError(f"not a unicast short: {dst!r}")


async def run_request(
    core: NodeCore,
    *,
    dst: int,
    kind: RequestKind,
    envelope_for: Callable[[int], Envelope],
    build: Builder,
) -> PendingResult:
    """One request (module docstring); returns the matched result."""
    _check_dst(dst)
    core.check_ready()
    async with core.dst_lock(dst):
        core.check_ready()
        async with core.in_flight:
            core.check_ready()
            return await _attempts(core, dst=dst, kind=kind, envelope_for=envelope_for, build=build)


async def _attempts(
    core: NodeCore,
    *,
    dst: int,
    kind: RequestKind,
    envelope_for: Callable[[int], Envelope],
    build: Builder,
) -> PendingResult:
    pending_map, config = core.pending, core.config
    allocator = core.allocators.zdo if kind == "zdo" else core.allocators.tsn
    seq = allocator.next(skip=lambda value: pending_map.key_in_use((dst, kind, value)))
    envelope = envelope_for(seq)
    pending = pending_map.register(envelope)
    _LOGGER.debug("pending %s seq %d to 0x%04X registered", kind, seq, dst)
    try:
        for attempt in range(config.request_attempts):
            if pending.future.done():  # answered in the same iteration as the timeout
                return pending.future.result()
            if attempt:
                core.stats.retransmits += 1
            pending.attempts += 1
            await core.send_secure(build(seq, core.allocators.nwk.next()))
            try:
                async with core.clock.timeout(config.request_timeout):
                    return await asyncio.shield(pending.future)
            except TimeoutError:
                _LOGGER.debug("%s seq %d to 0x%04X: attempt %d timed out", kind, seq, dst, attempt)
        if pending.future.done():  # answered in the same iteration as the last timeout
            return pending.future.result()
        core.stats.timeouts += 1
        raise RequestTimeoutError(dst, kind, seq)
    finally:
        pending_map.retire(envelope.key)
        _LOGGER.debug("pending %s seq %d to 0x%04X retired", kind, seq, dst)


async def zdo_request[R: ZdoResponse](
    core: NodeCore, dst: int, request: ZdoRequest, response: type[R]
) -> R:
    cluster = request.CLUSTER_ID | _ZDO_RESPONSE_BIT
    if getattr(response, "CLUSTER_ID", None) != cluster:
        raise TypeError(f"{response.__name__} does not answer {type(request).__name__}")
    noi = request.nwk_addr if isinstance(request, ADDRESS_OF_INTEREST_REQUESTS) else None

    def envelope_for(seq: int) -> Envelope:
        return Envelope(
            src_short=dst,
            kind="zdo",
            seq=seq,
            profile_id=ZDO_PROFILE_ID,
            cluster_id=cluster,
            nwk_addr_of_interest=noi,
        )

    def build(seq: int, nwk_seq: int) -> bytes:
        return zdo_unicast_npdu(
            dst=dst,
            own_short=core.own_short,
            nwk_seq=nwk_seq,
            cluster_id=request.CLUSTER_ID,
            zdo_payload=dataclasses.replace(request, seq=seq).encode(),
        )

    result = await run_request(core, dst=dst, kind="zdo", envelope_for=envelope_for, build=build)
    if not isinstance(result, response):  # pragma: no cover - the envelope fixes the cluster
        raise TypeError(f"unexpected {type(result).__name__}")
    return result


async def zcl_request(
    core: NodeCore,
    *,
    dst: int,
    endpoint: int,
    cluster: int,
    profile: int,
    manufacturer: int | None,
    command: ZclGlobalCommand,
    response_command: int,
    on_default_success: ZclGlobalCommand | None = None,
) -> ZclGlobalCommand:
    """A ZCL global request. A matched Default Response raises ``ZclStatusError(status)``,
    except status SUCCESS when ``on_default_success`` is given (returned instead)."""

    def envelope_for(seq: int) -> Envelope:
        return Envelope(
            src_short=dst,
            kind="zcl",
            seq=seq,
            profile_id=profile,
            cluster_id=cluster,
            remote_endpoint=endpoint,
            local_endpoint=LOCAL_ENDPOINT,
            manufacturer_code=manufacturer,
            request_command=command.COMMAND_ID,
            response_commands=frozenset({response_command}),
        )

    def build(seq: int, nwk_seq: int) -> bytes:
        frame = ZclFrame.build(seq, command, manufacturer_code=manufacturer)
        return zcl_unicast_npdu(
            dst=dst,
            own_short=core.own_short,
            nwk_seq=nwk_seq,
            dst_endpoint=endpoint,
            cluster_id=cluster,
            profile_id=profile,
            zcl_frame=frame.encode(),
            aps_counter=core.allocators.aps.next(),
        )

    result = await run_request(core, dst=dst, kind="zcl", envelope_for=envelope_for, build=build)
    if not isinstance(result, ZclResponse):  # pragma: no cover - zcl envelopes resolve these
        raise TypeError(f"unexpected {type(result).__name__}")
    if isinstance(result.command, DefaultResponse):
        status = result.command.status
        if status == ZclStatus.SUCCESS and on_default_success is not None:
            return on_default_success
        raise ZclStatusError(status)
    return result.command


async def zcl_read(
    core: NodeCore,
    *,
    dst: int,
    endpoint: int,
    cluster: int,
    attrs: Sequence[int],
    profile: int,
    manufacturer: int | None,
) -> tuple[ReadAttributeStatus, ...]:
    result = await zcl_request(
        core,
        dst=dst,
        endpoint=endpoint,
        cluster=cluster,
        profile=profile,
        manufacturer=manufacturer,
        command=ReadAttributes(tuple(attrs)),
        response_command=ZclCommandId.READ_ATTRIBUTES_RESPONSE,
    )
    if not isinstance(result, ReadAttributesResponse):  # pragma: no cover - envelope command
        raise TypeError(f"unexpected {type(result).__name__}")
    return result.records


async def zcl_write(
    core: NodeCore,
    *,
    dst: int,
    endpoint: int,
    cluster: int,
    records: Sequence[AttributeRecord],
    profile: int,
    manufacturer: int | None,
) -> WriteAttributesResponse:
    result = await zcl_request(
        core,
        dst=dst,
        endpoint=endpoint,
        cluster=cluster,
        profile=profile,
        manufacturer=manufacturer,
        command=WriteAttributes(tuple(records)),
        response_command=ZclCommandId.WRITE_ATTRIBUTES_RESPONSE,
        on_default_success=WriteAttributesResponse((WriteAttributeStatus(ZclStatus.SUCCESS),)),
    )
    if not isinstance(result, WriteAttributesResponse):  # pragma: no cover - envelope command
        raise TypeError(f"unexpected {type(result).__name__}")
    return result


__all__ = ["run_request", "zcl_read", "zcl_request", "zcl_write", "zdo_request"]
