"""Request engine of a ``ZigbeeDirectNode``: locks, allocation, pending lifecycle, retries (T11).

Private helper of ``node.py`` (see the ``ZigbeeDirectNode`` docstring "Requests"):

1. per-destination lock, then the global ``max_in_flight`` semaphore;
2. allocate the ZDO seq / ZCL TSN, skipping values whose ``(dst, kind, seq)`` key is pending
   or retired within the late window (per destination: matching is per source);
3. register the pending entry BEFORE the first send (a response racing the write still
   matches);
4. up to ``request_attempts`` attempts, each a new NWK seq (and APS counter for ZCL) with the
   same ZDO seq / TSN. The caller's ``guard`` (if any) runs before each attempt is queued
   and again when the transport writer dequeues it, right before encryption; if it raises,
   that attempt is not sent and the request fails with its exception. Each attempt awaits
   the future (never cancelled) or the attempt's signal inside ``clock.timeout``: an
   attempt timeout never cancels the future, so a late answer to attempt 1 resolves
   attempt 2;
4a. each attempt's signal is armed BEFORE its send (``Pending.arm_attempt``; removed if the
   send raises). A retryable Network Status (``routing.ATTEMPT_FAILURE_STATUSES``: 0x05/0x06,
   the parent of a sleepy destination dropped a frame) goes to the OLDEST outstanding attempt
   (``PendingMap.fail_attempt``): one of the current attempt ends it early, one of an earlier,
   timed-out attempt is consumed without effect. The next attempt is sent at once (0x05: after
   ``routing.NO_INDIRECT_CAPACITY_RETRY_DELAY``, cut short if the request completes meanwhile)
   and counted in ``NodeStats.indirect_retries`` when it is sent. It consumes one attempt of
   the budget: after the last one the ``RouteError`` is raised;
5. an answer that arrived in the same loop iteration as the last attempt's timeout still
   wins over ``RequestTimeoutError``;
6. ``PendingMap.retire`` in a ``finally`` exactly once (success, timeout, error, cancel).
"""

from __future__ import annotations

import asyncio
import contextlib
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
from vicare_local_ble.zigbee_direct.errors import RequestTimeoutError, RouteError, ZclStatusError
from vicare_local_ble.zigbee_direct.frames import LOCAL_ENDPOINT, zcl_unicast_npdu, zdo_unicast_npdu
from vicare_local_ble.zigbee_direct.node_match import ADDRESS_OF_INTEREST_REQUESTS
from vicare_local_ble.zigbee_direct.requests import Envelope, ZclResponse
from vicare_local_ble.zigbee_direct.routing import attempt_retry_delay

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
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.node")
_ZDO_RESPONSE_BIT: Final = 0x8000
_FIRST_BROADCAST: Final = 0xFFF8

#: ``build(seq, nwk_seq) -> npdu`` for one attempt.
type Builder = Callable[[int, int], bytes]
#: Called before every attempt; raises to fail the request without sending that attempt.
type Guard = Callable[[], None]


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
    guard: Guard | None = None,
) -> PendingResult:
    """One request (module docstring); returns the matched result."""
    _check_dst(dst)
    core.check_ready()
    async with core.dst_lock(dst):
        core.check_ready()
        async with core.in_flight:
            core.check_ready()
            return await _attempts(
                core, dst=dst, kind=kind, envelope_for=envelope_for, build=build, guard=guard
            )


async def _attempts(
    core: NodeCore,
    *,
    dst: int,
    kind: RequestKind,
    envelope_for: Callable[[int], Envelope],
    build: Builder,
    guard: Guard | None,
) -> PendingResult:
    pending_map, config = core.pending, core.config
    allocator = core.allocators.zdo if kind == "zdo" else core.allocators.tsn
    seq = allocator.next(skip=lambda value: pending_map.key_in_use((dst, kind, value)))
    envelope = envelope_for(seq)
    pending = pending_map.register(envelope)
    _LOGGER.debug("pending %s seq %d to 0x%04X registered", kind, seq, dst)
    try:
        dropped: RouteError | None = None  # the last attempt's retryable Network Status
        for attempt in range(config.request_attempts):
            if pending.future.done():  # answered in the same iteration as a timeout / delay
                return pending.future.result()
            resend_after_drop = dropped is not None
            dropped = None
            if guard is not None:
                guard()  # the destination may no longer be the intended device
            # armed before the send: a status racing the write still ends this attempt
            signal = pending.arm_attempt()
            try:
                await core.send_secure(build(seq, core.allocators.nwk.next()), guard)
            except BaseException:
                pending.disarm(signal)
                raise
            pending.attempts += 1  # counted once the frame is out
            if attempt:
                core.stats.retransmits += 1
                if resend_after_drop:
                    core.stats.indirect_retries += 1
            with contextlib.suppress(TimeoutError):
                async with core.clock.timeout(config.request_timeout):
                    await asyncio.wait(
                        (pending.future, signal), return_when=asyncio.FIRST_COMPLETED
                    )
            if pending.future.done():  # also an answer racing the timeout: it wins
                return pending.future.result()
            if not signal.done():  # stays outstanding: its status may still come
                _LOGGER.debug("%s seq %d to 0x%04X: attempt %d timed out", kind, seq, dst, attempt)
                continue
            dropped = _dropped(signal)
            _LOGGER.debug(
                "%s seq %d to 0x%04X: attempt %d dropped (network status 0x%02X)",
                kind,
                seq,
                dst,
                attempt,
                dropped.status,
            )
            if attempt + 1 < config.request_attempts and (
                delay := attempt_retry_delay(dropped.status)
            ):
                await _backoff(core, pending.future, delay)
        if dropped is not None:
            raise dropped
        core.stats.timeouts += 1
        raise RequestTimeoutError(dst, kind, seq)
    finally:
        pending_map.retire(envelope.key)
        _LOGGER.debug("pending %s seq %d to 0x%04X retired", kind, seq, dst)


async def _backoff(core: NodeCore, future: asyncio.Future[PendingResult], delay: float) -> None:
    """Wait ``delay`` s before a resend, or less if ``future`` completes first (answer,
    ``fail_dst``, node close); never cancels ``future``. The caller checks it next."""
    with contextlib.suppress(TimeoutError):
        async with core.clock.timeout(delay):
            await asyncio.wait((future,))


def _dropped(signal: asyncio.Future[None]) -> RouteError:
    """The ``RouteError`` an attempt signal was failed with (``PendingMap.fail_attempt``)."""
    exc = signal.exception()
    if not isinstance(exc, RouteError):  # pragma: no cover - fail_attempt sets RouteError only
        raise TypeError(f"unexpected attempt signal {exc!r}")
    return exc


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
    expect_ieee: Eui64 | None = None,
    guard: Guard | None = None,
) -> ZclGlobalCommand:
    """A ZCL global request. A matched Default Response raises ``ZclStatusError(status)``,
    except status SUCCESS when ``on_default_success`` is given (returned instead).
    ``expect_ieee``: ``Envelope.expect_ieee``; ``guard``: see the module docstring (4)."""

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
            expect_ieee=expect_ieee,
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

    result = await run_request(
        core, dst=dst, kind="zcl", envelope_for=envelope_for, build=build, guard=guard
    )
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
    expect_ieee: Eui64 | None = None,
    guard: Guard | None = None,
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
        expect_ieee=expect_ieee,
        guard=guard,
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
    expect_ieee: Eui64 | None = None,
    guard: Guard | None = None,
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
        expect_ieee=expect_ieee,
        guard=guard,
    )
    if not isinstance(result, WriteAttributesResponse):  # pragma: no cover - envelope command
        raise TypeError(f"unexpected {type(result).__name__}")
    return result


__all__ = ["run_request", "zcl_read", "zcl_request", "zcl_write", "zdo_request"]
