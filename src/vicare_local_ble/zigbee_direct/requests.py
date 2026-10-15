"""Allocators, envelopes, pending requests, the retired window and the join slot (spec §1.3).

Implemented by T11; frozen interface (T2). Pure bookkeeping on the loop thread: no I/O, no
tasks. Futures are created on the running loop by ``PendingMap.register``/``JoinSlot.open``.
Time comes from the injected ``Clock`` (TTL checks are lazy, no timers).

Who calls what
    * ``ZigbeeDirectNode`` owns one ``Allocators``, one ``PendingMap`` and one ``JoinSlot``.
    * The node registers a ``Pending`` **before** ``transport.send_npdu`` (a response racing
      the write return must still match), keeps it registered across retransmits (same key),
      and calls ``retire`` exactly once when the request ends (success, timeout, error or
      cancellation). Each attempt awaits ``asyncio.shield(pending.future)`` inside
      ``clock.timeout(request_timeout)``, so an attempt timeout never cancels the future and a
      late answer to attempt 1 resolves the request during attempt 2. Besides a matching
      response (``resolve``), only ``fail_dst`` (``RouteError``), ``retire`` and ``fail_all``
      (node close) complete or cancel a pending future. ``fail_attempt`` (a retryable Network
      Status) touches only the oldest outstanding attempt signal (``Pending.signals``): the
      node resends under the same key, so a late answer still resolves the request.
    * ``Dispatcher`` (``dispatch.py``) calls ``match_*``/``resolve``, ``is_retired`` and
      ``for_src`` (fallback); ``Router.on_network_status`` calls ``fail_dst`` or
      ``fail_attempt``.
    * ``node.join`` opens a ``JoinToken`` per attempt, each with a NEW placeholder (previous
      placeholders of this join are avoided); the dispatcher offers every NWK Commissioning
      Response to ``JoinSlot.offer``, so a response to an older attempt's placeholder is
      rejected (DEBUG) once its token was replaced.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Final, Self

from vicare_local_ble.zigbee_direct.codec.aps import ZDO_PROFILE_ID
from vicare_local_ble.zigbee_direct.codec.fallback import ExpectedZcl, ExpectedZdo
from vicare_local_ble.zigbee_direct.codec.zcl import ZclCommandId
from vicare_local_ble.zigbee_direct.errors import SequenceExhaustedError
from vicare_local_ble.zigbee_direct.node_match import (
    default_response_command,
    zcl_verdict,
    zdo_verdict,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.codec.aps import ApsDataFrame
    from vicare_local_ble.zigbee_direct.codec.fallback import Expected, ZdoResponse
    from vicare_local_ble.zigbee_direct.codec.nwk import NwkFrame
    from vicare_local_ble.zigbee_direct.codec.nwk_commands import CommissioningResponse
    from vicare_local_ble.zigbee_direct.codec.zcl import ZclFrame, ZclGlobalCommand, ZclHeader
    from vicare_local_ble.zigbee_direct.codec.zdo import (
        ActiveEpReq,
        IeeeAddrReq,
        MatchDescReq,
        NwkAddrReq,
        SimpleDescReq,
    )
    from vicare_local_ble.zigbee_direct.codec.zdo_mgmt import MgmtLqiReq
    from vicare_local_ble.zigbee_direct.errors import RequestKind
    from vicare_local_ble.zigbee_direct.types import Eui64

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.node")

#: Retired keys kept at most (oldest evicted first), in addition to the TTL.
MAX_RETIRED: Final = 512

type ZdoRequest = MgmtLqiReq | ActiveEpReq | SimpleDescReq | IeeeAddrReq | NwkAddrReq | MatchDescReq
"""ZDO requests the node can send. Their ``seq`` field is ignored: ``zdo_request`` replaces it
(``dataclasses.replace``) with the allocated ZDO seq. Response cluster = ``CLUSTER_ID | 0x8000``."""

type PendingKey = tuple[int, RequestKind, int]
"""``(src_short, kind, seq)``: the device we expect the response from, namespace, ZDO seq/TSN."""


class SeqAllocator:
    """8-bit wrapping counter. ``next(skip=...)`` returns the next value for which ``skip`` is
    false, advancing past skipped values; raises ``SequenceExhaustedError`` if all 256 values
    are skipped.
    """

    __slots__ = ("_next",)

    def __init__(self, start: int = 0) -> None:
        if not 0 <= start <= 0xFF:
            raise ValueError(f"start out of range 0..255: {start!r}")
        self._next = start

    def next(self, *, skip: Callable[[int], bool] | None = None) -> int:
        for _ in range(256):
            value = self._next
            self._next = (value + 1) & 0xFF
            if skip is None or not skip(value):
                return value
        raise SequenceExhaustedError("all 256 sequence values are in use")

    def peek(self) -> int:
        """The value ``next()`` would try first (no skipping, no advance)."""
        return self._next


@dataclass(slots=True)
class Allocators:
    """One allocator per sequence space, owned by one node (never shared module state).

    * ``nwk``: NWK sequence numbers for every frame we originate (join, data, routing).
    * ``zdo``: ZDO transaction sequence numbers; the node skips values whose key
      ``(dst, "zdo", seq)`` is pending or retired for THAT destination
      (``PendingMap.key_in_use``): matching is per source, so other devices may share a seq.
    * ``tsn``: ZCL transaction sequence numbers, skipped the same way (``kind="zcl"``).
    * ``aps``: APS counter for ZCL unicasts and broadcasts. Not a correlation key (PN §5.7).
      ZDO unicasts use APS counter 0 as the live client did (``frames.zdo_unicast_npdu``).

    Start values are 1 (live: commissioning used NWK seq 1). Tests may inject others.
    """

    nwk: SeqAllocator
    zdo: SeqAllocator
    tsn: SeqAllocator
    aps: SeqAllocator

    @classmethod
    def create(cls, start: int = 1) -> Self:
        return cls(
            nwk=SeqAllocator(start),
            zdo=SeqAllocator(start),
            tsn=SeqAllocator(start),
            aps=SeqAllocator(start),
        )


class EnvelopeMatch(Enum):
    """Result of matching a decoded response against an ``Envelope``."""

    NO_MATCH = "no_match"
    MATCH = "match"
    #: Matched, but a manufacturer-specific request was answered without the MS header
    #: (accepted per PN §5.11, counted in ``NodeStats.mfr_header_missing``).
    MATCH_MFR_HEADER_MISSING = "match_mfr_header_missing"


@dataclass(frozen=True, slots=True)
class Envelope:
    """Everything a response must carry to resolve a pending request (spec §1.3 table).

    ZCL (``kind="zcl"``): ``seq`` is the TSN; response must come from ``src_short``, with APS
    profile ``profile_id``, cluster ``cluster_id``, APS src endpoint ``remote_endpoint`` (the
    request's dst endpoint), APS dst endpoint ``local_endpoint``, ZCL global frame,
    server->client direction, and a command in ``response_commands`` or a Default Response whose
    ``command_id == request_command``. ``manufacturer_code``: a response that carries a code must
    match it; a response without one to a manufacturer request is accepted as
    ``MATCH_MFR_HEADER_MISSING``; a response with a code to a standard request never matches.

    ZDO (``kind="zdo"``): ``seq`` is the ZDO seq; response from ``src_short``, profile 0, cluster
    ``cluster_id`` (request cluster | 0x8000). Endpoints are not checked. If
    ``nwk_addr_of_interest`` is set and the decoded response has an address-of-interest field
    (``nwk_addr`` on Active_EP/Simple_Desc/IEEE_addr responses), it must be equal; Mgmt_Lqi has
    none. (The spec table says Active_EP and Simple_Desc have none; their codecs do carry
    ``nwk_addr`` and PN §1.5 shows the valve short there, so T2 chose to check it.)
    """

    src_short: int
    kind: RequestKind
    seq: int
    profile_id: int
    cluster_id: int
    remote_endpoint: int | None = None
    local_endpoint: int | None = None
    manufacturer_code: int | None = None
    request_command: int | None = None
    response_commands: frozenset[int] = frozenset()
    nwk_addr_of_interest: int | None = None

    @property
    def key(self) -> PendingKey:
        return (self.src_short, self.kind, self.seq)

    def match_zcl(self, src_short: int, aps: ApsDataFrame, frame: ZclFrame) -> EnvelopeMatch:
        """Check a standard-decoded ZCL response against every envelope field."""
        if (
            self.kind != "zcl"
            or src_short != self.src_short
            or aps.profile_id != self.profile_id
            or aps.cluster_id != self.cluster_id
            or (self.remote_endpoint is not None and aps.src_endpoint != self.remote_endpoint)
            or (self.local_endpoint is not None and aps.dst_endpoint != self.local_endpoint)
        ):
            return EnvelopeMatch.NO_MATCH
        header = frame.header
        default_command = None
        if header.command_id == ZclCommandId.DEFAULT_RESPONSE:
            default_command = default_response_command(frame.payload)
        return EnvelopeMatch(zcl_verdict(self, header, default_command))

    def match_zdo(self, src_short: int, aps: ApsDataFrame, response: ZdoResponse) -> bool:
        """Check a standard-decoded ZDO response (profile, cluster, seq, address of interest)."""
        return (
            src_short == self.src_short
            and aps.profile_id == ZDO_PROFILE_ID == self.profile_id
            and aps.cluster_id == self.cluster_id
            and zdo_verdict(self, response)
        )

    def expected(self) -> Expected:
        """The ``codec.fallback`` expectation for this envelope (``ExpectedZcl``/``ExpectedZdo``),
        used only after the standard decode failed; a ``ScanMatch`` must still pass command,
        TSN/seq and manufacturer checks."""
        if self.kind == "zdo":
            return ExpectedZdo(src_short=self.src_short, cluster_id=self.cluster_id, seq=self.seq)
        command = min(self.response_commands, default=ZclCommandId.DEFAULT_RESPONSE)
        return ExpectedZcl(
            src_short=self.src_short,
            tsn=self.seq,
            command_id=command,
            cluster_id=self.cluster_id,
            manufacturer_code=self.manufacturer_code,
        )


@dataclass(frozen=True, slots=True)
class ZclResponse:
    """A matched ZCL response: header, decoded global command, and how it was found."""

    header: ZclHeader
    command: ZclGlobalCommand
    via_fallback: bool = False


type PendingResult = ZdoResponse | ZclResponse


@dataclass(slots=True, eq=False)
class Pending:
    """One in-flight request. ``future`` resolves with the matched response or fails with
    ``RouteError``/``ConnectionLostError``. Attempt timeouts are the node's and never touch the
    future (attempts never cancel it); ``retire`` cancels it if unfinished. ``attempts`` counts
    sends so far (diagnostics). ``signals``: one per attempt, armed BEFORE its send; the last
    is the current attempt. A signal not yet done is outstanding (its frame may still draw a
    0x05/0x06; a timed-out attempt stays outstanding). ``PendingMap.fail_attempt`` gives each
    status to the OLDEST outstanding one: the current one fails with the ``RouteError``, an
    earlier one is consumed (``None``). ``retire`` drops them all."""

    envelope: Envelope
    future: asyncio.Future[PendingResult]
    created_at: float
    attempts: int = 0
    signals: list[asyncio.Future[None]] = field(default_factory=list)

    def arm_attempt(self) -> asyncio.Future[None]:
        """A fresh outstanding signal for the attempt about to be sent (now the current one)."""
        signal: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.signals.append(signal)
        return signal

    def disarm(self, signal: asyncio.Future[None]) -> None:
        """Forget ``signal`` (its send raised, so no frame went out)."""
        with contextlib.suppress(ValueError):
            self.signals.remove(signal)
        _drop(signal)

    def drop_signals(self) -> None:
        for signal in self.signals:
            _drop(signal)
        self.signals.clear()


def _drop(signal: asyncio.Future[None]) -> None:
    """Cancel an unfinished attempt signal, or mark its failure as retrieved."""
    if not signal.done():
        signal.cancel()
    elif not signal.cancelled():
        signal.exception()


@dataclass(slots=True)
class RetiredWindow:
    """Bounded TTL set of retired keys: at most ``max_size`` keys, each kept ``ttl`` seconds.

    Pruning is lazy (on every ``add``/``contains``), from the clock's ``now()``.
    """

    clock: Clock
    ttl: float
    max_size: int = MAX_RETIRED
    _entries: dict[PendingKey, float] = field(default_factory=dict)

    def add(self, key: PendingKey) -> None:
        self._prune()
        self._entries.pop(key, None)  # re-adding refreshes the TTL and the eviction order
        self._entries[key] = self.clock.now()
        while len(self._entries) > self.max_size:
            del self._entries[next(iter(self._entries))]

    def contains(self, key: PendingKey) -> bool:
        self._prune()
        return key in self._entries

    def seq_in_use(self, kind: RequestKind, seq: int) -> bool:
        """True if any retired key of ``kind`` with ``seq`` is still in the window (any src)."""
        self._prune()
        return any(k[1] == kind and k[2] == seq for k in self._entries)

    def discard(self, key: PendingKey) -> None:
        """Forget ``key`` (it is pending again). T11 addition."""
        self._entries.pop(key, None)

    def __len__(self) -> int:
        self._prune()
        return len(self._entries)

    def _prune(self) -> None:
        now = self.clock.now()
        entries = self._entries
        while entries:
            key, retired_at = next(iter(entries.items()))
            if now - retired_at < self.ttl:
                return
            del entries[key]


class PendingMap:
    """Pending requests by key plus the retired window. One per node."""

    __slots__ = ("_clock", "_entries", "_retired")

    def __init__(self, *, clock: Clock, late_window: float, max_retired: int = MAX_RETIRED) -> None:
        self._clock = clock
        self._entries: dict[PendingKey, Pending] = {}
        self._retired = RetiredWindow(clock, late_window, max_retired)

    def register(self, envelope: Envelope) -> Pending:
        """Create the future and store the entry; ``ValueError`` if the key is pending."""
        key = envelope.key
        if key in self._entries:
            raise ValueError(f"request {key!r} is already pending")
        future: asyncio.Future[PendingResult] = asyncio.get_running_loop().create_future()
        pending = Pending(envelope, future, self._clock.now())
        self._retired.discard(key)
        self._entries[key] = pending
        return pending

    def get(self, key: PendingKey) -> Pending | None:
        return self._entries.get(key)

    def for_src(self, src_short: int) -> tuple[Pending, ...]:
        """Pending entries expecting a response from ``src_short`` (fallback candidates)."""
        return tuple(p for k, p in self._entries.items() if k[0] == src_short)

    def seq_in_use(self, kind: RequestKind, seq: int) -> bool:
        """True if ``seq`` of ``kind`` is pending for any src or retired within the window
        (destination-independent; requests use the per-destination ``key_in_use``)."""
        return any(k[1] == kind and k[2] == seq for k in self._entries) or self._retired.seq_in_use(
            kind, seq
        )

    def key_in_use(self, key: PendingKey) -> bool:
        """True if ``key`` is pending or retired within the window: the allocators' ``skip``
        predicate for one destination. T11 addition (CP3: collisions are per source)."""
        return key in self._entries or self._retired.contains(key)

    def is_retired(self, key: PendingKey) -> bool:
        return key not in self._entries and self._retired.contains(key)

    def resolve(self, key: PendingKey, result: PendingResult) -> bool:
        """Set the result if the entry exists and is not done; False otherwise."""
        pending = self._entries.get(key)
        if pending is None or pending.future.done():
            return False
        pending.future.set_result(result)
        return True

    def retire(self, key: PendingKey) -> None:
        """Remove the entry (cancelling an unfinished future) and add the key to the window.
        Idempotent."""
        pending = self._entries.pop(key, None)
        if pending is None:
            return
        future = pending.future
        if not future.done():
            future.cancel()
        elif not future.cancelled():
            future.exception()  # mark a failure as retrieved (the caller already saw it)
        pending.drop_signals()
        self._retired.add(key)

    def fail_dst(self, dst: int, exc: BaseException) -> int:
        """Fail every pending future expecting ``dst`` with ``exc``; returns how many.

        The SAME exception instance is set on every failed future (copying is not generally
        possible: library exceptions take custom constructor arguments); each awaiting task
        re-raises it, so its ``__traceback__`` accumulates frames from all of them."""
        failed = 0
        for key, pending in self._entries.items():
            if key[0] == dst and not pending.future.done():
                pending.future.set_exception(exc)
                failed += 1
        return failed

    def fail_attempt(self, dst: int, exc: BaseException) -> int:
        """Give a retryable status about ``dst`` to the oldest outstanding attempt of each
        unfinished entry expecting ``dst`` (see ``Pending``); returns how many CURRENT attempts
        were failed. Nothing outstanding (or nothing pending) -> no effect."""
        failed = 0
        for key, pending in self._entries.items():
            if key[0] != dst or pending.future.done():
                continue
            signal = next((s for s in pending.signals if not s.done()), None)
            if signal is None:
                continue
            if signal is pending.signals[-1]:
                signal.set_exception(exc)
                failed += 1
            else:
                signal.set_result(None)
                _LOGGER.debug("status for an earlier attempt of %r consumed", key)
        return failed

    def fail_all(self, exc: BaseException) -> None:
        """Fail every pending future (node close) with the one shared ``exc`` (see
        ``fail_dst``)."""
        for pending in self._entries.values():
            if not pending.future.done():
                pending.future.set_exception(exc)

    def __len__(self) -> int:
        return len(self._entries)


@dataclass(frozen=True, slots=True)
class JoinToken:
    """The active join attempt: a Commissioning Response resolves it only if its NWK src is
    ``zdd_short``, its NWK dst is ``placeholder``, and its dst IEEE (if present) is ``own_eui``.
    ``nwk_seq`` is the Commissioning Request's NWK seq (diagnostics only, not matched).
    Every join attempt uses a fresh placeholder, so tokens of one join never share one."""

    placeholder: int
    nwk_seq: int
    zdd_short: int
    own_eui: Eui64


class JoinSlot:
    """Holds at most one ``JoinToken`` and its future.

    ``open`` replaces (and cancels) any previous token; ``offer`` is called by the dispatcher for
    every decoded Commissioning Response and returns True if it resolved the active token;
    mismatching or token-less responses return False (the dispatcher logs one DEBUG line).
    ``close`` cancels the active future. Validation of the assigned short and status is the
    node's job after the future resolves.
    """

    __slots__ = ("_future", "_token")

    def __init__(self) -> None:
        self._token: JoinToken | None = None
        self._future: asyncio.Future[CommissioningResponse] | None = None

    def open(self, token: JoinToken) -> asyncio.Future[CommissioningResponse]:
        self.close()
        future: asyncio.Future[CommissioningResponse] = asyncio.get_running_loop().create_future()
        self._token, self._future = token, future
        return future

    def offer(self, frame: NwkFrame, response: CommissioningResponse) -> bool:
        token, future = self._token, self._future
        if token is None or future is None or future.done():
            return False
        if frame.src != token.zdd_short or frame.dst != token.placeholder:
            return False
        if frame.dst_ieee is not None and frame.dst_ieee != token.own_eui:
            return False
        future.set_result(response)
        return True

    def close(self) -> None:
        future = self._future
        if future is not None and not future.done():
            future.cancel()
        self._token = self._future = None

    @property
    def active(self) -> JoinToken | None:
        return self._token


__all__ = [
    "MAX_RETIRED",
    "Allocators",
    "Envelope",
    "EnvelopeMatch",
    "JoinSlot",
    "JoinToken",
    "Pending",
    "PendingKey",
    "PendingMap",
    "PendingResult",
    "RetiredWindow",
    "SeqAllocator",
    "ZclResponse",
    "ZdoRequest",
]
