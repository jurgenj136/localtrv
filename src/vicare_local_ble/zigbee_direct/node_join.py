"""The NWK join of a ``ZigbeeDirectNode``: STATUS -> COMMISSIONING -> ANNOUNCED -> ROUTED.

Private helper of ``node.py`` (docs/protocol.md §6; ``ZigbeeDirectNode`` docstring).
Each Commissioning Request attempt draws a NEW placeholder short and opens a fresh
``JoinToken``, so a late response to an older attempt no longer matches. The Commissioning
Status is reduced to ``NetworkSummary`` at once and never logged.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Final

from vicare_local_ble.zigbee_direct.codec.nwk_commands import commissioning_request_npdu
from vicare_local_ble.zigbee_direct.errors import (
    CommissioningDecodeError,
    DecodeError,
    JoinError,
    JoinRejectedError,
)
from vicare_local_ble.zigbee_direct.node_types import JoinInfo, NetworkSummary
from vicare_local_ble.zigbee_direct.requests import JoinToken
from vicare_local_ble.zigbee_direct.types import COORDINATOR

if TYPE_CHECKING:
    from vicare_local_ble.zigbee_direct.codec.nwk_commands import CommissioningResponse
    from vicare_local_ble.zigbee_direct.node_core import NodeCore

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.node")

#: Valid unicast shorts we may request or be assigned: 0x0001..0xFFF7.
MIN_SHORT: Final = 0x0001
MAX_SHORT: Final = 0xFFF7


def is_valid_own_short(short: int, zdd_short: int) -> bool:
    """An assigned or requested own short: 0x0001..0xFFF7 and not the ZDD's short."""
    return MIN_SHORT <= short <= MAX_SHORT and short != zdd_short


def pick_placeholder(core: NodeCore, *, first: bool, avoid: set[int]) -> int:
    """``preferred_short`` on the first attempt if valid and not avoided, else a random draw
    from 0x0001..0xFFF7 re-drawn while it falls in ``avoid``."""
    preferred = core.config.preferred_short
    if (
        first
        and preferred is not None
        and MIN_SHORT <= preferred <= MAX_SHORT
        and preferred not in avoid
    ):
        return preferred
    while True:
        short = core.rng.randrange(MIN_SHORT, MAX_SHORT + 1)
        if short not in avoid:
            return short


async def run_join(core: NodeCore) -> JoinInfo:
    """Join through the ZDD and return the result (see module docstring)."""
    core.check_open()
    if core.join_started:
        raise RuntimeError("join() may be called once")
    core.join_started = True
    zdd_eui = core.zdd_eui
    zdd_short, network = await _read_status(core)
    if zdd_short is None or zdd_short > MAX_SHORT:
        raise JoinError("Commissioning Status has no valid ZDD short (TLV 0x06)")
    # COMMISSIONING
    requested, response = await _commission(core, zdd_short)
    if not response.success:
        raise JoinRejectedError(response.status)
    own_short = response.short
    if not is_valid_own_short(own_short, zdd_short):
        raise JoinError(f"invalid assigned short 0x{own_short:04X}")
    core.current_short = own_short
    _LOGGER.debug("commissioned as 0x%04X (requested 0x%04X)", own_short, requested)
    # ANNOUNCED, ROUTED
    await core.router.announce()
    await core.router.send_mtorr_burst()
    core.router.start_periodic()
    info = JoinInfo(
        own_short=own_short,
        own_eui=core.own_eui,
        zdd_short=zdd_short,
        zdd_eui=zdd_eui,
        requested_short=requested,
        network=network,
    )
    core.join_info = info
    _LOGGER.info(
        "joined: own short 0x%04X (requested 0x%04X) via ZDD 0x%04X",
        own_short,
        requested,
        zdd_short,
    )
    return info


async def _read_status(core: NodeCore) -> tuple[int | None, NetworkSummary]:
    """STATUS: read and reduce the Commissioning Status (ZDD short, ``NetworkSummary``).

    The status (and any decode error, whose traceback frames hold the decrypted plaintext as
    locals) holds the network, link and admin keys. Every failure is turned into a JoinError
    raised OUTSIDE the ``except`` block, so it has neither ``__cause__`` nor ``__context__``
    and nothing keeps those frames alive. Only a plain string survives the ``except``: the
    ``safe_detail`` of a ``CommissioningDecodeError`` (TLV headers up to the first unverified
    one, see ``safe_status_layout``), else just the exception type. A codec
    message is never used: with a lying TLV length, its offsets and lengths could be key bytes.
    """
    detail: str | None = None
    try:
        status = await core.transport.read_commissioning_status()
    except DecodeError as exc:
        safe = exc.safe_detail if isinstance(exc, CommissioningDecodeError) else None
        detail = safe if safe is not None else type(exc).__name__
        del exc  # drop the reference (and its traceback frames) before leaving the block
    if detail is not None:
        raise JoinError(f"malformed Commissioning Status ({detail})")
    try:
        zdd_short = status.nwk_address
        ieee = status.ieee_address
        network = NetworkSummary.from_status(status)
    except Exception as exc:
        detail = type(exc).__name__
        del exc
    del status  # the full status holds the network, link and admin keys
    if detail is not None:
        raise JoinError(f"unusable Commissioning Status: {detail}")
    if network.status_deviations:  # headers only: (tag, length), never a value byte
        _LOGGER.info(
            "Commissioning Status deviates from ZD 1.0: %s",
            ", ".join(f"tag 0x{tag:02X} len {length}" for tag, length in network.status_deviations),
        )
    if ieee is not None and ieee != core.zdd_eui:
        _LOGGER.warning("Commissioning Status IEEE (TLV 0x08) differs from the SE2 EUI; using SE2")
    return zdd_short, network


async def _commission(core: NodeCore, zdd_short: int) -> tuple[int, CommissioningResponse]:
    """Up to ``join_attempts`` Commissioning Requests, each with a fresh placeholder/token."""
    config = core.config
    avoid = set(config.avoid_shorts) | {COORDINATOR, zdd_short}
    try:
        for attempt in range(config.join_attempts):
            placeholder = pick_placeholder(core, first=attempt == 0, avoid=avoid)
            avoid.add(placeholder)
            nwk_seq = core.allocators.nwk.next()
            token = JoinToken(
                placeholder=placeholder, nwk_seq=nwk_seq, zdd_short=zdd_short, own_eui=core.own_eui
            )
            future = core.join_slot.open(token)
            core.join_future = future
            npdu = commissioning_request_npdu(
                zvd_eui=core.own_eui,
                zdd_eui=core.zdd_eui,
                zdd_short=zdd_short,
                placeholder_short=placeholder,
                seq=nwk_seq,
            )
            await core.send(npdu, secure=False)
            try:
                async with core.clock.timeout(config.join_timeout):
                    # shielded: a timeout never cancels the token's future, so a response
                    # that arrived in the same iteration as the timeout is still used
                    response = await asyncio.shield(future)
            except TimeoutError:
                if future.done() and not future.cancelled():
                    return placeholder, future.result()
                _LOGGER.debug(
                    "no Commissioning Response for 0x%04X (attempt %d)", placeholder, attempt + 1
                )
                continue
            return placeholder, response
    finally:
        last = core.join_future
        if last is not None and last.done() and not last.cancelled():
            last.exception()  # e.g. failed by close() while we were sending: retrieved
        core.join_future = None
        core.join_slot.close()
    raise JoinError(f"no Commissioning Response after {config.join_attempts} attempt(s)")


__all__ = ["MAX_SHORT", "MIN_SHORT", "is_valid_own_short", "pick_placeholder", "run_join"]
