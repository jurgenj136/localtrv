"""One connection attempt/generation of ``ZdConnection`` and its ordered teardown.

Private helper of ``connection.py``. A ``Session`` is created per attempt and owns the client,
transport, node and the generation's spawned tasks. ``teardown`` runs the contract order:
cancel and await spawned tasks -> ``node.close`` -> ``transport.close`` -> bounded disconnect.
Leaving READY is the connection's business and happens before ``teardown`` is called.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import TYPE_CHECKING, Any

from bleak_retry_connector import BleakClientWithServiceCache

from vicare_local_ble.zigbee_direct.errors import ConnectionLostError, TransportError
from vicare_local_ble.zigbee_direct.transport import ZigbeeDirectTransport

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from vicare_local_ble.zigbee_direct.clock import Clock
    from vicare_local_ble.zigbee_direct.connection_types import (
        Connector,
        DeviceResolver,
        Generation,
    )
    from vicare_local_ble.zigbee_direct.node import ZigbeeDirectNode
    from vicare_local_ble.zigbee_direct.node_types import NodeStats
    from vicare_local_ble.zigbee_direct.transport import GattClient
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

_LOGGER = logging.getLogger("vicare_local_ble.zigbee_direct.connection")


class Session:
    """State of one attempt; becomes a generation once READY (see module docstring).

    ``lost`` resolves with the failure reason of the first trigger (disconnect, transport fatal,
    rejoin, address conflict); later triggers are ignored. ``ended`` is set when teardown starts.
    """

    __slots__ = (
        "clear_cache",
        "client",
        "conflicted",
        "ended",
        "generation",
        "lost",
        "node",
        "tasks",
        "transport",
    )

    def __init__(self) -> None:
        self.client: GattClient | None = None
        self.transport: ZigbeeDirectTransport | None = None
        self.node: ZigbeeDirectNode | None = None
        self.generation: Generation | None = None
        self.tasks: set[asyncio.Task[Any]] = set()
        self.lost: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self.conflicted = False
        self.ended = False
        self.clear_cache = False  # stale GATT cache: clear the client cache before teardown

    def fail(self, reason: str) -> bool:
        """Record the first trigger; False if the session already failed or is ending."""
        if self.ended or self.lost.done():
            return False
        self.lost.set_result(reason)
        return True

    def spawn[T](self, coro: Coroutine[Any, Any, T], name: str) -> asyncio.Task[T]:
        task = asyncio.get_running_loop().create_task(coro, name=name)
        self.tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task[Any]) -> None:
        self.tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.warning("task %s failed: %s: %s", task.get_name(), type(exc).__name__, exc)

    async def teardown(
        self, clock: Clock, *, disconnect_timeout: float, tasks_timeout: float
    ) -> NodeStats | None:
        """Ordered teardown; returns a final snapshot of the node's stats (if any node).

        Spawned tasks get ``tasks_timeout`` to finish after cancellation; stragglers are logged
        at WARNING by name and the teardown continues without them.
        """
        self.ended = True
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            try:
                async with clock.timeout(tasks_timeout):
                    await asyncio.wait(tasks)
            except TimeoutError:
                names = sorted(t.get_name() for t in tasks if not t.done())
                _LOGGER.warning("tasks ignored cancellation at teardown: %s", ", ".join(names))
        snapshot: NodeStats | None = None
        if self.node is not None:
            snapshot = dataclasses.replace(self.node.stats)
            try:
                await self.node.close(ConnectionLostError("connection generation torn down"))
            except Exception as exc:  # pragma: no cover - node.close does not raise
                _LOGGER.debug("node close failed: %s", type(exc).__name__)
        if self.transport is not None:
            try:
                await self.transport.close()
            except Exception as exc:  # pragma: no cover - transport.close does not raise
                _LOGGER.debug("transport close failed: %s", type(exc).__name__)
        if self.client is not None:
            await disconnect_client(self.client, clock, disconnect_timeout)
        return snapshot


async def disconnect_client(client: GattClient, clock: Clock, timeout: float) -> None:
    """``client.disconnect()`` bounded to ``timeout``; failures are logged at DEBUG only."""
    try:
        async with clock.timeout(timeout):
            await client.disconnect()
    except Exception as exc:  # TimeoutError included
        _LOGGER.debug("disconnect failed: %s", type(exc).__name__)


async def run_validation(
    resolve_device: DeviceResolver,
    *,
    own_eui: Eui64,
    psk: SecretBytes,
    clock: Clock,
    connector: Connector,
    timeout: float,
    disconnect_timeout: float,
    max_attempts: int,
) -> Eui64:
    """Handshake-only attempt for ``validate_connection`` (see its docstring)."""
    client: GattClient | None = None
    try:
        async with clock.timeout(timeout):
            device = resolve_device()
            if device is None:
                raise TransportError("device not found", reason="not_found")
            client = await connector(
                BleakClientWithServiceCache,
                device,
                "ZDD",
                None,
                use_services_cache=True,
                max_attempts=max_attempts,
            )
            transport = ZigbeeDirectTransport(client, own_eui=own_eui, psk=psk, clock=clock)
            try:
                info = await transport.open()
            finally:
                await transport.close()
            return info.zdd_eui
    finally:
        if client is not None:
            await run_protected(disconnect_client(client, clock, disconnect_timeout))


async def run_protected[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run ``coro`` in its own task to completion even if the caller is cancelled (any number
    of times) meanwhile; the caller's cancellation is re-raised once it is done."""
    task = asyncio.get_running_loop().create_task(coro)
    cancelled = False
    while True:
        try:
            result = await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                raise
            cancelled = True
            continue
        if cancelled:
            raise asyncio.CancelledError
        return result


__all__ = ["Session", "disconnect_client", "run_protected", "run_validation"]
