"""``FakeBleakClient`` and ``FakeConnector``: the client side of the simulated R0 (T8).

Re-exported by ``testing.gatt`` (the documented import path). The client is a thin
per-connection handle: it owns its subscriptions and its connected flag and forwards every GATT
operation to its ``SimulatedR0``, which holds all device behaviour and fault knobs.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from bleak.exc import BleakError

from vicare_local_ble.testing.errors import GATT_ERROR_UNLIKELY, FakeGattError
from vicare_local_ble.testing.gatt_services import CHARACTERISTICS, FakeServices

if TYPE_CHECKING:
    from collections.abc import Callable

    from bleak.backends.device import BLEDevice
    from bleak_retry_connector import BleakClientWithServiceCache

    from vicare_local_ble.testing.gatt import SimulatedR0
    from vicare_local_ble.zigbee_direct.transport import GattClient, NotifyCallback


class FakeBleakClient:
    """Per-connection client bound to a ``SimulatedR0``; satisfies ``GattClient``.

    After disconnect every operation raises ``FakeGattError`` (code 0x0E, like a dead bleak
    client) except ``disconnect()`` (idempotent) and ``clear_cache()`` (works offline, like
    bleak's). ``write_gatt_char`` requires ``response=True``. Created by
    ``SimulatedR0.connect``; ``disconnected_callback(client)`` fires once on any disconnect.
    """

    __slots__ = ("_callback", "_connected", "_device", "_r0", "_services", "_subscriptions")

    def __init__(
        self,
        r0: SimulatedR0,
        *,
        device: BLEDevice,
        disconnected_callback: Callable[[GattClient], None] | None = None,
    ) -> None:
        self._r0 = r0
        self._device = device
        self._callback = disconnected_callback
        self._connected = True
        self._services = FakeServices(stale=r0.stale_services)
        self._subscriptions: dict[str, NotifyCallback] = {}

    def __repr__(self) -> str:
        return f"FakeBleakClient(address={self.address}, connected={self._connected})"

    @property
    def address(self) -> str:
        return self._device.address

    @property
    def device(self) -> BLEDevice:
        return self._device

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def mtu_size(self) -> int:
        return self._r0.mtu_size

    @property
    def services(self) -> FakeServices:
        """Characteristic lookup; with ``stale_services`` (at connect time) the Tunnel
        characteristic is missing (``None``) and Tunnel operations raise
        ``BleakCharacteristicNotFoundError``."""
        return self._services

    async def start_notify(self, char_specifier: str, callback: NotifyCallback) -> None:
        self._check()
        self._subscriptions[self._services.resolve(char_specifier).uuid] = callback

    async def stop_notify(self, char_specifier: str) -> None:
        self._check()
        self._subscriptions.pop(self._services.resolve(char_specifier).uuid, None)

    async def write_gatt_char(
        self, char_specifier: str, data: bytes, response: bool | None = None
    ) -> None:
        self._check()
        if response is not True:
            raise ValueError("FakeBleakClient.write_gatt_char requires response=True")
        char = self._services.resolve(char_specifier)
        await self._r0._gatt_write(self, char, bytes(data))

    async def read_gatt_char(self, char_specifier: str) -> bytearray:
        self._check()
        char = self._services.resolve(char_specifier)
        return bytearray(await self._r0._gatt_read(self, char))

    async def disconnect(self) -> None:
        self._r0._drop(self)

    async def clear_cache(self) -> bool:
        """Clear the R0's ``stale_services`` (takes effect for the NEXT connection, like a real
        GATT cache) and return True."""
        self._r0.stale_services = False
        return True

    # --- used by SimulatedR0 ---

    def _subscribed(self, char_uuid: str) -> bool:
        return self._connected and char_uuid in self._subscriptions

    def _deliver(self, char_uuid: str, value: bytes) -> bool:
        """Call the notify callback for ``char_uuid``; False if not connected/subscribed."""
        callback = self._subscriptions.get(char_uuid) if self._connected else None
        if callback is None:
            return False
        callback(CHARACTERISTICS[char_uuid], bytearray(value))
        return True

    def _on_disconnected(self) -> None:
        """Mark dead and fire the disconnected callback (exactly once)."""
        if not self._connected:
            return
        self._connected = False
        self._subscriptions.clear()
        callback, self._callback = self._callback, None
        if callback is not None:
            callback(self)

    def _check(self) -> None:
        if not self._connected:
            raise FakeGattError("not connected", code=GATT_ERROR_UNLIKELY)


class FakeConnector:
    """``zigbee_direct.connection.Connector`` backed by a ``SimulatedR0``.

    Records every device it was called with (``devices``), and can be told to fail the next
    calls (``fail_next``) with a given exception (default: ``bleak.exc.BleakError``) or to
    hang until cancelled (``hang_next``). A successful call takes ``connect_latency`` virtual
    seconds; a failing one fails after the same latency.
    """

    __slots__ = ("_devices", "_failures", "_hangs", "_latency", "_r0")

    def __init__(self, r0: SimulatedR0, *, connect_latency: float = 0.5) -> None:
        self._r0 = r0
        self._latency = connect_latency
        self._devices: list[BLEDevice] = []
        self._failures: list[BaseException | None] = []
        self._hangs = 0

    async def __call__(
        self,
        client_class: type[BleakClientWithServiceCache],
        device: BLEDevice,
        name: str,
        disconnected_callback: Callable[[GattClient], None] | None = None,
        *,
        use_services_cache: bool = True,
        max_attempts: int = 3,
    ) -> GattClient:
        self._devices.append(device)
        if self._hangs:
            self._hangs -= 1
            await asyncio.get_running_loop().create_future()  # until cancelled
        await self._r0.clock.sleep(self._latency)
        if self._failures:
            exc = self._failures.pop(0)
            raise exc if exc is not None else BleakError(f"simulated connect failure: {name}")
        return self._r0.connect(device, disconnected_callback)

    def fail_next(self, count: int = 1, *, exc: BaseException | None = None) -> None:
        self._failures.extend([exc] * count)

    def hang_next(self, count: int = 1) -> None:
        self._hangs += count

    @property
    def devices(self) -> tuple[BLEDevice, ...]:
        return tuple(self._devices)


def fake_connector(r0: SimulatedR0, *, connect_latency: float = 0.5) -> FakeConnector:
    """A ``Connector`` for ``ZdConnection``/``validate_connection`` that connects to ``r0``."""
    return FakeConnector(r0, connect_latency=connect_latency)


__all__ = ["FakeBleakClient", "FakeConnector", "fake_connector"]
