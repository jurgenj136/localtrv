"""Bluetooth test helpers (adapted from Home Assistant core tests/components/bluetooth)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from habluetooth import BluetoothServiceInfoBleak
from homeassistant.components.bluetooth import async_get_advertisement_callback

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

DUMMY_ADDRESS = "AA:BB:CC:00:11:22"
UBISYS_SERVICE_UUID = "0000fff7-0000-1000-8000-00805f9b34fb"
R0_NAME = "ubisys R0"
LOCAL_SOURCE = "local"


def generate_ble_device(address: str, name: str | None) -> BLEDevice:
    """Build a BLEDevice."""
    return BLEDevice(address, name, {})


def generate_advertisement_data(
    *,
    local_name: str | None = None,
    service_uuids: list[str] | None = None,
    rssi: int = -60,
) -> AdvertisementData:
    """Build AdvertisementData."""
    return AdvertisementData(
        local_name=local_name,
        manufacturer_data={},
        service_data={},
        service_uuids=service_uuids or [],
        rssi=rssi,
        tx_power=-127,
        platform_data=(),
    )


def make_service_info(
    *,
    address: str = DUMMY_ADDRESS,
    name: str | None = R0_NAME,
    service_uuids: list[str] | None = None,
    connectable: bool = True,
    source: str = LOCAL_SOURCE,
) -> BluetoothServiceInfoBleak:
    """Build a BluetoothServiceInfoBleak."""
    return BluetoothServiceInfoBleak.from_device_and_advertisement_data(
        generate_ble_device(address, name),
        generate_advertisement_data(local_name=name, service_uuids=service_uuids),
        source,
        time.monotonic(),
        connectable,
    )


def r0_service_info(
    *,
    address: str = DUMMY_ADDRESS,
    name: str = R0_NAME,
    connectable: bool = True,
) -> BluetoothServiceInfoBleak:
    """Advertisement of an R0: name "ubisys ..." plus the Zigbee Direct service 0xFFF7."""
    return make_service_info(
        address=address,
        name=name,
        service_uuids=[UBISYS_SERVICE_UUID],
        connectable=connectable,
    )


def inject_bluetooth_service_info(hass: HomeAssistant, info: BluetoothServiceInfoBleak) -> None:
    """Feed a service info into HA's bluetooth manager (fires discovery and callbacks)."""
    async_get_advertisement_callback(hass)(info)
