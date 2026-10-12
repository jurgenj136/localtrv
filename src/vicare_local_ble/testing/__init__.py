"""Public test helpers: handshake responder, simulated R0, network and valves (spec §1.7).

For consumers of this library (the Home Assistant integration tests) and its own tests. No
hardware, BLE or network access: everything runs on a ``VirtualClock``.

* ``FakeZdd``: SE1-SE4 responder plus session crypto (``zdd.py``).
* ``SimulatedR0``, ``FakeBleakClient``, ``fake_connector``: the GATT level (``gatt.py``).
* ``SimNetwork``, ``SimValve``: the Zigbee side (``network.py``, ``valve.py``).
* ``default_installation``: a wired research-like installation (``scenario.py``).
"""

from vicare_local_ble.testing.errors import GATT_ERROR_REJECTED, GATT_ERROR_UNLIKELY, FakeGattError
from vicare_local_ble.testing.gatt import (
    FakeBleakClient,
    FakeConnector,
    SimulatedR0,
    WriteFaultSpec,
    fake_connector,
)
from vicare_local_ble.testing.network import SimNetwork, SimRouter
from vicare_local_ble.testing.scenario import Installation, default_installation
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.testing.zdd import FakeZdd, ZddCounterModel

__all__ = [
    "GATT_ERROR_REJECTED",
    "GATT_ERROR_UNLIKELY",
    "FakeBleakClient",
    "FakeConnector",
    "FakeGattError",
    "FakeZdd",
    "Installation",
    "SimNetwork",
    "SimRouter",
    "SimValve",
    "SimulatedR0",
    "WriteFaultSpec",
    "ZddCounterModel",
    "default_installation",
    "fake_connector",
]
