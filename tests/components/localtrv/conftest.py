"""Fixtures for the Home Assistant integration tests.

No real Bluetooth adapter is touched: ``enable_bluetooth`` swaps in PHACC's mocked
adapters and scanner start.
"""

from __future__ import annotations

import asyncio
import importlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import PropertyMock, patch

import custom_components.localtrv as integration
import pytest
from custom_components.localtrv.const import (
    CONF_ADDRESS,
    CONF_NETWORK_KEY,
    CONF_ROUTE_REPLY_MODE,
    CONF_SCAN_INTERVAL,
    CONF_ZDD_EUI,
    CONF_ZVD_EUI,
    DOMAIN,
)
from homeassistant.config_entries import ConfigEntryState
from homeassistant.helpers import discovery_flow
from pytest_homeassistant_custom_component.common import (  # type: ignore[import-untyped]
    MockConfigEntry,
)

import localtrv
from bluetooth_helpers import DUMMY_ADDRESS
from localtrv.testing.network_aps import is_aps_ack
from localtrv.testing.scenario import default_installation
from localtrv.zigbee_direct.codec.aps import HA_PROFILE_ID, ApsDataFrame
from localtrv.zigbee_direct.codec.nwk import NwkFrameType

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Iterator

    from bleak.backends.device import BLEDevice
    from custom_components.localtrv.coordinator import VicareRuntime
    from homeassistant.core import HomeAssistant

    from localtrv.testing.scenario import Installation
    from localtrv.zigbee_direct.clock import VirtualClock

# HA mounts PHACC's testing_config dir first and would import ITS ``custom_components``
# package (which shadows ours). Importing ours up front (repo root is on sys.path via
# ``pythonpath = ["."]``) pins ``sys.modules["custom_components"]`` to this repo.
importlib.import_module("custom_components.localtrv")


@pytest.fixture(autouse=True)
def _auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Let HA load custom_components/localtrv."""


@pytest.fixture(name="mock_bluetooth")
def mock_bluetooth_fixture(enable_bluetooth: None) -> None:
    """Bring up HA's bluetooth integration on mocked adapters."""


@pytest.fixture(autouse=True)
def _no_bluez_history() -> Iterator[None]:
    """PHACC fakes a Linux adapter list but not its BlueZ history.

    Where dbus-fast is unavailable (macOS dev machines) reading that history crashes
    with ``'NoneType' object is not callable``. An empty history is what CI sees.
    """
    with patch(
        "bluetooth_adapters.systems.linux.LinuxAdapters.history",
        new_callable=PropertyMock,
        return_value={},
    ):
        yield


@pytest.fixture(autouse=True)
def _only_our_discovery_flows() -> Iterator[None]:
    """Injected adverts must never start other integrations' discovery flows.

    HA's bluetooth manager calls ``discovery_flow.async_create_flow`` for every matching core
    domain; those integrations' requirements (e.g. ``led_ble``) are not installed here.
    """
    real = discovery_flow.async_create_flow

    def only_ours(hass: HomeAssistant, domain: str, *args: Any, **kwargs: Any) -> None:
        if domain == "localtrv":
            real(hass, domain, *args, **kwargs)

    with patch.object(discovery_flow, "async_create_flow", only_ours):
        yield


# --- simulator harness -----------------------------------------------------------------------
#
# Time: the library runs on the simulator's ``VirtualClock``. ``LoopClock`` is patched in the
# integration module to return it, so every library and simulator delay (handshake, joins,
# sleepy valves, backoff) is virtual; HA's own timers (coordinator schedule, Store delayed save,
# config entry retries) stay on the real loop and are driven with ``async_fire_time_changed``.
# ``Sim.drive*`` jumps the virtual clock from timer to timer while HA tasks run; when no
# virtual timer is due it yields real time (HA's loader uses executor jobs during setup).

INIT = "custom_components.localtrv"
FIRST_BROADCAST = 0xFFF8


@dataclass
class Sim:
    """A config entry wired to a simulated installation (no Bluetooth, virtual library time)."""

    hass: HomeAssistant
    inst: Installation
    entry: MockConfigEntry
    device: Callable[[], BLEDevice | None]

    @property
    def clock(self) -> VirtualClock:
        return self.inst.clock

    @property
    def runtime(self) -> VicareRuntime:
        runtime: VicareRuntime = self.entry.runtime_data
        return runtime

    def resolve(self, _hass: HomeAssistant, _address: str, connectable: bool = True) -> Any:
        assert connectable
        return self.device()

    async def drive[T](self, awaitable: Awaitable[T], *, limit: float = 3600.0) -> T:
        """Await ``awaitable`` while advancing virtual time."""
        task = asyncio.ensure_future(awaitable)
        try:
            await self.drive_until(task.done, limit=limit)
            return task.result()
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def drive_until(self, done: Callable[[], bool], *, limit: float = 3600.0) -> None:
        """Advance virtual time timer by timer until ``done()``; fails after ``limit`` s."""
        clock = self.clock
        deadline = clock.now() + limit
        idle = 0
        while True:
            await clock.run_until_idle()
            if done():
                return
            when = clock.next_deadline()
            if when is None:
                idle += 1
                assert idle < 2000, "blocked: no virtual timer and no progress"
                # real time without a loop timer (the loop clock may be frozen by
                # ``freezer``): lets HA executor jobs (integration loading) finish
                await asyncio.get_running_loop().run_in_executor(None, time.sleep, 0.001)
                continue
            assert when <= deadline, "condition not reached within the virtual time limit"
            await clock.advance_to(when)

    async def setup(self) -> bool:
        return await self.drive(self.hass.config_entries.async_setup(self.entry.entry_id))

    async def unload(self) -> bool:
        return await self.drive(self.hass.config_entries.async_unload(self.entry.entry_id))

    def zcl_frames(self, start: int = 0) -> list[tuple[int, int]]:
        """``(dst, cluster)`` of every unicast ZCL (HA profile) frame the ZVD sent."""
        out: list[tuple[int, int]] = []
        for frame in self.inst.network.received[start:]:
            if frame.frame_type is not NwkFrameType.DATA or frame.dst >= FIRST_BROADCAST:
                continue
            if is_aps_ack(frame):  # the node acks the valves' responses
                continue
            aps = ApsDataFrame.decode(frame.payload)
            if aps.profile_id == HA_PROFILE_ID:
                out.append((frame.dst, aps.cluster_id))
        return out


OUR_DIRS = (Path(localtrv.__file__).parent, Path(integration.__file__).parent)


def our_tasks() -> list[asyncio.Task[Any]]:
    """Unfinished tasks running library or integration code (other than the caller).

    Matches on the package folders, not the name: checkout paths can contain "localtrv" too.
    """
    current = asyncio.current_task()
    found: list[asyncio.Task[Any]] = []
    for task in asyncio.all_tasks():
        if task is current or task.done():
            continue
        coro = task.get_coro()
        code = getattr(coro, "cr_code", None)
        if code is not None:
            ours = any(Path(code.co_filename).is_relative_to(d) for d in OUR_DIRS)
        else:
            ours = type(coro).__module__.split(".")[0] in {"localtrv", "custom_components"}
        if ours:
            found.append(task)
    return found


def make_entry(inst: Installation, **options: Any) -> MockConfigEntry:
    """Config entry as the config flow creates it, for the simulator's dummy key and EUIs."""
    return MockConfigEntry(
        domain=DOMAIN,
        unique_id=DUMMY_ADDRESS,
        title="ubisys R0",
        data={
            CONF_ADDRESS: DUMMY_ADDRESS,
            CONF_NETWORK_KEY: inst.network_key.reveal().hex(),
            CONF_ZVD_EUI: str(inst.zvd_eui),
            CONF_ZDD_EUI: str(inst.zdd_eui),
        },
        options={CONF_SCAN_INTERVAL: 300, CONF_ROUTE_REPLY_MODE: "live"} | options,
    )


@pytest.fixture(name="sim")
async def sim_fixture(hass: HomeAssistant, mock_bluetooth: None) -> AsyncIterator[Sim]:
    """Two valves behind the coordinator; the entry is added but not set up."""
    inst = default_installation(n_valves=2, behind_router=0, seed=0)
    entry = make_entry(inst)
    entry.add_to_hass(hass)
    sim = Sim(hass, inst, entry, inst.r0.ble_device)
    with (
        patch(f"{INIT}.LoopClock", return_value=inst.clock),
        patch(f"{INIT}.establish_connection", inst.connector),
        patch(f"{INIT}.async_ble_device_from_address", sim.resolve),
    ):
        yield sim
        if entry.state is ConfigEntryState.LOADED:
            await sim.unload()
