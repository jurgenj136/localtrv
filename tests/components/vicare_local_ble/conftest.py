"""Fixtures for the Home Assistant integration tests.

No real Bluetooth adapter is touched: ``enable_bluetooth`` swaps in PHACC's mocked
adapters and scanner start.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any
from unittest.mock import PropertyMock, patch

import pytest
from homeassistant.helpers import discovery_flow

if TYPE_CHECKING:
    from collections.abc import Iterator

    from homeassistant.core import HomeAssistant

# HA mounts PHACC's testing_config dir first and would import ITS ``custom_components``
# package (which shadows ours). Importing ours up front (repo root is on sys.path via
# ``pythonpath = ["."]``) pins ``sys.modules["custom_components"]`` to this repo.
importlib.import_module("custom_components.vicare_local_ble")


@pytest.fixture(autouse=True)
def _auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Let HA load custom_components/vicare_local_ble."""


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
        if domain == "vicare_local_ble":
            real(hass, domain, *args, **kwargs)

    with patch.object(discovery_flow, "async_create_flow", only_ours):
        yield
