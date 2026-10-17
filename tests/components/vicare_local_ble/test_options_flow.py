"""Options flow tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import pytest
from custom_components.vicare_local_ble.const import (
    CONF_ADDRESS,
    CONF_NETWORK_KEY,
    CONF_ROUTE_REPLY_MODE,
    CONF_SCAN_INTERVAL,
    CONF_ZVD_EUI,
    DEFAULT_ROUTE_REPLY_MODE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    SECTION_ADVANCED,
)
from homeassistant.data_entry_flow import FlowResultType, InvalidData, section
from pytest_homeassistant_custom_component.common import (  # type: ignore[import-untyped]
    MockConfigEntry,
)

from bluetooth_helpers import DUMMY_ADDRESS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from homeassistant.config_entries import ConfigFlowResult
    from homeassistant.core import HomeAssistant


@pytest.fixture(autouse=True)
def _bluetooth(mock_bluetooth: None) -> None:
    """Flows load the integration, whose dependency is bluetooth_adapters."""


@pytest.fixture(autouse=True)
def mock_setup_entry() -> Iterator[AsyncMock]:
    """Options changes reload the entry; keep setup out of these tests."""
    with patch("custom_components.vicare_local_ble.async_setup_entry", return_value=True) as m:
        yield m


def _entry() -> MockConfigEntry:
    data = {
        CONF_ADDRESS: DUMMY_ADDRESS,
        CONF_NETWORK_KEY: "a5" * 16,  # dummy
        CONF_ZVD_EUI: "02:00:00:00:00:00:00:01",
    }
    return MockConfigEntry(domain=DOMAIN, unique_id=DUMMY_ADDRESS, data=data, title="R0")


def _options_schema(result: ConfigFlowResult) -> dict[str, Any]:
    schema = result["data_schema"]
    assert schema is not None
    return {str(k): (k, v) for k, v in schema.schema.items()}


async def test_options_defaults_and_save(hass: HomeAssistant) -> None:
    entry = _entry()
    entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"
    fields = _options_schema(result)
    assert set(fields) == {CONF_SCAN_INTERVAL, SECTION_ADVANCED}
    assert fields[CONF_SCAN_INTERVAL][0].default() == DEFAULT_SCAN_INTERVAL
    advanced = fields[SECTION_ADVANCED][1]
    assert isinstance(advanced, section)
    assert advanced.options["collapsed"] is True
    inner = {str(k): k.default() for k in advanced.schema.schema}
    assert inner == {CONF_ROUTE_REPLY_MODE: DEFAULT_ROUTE_REPLY_MODE}

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {CONF_SCAN_INTERVAL: 120, SECTION_ADVANCED: {CONF_ROUTE_REPLY_MODE: "live"}},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options == {CONF_SCAN_INTERVAL: 120, CONF_ROUTE_REPLY_MODE: "live"}
    assert isinstance(entry.options[CONF_SCAN_INTERVAL], int)


async def test_options_route_reply_mode_saved_and_prefilled(hass: HomeAssistant) -> None:
    entry = _entry()
    entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {CONF_SCAN_INTERVAL: 3600, SECTION_ADVANCED: {CONF_ROUTE_REPLY_MODE: "spec"}},
    )
    assert entry.options == {CONF_SCAN_INTERVAL: 3600, CONF_ROUTE_REPLY_MODE: "spec"}

    result = await hass.config_entries.options.async_init(entry.entry_id)
    fields = _options_schema(result)
    assert fields[CONF_SCAN_INTERVAL][0].default() == 3600
    inner = {str(k): k.default() for k in fields[SECTION_ADVANCED][1].schema.schema}
    assert inner == {CONF_ROUTE_REPLY_MODE: "spec"}
    # Collapsed section left untouched: the inner default keeps the stored mode.
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_SCAN_INTERVAL: 60, SECTION_ADVANCED: {}}
    )
    assert entry.options == {CONF_SCAN_INTERVAL: 60, CONF_ROUTE_REPLY_MODE: "spec"}


@pytest.mark.parametrize("value", [59, 3601, 0])
async def test_options_scan_interval_range(hass: HomeAssistant, value: int) -> None:
    entry = _entry()
    entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    with pytest.raises(InvalidData):
        await hass.config_entries.options.async_configure(
            result["flow_id"], {CONF_SCAN_INTERVAL: value, SECTION_ADVANCED: {}}
        )
    assert entry.options == {}


async def test_options_route_reply_mode_rejects_unknown(hass: HomeAssistant) -> None:
    entry = _entry()
    entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    with pytest.raises(InvalidData):
        await hass.config_entries.options.async_configure(
            result["flow_id"],
            {CONF_SCAN_INTERVAL: 300, SECTION_ADVANCED: {CONF_ROUTE_REPLY_MODE: "bogus"}},
        )
