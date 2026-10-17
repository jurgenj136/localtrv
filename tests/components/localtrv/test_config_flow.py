"""Config flow tests. ``validate_connection`` is always patched."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import pytest
from bleak.exc import BleakError
from custom_components.localtrv.const import (
    CONF_ADDRESS,
    CONF_NETWORK_KEY,
    CONF_VALIDATE,
    CONF_ZDD_EUI,
    CONF_ZVD_EUI,
    DOMAIN,
    VALIDATE_TIMEOUT,
)
from homeassistant.config_entries import SOURCE_BLUETOOTH, SOURCE_USER
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import (  # type: ignore[import-untyped]
    MockConfigEntry,
)

from bluetooth_helpers import (
    DUMMY_ADDRESS,
    inject_bluetooth_service_info,
    make_service_info,
    r0_service_info,
)
from localtrv.zigbee_direct import (
    Eui64,
    HandshakeRejectedError,
    SecretBytes,
    TransportError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from homeassistant.config_entries import ConfigFlowResult
    from homeassistant.core import HomeAssistant

FLOW = "custom_components.localtrv.config_flow"

# Dummy material only; built at runtime so no key-shaped literal sits in the source.
KEY = "a5" * 16
KEY_UPPER = KEY.upper()
OTHER_KEY = "5a" * 16
ZVD_EUI = Eui64.from_str("02:00:00:00:00:00:00:01")
ZDD_EUI = Eui64.from_str("00:1F:EE:00:00:00:00:02")
OTHER_ADDRESS = "AA:BB:CC:00:11:33"


@pytest.fixture(autouse=True)
def _bluetooth(mock_bluetooth: None) -> None:
    """Every flow test runs on HA's mocked bluetooth stack."""


@pytest.fixture(autouse=True)
def mock_setup_entry() -> Iterator[AsyncMock]:
    """Keep entry setup out of the flow tests."""
    with patch("custom_components.localtrv.async_setup_entry", return_value=True) as m:
        yield m


@pytest.fixture(name="validate")
def validate_fixture() -> Iterator[AsyncMock]:
    """Patched ``validate_connection``; succeeds with ``ZDD_EUI`` by default."""
    with patch(f"{FLOW}.validate_connection", new_callable=AsyncMock) as m:
        m.return_value = ZDD_EUI
        yield m


@pytest.fixture(name="gen_eui")
def gen_eui_fixture() -> Iterator[AsyncMock]:
    """Deterministic ``generate_zvd_eui`` (counts calls)."""
    with patch(f"{FLOW}.generate_zvd_eui", return_value=ZVD_EUI) as m:
        yield m


def _last_call(mock: AsyncMock) -> Any:
    call = mock.await_args
    assert call is not None
    return call


def _entry(**data: Any) -> MockConfigEntry:
    base: dict[str, Any] = {
        CONF_ADDRESS: DUMMY_ADDRESS,
        CONF_NETWORK_KEY: KEY,
        CONF_ZVD_EUI: str(ZVD_EUI),
        CONF_ZDD_EUI: str(ZDD_EUI),
    }
    return MockConfigEntry(domain=DOMAIN, unique_id=DUMMY_ADDRESS, data=base | data, title="R0")


async def _bluetooth_to_key_step(hass: HomeAssistant) -> ConfigFlowResult:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=r0_service_info()
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "bluetooth_confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "network_key"
    return result


def _assert_no_key(result: ConfigFlowResult) -> None:
    text = repr(result.get("errors")) + repr(result.get("description_placeholders"))
    assert KEY not in text.lower()
    assert OTHER_KEY not in text.lower()


# --- bluetooth discovery -------------------------------------------------------------------


async def test_bluetooth_confirm_key_happy_path(
    hass: HomeAssistant, validate: AsyncMock, gen_eui: AsyncMock
) -> None:
    result = await _bluetooth_to_key_step(hass)
    assert result["errors"] == {}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY_UPPER, CONF_VALIDATE: True}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "ubisys R0"
    assert result["data"] == {
        CONF_ADDRESS: DUMMY_ADDRESS,
        CONF_NETWORK_KEY: KEY,  # stored lowercase
        CONF_ZVD_EUI: str(ZVD_EUI),
        CONF_ZDD_EUI: str(ZDD_EUI),
    }
    assert result["result"].unique_id == DUMMY_ADDRESS

    validate.assert_awaited_once()
    kwargs = _last_call(validate).kwargs
    assert kwargs["own_eui"] == ZVD_EUI
    assert kwargs["network_key"] == SecretBytes(bytes.fromhex(KEY))
    assert kwargs["timeout"] == VALIDATE_TIMEOUT
    gen_eui.assert_called_once_with()


async def test_resolver_is_a_fresh_connectable_lookup(
    hass: HomeAssistant, validate: AsyncMock, gen_eui: AsyncMock
) -> None:
    result = await _bluetooth_to_key_step(hass)
    await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_NETWORK_KEY: KEY})
    resolve = _last_call(validate).args[0]
    assert resolve() is None  # nothing advertised yet
    inject_bluetooth_service_info(hass, r0_service_info())
    await hass.async_block_till_done()
    device = resolve()
    assert device is not None
    assert device.address == DUMMY_ADDRESS


async def test_zvd_eui_generated_once_across_retries(
    hass: HomeAssistant, validate: AsyncMock
) -> None:
    validate.side_effect = [HandshakeRejectedError("rejected"), ZDD_EUI]
    result = await _bluetooth_to_key_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: OTHER_KEY}
    )
    assert result["errors"] == {CONF_NETWORK_KEY: "invalid_auth"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    first, second = (call.kwargs["own_eui"] for call in validate.await_args_list)
    assert first == second
    assert result["data"][CONF_ZVD_EUI] == str(first)
    # Locally administered, unicast.
    assert first.wire[7] & 0x02
    assert not first.wire[7] & 0x01


async def test_zvd_eui_is_random_per_flow(hass: HomeAssistant, validate: AsyncMock) -> None:
    euis = []
    for address in (DUMMY_ADDRESS, OTHER_ADDRESS):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=r0_service_info(address=address)
        )
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_NETWORK_KEY: KEY}
        )
        assert result["type"] is FlowResultType.CREATE_ENTRY
        euis.append(result["data"][CONF_ZVD_EUI])
    assert euis[0] != euis[1]


async def test_bluetooth_already_configured(hass: HomeAssistant) -> None:
    _entry().add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=r0_service_info()
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_bluetooth_without_zigbee_direct_service_not_supported(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=make_service_info(service_uuids=[])
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "not_supported"


async def test_bluetooth_flow_already_in_progress(hass: HomeAssistant) -> None:
    await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=r0_service_info()
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=r0_service_info()
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_in_progress"


# --- user step -----------------------------------------------------------------------------


async def test_user_no_devices_found(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_devices_found"


async def test_user_no_devices_when_only_configured_r0_seen(hass: HomeAssistant) -> None:
    _entry().add_to_hass(hass)
    inject_bluetooth_service_info(hass, r0_service_info())
    await hass.async_block_till_done()
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_devices_found"


async def test_user_lists_discovered_r0s_and_creates_entry(
    hass: HomeAssistant, validate: AsyncMock, gen_eui: AsyncMock
) -> None:
    # UUID-only and name-only R0s are listed; unrelated devices are not.
    inject_bluetooth_service_info(hass, r0_service_info())
    inject_bluetooth_service_info(
        hass, make_service_info(address=OTHER_ADDRESS, name="ubisys R0 b", service_uuids=[])
    )
    inject_bluetooth_service_info(
        hass,
        make_service_info(
            address="AA:BB:CC:00:11:44",
            name="Unrelated sensor",  # matches no bluetooth matcher in HA core
            service_uuids=["0000aaaa-0000-1000-8000-00805f9b34fb"],
        ),
    )
    await hass.async_block_till_done()

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    schema = result["data_schema"]
    assert schema is not None
    selector = schema.schema[CONF_ADDRESS]
    values = sorted(opt["value"] for opt in selector.config["options"])
    assert values == sorted([DUMMY_ADDRESS, OTHER_ADDRESS])

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: OTHER_ADDRESS}
    )
    assert result["step_id"] == "network_key"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "ubisys R0 b"
    assert result["data"][CONF_ADDRESS] == OTHER_ADDRESS
    assert result["result"].unique_id == OTHER_ADDRESS


async def test_user_already_configured(hass: HomeAssistant) -> None:
    inject_bluetooth_service_info(hass, r0_service_info())
    await hass.async_block_till_done()
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["step_id"] == "user"
    _entry().add_to_hass(hass)  # configured while the form was open
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: DUMMY_ADDRESS}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


# --- key step errors -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    ["", "a5" * 15, "a5" * 17, "g" + "a5" * 15 + "a", "a5 " * 16, "0x" + "a5" * 15],
    ids=["empty", "short", "long", "non-hex", "spaced", "0x-prefix"],
)
async def test_invalid_key_format(hass: HomeAssistant, validate: AsyncMock, bad: str) -> None:
    result = await _bluetooth_to_key_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: bad}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {CONF_NETWORK_KEY: "invalid_key"}
    validate.assert_not_awaited()


@pytest.mark.parametrize(
    ("exc", "field", "error"),
    [
        (HandshakeRejectedError("rejected"), CONF_NETWORK_KEY, "invalid_auth"),
        (TransportError("gatt", reason="write"), "base", "cannot_connect"),
        (TransportError("absent", reason="not_found"), "base", "cannot_connect"),
        (TimeoutError(), "base", "cannot_connect"),
        (BleakError("busy"), "base", "cannot_connect"),
        (RuntimeError("boom"), "base", "unknown"),
    ],
    ids=["invalid_auth", "transport", "not_found", "timeout", "bleak", "unknown"],
)
async def test_validation_errors_then_recover(
    hass: HomeAssistant,
    validate: AsyncMock,
    caplog: pytest.LogCaptureFixture,
    exc: Exception,
    field: str,
    error: str,
) -> None:
    caplog.set_level(logging.DEBUG)
    validate.side_effect = exc
    result = await _bluetooth_to_key_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "network_key"
    assert result["errors"] == {field: error}
    _assert_no_key(result)

    validate.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert KEY not in caplog.text.lower()


async def test_unknown_error_logs_type_only(
    hass: HomeAssistant, validate: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    validate.side_effect = RuntimeError(f"leaky {KEY}")  # a hostile message must not be logged
    result = await _bluetooth_to_key_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY}
    )
    assert result["errors"] == {"base": "unknown"}
    assert "RuntimeError" in caplog.text
    assert KEY not in caplog.text.lower()
    assert "leaky" not in caplog.text


async def test_validate_false_skips_handshake(
    hass: HomeAssistant, validate: AsyncMock, gen_eui: AsyncMock
) -> None:
    result = await _bluetooth_to_key_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY, CONF_VALIDATE: False}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        CONF_ADDRESS: DUMMY_ADDRESS,
        CONF_NETWORK_KEY: KEY,
        CONF_ZVD_EUI: str(ZVD_EUI),
    }
    validate.assert_not_awaited()
    gen_eui.assert_called_once_with()


async def test_key_form_never_prefills_the_key(hass: HomeAssistant, validate: AsyncMock) -> None:
    validate.side_effect = HandshakeRejectedError("rejected")
    result = await _bluetooth_to_key_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY, CONF_VALIDATE: True}
    )
    schema = result["data_schema"]
    assert schema is not None
    for marker in schema.schema:
        if marker == CONF_NETWORK_KEY:
            assert KEY not in repr(marker.default).lower()
            assert KEY not in repr(getattr(marker, "description", None)).lower()
    _assert_no_key(result)


# --- reauth --------------------------------------------------------------------------------


async def test_reauth_keeps_eui_and_updates_key(
    hass: HomeAssistant, validate: AsyncMock, gen_eui: AsyncMock, mock_setup_entry: AsyncMock
) -> None:
    stored_eui = Eui64.from_str("06:11:22:33:44:55:66:77")
    entry = _entry(**{CONF_NETWORK_KEY: OTHER_KEY, CONF_ZVD_EUI: str(stored_eui)})
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"
    _assert_no_key(result)

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: KEY_UPPER}
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_NETWORK_KEY] == KEY
    assert entry.data[CONF_ZVD_EUI] == str(stored_eui)
    assert entry.data[CONF_ZDD_EUI] == str(ZDD_EUI)
    assert _last_call(validate).kwargs["own_eui"] == stored_eui
    assert _last_call(validate).kwargs["network_key"] == SecretBytes(bytes.fromhex(KEY))
    gen_eui.assert_not_called()
    assert mock_setup_entry.await_count == 1  # reloaded


async def test_reauth_invalid_auth_and_format(hass: HomeAssistant, validate: AsyncMock) -> None:
    entry = _entry()
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: "nope"}
    )
    assert result["errors"] == {CONF_NETWORK_KEY: "invalid_key"}
    validate.side_effect = HandshakeRejectedError("rejected")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: OTHER_KEY}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {CONF_NETWORK_KEY: "invalid_auth"}
    _assert_no_key(result)
    validate.side_effect = TransportError("gatt")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: OTHER_KEY}
    )
    assert result["errors"] == {"base": "cannot_connect"}
    assert entry.data[CONF_NETWORK_KEY] == KEY  # unchanged


async def test_reauth_timeout_saves_with_warning(
    hass: HomeAssistant, validate: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    entry = _entry()
    entry.add_to_hass(hass)
    validate.side_effect = TimeoutError()
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: OTHER_KEY}
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_NETWORK_KEY] == OTHER_KEY
    assert entry.data[CONF_ZDD_EUI] == str(ZDD_EUI)  # kept
    assert any(r.levelno == logging.WARNING for r in caplog.records)
    assert OTHER_KEY not in caplog.text.lower()


async def test_reauth_handshake_timeout_transport_error_saves_with_warning(
    hass: HomeAssistant, validate: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    """The real handshake timeout is ``TransportError(reason="timeout")``, not TimeoutError."""
    caplog.set_level(logging.DEBUG)
    entry = _entry()
    entry.add_to_hass(hass)
    validate.side_effect = TransportError("handshake timed out", reason="timeout")
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_NETWORK_KEY: OTHER_KEY}
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_NETWORK_KEY] == OTHER_KEY
    assert any(r.levelno == logging.WARNING for r in caplog.records)
    assert OTHER_KEY not in caplog.text.lower()
