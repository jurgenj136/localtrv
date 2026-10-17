"""Config flow for ViCare Local (Bluetooth via ubisys R0).

Steps::

    bluetooth -> bluetooth_confirm -> network_key -> entry
    user (pick a discovered R0) -> network_key -> entry
    reauth -> reauth_confirm -> update entry + reload
    options: init (scan_interval, route_reply_mode [advanced])

The network key is never echoed back: not in form defaults, errors, placeholders or logs.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, override

import probatio
from bleak.exc import BleakError
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
    async_discovered_service_info,
)
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.core import callback
from homeassistant.data_entry_flow import section
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from vicare_local_ble.zigbee_direct import (
    Eui64,
    HandshakeRejectedError,
    SecretBytes,
    TransportError,
    generate_zvd_eui,
    validate_connection,
)

from .const import (
    CONF_ADDRESS,
    CONF_NETWORK_KEY,
    CONF_ROUTE_REPLY_MODE,
    CONF_SCAN_INTERVAL,
    CONF_VALIDATE,
    CONF_ZDD_EUI,
    CONF_ZVD_EUI,
    DEFAULT_ROUTE_REPLY_MODE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    LOCAL_NAME_PREFIX,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
    ROUTE_REPLY_MODES,
    SECTION_ADVANCED,
    VALIDATE_TIMEOUT,
    ZIGBEE_DIRECT_SERVICE_UUID,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from bleak.backends.device import BLEDevice
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

_KEY_RE = re.compile(r"[0-9a-fA-F]{32}")
DEFAULT_NAME = "ubisys R0"

KEY_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def _is_r0(info: BluetoothServiceInfoBleak) -> bool:
    """User-step filter: Zigbee Direct service **or** an "ubisys" name."""
    return ZIGBEE_DIRECT_SERVICE_UUID in info.service_uuids or (info.name or "").startswith(
        LOCAL_NAME_PREFIX
    )


def _normalize_key(raw: object) -> str | None:
    """Lowercase 32-hex key, or ``None`` if the format is wrong."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    return text.lower() if _KEY_RE.fullmatch(text) else None


async def _async_validate(
    hass: HomeAssistant, address: str, own_eui: Eui64, key_hex: str
) -> tuple[Eui64 | None, str | None, bool]:
    """Run one handshake. Returns ``(zdd_eui, error, timed_out)``; never logs the key."""

    def resolve() -> BLEDevice | None:
        return async_ble_device_from_address(hass, address, connectable=True)

    try:
        zdd = await validate_connection(
            resolve,
            own_eui=own_eui,
            network_key=SecretBytes(bytes.fromhex(key_hex)),
            timeout=VALIDATE_TIMEOUT,
        )
    except HandshakeRejectedError:
        return None, "invalid_auth", False
    except TimeoutError:
        return None, "cannot_connect", True
    except TransportError as err:
        if err.reason == "timeout":  # the real handshake timeout shape
            return None, "cannot_connect", True
        _LOGGER.debug("Validation of %s failed: %s", address, type(err).__name__)
        return None, "cannot_connect", False
    except BleakError as err:
        _LOGGER.debug("Validation of %s failed: %s", address, type(err).__name__)
        return None, "cannot_connect", False
    except Exception as err:  # map anything else to "unknown"
        _LOGGER.error("Unexpected error validating %s: %s", address, type(err).__name__)
        return None, "unknown", False
    return zdd, None, False


class ViCareLocalConfigFlow(ConfigFlow, domain=DOMAIN):
    """Bluetooth discovery / user pick, then the network key."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialise per-flow state; the ZVD EUI is generated lazily, once."""
        self._address: str | None = None
        self._name: str = DEFAULT_NAME
        self._zvd_eui: Eui64 | None = None
        self._discovered: dict[str, str] = {}

    @staticmethod
    @callback
    @override
    def async_get_options_flow(config_entry: ConfigEntry) -> ViCareLocalOptionsFlow:
        """Return the options flow."""
        return ViCareLocalOptionsFlow()

    def _own_eui(self) -> Eui64:
        if self._zvd_eui is None:
            self._zvd_eui = generate_zvd_eui()
        return self._zvd_eui

    def _set_device(self, address: str, name: str | None) -> None:
        self._address = address
        self._name = name or DEFAULT_NAME
        self.context["title_placeholders"] = {"name": self._name}

    @override
    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle an R0 found by the bluetooth matcher."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        if ZIGBEE_DIRECT_SERVICE_UUID not in discovery_info.service_uuids:
            return self.async_abort(reason="not_supported")
        self._set_device(discovery_info.address, discovery_info.name)
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm the discovered R0."""
        if user_input is not None:
            return await self.async_step_network_key()
        self._set_confirm_only()
        return self.async_show_form(
            step_id="bluetooth_confirm", description_placeholders={"name": self._name}
        )

    @override
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Pick one of the discovered R0s."""
        if user_input is not None:
            address: str = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._set_device(address, self._discovered.get(address))
            return await self.async_step_network_key()

        current = self._async_current_ids(include_ignore=False)
        self._discovered = {
            info.address: info.name or DEFAULT_NAME
            for info in async_discovered_service_info(self.hass, connectable=True)
            if _is_r0(info) and info.address not in current
        }
        if not self._discovered:
            return self.async_abort(reason="no_devices_found")
        options = [
            SelectOptionDict(value=address, label=f"{name} ({address})")
            for address, name in self._discovered.items()
        ]
        schema = probatio.Schema(
            {
                probatio.Required(CONF_ADDRESS): SelectSelector(
                    SelectSelectorConfig(options=options, mode=SelectSelectorMode.LIST)
                )
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_network_key(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the network key, optionally validate it with one handshake."""
        if self._address is None:  # only reachable through bluetooth_confirm / user
            return self.async_abort(reason="no_devices_found")
        errors: dict[str, str] = {}
        validate = True
        if user_input is not None:
            validate = bool(user_input.get(CONF_VALIDATE, True))
            key = _normalize_key(user_input.get(CONF_NETWORK_KEY))
            if key is None:
                errors[CONF_NETWORK_KEY] = "invalid_key"
            else:
                own_eui = self._own_eui()
                zdd: Eui64 | None = None
                if validate:
                    zdd, error, _ = await _async_validate(self.hass, self._address, own_eui, key)
                    if error is not None:
                        errors[_error_field(error)] = error
                if not errors:
                    self._abort_if_unique_id_configured()
                    data: dict[str, Any] = {
                        CONF_ADDRESS: self._address,
                        CONF_NETWORK_KEY: key,
                        CONF_ZVD_EUI: str(own_eui),
                    }
                    if zdd is not None:
                        data[CONF_ZDD_EUI] = str(zdd)
                    return self.async_create_entry(title=self._name, data=data)

        schema = probatio.Schema(
            {
                probatio.Required(CONF_NETWORK_KEY): KEY_SELECTOR,
                probatio.Required(CONF_VALIDATE, default=validate): BooleanSelector(),
            }
        )
        return self.async_show_form(
            step_id="network_key",
            data_schema=schema,
            errors=errors,
            description_placeholders={"name": self._name},
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Start reauth after ``ConfigEntryAuthFailed``."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for a new key; keep the stored ZVD EUI (the BAK depends on both)."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            key = _normalize_key(user_input.get(CONF_NETWORK_KEY))
            if key is None:
                errors[CONF_NETWORK_KEY] = "invalid_key"
            else:
                address: str = entry.data[CONF_ADDRESS]
                own_eui = Eui64.from_str(entry.data[CONF_ZVD_EUI])
                zdd, error, timed_out = await _async_validate(self.hass, address, own_eui, key)
                if timed_out:
                    _LOGGER.warning(
                        "Could not reach %s to verify the new network key; saving it anyway",
                        address,
                    )
                elif error is not None:
                    errors[_error_field(error)] = error
                if not errors:
                    updates: dict[str, Any] = {CONF_NETWORK_KEY: key}
                    if zdd is not None:
                        updates[CONF_ZDD_EUI] = str(zdd)
                    return self.async_update_reload_and_abort(entry, data_updates=updates)

        schema = probatio.Schema({probatio.Required(CONF_NETWORK_KEY): KEY_SELECTOR})
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=schema,
            errors=errors,
            description_placeholders={"name": entry.title},
        )


def _error_field(error: str) -> str:
    """Key errors sit on the key field; connection errors are form-wide."""
    return CONF_NETWORK_KEY if error == "invalid_auth" else "base"


class ViCareLocalOptionsFlow(OptionsFlowWithReload):
    """Poll interval plus a collapsed "advanced" section; reloads the entry on change.

    The section replaces ``show_advanced_options`` (deprecated in HA 2026.x). Options are stored
    flat: ``{scan_interval, route_reply_mode}``.
    """

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show and save the options."""
        options = self.config_entry.options
        route_mode = options.get(CONF_ROUTE_REPLY_MODE, DEFAULT_ROUTE_REPLY_MODE)
        if user_input is not None:
            advanced: dict[str, Any] = user_input.get(SECTION_ADVANCED) or {}
            return self.async_create_entry(
                data={
                    CONF_SCAN_INTERVAL: int(user_input[CONF_SCAN_INTERVAL]),
                    CONF_ROUTE_REPLY_MODE: advanced.get(CONF_ROUTE_REPLY_MODE, route_mode),
                }
            )

        schema = probatio.Schema(
            {
                probatio.Required(
                    CONF_SCAN_INTERVAL,
                    default=options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): NumberSelector(
                    NumberSelectorConfig(
                        min=MIN_SCAN_INTERVAL,
                        max=MAX_SCAN_INTERVAL,
                        step=1,
                        mode=NumberSelectorMode.BOX,
                        unit_of_measurement="s",
                    )
                ),
                probatio.Required(SECTION_ADVANCED): section(
                    probatio.Schema(
                        {
                            probatio.Required(
                                CONF_ROUTE_REPLY_MODE, default=route_mode
                            ): SelectSelector(
                                SelectSelectorConfig(
                                    options=list(ROUTE_REPLY_MODES),
                                    translation_key=CONF_ROUTE_REPLY_MODE,
                                    mode=SelectSelectorMode.DROPDOWN,
                                )
                            )
                        }
                    ),
                    {"collapsed": True},
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
