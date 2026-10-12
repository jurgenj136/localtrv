"""Config flow for ViCare Local (Bluetooth via ubisys R0), implemented in T15."""

from __future__ import annotations

from homeassistant.config_entries import ConfigFlow

from .const import DOMAIN


class ViCareLocalConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow stub; implemented in T15."""

    VERSION = 1
