"""Diagnostics allowlist and the secret test (spec §2.6, #2; task T16).

Distinct dummy secrets: the network key (0x11 x16), link key (0x22 x16) and admin key
(0x33 x16) of the simulator's Commissioning Status, plus a KEY128 ZCL attribute value
(``A0..AF``) served by a valve in a poll response and in a report. None of their hex forms may
appear in the diagnostics JSON or in caplog at DEBUG after a full simulated session.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from custom_components.vicare_local_ble.diagnostics import async_get_config_entry_diagnostics
from pytest_homeassistant_custom_component.common import (  # type: ignore[import-untyped]
    async_fire_time_changed,
)

from bluetooth_helpers import DUMMY_ADDRESS
from conftest import our_tasks
from vicare_local_ble.testing import valve_table as vt
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.types import SecretBytes

if TYPE_CHECKING:
    import pytest
    from freezegun.api import FrozenDateTimeFactory
    from homeassistant.core import HomeAssistant

    from conftest import Sim

KEY128_VALUE = bytes(range(0xA0, 0xB0))  # dummy KEY128 attribute value
LINK_KEY = bytes([0x22]) * 16  # simulator dummies (default_installation)
ADMIN_KEY = bytes([0x33]) * 16
KEY_ATTR = 0x4F00  # a KEY128-typed attribute that only the report carries


def _hex_forms(secret: bytes) -> set[str]:
    forms: set[str] = set()
    for data in (secret, secret[::-1]):
        for text in (data.hex(), data.hex(" "), data.hex(":")):
            forms |= {text, text.upper()}
    return forms


async def _full_session(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> dict[str, Any]:
    secret = SecretBytes(KEY128_VALUE)
    valve = sim.inst.valves[0]
    # the poll's FAST read gets a KEY128 instead of the temperature; the report carries one too
    valve.set_attribute(vt.CL_THERMOSTAT, 0x0000, ZclDataType.KEY128, secret)
    valve.set_attribute(vt.CL_THERMOSTAT, KEY_ATTR, ZclDataType.KEY128, secret)
    assert await sim.setup()
    coordinator = sim.runtime.coordinator
    euis = {v.eui for v in sim.inst.valves}
    await sim.drive_until(
        lambda: (
            all(coordinator.data.available.get(e) for e in euis)
            and not any("initial poll" in t.get_name() for t in our_tasks())
        )
    )
    valve.report(vt.CL_THERMOSTAT, (KEY_ATTR, 0x0012))
    await sim.clock.advance(1.0)
    freezer.tick(timedelta(seconds=301))  # one scheduled poll through the coordinator
    async_fire_time_changed(hass)
    await sim.drive_until(lambda: coordinator.data.states[valve.eui].setpoint_c is not None)
    await sim.clock.advance(120.0)
    diagnostics = await async_get_config_entry_diagnostics(hass, sim.entry)
    json.dumps(diagnostics)  # serialisable as is
    return diagnostics


async def test_diagnostics_allowlist(
    hass: HomeAssistant, sim: Sim, freezer: FrozenDateTimeFactory
) -> None:
    diagnostics = await _full_session(hass, sim, freezer)
    assert set(diagnostics) == {
        "entry",
        "connection",
        "transport",
        "node",
        "join",
        "bridge",
        "valves",
        "npdu_records",
    }
    assert diagnostics["entry"] == {
        "options": {"scan_interval": 300, "route_reply_mode": "live"},
        "has_network_key": True,
        "has_zvd_eui": True,
        "has_zdd_eui": True,
    }
    connection = diagnostics["connection"]
    assert connection["state"] == "ready"
    assert connection["generation"] == 1
    assert connection["mtu"] == 247
    assert connection["issues"] == []
    assert connection["last_failure_detail"] is None
    assert diagnostics["transport"]["counter_model"] == "shared"
    assert diagnostics["node"]["reports"] >= 1
    assert diagnostics["node"]["aps_acks_sent"] >= 1  # the simulator requests APS acks
    assert diagnostics["node"]["aps_ack_failures"] == 0
    join = diagnostics["join"]
    assert join["own_short"] == sim.runtime.connection.last_join.own_short  # type: ignore[union-attr]
    assert join["pan_id"] == 0x1A2B
    assert join["status_deviations"] == []  # the spec-layout simulator status has none
    assert set(diagnostics["valves"]) == {"valve_1", "valve_2"}
    valve_1 = diagnostics["valves"]["valve_1"]
    assert set(valve_1) == {
        "eui",
        "short",
        "endpoint",
        "manufacturer",
        "model",
        "sw_build",
        "limits",
        "available",
        "misses",
        "state",
        "setpoint",
    }
    assert valve_1["state"]["system_mode_raw"] is not None
    assert diagnostics["bridge"]["discovery"]["topology"]["complete"] is True
    records = diagnostics["npdu_records"]
    assert records
    assert any(r.get("redacted") == "zcl_secret" for r in records)

    # identifiers: the R0 address and the real valve EUIs are absent (pseudonyms only)
    text = json.dumps(diagnostics)
    assert DUMMY_ADDRESS not in text
    assert DUMMY_ADDRESS.replace(":", "").lower() not in text.lower()
    for sim_valve in sim.inst.valves:
        eui = sim_valve.eui
        for form in (str(eui), str(eui).replace(":", ""), eui.wire.hex()):
            assert form.lower() not in text.lower()


async def test_diagnostics_and_logs_hold_no_secrets(
    hass: HomeAssistant,
    sim: Sim,
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    for name in ("vicare_local_ble", "custom_components.vicare_local_ble"):
        logging.getLogger(name).setLevel(logging.DEBUG)
    network_key = sim.inst.network_key.reveal()
    secrets = {network_key, LINK_KEY, ADMIN_KEY, KEY128_VALUE}
    assert len(secrets) == 4  # distinct

    diagnostics = await _full_session(hass, sim, freezer)
    assert await sim.unload()

    text = json.dumps(diagnostics)
    logs = caplog.text
    assert "NPDU {" in logs  # the debug NPDU log was on
    for secret in secrets:
        for form in _hex_forms(secret):
            assert form not in text, form
            assert form not in logs, form
