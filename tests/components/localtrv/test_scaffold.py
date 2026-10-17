"""Scaffold tests: lockstep versioning, translations, matchers, integration loading."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from homeassistant.components.bluetooth.match import ble_device_matches
from homeassistant.loader import async_get_integration

from bluetooth_helpers import inject_bluetooth_service_info, make_service_info, r0_service_info

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

ROOT = Path(__file__).resolve().parents[3]
COMPONENT = ROOT / "custom_components" / "localtrv"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


MANIFEST = _json(COMPONENT / "manifest.json")


def test_manifest_version_matches_pyproject() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert MANIFEST["version"] == project["version"]


def test_manifest_requirement_is_lockstep_pin() -> None:
    assert MANIFEST["requirements"] == [f"localtrv=={MANIFEST['version']}"]


def test_manifest_required_keys() -> None:
    for key in ("domain", "name", "codeowners", "documentation", "issue_tracker", "version"):
        assert MANIFEST[key], key
    assert MANIFEST["domain"] == COMPONENT.name == "localtrv"
    assert MANIFEST["config_flow"] is True
    assert MANIFEST["dependencies"] == ["bluetooth_adapters"]
    assert MANIFEST["iot_class"] == "local_polling"
    assert MANIFEST["integration_type"] == "hub"


def test_hacs_json() -> None:
    hacs = _json(ROOT / "hacs.json")
    assert hacs["name"] == MANIFEST["name"]
    assert re.fullmatch(r"\d{4}\.\d+\.\d+(b\d+)?", hacs["homeassistant"])
    assert not hacs.get("content_in_root")


def test_strings_equal_en_translation() -> None:
    assert _json(COMPONENT / "strings.json") == _json(COMPONENT / "translations" / "en.json")


def test_icons_json_is_valid() -> None:
    icons = _json(COMPONENT / "icons.json")
    assert "entity" in icons


@pytest.mark.parametrize(
    ("name", "size"),
    [("icon.png", 256), ("icon@2x.png", 512), ("logo.png", 128), ("logo@2x.png", 256)],
)
def test_brand_pngs(name: str, size: int) -> None:
    data = (COMPONENT / "brand" / name).read_bytes()
    assert data.startswith(PNG_MAGIC)
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    assert min(width, height) == size


def _matches(info: Any) -> bool:
    return any(ble_device_matches(matcher, info) for matcher in MANIFEST["bluetooth"])


def test_matcher_accepts_r0_advertisement() -> None:
    assert _matches(r0_service_info())


def test_matcher_rejects_name_only_and_uuid_only() -> None:
    # The matcher is one combined dict: UUID and name are ANDed.
    assert not _matches(make_service_info(name="ubisys R0", service_uuids=[]))
    assert not _matches(
        make_service_info(name="Other", service_uuids=["0000fff7-0000-1000-8000-00805f9b34fb"])
    )


def test_matcher_rejects_unrelated_device() -> None:
    assert not _matches(
        make_service_info(name="LEDnet", service_uuids=["0000ffe5-0000-1000-8000-00805f9b34fb"])
    )


def test_matcher_rejects_non_connectable_r0() -> None:
    assert not _matches(r0_service_info(connectable=False))


def test_local_name_matcher_not_too_broad() -> None:
    # HA rejects patterns in the first 3 characters of a local_name matcher.
    for matcher in MANIFEST["bluetooth"]:
        assert "*" not in matcher["local_name"][:3]


async def test_integration_manifest_loads(hass: HomeAssistant) -> None:
    integration = await async_get_integration(hass, "localtrv")
    assert integration.domain == "localtrv"
    assert integration.config_flow is True
    assert str(integration.version) == MANIFEST["version"]
    assert integration.requirements == MANIFEST["requirements"]
    assert integration.has_branding
    assert integration.bluetooth == MANIFEST["bluetooth"]
    assert integration.get_platform("config_flow") is not None


@pytest.mark.usefixtures("mock_bluetooth")
async def test_injected_r0_advertisement_is_discovered(hass: HomeAssistant) -> None:
    from homeassistant.components.bluetooth import async_discovered_service_info

    info = r0_service_info()
    inject_bluetooth_service_info(hass, info)
    await hass.async_block_till_done()
    found = async_discovered_service_info(hass, connectable=True)
    assert [i.address for i in found] == [info.address]
