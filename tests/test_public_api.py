"""Every name in each package ``__all__`` resolves; re-exports are the canonical objects."""

from __future__ import annotations

import importlib

import pytest

from vicare_direct.zigbee_direct import codec
from vicare_direct.zigbee_direct.codec import commissioning, zdo_mgmt

PACKAGES = ["vicare_direct.zigbee_direct", "vicare_direct.zigbee_direct.codec"]


@pytest.mark.parametrize("name", PACKAGES)
def test_all_names_resolve(name: str) -> None:
    module = importlib.import_module(name)
    exported = module.__all__
    assert len(exported) == len(set(exported))
    missing = [attr for attr in exported if not hasattr(module, attr)]
    assert missing == []


def test_codec_exports_every_submodule_public_name() -> None:
    renamed = {"DeviceType"}
    for sub in (
        "tlv",
        "nwk",
        "nwk_commands",
        "commissioning",
        "aps",
        "zdo",
        "zdo_mgmt",
        "zcl",
        "zcl_types",
        "fallback",
    ):
        module = importlib.import_module(f"vicare_direct.zigbee_direct.codec.{sub}")
        for attr, value in vars(module).items():
            if attr.startswith("_") or attr in renamed or not hasattr(codec, attr):
                continue
            assert getattr(codec, attr) is value, f"{sub}.{attr} shadowed"


def test_device_type_aliases() -> None:
    assert codec.CommissioningDeviceType is commissioning.DeviceType
    assert codec.NeighborDeviceType is zdo_mgmt.DeviceType
    assert "DeviceType" not in codec.__all__
