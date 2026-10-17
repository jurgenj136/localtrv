"""Every name in each package ``__all__`` resolves; re-exports are the canonical objects."""

from __future__ import annotations

import importlib
import inspect
from typing import TYPE_CHECKING

import pytest

from localtrv.bridge import ViCareBridge
from localtrv.zigbee_direct import codec
from localtrv.zigbee_direct.codec import commissioning, zdo_mgmt
from localtrv.zigbee_direct.connection import Connector, ZdConnection
from localtrv.zigbee_direct.requests import Envelope
from localtrv.zigbee_direct.types import Eui64, SecretBytes

if TYPE_CHECKING:
    from bleak_retry_connector import BleakClientWithServiceCache

    from localtrv.testing import FakeBleakClient, FakeConnector
    from localtrv.zigbee_direct.transport import GattClient

PACKAGES = [
    "localtrv.zigbee_direct",
    "localtrv.zigbee_direct.codec",
    "localtrv.testing",
]
MODULES = [
    "localtrv.bridge",
    "localtrv.bridge_cache",
    "localtrv.valves",
    "localtrv.valves.constants",
    "localtrv.valves.decode",
    "localtrv.valves.models",
    "localtrv.testing.errors",
    "localtrv.testing.gatt",
    "localtrv.testing.network",
    "localtrv.testing.scenario",
    "localtrv.testing.valve",
    "localtrv.testing.zdd",
    "localtrv.zigbee_direct.clock",
    "localtrv.zigbee_direct.connection",
    "localtrv.zigbee_direct.debug",
    "localtrv.zigbee_direct.discovery",
    "localtrv.zigbee_direct.dispatch",
    "localtrv.zigbee_direct.errors",
    "localtrv.zigbee_direct.frames",
    "localtrv.zigbee_direct.node",
    "localtrv.zigbee_direct.node_types",
    "localtrv.zigbee_direct.requests",
    "localtrv.zigbee_direct.routing",
    "localtrv.zigbee_direct.session",
    "localtrv.zigbee_direct.transport",
]

#: Every public and shared name, by defining module.
FROZEN_NAMES = {
    "localtrv.zigbee_direct.clock": ["Clock", "Cancellable", "LoopClock", "VirtualClock"],
    "localtrv.zigbee_direct.errors": [
        "TransportError",
        "ConnectionLostError",
        "HandshakeRejectedError",
        "JoinError",
        "JoinRejectedError",
        "RequestTimeoutError",
        "RouteError",
        "ZclStatusError",
    ],
    "localtrv.zigbee_direct.transport": [
        "MIN_RECOMMENDED_MTU",
        "SessionInfo",
        "TransportStats",
        "ZigbeeDirectTransport",
    ],
    "localtrv.zigbee_direct.node": [
        "RouteReplyMode",
        "NodeConfig",
        "JoinInfo",
        "NetworkSummary",
        "ReportEvent",
        "NodeStats",
        "ZigbeeDirectNode",
    ],
    "localtrv.zigbee_direct.requests": ["Envelope", "Pending", "PendingMap"],
    "localtrv.zigbee_direct.discovery": ["Topology", "walk_topology"],
    "localtrv.zigbee_direct.connection": [
        "ConnectionState",
        "DeviceResolver",
        "Connector",
        "Generation",
        "ConnectionStats",
        "ZdConnection",
        "validate_connection",
    ],
    "localtrv.zigbee_direct.debug": ["NpduRecorder", "sanitize_records"],
    "localtrv.zigbee_direct.session": ["CounterModel"],
    "localtrv.bridge": [
        "BridgeCache",
        "CachedValve",
        "SetpointStatus",
        "DiscoveryStatus",
        "TopologySummary",
        "BridgeSnapshot",
        "ViCareBridge",
    ],
    "localtrv.valves": [
        "AttrSpec",
        "FAST",
        "SLOW",
        "STATIC",
        "Valve",
        "ValveState",
        "SetpointLimits",
        "apply_reads",
        "setpoint_record",
        "window_open",
        "is_supported_valve",
        "SETPOINT_STEP_C",
        "MFR_VIESSMANN",
        "MODEL_IDS",
        "MANUFACTURER",
        "OUI_HINT",
    ],
    "localtrv.testing": [
        "FakeZdd",
        "FakeGattError",
        "FakeBleakClient",
        "SimulatedR0",
        "SimNetwork",
        "SimValve",
        "default_installation",
        "fake_connector",
    ],
}


@pytest.mark.parametrize("name", PACKAGES + MODULES)
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
        "nwk_mesh",
        "commissioning",
        "aps",
        "zdo",
        "zdo_mgmt",
        "zcl",
        "zcl_types",
        "fallback",
    ):
        module = importlib.import_module(f"localtrv.zigbee_direct.codec.{sub}")
        for attr, value in vars(module).items():
            if attr.startswith("_") or attr in renamed or not hasattr(codec, attr):
                continue
            assert getattr(codec, attr) is value, f"{sub}.{attr} shadowed"


def test_device_type_aliases() -> None:
    assert codec.CommissioningDeviceType is commissioning.DeviceType
    assert codec.NeighborDeviceType is zdo_mgmt.DeviceType
    assert "DeviceType" not in codec.__all__


@pytest.mark.parametrize("module_name", sorted(FROZEN_NAMES))
def test_frozen_names_exported(module_name: str) -> None:
    module = importlib.import_module(module_name)
    for name in FROZEN_NAMES[module_name]:
        assert hasattr(module, name), f"{module_name}.{name}"
        assert name in module.__all__, f"{name} not in {module_name}.__all__"


def test_frozen_methods_and_callbacks() -> None:
    for method in ("spawn", "request_rejoin", "notify_seen", "update_node_config", "start"):
        assert callable(getattr(ZdConnection, method))
    for prop in ("last_join", "last_node_stats", "transport_stats"):
        assert isinstance(getattr(ZdConnection, prop), property)
    for method in ("attach", "snapshot", "poll", "set_setpoint", "export_cache"):
        assert callable(getattr(ViCareBridge, method))
    params = inspect.signature(ViCareBridge.__init__).parameters
    assert {"on_update", "on_new_valve", "on_cache_changed"} <= params.keys()


def test_zigbee_direct_reexports_are_canonical() -> None:
    package = importlib.import_module("localtrv.zigbee_direct")
    for module_name, names in FROZEN_NAMES.items():
        if not module_name.startswith("localtrv.zigbee_direct."):
            continue
        module = importlib.import_module(module_name)
        for name in names:
            if name in package.__all__:
                assert getattr(package, name) is getattr(module, name)


def test_testing_module_keeps_legacy_imports() -> None:
    legacy = importlib.import_module("localtrv.testing")
    zdd = importlib.import_module("localtrv.testing.zdd")
    assert legacy.FakeZdd is zdd.FakeZdd
    assert legacy.GATT_ERROR_REJECTED == 0x80
    zdd_eui = Eui64.from_str("02:00:00:00:00:00:00:02")
    fake = legacy.FakeZdd(eui=zdd_eui, psk=SecretBytes(bytes(16)))
    assert fake.counter_model is legacy.ZddCounterModel.SHARED


def test_envelope_key() -> None:
    env = Envelope(src_short=0x5E6F, kind="zcl", seq=0x2B, profile_id=0x0104, cluster_id=0x0201)
    assert env.key == (0x5E6F, "zcl", 0x2B)


# Static structural checks (mypy verifies these assignments; the bodies never run).
def _bleak_client_is_gatt_client(client: BleakClientWithServiceCache) -> GattClient:
    return client


def _fake_client_is_gatt_client(client: FakeBleakClient) -> GattClient:
    return client


def _fake_connector_is_connector(connector: FakeConnector) -> Connector:
    return connector


def test_structural_helpers_exist() -> None:
    assert callable(_bleak_client_is_gatt_client)
    assert callable(_fake_client_is_gatt_client)
    assert callable(_fake_connector_is_connector)


def test_cache_types_reexported_from_bridge() -> None:
    bridge = importlib.import_module("localtrv.bridge")
    cache = importlib.import_module("localtrv.bridge_cache")
    assert bridge.BridgeCache is cache.BridgeCache
    assert bridge.CachedValve is cache.CachedValve


def test_valves_package_reexports_submodules() -> None:
    valves = importlib.import_module("localtrv.valves")
    for sub in ("constants", "models", "decode"):
        module = importlib.import_module(f"localtrv.valves.{sub}")
        for name in module.__all__:
            assert getattr(valves, name) is getattr(module, name), f"{sub}.{name}"
