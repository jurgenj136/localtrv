"""vicare-local-ble: local Zigbee Direct (BLE) client for Viessmann ZK03840 valves."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("vicare-local-ble")
except PackageNotFoundError:  # pragma: no cover - running from an uninstalled tree
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
