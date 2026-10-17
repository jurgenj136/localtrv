"""Thin command line: ``scan`` lists Zigbee Direct devices, ``status`` checks one (no key echo).

The network key is read only from an environment variable or a file, never from an argument
(shell history), wrapped in ``SecretBytes`` and never printed.

Exit codes: 0 ok, 2 usage, 3 not found, 4 authentication failed, 5 other connection error.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import secrets
import stat
import sys
from typing import TYPE_CHECKING, Final

from bleak import BleakScanner
from bleak.exc import BleakError

from localtrv.zigbee_direct.clock import LoopClock
from localtrv.zigbee_direct.connection import ZdConnection, validate_connection
from localtrv.zigbee_direct.errors import (
    HandshakeRejectedError,
    TransportError,
    ZigbeeDirectError,
)
from localtrv.zigbee_direct.types import Eui64, SecretBytes
from localtrv.zigbee_direct.uuids import (
    COMMISSIONING_SERVICE,
    SECURITY_SERVICE,
    TUNNEL_SERVICE,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from bleak.backends.device import BLEDevice

EXIT_OK: Final = 0
EXIT_USAGE: Final = 2
EXIT_NOT_FOUND: Final = 3
EXIT_AUTH: Final = 4
EXIT_ERROR: Final = 5

_ZD_SERVICES: Final = frozenset({COMMISSIONING_SERVICE, SECURITY_SERVICE, TUNNEL_SERVICE})
_NAME_PREFIX: Final = "ubisys"
_KEY_LEN: Final = 16


class _UsageError(Exception):
    """Bad or missing user input (exit 2)."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="localtrv", description="Viessmann local BLE helper.")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    scan = sub.add_parser("scan", help="list Zigbee Direct devices in range (no connection)")
    scan.add_argument("--timeout", type=float, default=10.0, help="scan seconds (default 10)")

    status = sub.add_parser("status", help="connect, handshake and print the device EUI")
    status.add_argument("--address", required=True, help="BLE address of the device")
    group = status.add_mutually_exclusive_group(required=True)
    group.add_argument("--key-env", metavar="VAR", help="env var holding the 32-hex network key")
    group.add_argument("--key-file", metavar="PATH", help="file holding the 32-hex network key")
    status.add_argument("--timeout", type=float, default=60.0, help="seconds (default 60)")
    status.add_argument("--zvd-eui", help="own EUI-64 (default: random, locally administered)")
    status.add_argument("--join", action="store_true", help="also join and print join info")
    return parser


def _load_key(args: argparse.Namespace) -> SecretBytes:
    if args.key_env is not None:
        text = os.environ.get(args.key_env)
        if text is None:
            raise _UsageError(f"environment variable {args.key_env} is not set")
    else:
        path: str = args.key_file
        try:
            mode = os.stat(path).st_mode
            with open(path, encoding="ascii") as handle:
                text = handle.read()
        except (OSError, UnicodeDecodeError) as exc:
            raise _UsageError(f"cannot read key file {path}: {type(exc).__name__}") from None
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(f"warning: {path} is group/world accessible; chmod 600 it", file=sys.stderr)
    try:
        key = SecretBytes.from_hex(text)
    except ValueError:
        raise _UsageError("network key is not valid hex") from None
    if len(key) != _KEY_LEN:
        raise _UsageError(f"network key must be {_KEY_LEN} bytes (32 hex digits)")
    return key


def _zvd_eui(text: str | None) -> Eui64:
    if text is not None:
        try:
            return Eui64.from_str(text)
        except ValueError as exc:
            raise _UsageError(str(exc)) from None
    raw = bytearray(secrets.token_bytes(8))
    raw[0] = (raw[0] | 0x02) & 0xFE  # locally administered, unicast (display-order first byte)
    return Eui64.from_str(raw.hex())


def _matches(device: BLEDevice, service_uuids: Sequence[str]) -> bool:
    if _ZD_SERVICES & {u.lower() for u in service_uuids}:
        return True
    return (device.name or "").lower().startswith(_NAME_PREFIX)


async def _scan(timeout: float) -> int:
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    rows = [
        (device.address, device.name or "-", adv.rssi)
        for device, adv in found.values()
        if _matches(device, adv.service_uuids)
    ]
    rows.sort(key=lambda r: r[2], reverse=True)
    for address, name, rssi in rows:
        print(f"{address}  {name}  {rssi} dBm")
    if not rows:
        print("no Zigbee Direct devices found", file=sys.stderr)
    return EXIT_OK


async def _status(args: argparse.Namespace, key: SecretBytes, own_eui: Eui64) -> int:
    device = await BleakScanner.find_device_by_address(args.address, timeout=min(args.timeout, 15))
    if device is None:
        print(f"device {args.address} not found", file=sys.stderr)
        return EXIT_NOT_FOUND
    if not args.join:
        zdd = await validate_connection(
            lambda: device, own_eui=own_eui, network_key=key, timeout=args.timeout
        )
        print(f"handshake ok\nzdd_eui: {zdd}")
        return EXIT_OK
    conn = ZdConnection(lambda: device, own_eui=own_eui, network_key=key, clock=LoopClock())
    try:
        await conn.start(first_ready_timeout=args.timeout)
        info = conn.last_join
        print("handshake ok")
        if info is not None:
            print(f"zdd_eui: {info.zdd_eui}\nown_short: 0x{info.own_short:04x}")
            print(f"zdd_short: 0x{info.zdd_short:04x}")
            net = info.network
            if net.pan_id is not None:
                print(f"pan_id: 0x{net.pan_id:04x}")
        if conn.stats.mtu is not None:
            print(f"mtu: {conn.stats.mtu}")
    finally:
        await conn.stop()
    return EXIT_OK


async def _run(args: argparse.Namespace) -> int:
    if args.command == "scan":
        return await _scan(args.timeout)
    return await _status(args, _load_key(args), _zvd_eui(args.zvd_eui))


def _error_code(exc: BaseException) -> tuple[int, str]:
    if isinstance(exc, HandshakeRejectedError):
        return EXIT_AUTH, "authentication failed (wrong network key?)"
    if isinstance(exc, TransportError) and exc.reason == "not_found":
        return EXIT_NOT_FOUND, "device not found"
    if isinstance(exc, TimeoutError):
        return EXIT_ERROR, "timed out"
    return EXIT_ERROR, f"connection error: {type(exc).__name__}"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = _build_parser().parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except _UsageError as exc:
        print(f"localtrv: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (ZigbeeDirectError, BleakError, OSError, TimeoutError) as exc:
        code, message = _error_code(exc)
        print(f"localtrv: {message}", file=sys.stderr)
        return code
    except KeyboardInterrupt:
        with contextlib.suppress(Exception):
            print("interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
