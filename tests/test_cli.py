"""Thin CLI: usage errors, key loading, scan output, status exit codes. No BLE."""

from __future__ import annotations

import runpy
import types
from typing import TYPE_CHECKING, Any

import pytest

from vicare_local_ble import cli
from vicare_local_ble.zigbee_direct.errors import HandshakeRejectedError, TransportError
from vicare_local_ble.zigbee_direct.types import Eui64
from vicare_local_ble.zigbee_direct.uuids import COMMISSIONING_SERVICE

if TYPE_CHECKING:
    from pathlib import Path

KEY_HEX = "00112233445566778899aabbccddeeff"  # secret-scan: allow
ADDR = "AA:BB:CC:DD:EE:01"
ZDD = Eui64.from_str("0011223344556677")


def _dev(address: str, name: str | None) -> Any:
    return types.SimpleNamespace(address=address, name=name)


def _adv(rssi: int, uuids: list[str]) -> Any:
    return types.SimpleNamespace(rssi=rssi, service_uuids=uuids)


class _Scanner:
    found: dict[str, Any] = {}  # noqa: RUF012 - test double
    device: Any = None

    @staticmethod
    async def discover(**_: Any) -> dict[str, Any]:
        return _Scanner.found

    @staticmethod
    async def find_device_by_address(address: str, **_: Any) -> Any:
        return _Scanner.device


@pytest.fixture(autouse=True)
def scanner(monkeypatch: pytest.MonkeyPatch) -> type[_Scanner]:
    _Scanner.found = {}
    _Scanner.device = _dev(ADDR, "ubisys")
    monkeypatch.setattr(cli, "BleakScanner", _Scanner)
    monkeypatch.setenv("VICARE_KEY", KEY_HEX)
    return _Scanner


def _validate(monkeypatch: pytest.MonkeyPatch, result: object) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def fake(resolver: Any, **kwargs: Any) -> Eui64:
        calls.append({"device": resolver(), **kwargs})
        if isinstance(result, BaseException):
            raise result
        assert isinstance(result, Eui64)
        return result

    monkeypatch.setattr(cli, "validate_connection", fake)
    return calls


STATUS = ["status", "--address", ADDR, "--key-env", "VICARE_KEY"]


def _no_key_leak(capsys: pytest.CaptureFixture[str]) -> None:
    out = capsys.readouterr()
    assert KEY_HEX not in out.out + out.err


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["bogus"],
        ["status", "--address", ADDR],
        ["status", "--address", ADDR, "--key", KEY_HEX],
        ["status", "--address", ADDR, "--key-env", "A", "--key-file", "b"],
        ["scan", "--timeout", "abc"],
    ],
)
def test_usage_errors(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == cli.EXIT_USAGE
    _no_key_leak(capsys)


def test_key_from_env_reaches_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _validate(monkeypatch, ZDD)
    assert cli.main([*STATUS, "--timeout", "7"]) == 0
    assert calls[0]["network_key"].reveal() == bytes.fromhex(KEY_HEX)
    assert calls[0]["timeout"] == 7


def test_status_prints_eui_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _validate(monkeypatch, ZDD)
    assert cli.main(STATUS) == 0
    out = capsys.readouterr().out
    assert str(ZDD) in out
    assert KEY_HEX not in out


def test_key_from_file_and_permission_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _validate(monkeypatch, ZDD)
    key_file = tmp_path / "key"
    key_file.write_text(KEY_HEX + "\n")
    key_file.chmod(0o600)
    argv = ["status", "--address", ADDR, "--key-file", str(key_file)]
    assert cli.main(argv) == 0
    assert "warning" not in capsys.readouterr().err
    key_file.chmod(0o644)
    assert cli.main(argv) == 0
    out = capsys.readouterr()
    assert "group/world" in out.err
    assert KEY_HEX not in out.out + out.err


@pytest.mark.parametrize(
    "value",
    [None, "zz", "0011", KEY_HEX + "00"],
)
def test_bad_env_key(
    monkeypatch: pytest.MonkeyPatch, value: str | None, capsys: pytest.CaptureFixture[str]
) -> None:
    _validate(monkeypatch, ZDD)
    if value is None:
        monkeypatch.delenv("VICARE_KEY")
    else:
        monkeypatch.setenv("VICARE_KEY", value)
    assert cli.main(STATUS) == cli.EXIT_USAGE
    assert "error" in capsys.readouterr().err


def test_missing_key_file(tmp_path: Path) -> None:
    argv = ["status", "--address", ADDR, "--key-file", str(tmp_path / "nope")]
    assert cli.main(argv) == cli.EXIT_USAGE


def test_bad_zvd_eui() -> None:
    assert cli.main([*STATUS, "--zvd-eui", "xyz"]) == cli.EXIT_USAGE


def test_random_zvd_eui_locally_administered(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _validate(monkeypatch, ZDD)
    cli.main(STATUS)
    cli.main(STATUS)
    first, second = (c["own_eui"] for c in calls)
    assert first != second
    assert bytes.fromhex(str(first).replace(":", ""))[0] & 0x03 == 0x02


def test_explicit_zvd_eui(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _validate(monkeypatch, ZDD)
    cli.main([*STATUS, "--zvd-eui", "02:00:00:00:00:00:00:01"])
    assert calls[0]["own_eui"] == Eui64.from_str("0200000000000001")


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (HandshakeRejectedError("rejected"), cli.EXIT_AUTH),
        (TransportError("gone", reason="not_found"), cli.EXIT_NOT_FOUND),
        (TransportError("x", reason="write"), cli.EXIT_ERROR),
        (TimeoutError(), cli.EXIT_ERROR),
        (OSError("boom"), cli.EXIT_ERROR),
    ],
)
def test_status_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: BaseException,
    code: int,
) -> None:
    _validate(monkeypatch, error)
    assert cli.main(STATUS) == code
    _no_key_leak(capsys)


def test_status_device_not_found(
    scanner: type[_Scanner], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = _validate(monkeypatch, ZDD)
    scanner.device = None
    assert cli.main(STATUS) == cli.EXIT_NOT_FOUND
    assert not calls
    assert "not found" in capsys.readouterr().err


def test_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    _validate(monkeypatch, KeyboardInterrupt())
    assert cli.main(STATUS) == cli.EXIT_ERROR


def test_join_prints_join_info(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stopped: list[bool] = []

    class FakeConn:
        stats = types.SimpleNamespace(mtu=247)
        last_join = types.SimpleNamespace(
            zdd_eui=ZDD,
            own_short=0x1234,
            zdd_short=0x0001,
            network=types.SimpleNamespace(pan_id=0xBEEF),
        )

        def __init__(self, *_: Any, **kwargs: Any) -> None:
            assert kwargs["network_key"].reveal() == bytes.fromhex(KEY_HEX)

        async def start(self, *, first_ready_timeout: float) -> None:
            assert first_ready_timeout == 60.0

        async def stop(self) -> None:
            stopped.append(True)

    monkeypatch.setattr(cli, "ZdConnection", FakeConn)
    assert cli.main([*STATUS, "--join"]) == 0
    out = capsys.readouterr()
    assert "mtu: 247" in out.out
    assert "own_short: 0x1234" in out.out
    assert "pan_id: 0xbeef" in out.out
    assert KEY_HEX not in out.out + out.err
    assert stopped == [True]


def test_join_auth_failure_still_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    stopped: list[bool] = []

    class FakeConn:
        def __init__(self, *_: Any, **__: Any) -> None: ...

        async def start(self, *, first_ready_timeout: float) -> None:
            raise HandshakeRejectedError("no")

        async def stop(self) -> None:
            stopped.append(True)

    monkeypatch.setattr(cli, "ZdConnection", FakeConn)
    assert cli.main([*STATUS, "--join"]) == cli.EXIT_AUTH
    assert stopped == [True]


def test_scan_lists_zigbee_direct_devices(
    scanner: type[_Scanner], capsys: pytest.CaptureFixture[str]
) -> None:
    scanner.found = {
        "a": (_dev("AA:01", None), _adv(-70, [COMMISSIONING_SERVICE.upper()])),
        "b": (_dev("AA:02", "Ubisys-X"), _adv(-50, [])),
        "c": (_dev("AA:03", "toaster"), _adv(-40, ["0000180f-0000-1000-8000-00805f9b34fb"])),
    }
    assert cli.main(["scan", "--timeout", "1"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines == ["AA:02  Ubisys-X  -50 dBm", "AA:01  -  -70 dBm"]


def test_scan_empty(scanner: type[_Scanner], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan"]) == 0
    assert "no Zigbee Direct devices" in capsys.readouterr().err


def test_python_dash_m(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["vicare_local_ble", "scan", "--timeout", "0"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("vicare_local_ble", run_name="__main__")
    assert exc.value.code == 0
