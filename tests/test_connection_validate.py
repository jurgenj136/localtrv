"""``validate_connection``: handshake-only check for the config flow."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from bleak.exc import BleakError

from localtrv.testing.gatt_client import FakeBleakClient
from localtrv.testing.scenario import default_installation
from localtrv.zigbee_direct.connection import validate_connection
from localtrv.zigbee_direct.errors import HandshakeRejectedError, TransportError
from localtrv.zigbee_direct.types import SecretBytes

if TYPE_CHECKING:
    from localtrv.testing.scenario import Installation
    from localtrv.zigbee_direct.connection import DeviceResolver
    from localtrv.zigbee_direct.types import Eui64


def _validate(
    inst: Installation,
    *,
    key: SecretBytes | None = None,
    resolver: DeviceResolver | None = None,
    timeout: float = 60.0,
) -> asyncio.Future[Eui64]:
    return asyncio.ensure_future(
        validate_connection(
            resolver if resolver is not None else inst.resolver,
            own_eui=inst.zvd_eui,
            network_key=key if key is not None else inst.network_key,
            clock=inst.clock,
            connector=inst.connector,
            timeout=timeout,
        )
    )


@pytest.fixture
def disconnects(monkeypatch: pytest.MonkeyPatch) -> list[FakeBleakClient]:
    calls: list[FakeBleakClient] = []
    original = FakeBleakClient.disconnect

    async def record(self: FakeBleakClient) -> None:
        calls.append(self)
        await original(self)

    monkeypatch.setattr(FakeBleakClient, "disconnect", record)
    return calls


async def test_success_returns_zdd_eui_and_disconnects(disconnects: list[FakeBleakClient]) -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    eui = await inst.clock.run_task(_validate(inst))
    assert eui == inst.zdd_eui
    assert len(disconnects) == 1
    assert inst.r0.client is None
    assert inst.r0.tunnel_writes == ()  # handshake only: no join


async def test_wrong_key_raises_rejected_and_disconnects(
    disconnects: list[FakeBleakClient],
) -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    with pytest.raises(HandshakeRejectedError):
        await inst.clock.run_task(_validate(inst, key=SecretBytes(b"\x99" * 16)))
    assert len(disconnects) == 1
    assert inst.r0.client is None


async def test_not_found() -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    with pytest.raises(TransportError) as exc:
        await inst.clock.run_task(_validate(inst, resolver=lambda: None))
    assert exc.value.reason == "not_found"
    assert inst.r0.connect_count == 0


async def test_timeout_during_connect() -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    inst.connector.hang_next()
    task = _validate(inst, timeout=20.0)
    with pytest.raises(TimeoutError):
        await inst.clock.run_task(task)
    assert inst.clock.now() == pytest.approx(20.0)


async def test_timeout_during_handshake_disconnects(disconnects: list[FakeBleakClient]) -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    inst.r0.handshake_fault = "se2_silence"
    with pytest.raises(TimeoutError):
        await inst.clock.run_task(_validate(inst, timeout=5.0))
    assert len(disconnects) == 1
    assert inst.r0.client is None


async def test_connector_error_propagates() -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    inst.connector.fail_next(1)
    with pytest.raises(BleakError):
        await inst.clock.run_task(_validate(inst))


async def test_default_clock_is_the_loop_clock() -> None:
    inst = default_installation(n_valves=1, behind_router=0)
    with pytest.raises(TransportError):
        await validate_connection(
            lambda: None, own_eui=inst.zvd_eui, network_key=inst.network_key, timeout=1.0
        )
