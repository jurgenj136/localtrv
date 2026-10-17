"""Ready-made simulated installations.

``default_installation`` builds the layout of the tested installation:
the coordinator with ``n_valves - behind_router`` valve children, the R0 as a router, and one
extra router carrying ``behind_router`` valves. Every EUI is a dummy (``02:00:...``), every key
a distinct dummy ``SecretBytes``; the same ``seed`` gives the same installation and traffic.
The R0's ``zdd_short``/``eui`` and the network's ``zdd_short``/``zdd_eui`` are always set from
the same values (one source of truth in ``default_installation``).

Layout: shorts are drawn from ``random.Random(seed)`` (distinct, never 0x0000 or a
broadcast); the extra router exists only when ``behind_router > 0``. EUIs:
ZVD ``02:00:00:00:00:00:00:01``, R0 ``...:02``, coordinator ``...:04``, extra router
``...:05``, valve *i* ``02:00:00:00:00:01:00:<i+1>``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from vicare_local_ble.testing.gatt import SimulatedR0, fake_connector
from vicare_local_ble.testing.network import SimNetwork, SimRouter
from vicare_local_ble.testing.valve import SimValve
from vicare_local_ble.zigbee_direct.clock import VirtualClock
from vicare_local_ble.zigbee_direct.types import COORDINATOR, Eui64, SecretBytes

if TYPE_CHECKING:
    from vicare_local_ble.testing.gatt import FakeConnector
    from vicare_local_ble.zigbee_direct.connection import DeviceResolver

ZVD_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:01")
ZDD_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:02")
COORDINATOR_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:04")
ROUTER_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:05")
EXTENDED_PAN_ID: Final = Eui64.from_str("DD:DD:DD:DD:DD:DD:DD:01")
PAN_ID: Final = 0x1A2B


def valve_eui(index: int) -> Eui64:
    """Dummy EUI of valve ``index`` (0-based)."""
    return Eui64.from_str(f"02:00:00:00:00:01:00:{index + 1:02X}")


def _dummy_key(fill: int) -> SecretBytes:
    return SecretBytes(bytes([fill]) * 16)


@dataclass(frozen=True, slots=True)
class Installation:
    """A wired simulator: pass ``resolver``, ``zvd_eui``, ``network_key``, ``clock`` and
    ``connector`` to ``ZdConnection``/``validate_connection``."""

    clock: VirtualClock
    rng: random.Random
    r0: SimulatedR0
    network: SimNetwork
    valves: tuple[SimValve, ...]
    connector: FakeConnector
    resolver: DeviceResolver
    zvd_eui: Eui64
    zdd_eui: Eui64
    network_key: SecretBytes


def _draw_shorts(rng: random.Random, count: int) -> list[int]:
    shorts: list[int] = []
    while len(shorts) < count:
        short = rng.randrange(0x0001, 0xFFF8)
        if short not in shorts:
            shorts.append(short)
    return shorts


def default_installation(
    n_valves: int = 5, behind_router: int = 1, seed: int = 0, clock: VirtualClock | None = None
) -> Installation:
    """Build and wire R0, network and valves (a new ``VirtualClock`` if ``clock`` is None)."""
    if n_valves < 0 or not 0 <= behind_router <= n_valves:
        raise ValueError("need n_valves >= 0 and 0 <= behind_router <= n_valves")
    clock = VirtualClock() if clock is None else clock
    rng = random.Random(seed)  # noqa: S311 - deterministic simulator, not crypto
    zdd_short, router_short, *valve_shorts = _draw_shorts(rng, n_valves + 2)
    network_key = _dummy_key(0x11)
    r0 = SimulatedR0(
        clock,
        eui=ZDD_EUI,
        network_key=network_key,
        zdd_short=zdd_short,
        pan_id=PAN_ID,
        extended_pan_id=EXTENDED_PAN_ID,
        trust_center_eui=COORDINATOR_EUI,
        link_key=_dummy_key(0x22),
        admin_key=_dummy_key(0x33),
        rng=rng,
    )
    network = SimNetwork(
        clock,
        zdd_short=zdd_short,
        zdd_eui=ZDD_EUI,
        coordinator_eui=COORDINATOR_EUI,
        extended_pan_id=EXTENDED_PAN_ID,
        rng=rng,
    )
    network.attach(r0)
    if behind_router:
        network.add_router(SimRouter(eui=ROUTER_EUI, short=router_short))
    valves: list[SimValve] = []
    for index, short in enumerate(valve_shorts):
        valve = SimValve(clock, eui=valve_eui(index), short=short, rng=rng)
        parent = router_short if index >= n_valves - behind_router else COORDINATOR
        network.add_valve(valve, parent=parent)
        valves.append(valve)
    return Installation(
        clock=clock,
        rng=rng,
        r0=r0,
        network=network,
        valves=tuple(valves),
        connector=fake_connector(r0),
        resolver=r0.ble_device,
        zvd_eui=ZVD_EUI,
        zdd_eui=ZDD_EUI,
        network_key=network_key,
    )


__all__ = ["Installation", "default_installation", "valve_eui"]
