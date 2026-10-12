"""Ready-made simulated installations (T9).

Frozen interface (T2); implemented by T9. ``default_installation`` builds the research layout:
the coordinator with ``n_valves - behind_router`` valve children, the R0 as a router, and one
extra router carrying ``behind_router`` valves. Every EUI is a dummy (``02:00:...``), every key
a distinct dummy ``SecretBytes``; the same ``seed`` gives the same installation and traffic.
The R0's ``zdd_short``/``eui`` and the network's ``zdd_short``/``zdd_eui`` are always set from
the same values (one source of truth in ``default_installation``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import random

    from vicare_local_ble.testing.gatt import FakeConnector, SimulatedR0
    from vicare_local_ble.testing.network import SimNetwork
    from vicare_local_ble.testing.valve import SimValve
    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.connection import DeviceResolver
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes


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


def default_installation(
    n_valves: int = 5, behind_router: int = 1, seed: int = 0, clock: VirtualClock | None = None
) -> Installation:
    """Build and wire R0, network and valves (a new ``VirtualClock`` if ``clock`` is None)."""
    raise NotImplementedError("T9")


__all__ = ["Installation", "default_installation"]
