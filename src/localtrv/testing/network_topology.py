"""Who is in the simulated mesh: coordinator, routers, valves and their Mgmt_Lqi tables.

Used by ``SimNetwork``; holds no timing and sends nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from localtrv.testing import network_frames as nf
from localtrv.zigbee_direct.types import COORDINATOR, validate_short

if TYPE_CHECKING:
    from localtrv.testing.network import SimRouter
    from localtrv.testing.valve import SimValve
    from localtrv.zigbee_direct.codec.zdo_mgmt import Neighbor
    from localtrv.zigbee_direct.types import Eui64

FIRST_BROADCAST: Final = 0xFFF8


class MeshTopology:
    """Routers by short (insertion order), valves with their parent short."""

    def __init__(self, *, coordinator_eui: Eui64, extended_pan_id: Eui64) -> None:
        self._coordinator_eui = coordinator_eui
        self._ext_pan = extended_pan_id.as_int()
        self._routers: dict[int, SimRouter] = {}
        self._valves: list[tuple[SimValve, int]] = []

    @property
    def routers(self) -> tuple[SimRouter, ...]:
        return tuple(self._routers.values())

    @property
    def valves(self) -> tuple[SimValve, ...]:
        return tuple(v for v, _ in self._valves)

    def is_router(self, short: int) -> bool:
        return short == COORDINATOR or short in self._routers

    def valve_by_short(self, short: int) -> SimValve | None:
        return next((v for v, _ in self._valves if v.short == short), None)

    def eui_of(self, short: int) -> Eui64 | None:
        if short == COORDINATOR:
            return self._coordinator_eui
        if short in self._routers:
            return self._routers[short].eui
        valve = self.valve_by_short(short)
        return None if valve is None else valve.eui

    def check_short_free(self, short: int) -> None:
        validate_short(short)
        if short == COORDINATOR or short >= FIRST_BROADCAST or self.eui_of(short) is not None:
            raise ValueError(f"short 0x{short:04X} is reserved or already in use")

    def _check_new(self, eui: Eui64, short: int, parent: int) -> None:
        if not self.is_router(parent):
            raise ValueError(f"parent 0x{parent:04X} is not the coordinator or a router")
        self.check_short_free(short)
        euis = {self._coordinator_eui, *(r.eui for r in self._routers.values())}
        euis.update(v.eui for v, _ in self._valves)
        if eui in euis:
            raise ValueError(f"EUI {eui} is already in the network")

    def add_router(self, router: SimRouter) -> None:
        self._check_new(router.eui, router.short, router.parent)
        self._routers[router.short] = router

    def add_valve(self, valve: SimValve, parent: int) -> None:
        self._check_new(valve.eui, valve.short, parent)
        self._valves.append((valve, parent))

    def _depth(self, short: int) -> int:
        depth = 0
        while short != COORDINATOR:
            depth += 1
            short = self._routers[short].parent
        return depth

    def neighbor_table(self, short: int) -> tuple[Neighbor, ...]:
        """The Mgmt_Lqi table of the coordinator or a router: its valves, then its routers."""
        depth = self._depth(short) + 1
        valves = (
            nf.end_device_neighbor(self._ext_pan, v.eui, v.short, depth)
            for v, parent in self._valves
            if parent == short
        )
        routers = (
            nf.router_neighbor(self._ext_pan, r.eui, r.short, depth)
            for r in self._routers.values()
            if r.parent == short
        )
        return (*valves, *routers)


__all__ = ["FIRST_BROADCAST", "MeshTopology"]
