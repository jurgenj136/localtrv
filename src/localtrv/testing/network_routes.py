"""Scripted loss of a router's return route to the ZVD (used by ``SimNetwork``).

Live 2026-11-10: after a BLE proxy reconnect, every child of the coordinator stayed silent while
the R0's own child answered. Our requests still reached the children (each one made the
coordinator start route discovery to the ZVD on its behalf), but no reply came back, and
periodic MTORRs did not repair it. A new process (a full re-setup) did.

``ReturnRouteLoss.schedule(parent)`` arms the fault for the NEXT session: from that session's
reset on, children of ``parent`` still handle requests, but their replies and reports are
dropped and the parent emits a Route Request for the ZVD in their name instead. The following
session reset heals it (a rejoin). With ``heal_on_refresh`` a re-announcement of the ZVD (a
second Device_annce in the same session) heals it as well.
"""

from __future__ import annotations


class ReturnRouteLoss:
    """State of the scripted fault (see module docstring). Loop thread only."""

    __slots__ = ("_armed", "_heal_on_refresh", "_route_id", "parent")

    def __init__(self) -> None:
        self._armed: int | None = None
        self._heal_on_refresh = False
        self._route_id = 0x40
        #: The router whose children cannot reach the ZVD this session, or ``None``.
        self.parent: int | None = None

    def schedule(self, parent: int, *, heal_on_refresh: bool = False) -> None:
        """Lose ``parent``'s return route from the next session reset on."""
        self._armed = parent
        self._heal_on_refresh = heal_on_refresh

    def on_session_reset(self) -> None:
        self.parent, self._armed = self._armed, None

    def on_reannounce(self) -> None:
        if self._heal_on_refresh:
            self.parent = None

    def blocks(self, parent: int | None) -> bool:
        return parent is not None and parent == self.parent

    def next_route_id(self) -> int:
        self._route_id = (self._route_id + 1) & 0xFF
        return self._route_id


__all__ = ["ReturnRouteLoss"]
