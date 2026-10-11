"""GATT transport for Zigbee Direct (phase-2 stub, not implemented).

Design constraints for the implementation:

* ``ZigbeeDirectTransport`` wraps an already-connected ``bleak.BleakClient``. The library
  never scans and never connects. The caller (for example Home Assistant) creates the client via
  ``bleak_retry_connector.establish_connection``, possibly through an ESPHome Bluetooth proxy.
* Single serialized writer. Encrypting a frame and awaiting the GATT write happen under ONE
  ``asyncio.Lock`` (or a single writer task fed by a queue). Research bug: the session counter
  was incremented before the awaited write, so concurrent senders wrote frames out of order and
  the ZDD rejected them as replays. Counter allocation, encryption and write are one critical
  section.
* Futures, locks and queues are created lazily inside the running loop (never in ``__init__``
  at import time or from a different thread), so the object can be constructed outside a loop.
* MTU: query the negotiated ATT MTU; ESPHome proxies may report a small or default MTU. Chunk or
  reject frames that do not fit, and never assume 247 bytes.
* Notifications (indications) are decrypted through the sans-IO ``SessionCipher``; replay or MIC
  failures are surfaced as errors, not swallowed.
* Key material is never logged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bleak import BleakClient


class ZigbeeDirectTransport:
    """Encrypted GATT tunnel over an already-connected ``BleakClient`` (stub)."""

    def __init__(self, client: BleakClient) -> None:
        self._client = client

    async def send_npdu(self, npdu: bytes) -> None:
        """Encrypt and write one tunnel NPDU under the single writer lock."""
        raise NotImplementedError("phase 2")
