"""Simulated ubisys R0 at the GATT level: ``SimulatedR0``, ``FakeBleakClient``, ``fake_connector``.

Implemented by T8; frozen interface (T2). Everything runs on a shared ``VirtualClock``: every
delay is a ``clock.call_later``; indications are delivered by calling the client's notify
callback from a clock callback (or synchronously inside ``write_gatt_char`` when
``indicate_before_write_returns``), never from another thread.

Layers
    ``SimulatedR0`` is the device: GATT services, the handshake (``FakeZdd``), session crypto
    under a ``ZddCounterModel``, the Commissioning Status value, and fault injection. One R0
    serves at most one connected ``FakeBleakClient`` at a time (like the real R0).
    ``FakeBleakClient`` is the per-connection client object handed to the library; it forwards
    to the R0 and satisfies ``zigbee_direct.transport.GattClient``.
    ``fake_connector(r0)`` returns a ``Connector`` that "connects" by asking the R0 for a new
    client.

Seam to the network simulator (T9)
    The R0 decrypts every Tunnel write and hands the plaintext ``TunnelNpdu`` to its attached
    ``TunnelPeer`` (``SimNetwork``); the network answers by calling ``r0.indicate_npdu(...)``,
    which encrypts and indicates it (applying MTU and oversize behaviour). The R0 calls
    ``peer.on_session_reset()`` when the session ends (disconnect, reboot), so the network
    forgets join/gating state.

GATT behaviours (spec §1.7 "Required behaviours: GATT") and their knobs
    * SE3 with a bad tag -> ``FakeGattError(0x80)`` (always, via ``FakeZdd``).
    * Read of Commissioning Status or Identify before the session -> ``FakeGattError(0x80)``.
    * SE3 write failing with a non-0x80 error or a disconnect -> ``se3_fault``.
    * ZDD counter model -> ``counter_model``.
    * Out-of-order or replayed writes -> ``replay_behavior``.
    * Write faults raise / hang / disconnect -> ``inject_write_fault`` (cancel mid-flight is the
      test cancelling a caller while a write hangs or ``write_latency`` is running).
    * ``mtu_size``; oversized indications -> ``oversize_indication``.
    * Long writes on/off -> ``long_write_supported``.
    * Disconnect injection -> ``disconnect()``.
    * Stale services until ``clear_cache()`` -> ``stale_services``: while set, the client's
      ``services`` lookup returns ``None`` for the Tunnel characteristic and ``start_notify`` /
      ``write_gatt_char`` / ``read_gatt_char`` on Tunnel raise
      ``bleak.exc.BleakCharacteristicNotFoundError(char)`` (the real bleak class), which the
      transport maps to ``TransportError(reason="missing_characteristic")``.
      ``FakeBleakClient.clear_cache()`` clears ``stale_services`` on the R0 and returns True.
    * Handshake faults -> ``handshake_fault``: ``se2_silence`` / ``se4_silence`` (the
      indication never comes), ``malformed_se2`` (SE2 with a truncated point TLV).
    * Commissioning Status variants -> ``status_omit_short`` (TLV 0x06 missing) and
      ``status_ieee_override`` (TLV 0x08 differs from the SE2 EUI).
    * Tunnel indication faults -> ``inject_replayed_indication()`` (re-sends the last
      indication frame verbatim: ``ReplayError`` on the client) and
      ``inject_bad_mic_indication()`` (next indication with a corrupted MIC).
    * Response indication before ``write_gatt_char`` returns -> ``indicate_before_write_returns``.
    * Event ``r0_reboot()``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from vicare_local_ble.testing.errors import GATT_ERROR_REJECTED, GATT_ERROR_UNLIKELY, FakeGattError
from vicare_local_ble.testing.zdd import ZddCounterModel

if TYPE_CHECKING:
    import random
    from collections.abc import Callable

    from bleak.backends.device import BLEDevice
    from bleak_retry_connector import BleakClientWithServiceCache

    from vicare_local_ble.zigbee_direct.clock import VirtualClock
    from vicare_local_ble.zigbee_direct.codec.tlv import TunnelNpdu
    from vicare_local_ble.zigbee_direct.transport import (
        GattClient,
        GattServices,
        NotifyCallback,
    )
    from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes

type Se3Fault = Literal["none", "gatt_error", "disconnect"]
type ReplayBehavior = Literal["silent_drop", "gatt_error"]
type OversizeBehavior = Literal["truncate", "drop", "reject"]
type WriteFault = Literal["raise", "hang", "disconnect"]
type HandshakeFault = Literal["none", "se2_silence", "se4_silence", "malformed_se2"]


class TunnelPeer(Protocol):
    """The network behind the R0 (``SimNetwork`` implements it, T9)."""

    def on_zvd_npdu(self, npdu: TunnelNpdu) -> None:
        """A decrypted Tunnel write from the ZVD (sync; schedule replies on the clock)."""
        ...

    def on_session_reset(self) -> None:
        """The BLE session ended (disconnect or reboot): drop join and gating state."""
        ...


@dataclass(frozen=True, slots=True)
class WriteFaultSpec:
    """One pending write fault: applies to the ``after_writes``-th next write on ``char``
    (0 = the next one), then is consumed. ``code`` is the ATT code for ``"raise"``."""

    kind: WriteFault
    char: str
    after_writes: int = 0
    code: int = GATT_ERROR_UNLIKELY


class SimulatedR0:
    """A scripted ubisys R0 (ZDD). See module docstring for behaviours and knobs.

    Identity and Commissioning Status contents are constructor arguments; keys are dummy
    ``SecretBytes`` chosen by the test (the diagnostics secret test uses distinct values for
    ``network_key``, ``link_key`` and ``admin_key``). The PSK for each handshake is the BAK
    derived from ``network_key`` and the EUI the client sends in SE1, as on the real device.
    Knob attributes may be changed between steps.
    """

    def __init__(
        self,
        clock: VirtualClock,
        *,
        eui: Eui64,
        network_key: SecretBytes,
        zdd_short: int,
        pan_id: int,
        extended_pan_id: Eui64,
        trust_center_eui: Eui64,
        link_key: SecretBytes | None = None,
        admin_key: SecretBytes | None = None,
        address: str = "AA:BB:CC:DD:EE:01",
        name: str = "ubisys R0",
        rng: random.Random | None = None,
        mtu_size: int = 247,
        counter_model: ZddCounterModel = ZddCounterModel.SHARED,
        replay_behavior: ReplayBehavior = "silent_drop",
        oversize_indication: OversizeBehavior = "drop",
        long_write_supported: bool = True,
        se3_fault: Se3Fault = "none",
        se3_error_code: int = GATT_ERROR_UNLIKELY,
        stale_services: bool = False,
        indicate_before_write_returns: bool = False,
        write_latency: float = 0.0,
        handshake_latency: float = 0.05,
        handshake_fault: HandshakeFault = "none",
        status_omit_short: bool = False,
        status_ieee_override: Eui64 | None = None,
    ) -> None:
        raise NotImplementedError("T8")

    # --- wiring ---

    def attach_network(self, peer: TunnelPeer) -> None:
        raise NotImplementedError("T8")

    def ble_device(self, *, source: str = "hci0") -> BLEDevice:
        """A ``BLEDevice`` for this R0 as seen through adapter/proxy ``source`` (distinct
        objects per source, same address), for resolver and proxy-switch tests."""
        raise NotImplementedError("T8")

    def connect(
        self, device: BLEDevice, disconnected_callback: Callable[[GattClient], None] | None
    ) -> FakeBleakClient:
        """A new connected client; ``FakeGattError`` if another client is connected.
        ``disconnected_callback(client)`` is called once when that client disconnects."""
        raise NotImplementedError("T8")

    def indicate_npdu(self, npdu: bytes, *, secure: bool = True) -> None:
        """Encrypt ``npdu`` in a tunnel TLV and indicate it to the subscribed client.

        Dropped silently without a session or Tunnel subscription. Values above
        ``mtu_size - 3`` follow ``oversize_indication``.
        """
        raise NotImplementedError("T8")

    # --- fault injection and events ---

    def inject_write_fault(self, spec: WriteFaultSpec) -> None:
        raise NotImplementedError("T8")

    def inject_replayed_indication(self) -> None:
        """Re-indicate the last Tunnel indication frame verbatim (same counter)."""
        raise NotImplementedError("T8")

    def inject_bad_mic_indication(self) -> None:
        """Corrupt the MIC of the next Tunnel indication (the counter is still consumed)."""
        raise NotImplementedError("T8")

    def disconnect(self) -> None:
        """Drop the current connection from the device side (disconnect callback fires)."""
        raise NotImplementedError("T8")

    def r0_reboot(self) -> None:
        """Disconnect, forget the session, and reset the tunnel peer (``on_session_reset``)."""
        raise NotImplementedError("T8")

    # --- observation ---

    @property
    def client(self) -> FakeBleakClient | None:
        raise NotImplementedError("T8")

    @property
    def tunnel_writes(self) -> tuple[TunnelNpdu, ...]:
        """Every decrypted, accepted Tunnel write of the current session, in order."""
        raise NotImplementedError("T8")

    @property
    def write_counters(self) -> tuple[int, ...]:
        """Session counters of every Tunnel write received (accepted or not), in order."""
        raise NotImplementedError("T8")

    @property
    def connect_count(self) -> int:
        raise NotImplementedError("T8")


class FakeBleakClient:
    """Per-connection client bound to a ``SimulatedR0``; satisfies ``GattClient``.

    After disconnect every operation raises ``FakeGattError`` (like a dead bleak client) except
    ``disconnect()`` (idempotent). ``write_gatt_char`` requires ``response=True``.
    """

    def __init__(self, r0: SimulatedR0, *, device: BLEDevice) -> None:
        raise NotImplementedError("T8")

    @property
    def address(self) -> str:
        raise NotImplementedError("T8")

    @property
    def device(self) -> BLEDevice:
        raise NotImplementedError("T8")

    @property
    def is_connected(self) -> bool:
        raise NotImplementedError("T8")

    @property
    def mtu_size(self) -> int:
        raise NotImplementedError("T8")

    @property
    def services(self) -> GattServices:
        """Characteristic lookup; with ``stale_services`` the Tunnel characteristic is missing
        (``None``) until ``clear_cache()``, and Tunnel operations raise
        ``BleakCharacteristicNotFoundError``."""
        raise NotImplementedError("T8")

    async def start_notify(self, char_specifier: str, callback: NotifyCallback) -> None:
        raise NotImplementedError("T8")

    async def stop_notify(self, char_specifier: str) -> None:
        raise NotImplementedError("T8")

    async def write_gatt_char(
        self, char_specifier: str, data: bytes, response: bool | None = None
    ) -> None:
        raise NotImplementedError("T8")

    async def read_gatt_char(self, char_specifier: str) -> bytearray:
        raise NotImplementedError("T8")

    async def disconnect(self) -> None:
        raise NotImplementedError("T8")

    async def clear_cache(self) -> bool:
        """Clear the R0's ``stale_services`` (takes effect for the NEXT connection, like a real
        GATT cache) and return True."""
        raise NotImplementedError("T8")


class FakeConnector:
    """``zigbee_direct.connection.Connector`` backed by a ``SimulatedR0``.

    Records every device it was called with (``devices``), and can be told to fail the next
    calls (``fail_next``) with a given exception (default: ``bleak.exc.BleakError``) or to
    hang until cancelled.
    """

    def __init__(self, r0: SimulatedR0, *, connect_latency: float = 0.5) -> None:
        raise NotImplementedError("T8")

    async def __call__(
        self,
        client_class: type[BleakClientWithServiceCache],
        device: BLEDevice,
        name: str,
        disconnected_callback: Callable[[GattClient], None] | None = None,
        *,
        use_services_cache: bool = True,
        max_attempts: int = 3,
    ) -> GattClient:
        raise NotImplementedError("T8")

    def fail_next(self, count: int = 1, *, exc: BaseException | None = None) -> None:
        raise NotImplementedError("T8")

    def hang_next(self, count: int = 1) -> None:
        raise NotImplementedError("T8")

    @property
    def devices(self) -> tuple[BLEDevice, ...]:
        raise NotImplementedError("T8")


def fake_connector(r0: SimulatedR0, *, connect_latency: float = 0.5) -> FakeConnector:
    """A ``Connector`` for ``ZdConnection``/``validate_connection`` that connects to ``r0``."""
    raise NotImplementedError("T8")


__all__ = [
    "GATT_ERROR_REJECTED",
    "GATT_ERROR_UNLIKELY",
    "FakeBleakClient",
    "FakeConnector",
    "FakeGattError",
    "HandshakeFault",
    "OversizeBehavior",
    "ReplayBehavior",
    "Se3Fault",
    "SimulatedR0",
    "TunnelPeer",
    "WriteFault",
    "WriteFaultSpec",
    "fake_connector",
]
