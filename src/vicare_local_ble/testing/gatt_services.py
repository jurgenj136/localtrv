"""GATT table, characteristic lookup and Commissioning Status value of the simulated R0 (T8).

Private helpers of ``testing.gatt``; not part of the public test API. Nothing here logs or
formats the Commissioning Status value: it holds the network key.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from bleak.exc import BleakCharacteristicNotFoundError

from vicare_local_ble.zigbee_direct.codec.commissioning import StatusTag
from vicare_local_ble.zigbee_direct.codec.tlv import Tlv, encode_tlvs
from vicare_local_ble.zigbee_direct.errors import HandshakeError
from vicare_local_ble.zigbee_direct.session import (
    OPCODE_SE1,
    TLV_C25519_POINT,
    parse_handshake_message,
)
from vicare_local_ble.zigbee_direct.types import Eui64
from vicare_local_ble.zigbee_direct.uuids import (
    COMMISSIONING_FINDING_BINDING,
    COMMISSIONING_FORM_NETWORK,
    COMMISSIONING_IDENTIFY,
    COMMISSIONING_JOIN_NETWORK,
    COMMISSIONING_LEAVE_NETWORK,
    COMMISSIONING_MANAGE_JOINERS,
    COMMISSIONING_PERMIT_JOINING,
    COMMISSIONING_SERVICE,
    COMMISSIONING_STATUS,
    SECURITY_AUTHENTICATE_C25519,
    SECURITY_SERVICE,
    TUNNEL_NPDU,
    TUNNEL_SERVICE,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vicare_local_ble.zigbee_direct.types import SecretBytes

#: ATT "Read Not Permitted".
GATT_ERROR_READ_NOT_PERMITTED: Final = 0x02
#: ATT "Write Not Permitted".
GATT_ERROR_WRITE_NOT_PERMITTED: Final = 0x03
#: ATT "Request Not Supported" (what a stack without prepared writes answers a long write).
GATT_ERROR_REQUEST_NOT_SUPPORTED: Final = 0x06

#: Status map: joined (2) | centralized (0x10).
_STATUS_MAP_JOINED_CENTRALIZED: Final = 0x12
_DEVICE_TYPE_ROUTER: Final = 1
_LINK_KEY_FLAGS: Final = 0x00
_EUI_SIZE: Final = 8
_POINT_TLV_SIZE: Final = 40


@dataclass(frozen=True, slots=True)
class FakeCharacteristic:
    """Stand-in for ``BleakGATTCharacteristic`` (passed as the notify callback's first arg)."""

    uuid: str
    service_uuid: str


#: Every characteristic the simulated R0 exposes, by lowercase UUID.
CHARACTERISTICS: Final[Mapping[str, FakeCharacteristic]] = MappingProxyType(
    {
        c.uuid: c
        for c in (
            FakeCharacteristic(SECURITY_AUTHENTICATE_C25519, SECURITY_SERVICE),
            FakeCharacteristic(TUNNEL_NPDU, TUNNEL_SERVICE),
            FakeCharacteristic(COMMISSIONING_FORM_NETWORK, COMMISSIONING_SERVICE),
            FakeCharacteristic(COMMISSIONING_JOIN_NETWORK, COMMISSIONING_SERVICE),
            FakeCharacteristic(COMMISSIONING_PERMIT_JOINING, COMMISSIONING_SERVICE),
            FakeCharacteristic(COMMISSIONING_LEAVE_NETWORK, COMMISSIONING_SERVICE),
            FakeCharacteristic(COMMISSIONING_STATUS, COMMISSIONING_SERVICE),
            FakeCharacteristic(COMMISSIONING_MANAGE_JOINERS, COMMISSIONING_SERVICE),
            FakeCharacteristic(COMMISSIONING_IDENTIFY, COMMISSIONING_SERVICE),
            FakeCharacteristic(COMMISSIONING_FINDING_BINDING, COMMISSIONING_SERVICE),
        )
    }
)

#: Readable once the session exists (0x80 before it, like the live ZDD).
SESSION_READABLE: Final = frozenset(
    {COMMISSIONING_STATUS, COMMISSIONING_IDENTIFY, COMMISSIONING_MANAGE_JOINERS}
)


class FakeServices:
    """``GattServices`` view of one connection; ``stale`` hides the Tunnel characteristic."""

    __slots__ = ("_stale",)

    def __init__(self, *, stale: bool) -> None:
        self._stale = stale

    def get_characteristic(self, specifier: str) -> FakeCharacteristic | None:
        char = CHARACTERISTICS.get(specifier.lower())
        if char is None or (self._stale and char.uuid == TUNNEL_NPDU):
            return None
        return char

    def resolve(self, specifier: str) -> FakeCharacteristic:
        """Like ``get_characteristic`` but raises bleak's ``BleakCharacteristicNotFoundError``."""
        char = self.get_characteristic(specifier)
        if char is None:
            raise BleakCharacteristicNotFoundError(specifier)
        return char


def se1_eui(se1: bytes) -> Eui64 | None:
    """The initiator EUI carried in SE1's point TLV, or ``None`` if SE1 is malformed."""
    try:
        tlvs = parse_handshake_message(
            se1, opcode=OPCODE_SE1, known={TLV_C25519_POINT: _POINT_TLV_SIZE}
        )
    except HandshakeError:
        return None
    point = tlvs.get(TLV_C25519_POINT)
    return None if point is None else Eui64.from_wire(point[:_EUI_SIZE])


def status_value(
    *,
    extended_pan_id: Eui64,
    pan_id: int,
    network_key: SecretBytes,
    link_key: SecretBytes | None,
    admin_key: SecretBytes | None,
    zdd_short: int | None,
    ieee: Eui64,
    trust_center_eui: Eui64,
) -> bytes:
    """Plaintext Commissioning Status TLVs (holds the network key: never log it).

    ``zdd_short=None`` omits TLV 0x06 (``status_omit_short``).
    """
    tlvs = [
        Tlv(StatusTag.EXTENDED_PAN_ID, extended_pan_id.wire),
        Tlv(StatusTag.PAN_ID, pan_id.to_bytes(2, "little")),
        Tlv(StatusTag.NETWORK_KEY, network_key.reveal()),
    ]
    if link_key is not None:
        tlvs.append(Tlv(StatusTag.LINK_KEY, bytes([_LINK_KEY_FLAGS]) + link_key.reveal()))
    tlvs.append(Tlv(StatusTag.DEVICE_TYPE, bytes([_DEVICE_TYPE_ROUTER])))
    if zdd_short is not None:
        tlvs.append(Tlv(StatusTag.NWK_ADDRESS, zdd_short.to_bytes(2, "little")))
    tlvs += [
        Tlv(StatusTag.IEEE_ADDRESS, ieee.wire),
        Tlv(StatusTag.TRUST_CENTER_ADDRESS, trust_center_eui.wire),
        Tlv(StatusTag.NETWORK_STATUS_MAP, bytes([_STATUS_MAP_JOINED_CENTRALIZED])),
    ]
    if admin_key is not None:
        tlvs.append(Tlv(StatusTag.ADMIN_KEY, admin_key.reveal()))
    return encode_tlvs(tlvs)


__all__ = [
    "CHARACTERISTICS",
    "GATT_ERROR_READ_NOT_PERMITTED",
    "GATT_ERROR_REQUEST_NOT_SUPPORTED",
    "GATT_ERROR_WRITE_NOT_PERMITTED",
    "SESSION_READABLE",
    "FakeCharacteristic",
    "FakeServices",
    "se1_eui",
    "status_value",
]
