"""Decoder for the decrypted Zigbee Direct Commissioning Status characteristic.

The value is a back-to-back Zigbee TLV list (tag, len-1, value). Tag meanings
follow ZD 1.0 as encoded in Wireshark ``packet-zbee-tlv.h``
(``ZBEE_TLV_TYPE_COMM_*``) and value layouts as in ``packet-zbee-tlv.c``.

Deviation from research tools/zvd_client.py:89-116 (``parse_status_tlvs``):
research verified tags 0x01 (PAN ID), 0x06 (short) and 0x08 (ZDD EUI) live and
guessed the rest. Per ZD 1.0, tag 0x00 is the Extended PAN ID (research guessed
"trust-center-eui64") and 0x09 the Trust Center address (research guessed
"extended-pan-id"); 0x02 is the network channel list, 0x05 the device type,
0x0A the network status map, 0x0B the NWK update id and 0x0C the active key
sequence number.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Self

from vicare_local_ble.zigbee_direct.codec.tlv import Tlv, decode_tlvs
from vicare_local_ble.zigbee_direct.errors import CommissioningDecodeError, TlvDecodeError
from vicare_local_ble.zigbee_direct.types import Eui64, SecretBytes


class StatusTag(IntEnum):
    """Commissioning Status TLV tags (ZD 1.0)."""

    EXTENDED_PAN_ID = 0x00
    PAN_ID = 0x01
    NETWORK_CHANNEL = 0x02
    NETWORK_KEY = 0x03
    LINK_KEY = 0x04
    DEVICE_TYPE = 0x05
    NWK_ADDRESS = 0x06
    JOINING_METHOD = 0x07
    IEEE_ADDRESS = 0x08
    TRUST_CENTER_ADDRESS = 0x09
    NETWORK_STATUS_MAP = 0x0A
    NWK_UPDATE_ID = 0x0B
    ACTIVE_KEY_SEQ = 0x0C
    ADMIN_KEY = 0x0D
    STATUS_CODE = 0x0E


class DeviceType(IntEnum):
    COORDINATOR = 0
    ROUTER = 1
    END_DEVICE = 2


class JoiningMethod(IntEnum):
    MAC_ASSOCIATION = 0
    NWK_REJOIN = 1
    OOB_WITH_BEACON_CHECK = 2
    OOB_WITHOUT_BEACON_CHECK = 3


class JoinedStatus(IntEnum):
    """Network status map bits 0-2."""

    NO_NETWORK = 0
    JOINING = 1
    JOINED = 2
    JOINED_NO_PARENT = 3
    LEAVING = 4


_STATUS_MAP_JOINED = 0x07
_STATUS_MAP_OPEN = 0x08
_STATUS_MAP_CENTRALIZED = 0x10
_KEY_LEN = 16

_FIXED_LENGTHS: tuple[tuple[StatusTag, int], ...] = (
    (StatusTag.EXTENDED_PAN_ID, 8),
    (StatusTag.PAN_ID, 2),
    (StatusTag.NETWORK_KEY, _KEY_LEN),
    (StatusTag.LINK_KEY, 1 + _KEY_LEN),
    (StatusTag.DEVICE_TYPE, 1),
    (StatusTag.NWK_ADDRESS, 2),
    (StatusTag.JOINING_METHOD, 1),
    (StatusTag.IEEE_ADDRESS, 8),
    (StatusTag.TRUST_CENTER_ADDRESS, 8),
    (StatusTag.NETWORK_STATUS_MAP, 1),
    (StatusTag.NWK_UPDATE_ID, 1),
    (StatusTag.ACTIVE_KEY_SEQ, 1),
    (StatusTag.ADMIN_KEY, _KEY_LEN),
    (StatusTag.STATUS_CODE, 2),
)


@dataclass(frozen=True, slots=True)
class ChannelMask:
    """One 32-bit channel page/mask entry: page in bits 27-31, channel mask in bits 0-26."""

    page: int
    mask: int

    @property
    def channels(self) -> tuple[int, ...]:
        return tuple(ch for ch in range(27) if self.mask & (1 << ch))


@dataclass(frozen=True, slots=True)
class CommissioningStatus:
    """Typed view of the Commissioning Status TLVs; absent tags are ``None``.

    Key material (network/link/admin key) is wrapped in ``SecretBytes``.
    The channel TLV is kept raw and decoded lazily by ``channel_masks`` because
    its layout is not yet verified against a live ZDD.
    """

    extended_pan_id: Eui64 | None = None
    pan_id: int | None = None
    network_channel_raw: bytes | None = None
    network_key: SecretBytes | None = None
    link_key_flags: int | None = None
    link_key: SecretBytes | None = None
    device_type: int | None = None
    nwk_address: int | None = None
    joining_method: int | None = None
    ieee_address: Eui64 | None = None
    trust_center_address: Eui64 | None = None
    status_map: int | None = None
    nwk_update_id: int | None = None
    active_key_seq: int | None = None
    admin_key: SecretBytes | None = None
    status_code: tuple[int, int] | None = None
    unknown: tuple[Tlv, ...] = field(default=())

    @property
    def joined_status(self) -> int | None:
        """``JoinedStatus`` value from the status map (raw int if not a known member)."""
        return None if self.status_map is None else self.status_map & _STATUS_MAP_JOINED

    @property
    def permit_join_open(self) -> bool | None:
        return None if self.status_map is None else bool(self.status_map & _STATUS_MAP_OPEN)

    @property
    def centralized(self) -> bool | None:
        """True = centralized (Trust Center) network, False = distributed."""
        return None if self.status_map is None else bool(self.status_map & _STATUS_MAP_CENTRALIZED)

    @property
    def channel_masks(self) -> tuple[ChannelMask, ...] | None:
        """Decode ``count(1) ‖ count * mask(4 LE)``; raises on a malformed TLV."""
        raw = self.network_channel_raw
        if raw is None:
            return None
        count = raw[0]
        if len(raw) != 1 + 4 * count:
            raise CommissioningDecodeError(
                f"network channel TLV: {count} mask(s) need {1 + 4 * count} bytes, got {len(raw)}"
            )
        masks = []
        for i in range(count):
            word = int.from_bytes(raw[1 + 4 * i : 5 + 4 * i], "little")
            masks.append(ChannelMask(page=word >> 27, mask=word & 0x07FFFFFF))
        return tuple(masks)

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Decode the decrypted characteristic value; unknown tags are kept raw in ``unknown``."""
        try:
            tlvs = decode_tlvs(data)
        except TlvDecodeError as exc:
            raise CommissioningDecodeError(f"commissioning status: {exc}") from exc
        known: dict[StatusTag, bytes] = {}
        unknown: list[Tlv] = []
        expected = dict(_FIXED_LENGTHS)
        for tlv in tlvs:
            try:
                tag = StatusTag(tlv.tag)
            except ValueError:
                unknown.append(tlv)
                continue
            if tag in known:
                raise CommissioningDecodeError(f"duplicate commissioning status TLV {tag.name}")
            want = expected.get(tag)
            if want is not None and len(tlv.value) != want:
                raise CommissioningDecodeError(
                    f"{tag.name} TLV needs {want} bytes, got {len(tlv.value)}"
                )
            known[tag] = tlv.value
        return cls._from_values(known, tuple(unknown))

    @classmethod
    def _from_values(cls, v: dict[StatusTag, bytes], unknown: tuple[Tlv, ...]) -> Self:
        def eui(tag: StatusTag) -> Eui64 | None:
            return Eui64(v[tag]) if tag in v else None

        def u8(tag: StatusTag) -> int | None:
            return v[tag][0] if tag in v else None

        def u16(tag: StatusTag) -> int | None:
            return int.from_bytes(v[tag], "little") if tag in v else None

        def secret(tag: StatusTag, start: int = 0) -> SecretBytes | None:
            return SecretBytes(v[tag][start:]) if tag in v else None

        code = v.get(StatusTag.STATUS_CODE)
        return cls(
            extended_pan_id=eui(StatusTag.EXTENDED_PAN_ID),
            pan_id=u16(StatusTag.PAN_ID),
            network_channel_raw=v.get(StatusTag.NETWORK_CHANNEL),
            network_key=secret(StatusTag.NETWORK_KEY),
            link_key_flags=u8(StatusTag.LINK_KEY),
            link_key=secret(StatusTag.LINK_KEY, 1),
            device_type=u8(StatusTag.DEVICE_TYPE),
            nwk_address=u16(StatusTag.NWK_ADDRESS),
            joining_method=u8(StatusTag.JOINING_METHOD),
            ieee_address=eui(StatusTag.IEEE_ADDRESS),
            trust_center_address=eui(StatusTag.TRUST_CENTER_ADDRESS),
            status_map=u8(StatusTag.NETWORK_STATUS_MAP),
            nwk_update_id=u8(StatusTag.NWK_UPDATE_ID),
            active_key_seq=u8(StatusTag.ACTIVE_KEY_SEQ),
            admin_key=secret(StatusTag.ADMIN_KEY),
            status_code=None if code is None else (code[0], code[1]),
            unknown=unknown,
        )
