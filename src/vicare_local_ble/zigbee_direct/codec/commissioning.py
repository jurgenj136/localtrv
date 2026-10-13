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

Length schema (``CommissioningStatus.decode`` and ``safe_status_layout``). Tag order never
matters. Every known tag has a fixed set of allowed lengths; any other length is fatal
(``CommissioningDecodeError``), as are truncation and a repeated tag. Each tag allows exactly
its ZD 1.0 length, with one exception: 0x05 (device type) also allows 4 bytes, the ubisys R0
variant observed live on 2026-10-13 (semantics unknown). A 4-byte 0x05 leaves ``device_type``
``None``, keeps nothing of its value and records its header ``(0x05, 4)`` in ``deviations``.
Accepting that second length is a schema change justified by live evidence, not a general
tolerance; the out-of-scope class is unchanged (see ``safe_status_layout``): a schema-matching
header with a value of another size cannot be detected by any parser. Unknown tags are kept
raw; the channel TLV 0x02 is kept raw and decoded lazily.
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
#: The only channel TLV form ``safe_status_layout`` trusts: count 1 + one 4-byte mask.
_CHANNEL_LEN = 5

#: Allowed value lengths per tag (0x02 is variable; see ``safe_status_layout``).
_ALLOWED_LENGTHS: tuple[tuple[StatusTag, frozenset[int]], ...] = (
    (StatusTag.EXTENDED_PAN_ID, frozenset({8})),
    (StatusTag.PAN_ID, frozenset({2})),
    (StatusTag.NETWORK_KEY, frozenset({_KEY_LEN})),
    (StatusTag.LINK_KEY, frozenset({1 + _KEY_LEN})),
    (StatusTag.DEVICE_TYPE, frozenset({1, 4})),  # 1: ZD 1.0; 4: ubisys R0 (live 2026-10-13)
    (StatusTag.NWK_ADDRESS, frozenset({2})),
    (StatusTag.JOINING_METHOD, frozenset({1})),
    (StatusTag.IEEE_ADDRESS, frozenset({8})),
    (StatusTag.TRUST_CENTER_ADDRESS, frozenset({8})),
    (StatusTag.NETWORK_STATUS_MAP, frozenset({1})),
    (StatusTag.NWK_UPDATE_ID, frozenset({1})),
    (StatusTag.ACTIVE_KEY_SEQ, frozenset({1})),
    (StatusTag.ADMIN_KEY, frozenset({_KEY_LEN})),
    (StatusTag.STATUS_CODE, frozenset({2})),
)
#: Allowed non-ZD-1.0 lengths: the value is dropped and only the header kept in ``deviations``.
_VARIANTS: frozenset[tuple[StatusTag, int]] = frozenset({(StatusTag.DEVICE_TYPE, 4)})
_TAG_VALUES: frozenset[int] = frozenset(int(tag) for tag in StatusTag)


def safe_status_layout(data: bytes) -> tuple[str | None, str]:
    """``(fault, layout)`` of a status: its TLV headers up to the first unverified one.

    ``layout`` is ``"<n> B: TT/len ..."`` plus ``", <m> B withheld"`` for anything not shown;
    ``fault`` names the first unverified header (``None`` if the whole chain verified). It never
    includes a value byte, and no header past the first unverified one.

    Threat model: a header is trusted only while every earlier header matched the fixed schema
    exactly: a known tag, not repeated, with one of its allowed lengths (``_ALLOWED_LENGTHS``:
    one per tag, plus the R0's 4-byte 0x05; the channel TLV 0x02 only in its fixed form: 5 bytes
    with count 1, a single 2.4 GHz page). The first header that does
    not match is shown (it sits at an aligned offset) and everything after it is withheld. Key
    bytes live only inside key TLV values (0x03, 0x04, 0x0D), and every key TLV before the cut
    had exactly its key length, so as long as the encoder writes values of the size its headers
    declare, no key byte is read as a header. An encoder that writes a schema-matching header
    but a value of another size cannot be detected by any parser and is out of scope.
    """
    allowed = dict(_ALLOWED_LENGTHS)
    entries: list[str] = []
    seen: set[StatusTag] = set()
    fault: str | None = None
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            fault = "truncated TLV header"
            break
        raw_tag, length = data[offset], data[offset + 1] + 1
        entries.append(f"{raw_tag:02X}/{length}")  # aligned: a real header
        end = offset + 2 + length
        offset += 2
        known = raw_tag in _TAG_VALUES
        name = StatusTag(raw_tag).name if known else f"tag 0x{raw_tag:02X}"
        if end > len(data):
            fault = f"truncated {name}"
            break
        if not known:
            fault = f"unknown {name}"
            break
        tag = StatusTag(raw_tag)
        if tag in seen:
            fault = f"duplicate {name}"
            break
        if tag is StatusTag.NETWORK_CHANNEL:
            if length != _CHANNEL_LEN or data[offset] != 1:  # count/length agreement proves nothing
                fault = "unverified channel layout"
                break
        elif length not in allowed[tag]:
            fault = f"length mismatch on {name}"
            break
        seen.add(tag)
        offset = end
    layout = f"{len(data)} B: {' '.join(entries)}" if entries else f"{len(data)} B"
    withheld = len(data) - offset
    if withheld:
        layout += f", {withheld} B withheld"
    return fault, layout


def _decode_error(data: bytes) -> CommissioningDecodeError:
    """A decode error whose message and ``safe_detail`` hold no value bytes (see
    ``safe_status_layout``); codec-internal messages (offsets, TLV lengths) are never used."""
    fault, layout = safe_status_layout(data)
    detail = f"{fault or 'TLV structure invalid'}; layout {layout}"
    return CommissioningDecodeError(f"commissioning status: {detail}", safe_detail=detail)


@dataclass(frozen=True, slots=True)
class ChannelMask:
    """One 32-bit channel page/mask entry: page in bits 27-31, channel mask in bits 0-26.

    Bits 27-31 follow the Zigbee channel page structure and Wireshark's ZDP dissector
    (``ZBEE_ZDP_NWKUPDATE_PAGE`` 0xF8000000). Wireshark's ZD TLV helper reads only bits 27-29
    (``(mask >> 27) & 0x07``), which cannot hold sub-GHz pages 28-31; both agree on page 0.
    """

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
    its layout is not yet verified against a live ZDD. ``deviations`` holds the
    ``(tag, length)`` header of each allowed non-ZD-1.0 variant, i.e. ``(0x05, 4)`` on the R0
    (never its value; see the module docstring).
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
    deviations: tuple[tuple[int, int], ...] = ()

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
        """Decode the decrypted characteristic value; unknown tags are kept raw in ``unknown``.

        Allowed lengths follow the module docstring's schema.

        Every error is a ``CommissioningDecodeError`` raised outside any ``except`` (no cause,
        no context) whose message equals its key-free ``safe_detail``.
        """
        tlvs: tuple[Tlv, ...] | None
        try:
            tlvs = decode_tlvs(data)
        except TlvDecodeError:
            tlvs = None
        if tlvs is None:
            raise _decode_error(data)
        known: dict[StatusTag, bytes] = {}
        unknown: list[Tlv] = []
        deviations: list[tuple[int, int]] = []
        allowed = dict(_ALLOWED_LENGTHS)
        seen: set[StatusTag] = set()
        for tlv in tlvs:
            try:
                tag = StatusTag(tlv.tag)
            except ValueError:
                unknown.append(tlv)
                continue
            if tag in seen:
                raise _decode_error(data)
            seen.add(tag)
            lengths = allowed.get(tag)
            if lengths is not None and len(tlv.value) not in lengths:
                raise _decode_error(data)
            if (tag, len(tlv.value)) in _VARIANTS:
                deviations.append((int(tag), len(tlv.value)))
                continue
            known[tag] = tlv.value
        return cls._from_values(known, tuple(unknown), tuple(deviations))

    @classmethod
    def _from_values(
        cls,
        v: dict[StatusTag, bytes],
        unknown: tuple[Tlv, ...],
        deviations: tuple[tuple[int, int], ...],
    ) -> Self:
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
            deviations=deviations,
        )
