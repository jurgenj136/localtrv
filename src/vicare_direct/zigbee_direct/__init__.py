"""Generic Zigbee Direct (BLE) protocol support. No vendor-specific knowledge here.

Frame codecs live in :mod:`vicare_direct.zigbee_direct.codec`; GATT UUIDs in
:mod:`vicare_direct.zigbee_direct.uuids` (both re-exported as submodules).
"""

from vicare_direct.zigbee_direct import codec, uuids
from vicare_direct.zigbee_direct.crypto import (
    WELL_KNOWN_PSK,
    SecretType,
    derive_basic_authorization_key,
    install_code_to_link_key,
)
from vicare_direct.zigbee_direct.errors import (
    ApsDecodeError,
    AuthenticationError,
    CommissioningDecodeError,
    CounterExhaustedError,
    DecodeError,
    EncodeError,
    HandshakeError,
    NwkDecodeError,
    ReplayError,
    TlvDecodeError,
    UnsupportedFrameError,
    ZclDecodeError,
    ZdoDecodeError,
    ZigbeeDirectError,
)
from vicare_direct.zigbee_direct.session import (
    Established,
    HandshakeInitiator,
    HandshakeState,
    SendSe3,
    SessionCipher,
)
from vicare_direct.zigbee_direct.types import (
    BROADCAST_ALL,
    BROADCAST_ROUTERS,
    BROADCAST_RX_ON,
    COORDINATOR,
    Eui64,
    SecretBytes,
    generate_zvd_eui,
    validate_short,
)

__all__ = [
    "BROADCAST_ALL",
    "BROADCAST_ROUTERS",
    "BROADCAST_RX_ON",
    "COORDINATOR",
    "WELL_KNOWN_PSK",
    "ApsDecodeError",
    "AuthenticationError",
    "CommissioningDecodeError",
    "CounterExhaustedError",
    "DecodeError",
    "EncodeError",
    "Established",
    "Eui64",
    "HandshakeError",
    "HandshakeInitiator",
    "HandshakeState",
    "NwkDecodeError",
    "ReplayError",
    "SecretBytes",
    "SecretType",
    "SendSe3",
    "SessionCipher",
    "TlvDecodeError",
    "UnsupportedFrameError",
    "ZclDecodeError",
    "ZdoDecodeError",
    "ZigbeeDirectError",
    "codec",
    "derive_basic_authorization_key",
    "generate_zvd_eui",
    "install_code_to_link_key",
    "uuids",
    "validate_short",
]
