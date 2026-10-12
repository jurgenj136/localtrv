"""Golden wire fixtures, hand-written from docs/phase2-protocol-notes.md (PN) §1.1-1.6.

Rules (spec §1.7):
- Written by hand from the PN byte layouts; NEVER produced by calling production encoders.
- Dummy identities only: EUIs ``02:00:00:00:00:00:00:NN`` (locally administered), extended PAN
  ``DD:DD:DD:DD:DD:DD:DD:01``, made-up shorts, made-up points and tags. No key material.
- One field per line so a reviewer can check every byte against the PN.
- "live" = bytes the research client actually sent (PN §1.3, §1.4, §1.6).
  "synth" = the PN gives only the payload; the NWK/APS header around it is our assumption
  (the research never logged the header of frames *received*), marked per fixture.

EUIs are written in wire (little-endian) order inside frames.
"""

from __future__ import annotations

from typing import Final

from vicare_local_ble.zigbee_direct.types import Eui64


def h(*parts: str) -> bytes:
    """Concatenate space-separated hex fragments."""
    return bytes.fromhex(" ".join(parts))


# --- dummy identities ----------------------------------------------------------------------

ZVD_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:01")  # us (Zigbee Virtual Device)
ZDD_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:02")  # the R0
VALVE_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:03")
COORDINATOR_EUI: Final = Eui64.from_str("02:00:00:00:00:00:00:04")
EXT_PAN: Final = Eui64.from_str("DD:DD:DD:DD:DD:DD:DD:01")

ZVD_EUI_WIRE: Final = "01 00 00 00 00 00 00 02"
ZDD_EUI_WIRE: Final = "02 00 00 00 00 00 00 02"
VALVE_EUI_WIRE: Final = "03 00 00 00 00 00 00 02"
EXT_PAN_WIRE: Final = "01 DD DD DD DD DD DD DD"

ZDD_SHORT: Final = 0x2A1B  # wire 1B 2A
ZVD_SHORT: Final = 0x1234  # placeholder == assigned short (live: TC echoed it); wire 34 12
VALVE_SHORT: Final = 0x5E6F  # wire 6F 5E
OTHER_PLACEHOLDER: Final = 0x5678  # wire 78 56

# Dummy Curve25519 points and confirmation tags (not derived from anything).
_Q_ZVD = ("51 51 51 51 51 51 51 51", "51 51 51 51 51 51 51 51") * 2
_Q_ZDD = ("52 52 52 52 52 52 52 52", "52 52 52 52 52 52 52 52") * 2
_TAG_U = ("A1 A1 A1 A1 A1 A1 A1 A1", "A1 A1 A1 A1 A1 A1 A1 A1")
_TAG_V = ("B1 B1 B1 B1 B1 B1 B1 B1", "B1 B1 B1 B1 B1 B1 B1 B1")

# --- PN §1.1 handshake -----------------------------------------------------------------------

#: SE1, 47 B: opcode, method TLV (C25519/AES-MMO=1, secret type 3=BAK), point TLV (EUI ‖ Q).
SE1: Final = h(
    "01",  # opcode SE1
    "00 01",  # TLV 0x00 selected method, len-1 = 1
    "01 03",  # method 1, secret type 3 (BAK)
    "02 27",  # TLV 0x02 C25519 point, len-1 = 39 (40 B)
    ZVD_EUI_WIRE,
    *_Q_ZVD,
)
#: SE2: opcode, point TLV (ZDD EUI ‖ Q); the live R0 may append other TLVs (unlogged).
SE2: Final = h("02", "02 27", ZDD_EUI_WIRE, *_Q_ZDD)
#: SE3: opcode, MAC tag TLV 0x04 (len-1 = 15) with tag_U.
SE3: Final = h("03", "04 0F", *_TAG_U)
#: SE4: opcode, MAC tag TLV 0x04 with tag_V.
SE4: Final = h("04", "04 0F", *_TAG_V)

# --- PN §1.3 Commissioning Request / Response ---------------------------------------------

#: live, 52 B: NWK command, discover_route 0 (FC 09), dst+src IEEE (FC byte1 18), radius 1.
COMMISSIONING_REQUEST: Final = h(
    "09 18",  # FC: command, v2, discover 0 | dst IEEE, src IEEE
    "1B 2A",  # dst = ZDD short
    "34 12",  # src = placeholder short
    "01",  # radius 1
    "01",  # NWK seq 1 (live)
    ZDD_EUI_WIRE,  # dst IEEE
    ZVD_EUI_WIRE,  # src IEEE
    "0E",  # Commissioning Request
    "00",  # association type: initial join
    "8E",  # capability
    "48 16",  # Joiner Encapsulation TLV, len-1 = 22 (23 B)
    "41 09 01 00",  # Supported Key Negotiation Methods, len-1 = 9: 01 00 ‖ EUI
    ZVD_EUI_WIRE,
    "47 04 34 12 01 CF 00",  # Fragmentation Parameters: placeholder ‖ 01 ‖ CF 00
    "4C 01 01 00",  # Device Capability Extension: 01 00
)
#: Tunnel TLV around it: tag 00, len-1 = 53, flags 0 (no NWK security), npdu_len 52.
TUNNEL_COMMISSIONING_REQUEST: Final = h("00 35", "00 34") + COMMISSIONING_REQUEST

#: synth header; payload PN §1.3 ``0F short status`` (status 0, assigned = placeholder).
COMMISSIONING_RESPONSE: Final = h(
    "09 08",  # FC: command | dst IEEE
    "34 12",  # dst = placeholder
    "1B 2A",  # src = ZDD
    "1E",  # radius
    "05",  # seq
    ZVD_EUI_WIRE,  # dst IEEE = our EUI
    "0F",  # Commissioning Response
    "34 12",  # assigned short
    "00",  # status success
)
#: synth: a response for someone else's placeholder (must not resolve our join).
COMMISSIONING_RESPONSE_OTHER: Final = h("09 00", "78 56", "1B 2A", "1E", "06", "0F 78 56 00")

# --- PN §1.4 post-join frames ----------------------------------------------------------------

#: live (probe mode): Device_annce broadcast to 0xFFFD.
DEVICE_ANNCE: Final = h(
    "48 02",  # FC: data, discover_route 1 | security
    "FD FF",  # dst 0xFFFD
    "34 12",  # src = us
    "1E",  # radius 30
    "02",  # NWK seq
    "08",  # APS FC: data, broadcast delivery
    "00",  # dst endpoint 0
    "13 00",  # cluster 0x0013 Device_annce
    "00 00",  # profile ZDO
    "00",  # src endpoint 0
    "00",  # APS counter
    "01",  # ZDO seq
    "34 12",  # NWK address
    ZVD_EUI_WIRE,  # IEEE
    "8E",  # capability
)

#: live: many-to-one Route Request (src IEEE, no discover), route id 1.
MTORR: Final = h(
    "09 12",  # FC: command, discover 0 | security, src IEEE
    "FC FF",  # dst 0xFFFC
    "34 12",  # src = us
    "1E",  # radius 30
    "03",  # NWK seq
    ZVD_EUI_WIRE,  # src IEEE
    "01 08 01 FC FF 00",  # RREQ, options 0x08 (many-to-one), rid 1, dst FFFC, cost 0
)

#: live (probe mode): Route Reply with options 0x20 and BOTH EUIs (PN §5.1), to a valve.
RREP_LIVE: Final = h(
    "49 02",  # FC: command, discover_route 1 | security
    "6F 5E",  # dst = originator (valve)
    "34 12",  # src = us
    "1E",  # radius 30
    "04",  # NWK seq
    "02",  # Route Reply
    "20",  # options 0x20 (live), although both EUIs follow
    "07",  # route id
    "6F 5E",  # originator
    "34 12",  # responder (us)
    "00",  # path cost
    VALVE_EUI_WIRE,  # originator IEEE
    ZVD_EUI_WIRE,  # responder IEEE
)
#: spec mode (spec §1.3 table): same frame, options derived = 0x30.
RREP_SPEC: Final = h(
    "49 02",
    "6F 5E",
    "34 12",
    "1E",
    "04",
    "02 30 07",  # Route Reply, options 0x30, rid 7
    "6F 5E 34 12 00",  # originator, responder, cost
    VALVE_EUI_WIRE,
    ZVD_EUI_WIRE,
)

#: synth header: RREQ from a valve for our short, option 0x20 + dst IEEE (PN §3.5, §6).
RREQ_FROM_VALVE: Final = h(
    "09 12",  # FC: command | security, src IEEE
    "FC FF",  # broadcast to routers
    "6F 5E",  # src = originator (valve)
    "1E",
    "09",
    VALVE_EUI_WIRE,  # src IEEE
    "01 20 07",  # RREQ, options 0x20 (dst IEEE present), rid 7
    "34 12 00",  # dst = us, path cost 0
    ZVD_EUI_WIRE,  # dst IEEE
)
#: synth: same RREQ without a src IEEE (originator EUI unknown unless in the neighbor table).
RREQ_NO_SRC_IEEE: Final = h(
    "09 02", "FC FF", "6F 5E", "1E", "0A", "01 20 08 34 12 00", ZVD_EUI_WIRE
)

#: live layout: ZDO unicast Mgmt_Lqi_req to the coordinator, APS counter 0 (PN §1.4, §1.5).
MGMT_LQI_REQ: Final = h(
    "48 02",  # FC: data, discover_route 1 | security
    "00 00",  # dst coordinator
    "34 12",  # src = us
    "1E",
    "05",
    "00",  # APS FC: data, unicast
    "00",  # dst endpoint 0
    "31 00",  # cluster 0x0031 Mgmt_Lqi_req
    "00 00",  # profile ZDO
    "00",  # src endpoint 0
    "00",  # APS counter (always 0 live)
    "0A",  # ZDO seq (live: 10 + page)
    "00",  # start index
)
#: synth header; payload PN §1.5: page 1 of 3, valve (end device child) + R0 (router).
MGMT_LQI_RSP: Final = h(
    "08 02",  # FC: data | security
    "34 12",  # dst = us
    "00 00",  # src = coordinator
    "1E",
    "21",
    "00 00 31 80 00 00 00 11",  # APS: unicast, ep 0, cluster 0x8031, profile 0, ep 0, ctr 0x11
    "0A",  # ZDO seq
    "00",  # status success
    "03",  # neighbor table entries
    "00",  # start index
    "02",  # count
    EXT_PAN_WIRE,  # record 1: extended PAN
    VALVE_EUI_WIRE,  # IEEE
    "6F 5E",  # short
    "12",  # end device, rx_on_when_idle 0, relationship child
    "02",  # permit joining unknown
    "01",  # depth
    "B4",  # LQI
    EXT_PAN_WIRE,  # record 2
    ZDD_EUI_WIRE,
    "1B 2A",
    "15",  # router, rx_on_when_idle 1, relationship child
    "00",  # permit joining false
    "01",
    "C8",
)

#: PN §1.5 ZDO payloads (seq ‖ body) from a valve: endpoint 1 only.
ACTIVE_EP_RSP_ZDO: Final = h("0B", "00", "6F 5E", "01", "01")
#: PN §1.5: profile 0x0104, device 0x0301, 8 in-clusters, 2 out-clusters.
SIMPLE_DESC_RSP_ZDO: Final = h(
    "0C 00 6F 5E",  # seq, status, NWK addr of interest
    "1C",  # descriptor length 28
    "01",  # endpoint
    "04 01",  # profile HA
    "01 03",  # device id 0x0301
    "00",  # device version
    "08",  # in-cluster count
    "00 00 01 00 03 00 0A 00",  # 0000 0001 0003 000A
    "20 00 01 02 04 02 05 0B",  # 0020 0201 0204 0B05
    "02",  # out-cluster count
    "00 00 19 00",  # 0000 0019
)

# --- PN §1.6 ZCL -------------------------------------------------------------------------------

_NWK_TO_VALVE = ("48 02", "6F 5E", "34 12", "1E")  # FC, dst valve, src us, radius 30
_NWK_FROM_VALVE = ("08 02", "34 12", "6F 5E", "1E")  # synth: data | security, to us
_APS_THERMOSTAT = "00 01 01 02 04 01 01"  # unicast, ep 1, cluster 0x0201, profile 0x0104, ep 1

#: live layout: Read Attributes FAST plan (0000 0008 0012 001C), TSN 0x2B, APS ctr = TSN.
ZCL_READ: Final = h(
    *_NWK_TO_VALVE,
    "06",  # NWK seq
    _APS_THERMOSTAT,
    "2B",  # APS counter (= tsn, live)
    "00",  # ZCL FC: global, client->server
    "2B",  # tsn
    "00",  # Read Attributes
    "00 00 08 00 12 00 1C 00",
)
#: live layout: manufacturer-specific read of 0x4000 with MS code 0x1221 (``04 21 12 tsn 00``).
ZCL_READ_MFR: Final = h(
    *_NWK_TO_VALVE,
    "07",
    _APS_THERMOSTAT,
    "2C",
    "04 21 12",  # ZCL FC: global, manufacturer specific; code 0x1221
    "2C",  # tsn
    "00",  # Read Attributes
    "00 40",
)
#: synth header/FC; records from PN §1.6/§4: 19.65 °C ``00 00 00 29 AD 07``, demand 2,
#: setpoint 22.00 °C, systemMode 9.
ZCL_READ_RSP: Final = h(
    *_NWK_FROM_VALVE,
    "31",
    _APS_THERMOSTAT,
    "40",  # the valve's own APS counter
    "18",  # ZCL FC: global, server->client, disable default response
    "2B",  # tsn
    "01",  # Read Attributes Response
    "00 00 00 29 AD 07",  # localTemperature: success, int16, 1965
    "08 00 00 20 02",  # piHeatingDemand: success, uint8, 2
    "12 00 00 29 98 08",  # occupiedHeatingSetpoint: success, int16, 2200
    "1C 00 00 30 09",  # systemMode: success, enum8, 9
)
#: synth: mfr read response WITH the MS header (FC 1C, code 0x1221): window_open = 1.
ZCL_READ_RSP_MFR: Final = h(
    *_NWK_FROM_VALVE, "32", _APS_THERMOSTAT, "41", "1C 21 12 2C 01", "00 40 00 30 01"
)
#: synth: the same response WITHOUT the MS header (PN §5.11: never recorded which one is live).
ZCL_READ_RSP_MFR_NO_HEADER: Final = h(
    *_NWK_FROM_VALVE, "33", _APS_THERMOSTAT, "42", "18 2C 01", "00 40 00 30 01"
)
#: live layout: Write occupiedHeatingSetpoint = 21.50 °C (``00 tsn 02 12 00 29 <int16>``).
ZCL_WRITE: Final = h(
    *_NWK_TO_VALVE,
    "08",
    _APS_THERMOSTAT,
    "2D",
    "00 2D 02",  # FC, tsn, Write Attributes
    "12 00 29 66 08",  # 0x0012, int16, 2150
)
#: synth header; payload PN §1.6 ``FC tsn 04 00`` (all succeeded).
ZCL_WRITE_RSP: Final = h(*_NWK_FROM_VALVE, "34", _APS_THERMOSTAT, "43", "18 2D 04 00")
#: synth: Default Response 0xC3 (unsupported cluster) to a Read on Groups 0x0004 (PN §5.10).
ZCL_DEFAULT_RSP: Final = h(
    *_NWK_FROM_VALVE,
    "35",
    "00 01 04 00 04 01 01",  # APS: cluster 0x0004
    "44",
    "18 2E 0B",  # FC, tsn, Default Response
    "00 C3",  # command 0x00 (Read Attributes), status 0xC3
)
#: synth: Report Attributes of localTemperature (reports were never observed live).
ZCL_REPORT: Final = h(*_NWK_FROM_VALVE, "36", _APS_THERMOSTAT, "45", "18 2F 0A", "00 00 29 AD 07")

# --- PN §3.8 quirk ---------------------------------------------------------------------------

#: synth (hypothesis PN §3.8): read response with a 1-relay source-route subframe via the ZDD.
QUIRK_SOURCE_ROUTE: Final = h(
    "08 06",  # FC: data | security, source route
    "34 12",
    "6F 5E",
    "1E",
    "37",
    "01",  # relay count
    "00",  # relay index
    "1B 2A",  # relay = ZDD
    _APS_THERMOSTAT,
    "46",
    "18 2B 01",
    "00 00 00 29 AD 07",
)
#: synth: 4 bytes before the APS header that are NOT a subframe (FC bit clear); the ZCL
#: payload then sits at NWK-payload offset 12 (the research observation, PN §3.8).
QUIRK_GARBAGE4: Final = h(
    "08 02",
    "34 12",
    "6F 5E",
    "1E",
    "38",
    "00 5A 5A 00",  # garbage
    _APS_THERMOSTAT,
    "47",
    "18 2B 01",
    "00 00 00 29 AD 07",
)

# --- Network Status (PN §5.6, spec §1.7 gating) ----------------------------------------------

#: synth header: ``03 02 <dst>`` after a unicast with discover_route 0.
NETWORK_STATUS_NO_ROUTE: Final = h("09 02", "34 12", "1B 2A", "1E", "39", "03 02 6F 5E")
#: synth: address conflict (0x0D) naming our short, broadcast.
NETWORK_STATUS_CONFLICT: Final = h("09 02", "FD FF", "1B 2A", "1E", "3A", "03 0D 34 12")

#: Every complete NPDU above, for "decodes as NWK" checks.
ALL_NPDUS: Final = {
    "COMMISSIONING_REQUEST": COMMISSIONING_REQUEST,
    "COMMISSIONING_RESPONSE": COMMISSIONING_RESPONSE,
    "COMMISSIONING_RESPONSE_OTHER": COMMISSIONING_RESPONSE_OTHER,
    "DEVICE_ANNCE": DEVICE_ANNCE,
    "MTORR": MTORR,
    "RREP_LIVE": RREP_LIVE,
    "RREP_SPEC": RREP_SPEC,
    "RREQ_FROM_VALVE": RREQ_FROM_VALVE,
    "RREQ_NO_SRC_IEEE": RREQ_NO_SRC_IEEE,
    "MGMT_LQI_REQ": MGMT_LQI_REQ,
    "MGMT_LQI_RSP": MGMT_LQI_RSP,
    "ZCL_READ": ZCL_READ,
    "ZCL_READ_MFR": ZCL_READ_MFR,
    "ZCL_READ_RSP": ZCL_READ_RSP,
    "ZCL_READ_RSP_MFR": ZCL_READ_RSP_MFR,
    "ZCL_READ_RSP_MFR_NO_HEADER": ZCL_READ_RSP_MFR_NO_HEADER,
    "ZCL_WRITE": ZCL_WRITE,
    "ZCL_WRITE_RSP": ZCL_WRITE_RSP,
    "ZCL_DEFAULT_RSP": ZCL_DEFAULT_RSP,
    "ZCL_REPORT": ZCL_REPORT,
    "QUIRK_SOURCE_ROUTE": QUIRK_SOURCE_ROUTE,
    "QUIRK_GARBAGE4": QUIRK_GARBAGE4,
    "NETWORK_STATUS_NO_ROUTE": NETWORK_STATUS_NO_ROUTE,
    "NETWORK_STATUS_CONFLICT": NETWORK_STATUS_CONFLICT,
}
