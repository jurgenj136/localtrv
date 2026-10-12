# Protocol notes: Zigbee Direct to ZK03840 valves

Distilled from live research (one installation, October 2026) and the Zigbee R23 / Zigbee Direct 1.0
(ZD) specs. Describes what `vicare_local_ble` implements. Everything marked **unverified** has not been
confirmed on hardware. No installation-specific values appear here; `<ZDD short>` etc. are
placeholders.

Conventions: multi-byte fields little-endian unless noted; `‖` = concatenation; EUI-64 appears in
wire (little-endian) order inside frames (`Eui64.wire`), conventional big-endian in text.

## 1. Architecture

```text
ZVD (our client) --BLE GATT--> ZDD (ubisys R0) --Zigbee NWK--> TC/coordinator + valves
 encrypted session frames       router, already joined          sleepy end devices (children)
```

- ZVD = Zigbee Virtual Device (us). ZDD = Zigbee Direct Device (ubisys R0, a router already
  authorised on the network). TC = Trust Center (the vendor's coordinator).
- The ZDD applies and strips NWK security on our behalf. We send and receive plaintext NPDUs; the
  tunnel flag bit0 says "secure/secured". The ZVD never holds the network key for traffic.
- The network key is needed once, offline, to derive the Basic Authorization Key (BAK, section 3).
  It is a secret input; load by parameter, never log, never commit.
- No open join window and no TC pre-registration was needed: the BAK session grants Basic
  authorization, which the TC accepted via the ZDD.
- Single BLE connection: the R0 accepts one client at a time.

## 2. GATT services

Constants in `zigbee_direct/uuids.py`.

| Service | UUID | Characteristic | Use |
|---|---|---|---|
| Security | `29144af4-0000-4481-bfe9-6d0299b429e3` | `29144af4-0001-...` Authenticate (write + indicate) | SE1-SE4 handshake |
| Tunnel | `8bd178fd-0000-45f4-8120-b2378bd5313f` | `8bd178fd-0001-...` ZDTS NPDU (write + indicate) | NPDUs in session frames |
| Commissioning | `0xFFF7` | `7072377d-000N-421c-b163-491c27333a61` | 1 Form, 2 Join, 3 Permit, 4 Leave, **5 Status (read + notify)**, 6 Manage Joiners, 7 Identify, 8 Finding and Binding |

- Only Authenticate (C25519 / SPEKE variant) is offered by the R0. 0006-0008 roles are inferred.
- Before a session is up, even reading Commissioning Status fails with GATT error `0x80`.
- Advertisement carries 16-bit service `0xFFF7`; service data holds PAN ID (LE) and the ZDD short
  (interpretation plausible, not spec-verified).

## 3. Session establishment (SPEKE)

Implemented in `crypto.py`, `mmo.py`, `session.py` (`HandshakeInitiator`).

**Primitives.** AES-MMO-128 hash (R23 Annex B.4 padding, `mmo.py`), HMAC-AES-MMO-128, X25519.
Method `0x01` = Curve25519 / AES-MMO-128.

**Pre-shared secret (PSK, 16 bytes) by `SecretType`:**

| Type | Value | PSK |
|---|---|---|
| Symmetric auth token | 0x00 | caller supplied |
| Install code link key | 0x01 | `MMO(install_code ‖ CRC16_LE)` (`install_code_to_link_key`) |
| Variable-length passcode | 0x02 | caller supplied |
| **Basic Authorization Key** | 0x03 | see below |
| Admin Authorization Key | 0x04 | caller supplied |
| Anonymous well-known | 0x05 | `"ZigBeeAlliance18"` (`WELL_KNOWN_PSK`) |

```text
BAK = HMAC-AES-MMO( MMO( zvd_eui_wire ‖ network_key ), 0x03 )     # derive_basic_authorization_key
```

`zvd_eui_wire` is our own EUI-64, little-endian. The ZVD EUI is caller supplied
(`generate_zvd_eui()`: random, locally administered, unicast); the BAK depends on it, so persist it.

**Derivation:**

```text
G  = MMO(PSK) ‖ MMO(PSK)                  # base point, 32 B (secret-equivalent)
Q  = X25519(clamp(priv), G)               # our public point
xk = X25519(clamp(priv), Q_peer)          # all-zero result -> HandshakeError
I  = (EUI,Q) of the numerically smaller EUI first ‖ (EUI,Q) of the other   # tie: responder first
s  = MMO(xk ‖ I ‖ G)
session_key = HMAC-AES-MMO(s, 0x01)
```

"Numerically smaller" = EUI-64 compared as 64-bit integers (last wire byte most significant,
`eui64_compare`). A fresh ephemeral private key is generated per handshake.

**Messages.** Handshake TLV = `tag ‖ len-1 ‖ value`. Unknown TLVs ignored; duplicates, truncation,
wrong lengths rejected.

| Msg | Dir | Bytes |
|---|---|---|
| SE1 | ZVD to ZDD (write) | `01 ‖ TLV(00, method ‖ secret_type) ‖ TLV(02, own_EUI ‖ own_Q)` |
| SE2 | ZDD to ZVD (indication) | `02 ‖ TLV(02, peer_EUI ‖ peer_Q) [‖ TLV(00, method ‖ secret_type)]` |
| SE3 | ZVD to ZDD (write) | `03 ‖ TLV(04, tag_U)` |
| SE4 | ZDD to ZVD (indication) | `04 ‖ TLV(04, tag_V)` |

SE2 is validated strictly: opcode, point TLV present with exactly 40 bytes, method/secret-type echo
matches if present, peer EUI and point differ from ours (reflection). Whether the R0 echoes the
method TLV was not observed.

**Confirmation tags (16 B):**

```text
tag_U (SE3) = HMAC-AES-MMO(session_key, "KC_2_U" ‖ resp_EUI ‖ resp_Q ‖ init_EUI ‖ init_Q)
tag_V (SE4) = HMAC-AES-MMO(session_key, "KC_2_V" ‖ resp_EUI ‖ resp_Q ‖ init_EUI ‖ init_Q)
```

Responder-first order for **both** tags (Silicon Labs convention). The Telink/NIST initiator-first
order was rejected live with GATT error `0x80`. Our SE4 check is constant-time
(`hmac.compare_digest`). Wrong PSK shows as SE3 rejection by the ZDD or SE4 mismatch.

States: `IDLE -> AWAIT_SE2 -> AWAIT_SE4 -> DONE`; any validation failure goes to terminal `FAILED`.

## 4. Session frames (AES-CCM)

After SE4, every write/indication on the Tunnel and Commissioning Status characteristics is one frame (`SessionCipher`):

```text
frame = counter_LE(4) ‖ ciphertext ‖ MIC(4)
nonce = sender_EUI_wire(8) ‖ counter_LE(4) ‖ 0x05        # 13 B, security level 5 = ENC-MIC-32
AAD   = service_uuid(16) ‖ 0x00 ‖ char_uuid(16) ‖ 0x00   # canonical big-endian UUID bytes
```

- MIC is 4 bytes. Sender EUI = our EUI outgoing, the ZDD EUI (from SE2) incoming.
- **Outgoing:** one counter for the session, starting at 1. We write only to Authenticate (before
  the session exists) and Tunnel, so our nonces are never reused.
- **Incoming:** tracked per characteristic UUID; each accepts strictly increasing counters only. A
  counter shared across characteristics is **not demonstrated live** (PN §5.9): the prototype used
  Commissioning Status only in a session with no tunnel traffic. Both ZDD behaviours (one shared
  counter, or one per characteristic) are accepted. The first hardware run must check which.
- **Residual risk (ZDD nonce reuse).** The nonce has no characteristic in it. If the ZDD runs one
  counter per characteristic under one session key, it reuses CCM nonces across characteristics.
  The different AAD does **not** prevent that: equal counters on Status and Tunnel share a keystream,
  which leaks the XOR of those plaintexts and weakens CCM authenticity for them. This would be a ZDD
  flaw we cannot fix from the client. Detection only, no rejection: `SessionCipher.counter_model()`
  reports `SHARED`, `PER_CHARACTERISTIC` or `UNKNOWN`, logged once per session and shown in
  diagnostics (spec §1.1). Follow-ups if confirmed: isolate the Status read in its own short
  session, or cache the ZDD short.
- Receive order: length check, replay check on the counter, MIC check, then the counter advances.
- Outgoing counter is burned before sealing and never rolled back or reused. At `0xFFFFFFFF` the
  cipher raises `CounterExhaustedError`; reconnect and redo the handshake.
- Frames must be written in counter order; the ZDD treats out-of-order frames as replays. A failed
  or cancelled write burns the counter.

## 5. Tunnel TLV

`codec/tlv.py`. Zigbee TLV: `tag ‖ len-1 ‖ value` (value 1..256 B). Decrypted tunnel frame contains
NPDU TLVs:

```text
00 ‖ len-1 ‖ flags(1) ‖ npdu_len(1) ‖ npdu          # value = 2 + npdu_len, so NPDU <= 254 B
flags bit0 = NWK security (ZVD to ZDD: please secure; ZDD to ZVD: was secured)
```

- Outgoing flags are `1` after joining; only the Commissioning Request goes with `0`.
- `parse_tunnel_tlvs` skips unknown tags and raises on truncated TLVs. NPDU length must match
  exactly.

## 6. Joining the network

Builders in `codec/nwk.py`, `codec/nwk_commands.py`, `codec/zdo.py`.

**NWK header** (`NwkFrame`): `FC(2) ‖ dst(2) ‖ src(2) ‖ radius ‖ seq ‖ [dst IEEE] ‖ [src IEEE] ‖
[multicast ctrl] ‖ [source-route subframe] ‖ payload`. FC byte0: bits 0-1 type, 2-5 version (2),
6-7 discover route. FC byte1: bit0 multicast, bit1 security, bit2 source route, bit3 dst IEEE,
bit4 src IEEE, bit5 end-device initiator. The aux security header is never parsed (tunnel NPDUs are
plaintext).

### 6.1 Commissioning Request (`commissioning_request_npdu`)

```text
FC byte0 0x09 (command, v2, discover_route 0)   # only 0x09 was sent live (PN §5.2)
FC byte1 0x18 (dst IEEE + src IEEE present)     # REQUIRED; src-IEEE-only frames vanish silently
dst = <ZDD short>, src = <placeholder short>, radius = 1 (spec), seq
dst IEEE = ZDD EUI, src IEEE = ZVD EUI
payload: 0E ‖ assoc_type(00 initial join) ‖ capability(8E) ‖ TLV 48 [Joiner Encapsulation:
            41 ‖ 01 00 ‖ ZVD EUI            Supported Key Negotiation Methods
            47 ‖ placeholder_short(2) 01 CF 00   Fragmentation Parameters
            4C ‖ 01 00 ]                    Device Capability Extension
```

Wire form of the payload TLV section: `48 len-1 [41 09 01 00 EUI][47 04 short_le 01 CF 00][4C 01 01 00]`
(inner `4C` value `01 00`). The ZDD forwards this as a rejoin; the TC answers. All three pitfalls
(both IEEEs, the TLV context, radius 1) produced silent failure when missed. The research handover
claims 0x49 "also works", but no 0x49 send exists in the prototype code: only FC `0x09` is proven;
the library default is `discover_route=0` (PN §5.2). ZDD short and EUI come
from Commissioning Status / SE2; the placeholder short is caller supplied (no default).

### 6.2 Commissioning Response (`CommissioningResponse.decode`)

`0F ‖ short(2) ‖ status(1) ‖ TLVs`. Status `0x00` = success. The TC-assigned short is the truth
(research: it kept the requested placeholder).

### 6.3 Announce and routing (mandatory after the response)

Without these, no return traffic arrives from the valves.

1. **Device_annce** (ZDO cluster `0x0013`) as broadcast to `0xFFFD`: short, IEEE, capability.
2. **Many-to-one Route Request**, 1-2 times: NWK command `01`, options `0x08`, route id, dst
   `0xFFFC`, path cost 0, with src IEEE in the NWK header. Routers then create a route entry back to
   us. Why: valves reply through their parent; without a route to our short the unicast reply is
   dropped (Telink reference behaviour, confirmed live).
   Bytes: `01 08 <id> FC FF 00` (`many_to_one_route_request`).
3. **Unicast data frames use `discover_route = 1`** (FC byte0 `0x48`). Suppress (`0`) produced
   Network Status `0x02`.

### 6.4 Answering Route Requests

Devices without a route to us send Route Request (`01`) targeting our short; the ZDD relays it in
the tunnel as a broadcast. Nobody else answers, so we must send a Route Reply
(`RouteReply`): `02 ‖ options ‖ route_id ‖ originator(2) ‖ responder(2) ‖ path_cost ‖ [orig IEEE] ‖
[resp IEEE]`. Answer each `(originator, route_id)` once (valves retransmit; duplicates pile up BLE
writes).

Options are derived from present fields (R23 3.4.2.3.1): bit4 `0x10` originator IEEE, bit5 `0x20`
responder IEEE, bit6 multicast. Both EUIs gives **0x30**. The research client sent **0x20** with both
EUIs appended and that worked live. By spec 0x20 means "responder IEEE only", so the live frame
carried 8 extra bytes. 0x30 is spec-correct but **unverified live** (PN §5.1).

- **Default is the live mode:** `RouteReply.options_override=0x20` with both EUIs, NWK FC `49 02`
  (`discover_route=1`), payload `02 20 rid <orig> <own> 00 EUI_orig EUI_own`. 0x30 is opt-in, to be
  tested on hardware.
- **Benefit of answering is unproven:** the prototype sent RREPs only in probe mode; write-test,
  attrs, rooms and schedule never answered RREQs and still got responses after the many-to-one
  Route Request (PN §5.1).

NWK: src = our short, dst = originator, command frame, radius 30.

### 6.5 Commissioning Status (`CommissioningStatus.decode`)

Read after the session is up (decrypted value is a TLV list):

| Tag | Meaning | Len |
|---|---|---|
| 0x00 | Extended PAN ID | 8 |
| 0x01 | PAN ID | 2 |
| 0x02 | Network channel (kept raw) | var |
| **0x03** | Network key | 16 |
| **0x04** | Link key (flags ‖ key) | 17 |
| 0x05 | Device type | 1 |
| 0x06 | NWK (short) address | 2 |
| 0x07 | Joining method | 1 |
| 0x08 | ZDD IEEE | 8 |
| 0x09 | Trust Center address | 8 |
| 0x0A | Network status map | 1 |
| 0x0B | NWK update id | 1 |
| 0x0C | Active key sequence | 1 |
| **0x0D** | Admin key | 16 |
| 0x0E | Status code | 2 |

Bold tags carry key material: decoded into `SecretBytes`, never log them. Unknown tags are kept raw.
Research guessed 0x00 as TC EUI and 0x09 as extended PAN ID; the codec follows the ZD tag table
instead (0x00 extended PAN, 0x09 TC address). Confirmed: TLV 0x09 reversed equals exactly the
coordinator EUI found as the binding destination on every valve (PN §5.3), so the table is correct
and the research "TC EUI" label is really the extended PAN ID. The values seen live (PAN, ZDD short, ZDD EUI) matched
independent sources; the rest was never cross-checked.

## 7. Discovery

Valves are **sleepy end devices**: they miss broadcasts (`Match_Desc_req` to `0xFFFD` finds nothing).
Working sequence:

1. `Mgmt_Lqi_req` (ZDO `0x0031`: `seq ‖ start_index`) unicast to the coordinator (`0x0000`). The
   response (`0x8031`) lists neighbours as 22-byte records: `ext PAN(8) ‖ IEEE(8) ‖ short(2) ‖
   flags(1: type 2b, rx_on 2b, relationship 3b) ‖ permit_joining(1) ‖ depth ‖ LQI`. Valves appear as
   children of the coordinator. `rx_on_when_idle` and `permit_joining` are tri-state
   (`True`/`False`/`None` = unknown). Page through with `start_index`.
2. `Active_EP_req` (`0x0005`) per valve, unicast.
3. `Simple_Desc_req` (`0x0004`) per endpoint; confirms Thermostat cluster `0x0201`.

Responses take about 2-30 s (parent buffers until the child polls). Send requests in parallel and
collect. Addresses: key on EUI-64, resolve shorts at runtime; shorts change after re-pairing.

## 8. Incoming frame quirk

Research saw frames indicated by the ZDD where the ZDO/ZCL payload sat 12 bytes into the NWK payload
instead of the expected 8 (extra bytes, apparently including a 4-byte counter), so a standard APS
parse failed.

- **Hypothesis (unverified):** the extra 4 bytes are a 1-relay NWK source-route subframe
  (`relay_count=1, relay_index, relay(2)` = 4 B). `NwkFrame` now parses the subframe, so the
  standard APS decode may simply work. Confirm with real fixtures
  (`scripts/extract_npdu_fixtures.py`) before removing the fallback.
- **Root fact:** the NWK payload handed to the fallback starts with the real APS frame control at
  offset 0 (`NwkFrame` strips multicast/source-route subframes; no other prefix exists).
- **Fallback decoder** (`codec/fallback.py`, `scan_for_response`). Source short must match, then:
  1. Strict APS decode at offset 0, checked against the expected header (ZDO: profile 0, response
     cluster, dst endpoint 0; ZCL: cluster if given) and payload. Match has `offset=None`,
     `cluster_verified=True`.
  2. Otherwise classify only the offset-0 frame control. Non-data frame, reserved delivery mode
     `0b01`, APS security or extended header (fragmentation) → refused with a reason (payload may
     be ciphertext or a fragment), unless `allow_unsupported_aps=True`; such matches carry
     `aps_unsupported=True`. The opt-in exists because research `tools/zvd_tunnel.py:348-387` had
     a secured-APS path and handover §6 mentions a 4-byte frame counter (hypothesis; verify with
     phase-2 fixtures).
  3. Scan every offset 8..17 as a bare ZDO payload or ZCL frame, validated strictly against the
     expected kind (ZDO seq; ZCL tsn/command/manufacturer code; exact decode). The payload offset
     already judged by a well-formed step-1 decode is skipped. Nothing else is inferred from bytes
     before a candidate (no speculative header recovery).
  4. Several offsets validating to different results → ambiguous → failure with a reason.
- **Cluster not verifiable in scan mode:** the APS header bytes are what the quirk garbles, so scan
  matches have `cluster_verified=False`. Headerless `Active_EP_rsp` and `Simple_Desc_rsp` are
  indistinguishable; the caller must state which kind it expects for that seq.
- **Residual risk:** behind a plain unsecured data frame control, a crafted or garbled frame may
  yield a false match. Mitigation: correlation on (src_short, seq/tsn, command, exact length). The
  definitive fix is an explicit, fixture-backed quirk-layout decoder in phase 2 replacing the scan.
- **Trailing bytes:** `max_trailing=0` tolerates none. With `max_trailing>=4`, each candidate is
  retried with exactly 4 bytes (presumed MIC-32) trimmed after the exact decode fails. No capture
  proves those bytes are a MIC, and trimming can turn a malformed response into a success, so enable
  it only for a capture-backed quirk.
- `ScanMatch.aps` is excluded from the repr (its raw payload may hold a KEY128).

## 9. ZCL to the valves

**APS data frame** (`ApsDataFrame`), unicast, endpoint 1, profile `0x0104`, cluster `0x0201`:

```text
FC(0x00) ‖ dst_ep ‖ cluster(2) ‖ profile(2) ‖ src_ep ‖ aps_counter ‖ ZCL
FC bits: 0-1 type, 2-3 delivery (00 unicast, 10 broadcast, 11 group; 01 reserved), 4 ack format,
         5 security, 6 ack request, 7 extended header
```

Group delivery carries `group_addr(2)` instead of `dst_ep`. Only unsecured, unfragmented DATA frames
decode; ACK/command frames, APS-secured and extended-header frames raise `UnsupportedFrameError`.

**ZCL frame:** `FC ‖ [manufacturer code(2)] ‖ tsn ‖ cmd ‖ payload` (FC: bits 0-1 type, bit2
manufacturer specific, bit3 direction, bit4 disable default response). NWK around it: data frame,
FC byte0 `0x48`, radius 30, tunnel flags `0x01`.

| Command | Id | Payload |
|---|---|---|
| Read Attributes | 0x00 | `attr_id(2)` list |
| Read Attributes Response | 0x01 | per attr `id(2) ‖ status ‖ [type ‖ value]` (value only if status 0) |
| Write Attributes | 0x02 | per attr `id(2) ‖ type ‖ value` |
| Write Attributes Response | 0x04 | single `00` = all succeeded, else `(status, id)` list; empty is an error |
| Report Attributes | 0x0A | per attr `id(2) ‖ type ‖ value` |
| Default Response | 0x0B | `cmd ‖ status` |

Type table (`zcl_types.py`): nodata, data/bitmap 8-64, bool, uint/int 8-64, enum8/16, semi/single/
double floats, octet/char strings (1- or 2-byte length, 0xFF/0xFFFF = invalid, decoded to `None`),
UTC, cluster id, attribute id, EUI-64, key128. Unknown type code or truncated record raises
`ZclDecodeError`.

**ZK03840 Thermostat (0x0201), endpoint 1** (`valves.py`, the only Viessmann-specific module):

Full v1 map (PN §4). All five valves had identical cluster and attribute lists and every read
succeeded; reads were done 4 attributes per request (6+ never tried).

| Cluster/attr | Name | Type | Scaling / value seen | v1 |
|---|---|---|---|---|
| 0201/0000 | localTemperature | int16 0x29 | 0.01 C | read |
| 0201/0008 | piHeatingDemand | uint8 0x20 | **0-5 scale, not %** (2 or 5 seen) | read raw |
| 0201/0012 | occupiedHeatingSetpoint | int16 0x29 | 0.01 C; write proven, persists | read/write |
| 0201/0003, 0004 | absMin/absMaxHeatSetpointLimit | int16 | 800 / 3000 | read once |
| 0201/0015, 0016 | min/maxHeatSetpointLimit | int16 | 800 / 3000; writable per z2m, untested | read; clamp writes |
| 0201/001B | controlSequenceOfOperation | enum8 0x30 | 2 (heating only) | optional |
| 0201/001C | systemMode | enum8 0x30 | **9 = sleep** on all valves while they regulate; do not map to "off" | read |
| 0201/4000 mfr 0x1221 | window_open (internal) | enum8 0x30 | 1 everywhere; z2m: 3 = open/no heat, 4 = open/heat; 1 = closed is a **hypothesis** | raw/diagnostic only |
| 0201/4003, 4012, 4007 mfr | window_open_force / assembly_mode / unknown | bool 0x10 | 0 | do not write 4012 |
| 0201/4008 mfr | unknown | uint16 0x21 | 80-891, varies by valve | ignore |
| 0001/0021 | batteryPercentageRemaining | uint8 | **0.5 % units** (126 = 63 %) | read |
| 0204/0001 | keypadLockout | enum8 | 0 | optional |
| 0B05/011C, 011D | lastMessageLQI / lastMessageRSSI | uint8 / int8 0x28 | 116-212 / -71..-47 (link to parent) | diagnostic |
| 0020/0000, 0001 | check-in / long poll interval | uint32, quarter-seconds | 1200 = 300 s / 28 = 7 s | read-only, never write |

- Mfr attributes need their own request with the ZCL MS bit and code `0x1221`; they cannot be mixed
  with standard attrs in one frame.
- `localTemperatureCalibration` 0x0010 was **not** in the discovered attribute list: unsupported.
- Basic 0x0000: manufacturerName 0x0004 = "Viessmann", modelId 0x0005 = "7637434", powerSource
  0x0007 = 3 (battery), swBuildId 0x4000 = "01.18.0008 02.06", dateCode 0x0006 = "20230613". Valve
  EUI OUI `14:2D:41`; match on modelId + manufacturer, not OUI alone.
- Do not touch: Time 0x000A, Poll Control 0x0020, Identify, OTA.

Live write test: setpoint changed, read back, still held after 90 s (the vendor controller did not
revert it), then restored. A write is a manual override on a real heating system.
Other clusters seen on the endpoint: 0x0000, 0x0001, 0x0003, 0x000A, 0x0020, 0x0204, 0x0B05. Device
id `0x0301`.

**Override evidence (2 h).** On 2026-10-11 research wrote a setpoint over Zigbee Direct (19.0 to
23.0 C, read back 23.00). Within minutes the ViCare app showed the room as "manually set, for
2 hours" (spec §2.5). So a Zigbee Direct write behaves like turning the valve wheel: the valve
reports at its check-in (<= 300 s) to the OPTO2, which syncs to the cloud. The 2 h duration is
OPTO2/cloud logic, not a valve feature (the thermostat cluster has no hold or duration attribute).
After 2 h or at the next schedule transition the OPTO2 pushes the schedule setpoint again; last
writer wins. The manual state cannot be cancelled over Zigbee, only in the app or by expiry.

## 10. Fixes versus the research code

- **AES-MMO padding**: research was wrong for lengths 12/13 mod 16 and for inputs >= 8192 B. Now R23
  B.4 (16-bit length form below 2^16 bits, 32-bit form plus `0000` above).
- **Confirmation tag**: only the proven responder-first order; other variants dropped; SE4 compare is
  constant-time.
- **Route Reply options**: derived from present fields (0x30 with both EUIs) by default in the
  codec; the node uses the live 0x20 via `options_override`. 0x30 unverified live (section 6.4).
- **TLV parsing**: unknown tags skipped, truncation is an error, NPDU length checked, NPDU <= 254 B.
- **ZCL**: full type table; unknown types and truncated records raise instead of being swallowed;
  Report Attributes and Default Response parsers added; full frame control.
- **Offset scan**: tests all offsets 8..17 and rejects ambiguity (research mostly tested one);
  validates source, kind and seq.
- **APS**: real frame control parsing; no fake "aux header + MIC" skip; secured/fragmented frames
  refused, never treated as plaintext.
- **Mgmt_Lqi**: `rx_on_when_idle` tri-state; ext PAN, permit-join, depth, LQI kept; neighbour counts
  checked.
- **SE2** is validated strictly (opcode, point TLV length, echo, reflection, all-zero/low-order
  X25519 results rejected).
- **Counters**: length and replay checks before MIC; counter updates only after MIC passes; outgoing
  counter never reused or wrapped.
- **No hardcoded addresses**: no default placeholder short, no fixed ZDD short or EUI. The research
  incremented the counter before an awaited write (out-of-order frames, rejected as replays); the
  phase-2 transport serialises counter, encrypt, and write.

## 11. Phase 2 design constraints

From the `transport.py` and `node.py` stubs (not implemented):

- `ZigbeeDirectTransport` wraps a caller-owned, already connected `BleakClient`; the library never
  scans or connects (HA supplies the client, possibly through an ESPHome proxy).
- One critical section per send: allocate counter, encrypt, await GATT write (single `asyncio.Lock`
  or writer task). Ingress is ordered; replay/MIC failures surface as errors.
- Futures, locks and queues are created lazily inside the running loop.
- Respect the negotiated ATT MTU; never assume 247 B.
- `ZigbeeDirectNode`: join flow = session, Commissioning Request, Device_annce, many-to-one Route
  Request, answer Route Requests (dedupe per `(originator, route_id)` with TTL, any originator).
- One NWK sequence, ZDO sequence, ZCL TSN and APS counter allocator, owned by the node.
- Pending requests keyed by `(src_short, kind, seq)`; request timeout 30 s per attempt, 2 attempts (sleepy range 2-30 s;
  prototype used 10-15 s plus one retry, PN §5.8).
- Own short: random valid address avoiding known shorts; the short in the Commissioning Response
  is authoritative and may be persisted for the next join.
- Persistent connection preferred; start with passive change detection (listen for reports) before
  active polling, to spare the battery-powered valves.
- Test helper: `vicare_local_ble.testing.FakeZdd` (responder side of SE1-SE4 plus session crypto);
  phase 2 adds a scripted NWK/ZCL peer.

## 12. Open questions

1. **Membership aging.** No link status or keepalive is sent today. Does the TC/routers age out the
   virtual device over long sessions? The research joined fresh each run (about 2 s).
2. **R0 reboot.** Behaviour of the session, join and routes after the ZDD restarts is unknown.
3. **BLE message size via an ESPHome proxy.** MTU is negotiated per device (ATT payload = MTU - 3).
   Plan: keep writes at most about 240 B, or read bleak's `mtu_size`, and fail clearly if a frame
   does not fit. Session frame overhead is 8 B plus the tunnel TLV header (4 B).
4. **Valve count.** Research found 5 valves via the coordinator's LQI table; the claim that the
   vendor app lists 8 eTRVs is **unsupported**: no research doc shows more than 5 (PN §5.4). The
   prototype only paged the coordinator and R0 tables; valves hanging off other routers would need
   discovery to walk router neighbour tables.
5. **Route Reply options** 0x20 (research, worked; node default) vs 0x30 (spec). Verify live, and
   whether answering Route Requests helps at all.
6. **Source-route hypothesis** for the 4 extra bytes (section 8). Collect fixtures and decide
   whether the fallback decoder can go.
7. **SE2 contents.** Whether the method/secret-type TLV is echoed, and any further TLVs.
8. **Commissioning Status channel TLV (0x02) layout.** The decoder assumes `count ‖ count x 4-byte
   mask` (page in bits 27-31); unverified live. Also the semantics of 0x0A-0x0C as seen on the R0.
9. **Passive updates.** Do the valves already report to the coordinator, and does the R0 forward
   those frames into the tunnel? If yes, change detection needs no polling.
10. **Counters beyond 2^32 frames.** Handled by forced reconnect; behaviour of long-lived sessions
    near the limit is untested (practically unreachable).
11. **Single BLE connection.** The R0 allows one client; a second client (including the vendor app)
    blocks or kicks the first. Coordination with other users is up to the integration.
12. **Short-address collisions.** Whether the TC honours a requested short in all cases, or may
    reassign it on rejoin.
