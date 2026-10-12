# vicare-local-ble

Local, cloud-free control of Viessmann ViCare radiator valves (ZK03840) over Bluetooth, through a ubisys R0 Zigbee Direct bridge. Talks Zigbee Direct over Bluetooth LE through a ubisys R0 that is already on the valves' Zigbee network. (Formerly "vicare-direct".)

## Status

**Pre-alpha. No hardware validation yet.**

- Phase 1, done: offline protocol library. AES-MMO, SPEKE session, session-frame crypto,
  TLV/NWK/APS/ZDO/ZCL codecs, commissioning and route-reply builders, offset-scan fallback decoder,
  `FakeZdd` test helper. Tested against spec vectors and fakes.
- Phase 2, in progress ([docs/spec-phase2-ha.md](docs/spec-phase2-ha.md)): runtime (BLE transport,
  node/join flow, valve API) and a HACS Home Assistant integration "ViCare Local (Bluetooth via
  ubisys R0)" (domain `vicare_local_ble`), using HA's Bluetooth stack or an ESPHome Bluetooth proxy.
  Verified against a simulator only.
- Later: CLI / MQTT bridge.

Protocol details: [docs/protocol.md](docs/protocol.md).

## Architecture

```text
 you (CLI / HA)                       ubisys R0 (ZDD)            Zigbee network
+---------------+   BLE GATT      +----------------+   NWK   +------------------+
| vicare-local-ble | --------------> | Zigbee Direct  | ------> | coordinator (TC) |
| = ZVD         | <-------------- | router         | <------ | ZK03840 valves   |
+---------------+  AES-CCM frames +----------------+         +------------------+
   plaintext NPDUs in the session; the R0 applies NWK security for us
```

The network key is used once, offline, to derive the Basic Authorization Key for the BLE session.

## Package layout

```text
src/vicare_local_ble/                  library (PyPI: vicare-local-ble)
  valves/                Viessmann ZK03840 mapping (only vendor-specific package)
  bridge*.py             ViCareBridge: discovery, polling, setpoint transactions, cache
  testing/               simulator: fake R0 (GATT + session crypto), fake network and valves
  cli.py                 entry point (stub)
  zigbee_direct/         generic Zigbee Direct, no Viessmann knowledge
    crypto.py mmo.py     key derivation, SPEKE, AES-MMO, CCM session frames
    session.py           sans-IO handshake initiator + SessionCipher
    transport*.py        BLE GATT transport (bleak)
    connection*.py       supervised connection: backoff, rejoin, repair issues
    node*.py routing.py  virtual Zigbee node: join, requests, route replies
    debug.py redact.py   NPDU debug logging with redaction
    codec/               tlv, nwk, aps, zdo, zcl, commissioning, fallback
custom_components/vicare_local_ble/    Home Assistant integration (HACS)
scripts/                 check_secrets.py, extract_npdu_fixtures.py
docs/                    protocol.md, spec-phase2-ha.md, release.md
```

## Home Assistant integration

"ViCare Local (Bluetooth via ubisys R0)", domain `vicare_local_ble`. Local push-style integration
(`iot_class: local_push`): joins the valves' Zigbee network as a virtual node through the R0,
polls the valves, exposes each as a climate entity. No cloud.

### Requirements

- Home Assistant 2026.10.0 or newer.
- A ubisys R0 already on the valves' Zigbee network.
- A Bluetooth adapter in or reachable from HA, or an ESPHome Bluetooth proxy.
- The Zigbee network key (32 hex characters). Required; how you obtain it is out of scope here.
  It is stored in the config entry (HA's `.storage`). Treat backups accordingly.

### Install

HACS: Integrations, menu, Custom repositories, add this repository URL, category Integration.
Install "ViCare Local (Bluetooth via ubisys R0)", restart HA.

Manual: copy `custom_components/vicare_local_ble/` into `<config>/custom_components/`, restart HA.
HA installs the pinned library (`vicare-local-ble==<version>`) from PyPI on start. Until the first
PyPI release exists, pre-release installs cannot resolve that pin.

### Setup

1. **Close the ViCare app.** The R0 accepts one Bluetooth client.
2. If HA discovers an R0 (service `0xFFF7`, name `ubisys*`), accept it under Settings, Devices.
   Otherwise: Add Integration, "ViCare Local", pick the R0 from the list of connectable devices
   (service `0xFFF7` or a name starting with `ubisys`).
3. Enter the network key. It must be 32 hex characters. Leave "Test the connection" on.

Validate: connects to the R0, runs the Zigbee Direct handshake and the join, within 60 s. Nothing is
written to the valves.

| Result | Meaning |
|---|---|
| `invalid_auth` | R0 rejected the key |
| `cannot_connect` | no connection or timeout. Close the ViCare app, move adapter/proxy closer |

Untick "Test the connection" to save without checking. If the R0 later rejects the key, HA starts a
reauth flow for a new key.

### ESPHome Bluetooth proxy

- Dedicate a proxy connection slot to the R0. It holds the connection permanently.
- ESPHome config: `bluetooth_proxy: active: true`. Active connections are required.
- The R0 needs an ATT MTU large enough for Zigbee Direct frames, and GATT long writes. Some
  adapters or proxies do not provide them. The integration does not refuse; it raises a repair
  issue instead:
  - `mtu_too_small` (Bluetooth MTU too small): some replies may be lost.
  - `long_write_unsupported` (long GATT writes unsupported): large frames fail.
  Fix: use another adapter or proxy. The `mtu=` INFO line in the debug log shows the MTU.

### Entities

Per valve (device "ZK03840", via the R0 bridge device):

| Platform | Entity | Notes |
|---|---|---|
| climate | thermostat (name = device) | HVAC mode `heat` only, target temperature, 0.5 °C step, limits from the valve. No `hvac_action` |
| sensor | Battery | %, diagnostic |
| sensor | Heating demand | raw 0-5, no unit |
| sensor | Link quality | LQI to the valve's parent. Diagnostic, disabled by default |
| sensor | Signal strength | dBm. Diagnostic, disabled by default |
| binary_sensor | Window open (experimental) | disabled by default. Raw value is in diagnostics |

Per R0 (bridge device):

| Platform | Entity | Notes |
|---|---|---|
| binary_sensor | Connection | connectivity, diagnostic, on when the session is ready |
| sensor | Connection state | idle, connecting, joining, ready, backoff, auth_failed, stopped. Diagnostic |

A valve is unavailable after 3 consecutive missed polls. Valves already seen are cached and appear
immediately after a restart.

### Options

Settings, Devices, ViCare Local, Configure.

| Option | Range | Default |
|---|---|---|
| Poll interval (`scan_interval`) | 60-3600 s | 300 s |
| Route reply mode (`route_reply_mode`), under Advanced | `live`, `spec`, `off` | `live` |

Valves are battery powered and answer slowly; do not poll faster than needed. Push updates (valve
reports, connection state) do not reset the poll schedule. Leave route reply mode on `live` unless
asked to change it. Changing options reloads the entry.

### Setpoint semantics

- `climate.set_temperature` returns at the valve's acknowledgement, up to about 60 s (a sleepy
  valve answers in 2-30 s per attempt). The UI shows the requested value meanwhile.
- A confirming read runs in the background and updates the state. The service call does not wait
  for it.
- No acknowledgement: the request is reverted and the call fails with "did not acknowledge".
- A write is a manual override, same as turning the valve wheel. Observed 2026-10-11: after a
  write over Zigbee Direct (19.0 to 23.0 °C, read back 23.00), the ViCare app showed the room as
  "manually set, for 2 hours".
  - The 2 h is gateway/cloud logic (OPTO2), not a valve feature. The thermostat cluster has no
    hold or duration attribute.
  - After 2 h, or at the next schedule transition, the schedule setpoint is pushed again. Last
    writer wins.
  - The manual state cannot be cancelled over Zigbee, only in the ViCare app or by expiry.
  - The valve reports the change at its next check-in (up to about 5 min).

### Debug logging and diagnostics

```yaml
logger:
  logs:
    vicare_local_ble: debug
```

- NPDU frames are logged as JSON lines (logger `vicare_local_ble`). Redaction: keys are never
  logged (`SecretBytes` prints `<redacted>`); EUIs are scrubbed; frames that may carry key material
  are logged header-only or suppressed; undecodable frames are not logged raw.
- Turn saved HA log lines into test fixtures (review the output by hand):

  ```bash
  uv run python scripts/extract_npdu_fixtures.py --from-ha-log home-assistant.log > fixtures.jsonl
  ```

- Diagnostics: Settings, Devices, ViCare Local, Download diagnostics. Built from an explicit
  allowlist: option values, "has key" booleans, connection counters (state, MTU, replay drops, MIC
  failures), join and topology summary, per-valve model/limits/state, redacted NPDU ring buffer. No
  keys; EUIs and the Bluetooth address are excluded or pseudonymised.

### Hardware validation checklist

Not yet done. Spec [§5](docs/spec-phase2-ha.md#5-hardware-validation-checklist-first-session-with-the-r0)
has the full list. In short, in order:

1. Advertisement: name and `0xFFF7` together, scan-response name, service data.
2. MTU: local adapter and ESP32 proxy; long write of 48 B; truncated Mgmt_Lqi.
3. Handshake: SE2 TLVs, SE4; exact exception for a wrong key.
4. Counter model: per characteristic or shared (nonce reuse risk).
5. Join: response within 2 s, assigned short equals requested.
6. RREQ/RREP: one hour each in `live`, `spec`, `off`; compare timeouts.
7. Quirk: FC byte1 bit 0x04, `fallback_hits` = 0; save 20+ redacted NPDUs as fixtures.
8. Topology: valve count, valves behind routers, `complete` flag.
9. Latency: per-valve distribution, timeouts per 100 requests, `late_drops`.
10. Manufacturer read: header present, raw window values with a window open.
11. Reports: any report events over 24 h.
12. Write: ack and confirm times; reconfirm "manually set, for 2 hours".
13. Longevity: 24 h of MIC failures, replay drops, rejoins, availability.
14. Back-to-back ZDO requests to one device all answered.
15. Recovery: R0 power cycle and proxy reboot, time to ready.

## Safety

- **Secrets.** The Zigbee network key is required to derive the session key. Pass it as a parameter
  only. Never commit it or captures (`.gitignore` excludes `.viessmann-local/`). Key material is
  wrapped in `SecretBytes`; `repr` and `str` print `<redacted>`. Commissioning Status can carry
  network, link and admin keys: treat decoded frames accordingly.
- **Writes change a real heating system.** A setpoint write acts as a manual override. Read before
  writing, change one valve at a time, restore afterwards.
- **One BLE client at a time.** The R0 accepts a single connection. Close the vendor app or other
  clients first.
- **Mind the counter.** A failed write burns a session frame counter; reconnect with a new
  handshake rather than reusing a session in doubt.

## Disclaimer

Not affiliated with or endorsed by Viessmann or ubisys. ViCare is a trademark of Viessmann.
Reverse-engineered from a single installation and public specs (Zigbee R23, Zigbee Direct 1.0).
Use at your own risk; no warranty.

## Development

Python 3.14.2+, [uv](https://docs.astral.sh/uv/). Integration tests use
[pytest-homeassistant-custom-component](https://pypi.org/project/pytest-homeassistant-custom-component/)
(PHACC, pinned to Home Assistant 2026.10.x). No hardware, BLE or network in tests: the library
ships a simulator (`vicare_local_ble.testing`: fake R0, network and valves) that the tests drive.

```bash
uv sync
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
uv run pre-commit install                      # git hooks
uv run python scripts/check_secrets.py $(git ls-files)
```

Run HA locally against the working tree (`.ha-config/` is gitignored):

```bash
mkdir -p .ha-config/custom_components
ln -s "$PWD/custom_components/vicare_local_ble" .ha-config/custom_components/vicare_local_ble
uv run hass -c .ha-config --skip-pip-packages vicare-local-ble
```

Fixtures from saved terminal output of the research client (stdlib only, redaction is
best-effort, review the output by hand):

```bash
uv run python scripts/extract_npdu_fixtures.py capture.txt \
  --redact-eui 00:11:22:33:44:55:66:77 --redact-short 0x1234 > fixtures.jsonl
```

Test vectors that are public spec constants carry a trailing `# secret-scan: allow`. Tests use
dummy keys and EUIs only; no hardware, BLE or network.

## Release

Details and dry run: [docs/release.md](docs/release.md).

- Version lockstep: `pyproject.toml` `version`, `manifest.json` `version`, and the manifest pin
  `requirements: ["vicare-local-ble==X.Y.Z"]` must be identical.
- Tag `vX.Y.Z` triggers `.github/workflows/release.yml`: verify versions against the tag, run the
  gate (ruff, mypy, pytest), `uv build`, publish to PyPI via trusted publishing, create the GitHub
  release. PEP 440 pre-releases (`a`, `b`, `rc`, `.dev` suffixes) become GitHub prereleases.
- The first PyPI publish needs the owner's go-ahead and a PyPI trusted-publisher setup
  (project `vicare-local-ble`, this repo, workflow `release.yml`, environment `pypi`).

## License

MIT. See [LICENSE](LICENSE).
