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
src/vicare_local_ble/
  valves.py              Viessmann ZK03840 mapping (only vendor-specific module; stub)
  testing.py             FakeZdd: responder side of the handshake + session crypto
  cli.py                 entry point (stub)
  zigbee_direct/         generic Zigbee Direct, no Viessmann knowledge
    crypto.py mmo.py     key derivation, SPEKE, AES-MMO, CCM session frames
    session.py           sans-IO handshake initiator + SessionCipher
    uuids.py types.py    GATT UUIDs; Eui64, SecretBytes
    errors.py            exception hierarchy
    codec/               tlv, nwk, nwk_commands, commissioning, aps, zdo, zdo_mgmt, zcl, fallback
    transport.py node.py BLE transport and virtual node (phase-2 stubs)
scripts/                 check_secrets.py, extract_npdu_fixtures.py
docs/protocol.md         protocol distillation and open questions
```

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

Python 3.14+, [uv](https://docs.astral.sh/uv/). Integration tests use
[pytest-homeassistant-custom-component](https://pypi.org/project/pytest-homeassistant-custom-component/)
(pinned to Home Assistant 2026.10.x).

```bash
uv sync
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
uv run pre-commit install                      # git hooks
uv run python scripts/check_secrets.py $(git ls-files)
```

Fixtures from saved terminal output of the research client (stdlib only, redaction is
best-effort, review the output by hand):

```bash
uv run python scripts/extract_npdu_fixtures.py capture.txt \
  --redact-eui 00:11:22:33:44:55:66:77 --redact-short 0x1234 > fixtures.jsonl
```

Test vectors that are public spec constants carry a trailing `# secret-scan: allow`. Tests use
dummy keys and EUIs only; no hardware, BLE or network.

## License

MIT. See [LICENSE](LICENSE).
