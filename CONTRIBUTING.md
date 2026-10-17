# Contributing

Thanks for helping. This file covers the development setup, the rules every change follows, and
the code layout. User documentation lives in the [README](README.md).

## Ground rules

- **Never post a network key**, a Commissioning Status dump, or a raw capture in an issue, PR,
  commit or log. If you shared one by accident, tell us at once so we can delete it.
- **No hardware, BLE or network in tests.** The library ships a simulator
  (`localtrv.testing`: fake R0, fake network and valves) that the tests drive.
- **Dummy keys and EUIs only.** Public spec test vectors are fine; put `# secret-scan: allow` on
  the same line. `scripts/check_secrets.py` fails on anything else that looks like key material.
- Key material is wrapped in `SecretBytes` (`repr` and `str` print `<redacted>`). Never log it.
- [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat|fix|refactor|build|ci|chore|docs|style|perf|test`), small commits.
- Files under about 500 lines. mypy strict, fully typed, no module-level mutable state.
- Library and simulator code use the injected `zigbee_direct.clock.Clock`. Never call
  `asyncio.sleep`, `asyncio.timeout` or `loop.call_later` directly. Tests use `VirtualClock`.
- Add a regression test with every bug fix when it fits.

## Development setup

Python 3.14.2+ and [uv](https://docs.astral.sh/uv/). Integration tests use
[pytest-homeassistant-custom-component](https://pypi.org/project/pytest-homeassistant-custom-component/),
pinned to Home Assistant 2026.10.x.

```bash
uv sync
uv run pre-commit install        # git hooks: ruff, mypy, secret check
```

## Gate

Run before every PR (CI runs the same, plus hassfest and the HACS action):

```bash
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
git ls-files -z | xargs -0 uv run python scripts/check_secrets.py
```

Or the hooks at once: `uv run pre-commit run --all-files` (ruff, mypy, secret check). It does not
run the tests; run `uv run pytest` as well.

## Run Home Assistant locally

Runs HA against the working tree. `.ha-config/` is gitignored.

```bash
mkdir -p .ha-config/custom_components
ln -s "$PWD/custom_components/localtrv" .ha-config/custom_components/localtrv
uv run hass -c .ha-config --skip-pip-packages localtrv
```

## Test fixtures from logs

`scripts/extract_npdu_fixtures.py` turns logged frames into JSON-lines fixtures. Redaction is
best-effort: review the output by hand before committing it.

From a Home Assistant log with debug logging on:

```bash
uv run python scripts/extract_npdu_fixtures.py --from-ha-log home-assistant.log > fixtures.jsonl
```

From other saved terminal output with NPDU lines:

```bash
uv run python scripts/extract_npdu_fixtures.py capture.txt \
  --redact-eui 00:11:22:33:44:55:66:77 --redact-short 0x1234 > fixtures.jsonl
```

## Architecture

```text
 Home Assistant / CLI               ubisys R0 (ZDD)            Zigbee network
+--------------------+  BLE GATT   +----------------+   NWK   +------------------+
| LocalTRV           | ----------> | Zigbee Direct  | ------> | coordinator (TC) |
| (ZVD)              | <---------- | router         | <------ | ZK03840 valves   |
+--------------------+  AES-CCM    +----------------+         +------------------+
   plaintext NPDUs inside the session; the R0 applies NWK security
```

The network key is used offline to derive the Basic Authorization Key for the BLE session.
Protocol details: [docs/protocol.md](docs/protocol.md).

Layering: `zigbee_direct` holds no Viessmann constants. `bridge.py` orchestrates but takes every
cluster, attribute, scale, sentinel and model id from the `valves` package. `testing/valve.py` may
hold simulator fixture data written independently of `valves`. Codec frames are
`@dataclass(frozen=True, slots=True)` with `encode()` and `decode()`: pure, no I/O.

## Package layout

```text
src/localtrv/            library (PyPI: localtrv)
  valves/                Viessmann ZK03840 mapping (the only vendor-specific package)
  bridge*.py             ViCareBridge: discovery, polling, setpoint transactions, cache
  testing/               simulator: fake R0 (GATT + session crypto), fake network and valves
  cli.py                 `scan` / `status` CLI (key from env or file only)
  zigbee_direct/         generic Zigbee Direct, no Viessmann knowledge
    crypto.py mmo.py     key derivation, SPEKE, AES-MMO, CCM session frames
    session.py           sans-IO handshake initiator + SessionCipher
    transport*.py        BLE GATT transport (bleak)
    connection*.py       supervised connection: backoff, rejoin, repair issues
    node*.py routing.py  virtual Zigbee node: join, requests, route replies
    debug.py redact.py   NPDU debug logging with redaction
    codec/               tlv, nwk, aps, zdo, zcl, commissioning, fallback
custom_components/localtrv/  Home Assistant integration (HACS)
scripts/                 check_secrets.py, extract_npdu_fixtures.py
tests/                   unit, simulator and HA tests
docs/protocol.md         protocol notes
```

## Docs

- [docs/protocol.md](docs/protocol.md): protocol notes

## Releases

Maintainer only. `pyproject.toml`, `manifest.json` `version` and the manifest pin
`localtrv==X.Y.Z` move in lockstep, and a `vX.Y.Z` tag runs `release.yml` (gate, build, PyPI trusted publishing, GitHub release).
