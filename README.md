# vicare-direct

Local Zigbee Direct (BLE) client for Viessmann ZK03840 radiator valves, built to power a Home
Assistant integration without the cloud.

**Status:** phase 1, pre-alpha. Protocol codecs and session crypto only; transport, node and CLI
come in phase 2.

> Not affiliated with or endorsed by Viessmann or ubisys. ViCare is a trademark of Viessmann.
> Reverse-engineered; use at your own risk.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check
uv run mypy
uv run pytest
```
