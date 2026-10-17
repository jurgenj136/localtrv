# LocalTRV

[![GitHub release](https://img.shields.io/github/v/release/jurgenj136/localtrv?include_prereleases)](https://github.com/jurgenj136/localtrv/releases)
[![HACS Custom](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz/docs/faq/custom_repositories/)
[![License: MIT](https://img.shields.io/github/license/jurgenj136/localtrv)](https://github.com/jurgenj136/localtrv/blob/main/LICENSE)
[![CI](https://github.com/jurgenj136/localtrv/actions/workflows/ci.yml/badge.svg)](https://github.com/jurgenj136/localtrv/actions/workflows/ci.yml)

Local Bluetooth control for Viessmann ViCare radiator valves through a ubisys R0. LocalTRV is a
Home Assistant integration that needs a ubisys R0 **Series 2**; the Series 1 has no Bluetooth and
cannot be used.

<!-- screenshot: docs/images/climate-card.png (to be added) -->

> [!WARNING]
> **Early release.** Features, options and behaviour may still change between versions.

Not affiliated with or endorsed by Viessmann or ubisys. ViCare is a trademark of Viessmann. Use at
your own risk; no warranty.

## How it works

The ubisys R0 Series 2 is a Zigbee router that also speaks **Zigbee Direct**: a way to reach a
Zigbee network over Bluetooth. Home Assistant connects to the R0 over Bluetooth and talks to your
ViCare valves through it. Your ViCare gateway, app and schedules keep working as before.

## What you need

| Component | Required | Tested with |
|---|---|---|
| Radiator valves | Viessmann ViCare ZK03840 | 8 valves, firmware `01.18.0008 02.06`, model id `7637434` |
| Zigbee router | ubisys Router R0 **Series 2** (Series 1 has no Bluetooth), on the same Zigbee network as the valves | ubisys R0 Series 2 |
| ViCare gateway | the gateway that runs your ViCare Zigbee network | Vitoconnect OPTO2 |
| Home Assistant | 2026.10.0 or newer | 2026.10.1 on Home Assistant OS |
| Bluetooth | a local adapter or an ESPHome Bluetooth proxy in range of the R0 | ESP32-C3 ESPHome proxy |

Bluetooth details:

- An ESPHome proxy must allow active connections:

  ```yaml
  bluetooth_proxy:
    active: true
  ```

- The integration keeps one connection to the R0 open all the time. It needs one free connection
  slot on your adapter or proxy.
- The adapter must handle large Bluetooth packets (MTU). The tested ESP32-C3 proxy negotiated 247,
  which is plenty. If yours is too small, Home Assistant shows a repair issue
  ([Troubleshooting](#troubleshooting)).
- The R0 accepts only one Bluetooth client at a time.

You also need **the network key** of your ViCare Zigbee network. See the next section.

## The network key

The integration needs the 128-bit network key of your ViCare Zigbee network (32 hexadecimal
characters). Without it the R0 does not let anyone in. There is no way around this.

- This project does not retrieve the key for you.
- Only obtain the key for equipment you own or are authorized to administer.
- The third-party [ViLocal](https://github.com/kristian/ViLocal) guide describes one method, in
  the section "Find the Channel of your ViCare Network and sniff for your Network Key". It needs a
  Zigbee sniffer and (re)pairing a ViCare device; a spare or new device works too. Follow that
  guide's own instructions and warnings.
- Home Assistant stores the key in the config entry and uses it on every (re)connect. Home
  Assistant backups therefore contain it. Protect them.
- Never paste the key in issues, forum posts or logs. The integration never logs it.

## Installation

### HACS (recommended)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=jurgenj136&repository=localtrv&category=integration)

Or by hand:

1. In HACS, open the menu (three dots, top right) and choose **Custom repositories**.
2. Add `https://github.com/jurgenj136/localtrv` with type **Integration**.
3. Open **LocalTRV**.
4. Download it and restart Home Assistant.

### Manual

1. Download a [release](https://github.com/jurgenj136/localtrv/releases).
2. Copy `custom_components/localtrv/` into the `custom_components/` folder of your Home
   Assistant config.
3. Restart Home Assistant.

On first start, Home Assistant downloads the matching `localtrv` Python package from PyPI.
After that, the integration needs no internet.

## Setup

1. Make sure nothing else is connected to the R0 over Bluetooth: another adapter or proxy,
   another Home Assistant instance, or a phone app that talks to the R0.
2. Add the R0:
   - **Discovered:** go to **Settings > Devices & services**. Under Discovered you see
     **ubisys R0 found**. Click **Add** and confirm.
   - **Not discovered:** click **Add integration**, search for **LocalTRV**, and choose your R0
     in **Select the ubisys R0**.
3. In **Zigbee network key**, enter the key (32 hexadecimal characters).
4. Leave **Test the connection** on and submit.

**Test the connection** connects to the R0 and checks the key, then disconnects. It takes up to 60
seconds and writes nothing to the valves. It does not join the network or look for valves; that
happens after you save. Turn it off to save without checking, for example when the R0 is briefly
busy.

After saving, the integration joins the Zigbee network through the R0 and starts looking for
valves. Each valve appears as its own device once it answers. Valves sleep most of the time, so
this can take a few minutes.

**New key.** If the R0 rejects the stored key, Home Assistant asks you to **Re-enter the network
key**. Enter the current key. It is tested before it is saved. If the test times out, the key is
saved anyway; other connection errors keep the form open until you fix them and try again.

## What you get

Each valve is a device "ViCare valve …" (Viessmann ZK03840), linked to the R0 device.

| Entity | Type | Notes |
|---|---|---|
| (valve name) | Thermostat | Heat mode only. Current and target temperature, 0.5 °C steps, limits from the valve (8-30 °C if the valve does not report them). Shows heating while the valve asks for heat, idle when it does not, unknown while the heating demand is unknown |
| Heating demand | Sensor | 0-100 %, how far the valve wants to open |
| Battery | Sensor | %. Diagnostic |
| Link quality | Sensor | Zigbee link quality to the valve's parent. Diagnostic, disabled by default |
| Signal strength | Sensor | dBm. Diagnostic, disabled by default |
| Window open (experimental) | Binary sensor | Disabled by default. The meaning of the raw value is still a guess |

The R0 device has:

| Entity | Type | Notes |
|---|---|---|
| Connection | Binary sensor | On while the R0 connection is ready. Diagnostic |
| Connection state | Sensor | Idle, Connecting, Joining, Ready, Waiting to retry, Authentication failed or Stopped. Diagnostic |

### Setting a temperature

- The thermostat shows your new target right away, while the valve is still asleep.
- Before writing, the integration checks that the device at the valve's network address really
  is that valve. Only then does it send the new target.
- The call finishes when the valve acknowledges the write: usually a few seconds. On a weak link
  a dropped and resent request can stretch that to about 20 seconds; after 60 seconds the call
  gives up.
- If that fails, the target goes back to the old value and you get one of two errors:
  - "… The valve could not be reached to confirm its address, so nothing was sent. Try again."
  - "… The valve did not confirm the change." The valve may still have applied it; the
    thermostat shows the right value after the next poll.
- After the acknowledgement, the integration reads the target back in the background to confirm
  it. The call does not wait for that.
- A change from Home Assistant acts like turning the valve by hand: the ViCare app shows the room
  as "manually set, for 2 hours".
- Your ViCare gateway and schedule push their own target again later: after that period, or at the
  next schedule change. The last change wins. Only the ViCare app (or waiting) ends the manual
  override; Home Assistant cannot cancel it.

The thermostat also has the attributes `setpoint_pending`, `setpoint_acknowledged` and
`setpoint_confirmed` to follow a change.

## How updates work

- The integration asks every valve for its state every 300 seconds by default. Valves do not send
  updates over this connection on their own, so polling is how the data arrives.
- Valves sleep and answer slowly: typically 2-4 seconds, sometimes 10.
- A valve that misses 3 polls in a row becomes unavailable (15 minutes at the default). It comes
  back by itself when it answers again, and the log says so.
- If all valves stay silent, the integration rejoins the network by itself. If the Bluetooth
  connection drops, it reconnects with growing pauses (up to about 6 minutes).
- Known valves are remembered across restarts. They show up right away but stay unavailable until
  they answer. The valve list is refreshed every 6 hours, so new valves appear on their own.
- Every poll wakes the valve's radio. Keep the default interval unless you need faster updates.

## Options

**Settings > Devices & services > LocalTRV > Configure.** Saving reloads the integration.

| Option | Range | Default | Notes |
|---|---|---|---|
| Poll interval (seconds) | 60-3600 | 300 | Valves run on batteries; do not poll faster than you need |
| Route reply mode (under Advanced) | Live, Specification, Off | Live | Leave on Live unless asked to change it |

## Known limitations

- Heat mode only. No control over schedules, holiday mode or turning a valve off.
- Window open is experimental and disabled by default.
- The R0 accepts one Bluetooth client. While this integration runs, nothing else can connect to it.
- Polling only. Changes made in ViCare or on the valve show up at the next poll.

## FAQ

**Does the ViCare app keep working?**
Yes. Your valves stay on the ViCare network and the app works as before. The app goes through the
Viessmann cloud, not Bluetooth, so it does not compete for the R0. You do not need to close it.

**Why did my target temperature change back?**
Your ViCare schedule or gateway set it again. A change from Home Assistant is a manual override that
ViCare ends after a while or at the next schedule change. If the valve never confirmed the change,
the integration also puts the old value back.

**Can I use it without the network key?**
No. The R0 requires it. See [The network key](#the-network-key).

**Does it work with other Zigbee routers?**
It needs a router with Zigbee Direct over Bluetooth: the ubisys R0 Series 2. The R0 Series 1 has
no Bluetooth, and routers without Zigbee Direct cannot work.

**Does it need the internet?**
Only to install or update it (HACS and the Python package). After that everything stays local.

## Troubleshooting

| You see | Likely cause | Fix |
|---|---|---|
| "No ubisys R0 found over Bluetooth." | The R0 is out of range, or no adapter or proxy can connect to it | Move the adapter or proxy closer. Check `bluetooth_proxy: active: true` |
| "This device is not a ubisys R0 with Zigbee Direct." | A different Bluetooth device | Pick the R0 |
| "Could not connect to the R0. …" | Another client holds the R0, it is out of range, or the proxy has no free slot | Disconnect the other client, move closer, free a proxy slot, try again |
| "The R0 rejected the network key." | Wrong key | Check the key. Only the ViCare network key works |
| "The key must be exactly 32 hexadecimal characters." | Typo, spaces inside the key, or a different format | Enter 32 characters 0-9 and a-f |
| Setup keeps retrying with "The ubisys R0 is not reachable over Bluetooth." | After a reload the R0 needs about 15 seconds before it accepts a connection again | Wait; Home Assistant retries by itself |
| Repair issue "Bluetooth MTU too small" | Your adapter or proxy sends too small packets. Some replies may be lost | Use another adapter or an ESPHome proxy |
| Repair issue "Bluetooth long writes unsupported" | Your adapter or proxy cannot send large frames | Use another adapter or an ESPHome proxy |
| Connection state "Authentication failed" | The R0 rejected the stored key | Enter the key again when Home Assistant asks you to **Re-enter the network key** |
| A valve is unavailable | Weak Zigbee link, or the valve's parent did not get the request to it in time | Wait; it usually comes back within minutes. Check Battery and Link quality |
| Setting a temperature is slow or fails | The valve is asleep or has a weak link | Wait up to a minute. Try again later |

### Debug logging

Add this to `configuration.yaml` and restart:

```yaml
logger:
  logs:
    localtrv: debug
```

Or use **Enable debug logging** on the integration page. The line `connected, mtu=…` shows the
negotiated MTU. Debug logs never contain the network key, but they can contain Bluetooth and
Zigbee network addresses.

### Diagnostics

**Settings > Devices & services > LocalTRV**, menu, **Download diagnostics**.

- Never included: the network key or anything derived from it, the R0's Bluetooth address.
- Pseudonymised: device IDs (EUI-64) and the extended network ID.
- Included: options, connection counters, the MTU, network metadata (PAN ID, channel, short
  addresses), each valve's model, firmware, limits and state (temperatures, target, battery,
  heating demand), and a short, redacted log of recent frames.

### Reporting a bug

Open an [issue](https://github.com/jurgenj136/localtrv/issues/new/choose) and attach:

- Home Assistant and integration versions
- your Bluetooth adapter or proxy, and the `mtu=` log line
- a debug log covering the problem
- the diagnostics file

Read your log before you post it. Never include the network key.

## Removing the integration

1. **Settings > Devices & services > LocalTRV**, menu, **Delete**.
2. To remove the files too, uninstall it in HACS (or delete
   `custom_components/localtrv/`) and restart.

Deleting stops the Bluetooth connection, so the R0 is free again. It also deletes the stored valve
list and any repair issues of this integration. Older Home Assistant backups still contain the
network key.

## Contributing

See [CONTRIBUTING.md](https://github.com/jurgenj136/localtrv/blob/main/CONTRIBUTING.md).

## Security

Please report vulnerabilities privately. See [SECURITY.md](https://github.com/jurgenj136/localtrv/blob/main/SECURITY.md).

## Python library

The integration is built on the Python package
[`localtrv`](https://pypi.org/project/localtrv/). It handles the Bluetooth
connection, the Zigbee Direct session and the valve mapping, and includes a small CLI
(`localtrv scan`, `localtrv status`). The API is not stable yet. See
[CONTRIBUTING.md](https://github.com/jurgenj136/localtrv/blob/main/CONTRIBUTING.md) for the
code layout.

## Protocol documentation

How the R0, the Zigbee Direct session and the valves work: [docs/protocol.md](https://github.com/jurgenj136/localtrv/blob/main/docs/protocol.md).

## License

MIT. See [LICENSE](https://github.com/jurgenj136/localtrv/blob/main/LICENSE).
