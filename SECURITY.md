# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. This creates a private security advisory that is shared only with the
repository's maintainers.

Include what you found, how to reproduce it, and which version you used. You will get an answer as
soon as possible. This is a hobby project, so there is no fixed response time.

**Never include a real network key**, a Commissioning Status dump or an unredacted capture. If a
report needs key material, use a dummy key. If you shared a real key by accident, tell us at once
so we can delete it.

## Scope

In scope:

- Handling of the network key and anything derived from it: storage, memory, config flow.
- Logging and redaction: the network key, other keys or EUIs reaching a log line.
- Diagnostics: data in the download that should be removed or pseudonymised.
- The Zigbee Direct session: weaknesses in our handshake or frame protection.

Out of scope:

- Weaknesses in Zigbee, Zigbee Direct, the ubisys R0, ViCare devices or Viessmann services
  themselves. Report those to the vendor.
- Attacks that need the network key or full control of the Home Assistant host.

## Supported versions

Only the latest release gets fixes.
