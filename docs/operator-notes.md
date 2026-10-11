# Operator threat-model notes

This document describes how a network defender can detect and respond to a
carl-class implant. It is the defensive mirror of the tradecraft in the
framework. No offensive techniques are included.

## Beacon shape

A carl beacon is an HTTPS POST to a configured C2 path. The body is an
envelope:

```
{
  "v": 1,
  "g": "<campaign-group>",
  "n": "<16-byte nonce, b64>",
  "iv": "<16-byte IV, b64>",
  "ct": "<AES-256-CBC ciphertext, b64>",
  "tag": "<HMAC-SHA256(iv || ct), b64>",
  "type": "beacon"
}
```

The plaintext body is JSON with the host fingerprint, current user, OS,
elevation, and a `loot` array.

## Detection signals

**Network-layer**
- Periodic HTTPS POSTs at fixed intervals (60–180s by default) to a single
  host that the host has no other business talking to. Look for the
  highest-entropy destination by flow count.
- Beacons arriving at exact-window intervals. Compute the inter-arrival
  time per source IP; a tight distribution with low variance is a signal
  even when the absolute timing is jittered.
- JA3 fingerprint anomalies. The default libcurl / WinHTTP clients have
  well-known JA3 hashes; carl does not yet patch these (v0.2 mitigation
  pending).
- Outbound TLS to a host that has no DNS history older than 30 days. Most
  long-lived C2 domains are 1–6 months old; new domains with high
  outbound traffic are a strong signal.
- DNS over HTTPS to resolvers other than the org's resolver.

**Host-layer**
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\carlsync` on
  Windows, or `~/.config/systemd/user/carlsync.service` on Linux.
- A binary in `%APPDATA%\carlsync\` or `~/.local/share/carlsync/`
  with `FileAttribute: hidden, system` on Windows.
- A `crontab -l` line referencing the install path, or a `~/.config/
  autostart/carlsync.desktop` file.
- An empty or very small `loot.db` file in the install directory with
  periodic mtime updates.
- The dropper process exits cleanly and is relaunched from the install
  path within 1–2 seconds.

**Process-layer**
- The process makes outbound HTTPS, then sleeps. EDR sleep-monitor hooks
  on `Sleep`/`NtDelayExecution` can flag the cadence.
- Thread-creation events for a single-threaded network process.
- Module load events for `nlohmann_json.dll`, `libcurl.dll`,
  `libssl.dll` from a non-standard path (the install dir).

**Loot artifacts**
- Files written to `loot.db` carry AES ciphertext. Look for SQLite
  files in user-writable directories that fail to open with a normal
  SQLite client.
- Browser credential stores that suddenly empty (the implant decrypts
  and exfiltrates, leaving an inconsistent DB).

## Response actions

1. **Network isolation** — pull the host from the network. The implant
   has no offline capability (no SMB or peer beacon); isolation
   contains it.
2. **Memory capture** — before reimage, dump process memory. The
   implant holds the AES key in memory and the loot store handles.
3. **Disk image** — the install dir, the persistence keys, and the
   `loot.db` are all on disk. Imaging first, reimaging second.
4. **C2 takedown** — sinkhole the C2 host. The implant will continue
   beaconing; capture the next 24h of beacons to find the rest of the
   fleet via the same group ID.
5. **Credential rotation** — anything the host could reach via stored
   credentials (browsers, KeePass, AD, cloud) must be considered
   exposed until proven otherwise.

## Hardening recommendations (for defenders)

- Egress filtering. Most implants are killed by a well-configured
  default-deny outbound.
- EDR with sleep-monitor and ETW `Microsoft-Windows-Threat-Intelligence`
  enabled. Catches most usermode implants within hours.
- Sysmon with config covering Run key init (EID 13), image load
  (EID 7), process create (EID 1), and DNS query (EID 22).
- Periodic JA3 inventory. The default libcurl JA3 should not appear on
  endpoints that do not run code that uses libcurl.
- Canary credentials. Fake browser passwords, fake KeePass DBs, fake
  AD accounts in the password vault. A successful decrypt of a canary
  is a high-confidence signal.

## Reporting a carl sample

If you find a carl sample in the wild, the following are the unique
identifiers you can extract without decrypting the loot store:

- The campaign group ID in the envelope (`g` field).
- The host fingerprint ID (the first 16 hex of `host_id`).
- The install path (`service_name`).
- The persistence key path (DPAPI blob on win, `.k` file on linux).
- The C2 host and path.

These are sufficient to attribute the sample to a campaign and
correlate across a fleet.
