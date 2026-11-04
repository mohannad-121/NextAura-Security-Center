# Privacy

## Data the agent collects

| Category | Fields | Why |
|---|---|---|
| Device identity | hostname, OS name/version/build, architecture, model, RAM, CPU model, **last 4 characters** of the serial number | Identify the device and determine OS support |
| Security posture | firewall, encryption, update, screen-lock, Secure Boot / SIP / Gatekeeper / UAC, guest account, remote access state | The assessment itself |
| Antivirus | product name, real-time state, definition age, the product's own detection history (Defender only) | Protection coverage |
| Software inventory | application names, vendors, versions, install dates | CVE matching |
| Startup inventory | names/locations of autostart entries, services, scheduled tasks, launchd items | Persistence visibility |
| Network summary | firewall profile defaults, SMBv1 state, connection profile category | Exposure summary |
| Agent health | agent version, uptime, collector errors | Reliability |

## Data the agent never collects

Files or documents, browsing history, keystrokes, screenshots, credentials, email or chat contents, network traffic, full serial numbers, user names beyond the local Guest account state.

## Retention and deletion

- `retentionDays` per organization (default 90) governs how long assessment telemetry is intended to be kept.
- An OWNER can delete all organization telemetry from Settings → Data deletion (requires typing the organization slug). The deletion is audited.
- Revoking a device invalidates its token; the agent removes its local state on the next contact.

## Processing location

Data is stored in the Supabase Postgres project configured by `SUPABASE_DB_URL`. Vulnerability lookups send **product names and versions only** to NVD; nothing device-identifying leaves the server.

## Consent

The enrollment wizard shows the full collection summary before a code is generated, and the same text is returned by the API (`consentSummary`) so it can be shown to device users.
