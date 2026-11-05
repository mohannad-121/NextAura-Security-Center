# Threat Detection Architecture

## Purpose and truth model

NextAura is an evidence collection and investigation platform, not a guarantee that an endpoint is clean. It records what an authorized, read-only source actually observed and preserves collection gaps. The platform uses five evidence classifications:

- `CONFIRMED_DETECTION`: a trusted security product or an explicitly approved intelligence source reports a match.
- `SUSPICIOUS_INDICATOR`: observable evidence merits investigation but is not proof of malware.
- `INCONCLUSIVE`: analysis was bounded or blocked, such as an encrypted archive.
- `NO_FINDINGS_OBSERVED`: no configured rule matched the evidence that was available. This never means clean.
- `UNSUPPORTED`: the platform has no safe, reliable implementation for that evidence source.

## Implemented components

### Local file investigation engine

`nextaura-agent inspect-file --path FILE --approved-root DIR` performs an administrator-initiated local inspection. It:

- requires the target to be a regular file inside the explicitly supplied root;
- rejects files above the configured size limit;
- calculates SHA-256 locally;
- detects ZIP, ISO-9660, PE, MSI/OLE, LNK, PDF, RTF, scripts, and unknown data using magic bytes where available;
- identifies extension/content mismatches and suspicious double extensions;
- lists bounded ZIP entry metadata without extraction;
- reports encrypted entries, nested archives, high-risk entry names, path traversal names, expansion limits, and compression-ratio limits;
- reports PE certificate-table presence as metadata only; it does not claim that a signature is valid;
- optionally matches an administrator-supplied local SHA-256 intelligence map;
- optionally applies up to 50 bounded literal offline pattern rules to the first 64 KiB.

The result is JSON written locally to standard output. File contents and full paths are not uploaded or included in the result. The incident API accepts this metadata JSON; it does not accept the original file.

### Endpoint evidence collectors

The fixed collector allowlist remains the only remotely requestable collection surface. Existing collectors provide:

- Defender product state, definition age, real-time protection, and detection history;
- bounded Defender operational event counts for detection and protection-disable events, without event contents;
- Windows Run keys, startup folders, non-Microsoft scheduled tasks, and auto-start services;
- macOS LaunchAgents and LaunchDaemons with explicit visibility gaps for protected login-item data;
- firewall, disk encryption, OS update/support, screen lock, Secure Boot/SIP/Gatekeeper, remote access, and network posture;
- installed software inventory and cached NVD/CISA KEV matching.

Deterministic server rules create findings only from concrete evidence. A suspicious-persistence rule flags enabled entries in user-writable locations or using commonly abused command interpreters. A missing publisher by itself does not trigger a finding.

### Database and API

The application stores incidents, related devices/findings, file metadata, evidence timelines, limitations, and recommended actions. Every incident lookup is filtered by the active organization. Public Supabase roles retain no schema/table privileges; RLS is enabled without permissive public policies as defense in depth.

The isolated integration suite exercises enrollment, code expiry/reuse, token authentication and revocation, heartbeat persistence, replay handling, assessment ingestion, finding creation/retrieval, and cross-tenant denial through the actual agent HTTP router and migrated PostgreSQL database.

## Evidence flow

1. An administrator authorizes a file root or requests a fixed collector.
2. The agent applies time, size, entry-count, and scope limits.
3. The agent emits facts, classifications, and limitations; it performs no remediation.
4. The server validates the fixed contract, authenticates the device, and applies replay protection.
5. Deterministic rules create or update findings with source, confidence, collector version, and observed time.
6. An analyst associates findings and imported file metadata with an incident.
7. The incident page and PDF report preserve the timeline, confidence, limitations, and manual response guidance.

## Security boundaries

- No suspicious file execution, mounting, password bypass, archive extraction, upload, quarantine, or deletion.
- No shell, arbitrary command collector, exploitation, credential collection, or private-document content collection.
- PowerShell uses the installed execution policy; the agent does not pass an execution-policy bypass.
- Active antivirus scanning is not invoked because many engines may remediate automatically. NextAura reads existing product evidence only.
- Optional Sysmon/EDR evidence is unsupported until an administrator has separately deployed and authorized a documented integration.
- Checked-in installers remain unverified and unsigned. This branch changes source only and does not publish packages or releases.

## Implementation maturity

| Capability                                           | Status                                                           |
| ---------------------------------------------------- | ---------------------------------------------------------------- |
| Isolated database lifecycle integration tests        | Operational in local/CI isolated stack                           |
| ZIP metadata and PE/ISO/MSI/LNK/script type analysis | Implemented and unit tested                                      |
| Local SHA-256 intelligence feed                      | Implemented; administrator-supplied offline feed                 |
| Literal offline YARA-style rules                     | Prototype; not a full YARA parser or engine                      |
| Defender history and selected event counts           | Implemented; native Windows validation still required            |
| Suspicious persistence correlation                   | Implemented server rule; heuristic, not a malware verdict        |
| Incident storage/API/dashboard/PDF                   | Implemented; staging user acceptance remains                     |
| ISO filesystem traversal                             | Unsupported; image is never mounted                              |
| MSI signature validation                             | Unsupported                                                      |
| Online reputation services                           | Not configured; no hashes or files leave the endpoint by default |
| Sysmon and third-party EDR                           | Not installed or queried automatically                           |
