# Centralized Scanning Architecture

## Current behavior

NextAura uses one outbound HTTPS agent channel. An authenticated operator creates a scan job, the API validates organization membership and fixed operation inputs, and a device-authenticated agent pulls its request on heartbeat. No inbound listener, remote shell, arbitrary command, script, SQL, or server-supplied filesystem path exists.

```text
Scan Center -> Clerk session/RBAC -> scan_jobs transaction
            -> agent_requests (fixed operation + collector IDs or scope ID)
            -> authenticated agent pull -> local allowlist validation
            -> bounded read-only collection -> authenticated evidence POST
            -> schema/provenance validation -> tenant-scoped persistence
            -> findings / scan history / incident investigation / PDF
```

## Implemented operations

- `ASSESSMENT`: one or more of the six compiled collector IDs.
- `FILE_SCOPE_SCAN`: one locally generated `scope_<128-bit random>` identifier. The API never sends a path.
- Single-device, multi-device, and up-to-500-device fleet requests.
- One active request per device, a maximum 24-hour expiry, bounded agent retries, collector failure reporting, and partial results.
- Genuine states: `WAITING_FOR_AGENT`, `RUNNING` only after agent acknowledgement, and terminal `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`, or `EXPIRED`.
- Cancellation safely prevents pending/delivered work. Already-running local read-only collection is not force-killed and is reported honestly.

## Local scope consent

An administrator configures a scope on the endpoint:

```text
nextaura-agent scope add --root "D:\Approved\Installers" --label "Approved installers" --consent
nextaura-agent scope list
nextaura-agent scope revoke --id scope_...
```

Personal-directory roots require the additional explicit `--include-personal` acknowledgement. The protected local `scopes.json` contains the path; heartbeat reports only ID, label, and enabled state. Missing or revoked IDs are rejected locally. Directory symlinks and non-regular files are skipped; target symlinks are resolved and checked against the approved real root. Analysis uses the already-validated file handle and verifies file identity to reduce replacement races.

## Evidence provenance

Agent evidence is accepted only for the authenticated device, matching active request, requested scope, known detector ID, and current organization derived server-side. Idempotency is committed in the same PostgreSQL transaction as evidence. Filenames contain no separators, paths are represented only by a SHA-256 of their relative form, and file bytes are never uploaded.

Suspicious or confirmed authenticated file evidence also creates a tenant-scoped device finding so analysts can correlate it through the existing incident workflow.

Analyst-entered incident evidence remains separate and cannot impersonate agent evidence. Vendor evidence is not implemented and no vendor identity is claimed.

## Reliability boundaries

- Scope scans: 500 candidate files, 2,000 directories, 15 minutes, 128 MiB per file by default.
- Network submission: five attempts with bounded exponential backoff and stable idempotency key.
- A failed collector produces `PARTIAL` or `FAILED`, never a healthy result.
- Offline devices remain waiting until expiry.
- The current agent completes one request at a time. The server prevents an unbounded per-device queue.
