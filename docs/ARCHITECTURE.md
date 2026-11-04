# Architecture

```
┌──────────────┐  HTTPS, device token   ┌─────────────────────┐   SQL (TLS)   ┌───────────────┐
│ Go agent     │ ─────────────────────▶ │ Express API server  │ ────────────▶ │ Supabase      │
│ (Win/macOS)  │  /api/agent/v1/*       │                     │               │ Postgres      │
└──────────────┘                        │  /api/*  (Clerk)    │               └───────────────┘
                                        └─────────▲───────────┘
┌──────────────┐  HTTPS, Clerk session            │
│ React SPA    │ ─────────────────────────────────┘
└──────────────┘
```

## Components

- **Dashboard (artifacts/security-center)** — React/Vite SPA. Talks only to `/api/*` through hooks generated from `lib/api-spec/openapi.yaml`. Role-aware UI (OWNER / ADMIN / SECURITY_ANALYST / VIEWER).
- **API server (artifacts/api-server)**
  - `/api/*` dashboard API, authenticated by Clerk session. `requireIdentity` → `requireOrg` → `requireRole`.
  - `/api/agent/v1/*` agent API, authenticated by per-device bearer tokens (sha256 hash stored, 90-day TTL). Mounted *before* Clerk and CORS so browsers cannot reach it with cookies.
  - Services: `rules.ts` (deterministic rules), `assessments.ts` (ingest), `vulnerabilities.ts` (NVD/KEV), `reports.ts` (PDF/CSV), `emailSecurity.ts` (DNS audits).
- **Database (lib/db)** — Drizzle schema. All tenant tables carry `organization_id`.
- **Agent (agent/)** — single static binary, no third-party Go modules.

## Agent protocol

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /enroll` | enrollment code (single use, short TTL, rate limited per IP) | Returns device id + token + schedule config |
| `POST /heartbeat` | device token | Liveness, agent version, collector errors; returns config + pending request count. Replay-protected by `requestId`. |
| `GET /requests` | device token | Pending operator requests (fixed collector IDs only). Marks DELIVERED. |
| `POST /requests/ack` | device token | ACKNOWLEDGED or REJECTED (with reason) |
| `POST /assessments` | device token | Full collector payload; idempotent by `idempotencyKey` |

The agent decides *when* to run (posture every N hours, inventory every M hours, values pushed by the server). Operators can only ask for a re-run of the fixed collectors.

## Assessment ingestion

1. Validate payload (Zod, size-capped).
2. In one transaction: insert assessment + checks; replace `current` software/startup rows; upsert threats; apply rules.
3. Rules produce findings keyed by `(device, ruleId)`; existing findings are updated (`lastSeenAt`), missing ones auto-resolve, new ones open.
4. Coverage = share of checks with a definite status (`PASS/FAIL/WARNING`). Risk score = capped weighted sum of open findings (C30/H15/M7/L2); `null` when coverage is 0.
5. Software inventory is matched against the cached NVD/KEV data (never blocking on the network).

## Vulnerability intelligence

A single in-process worker queries the NVD 2.0 API by keyword for distinct (vendor, product) pairs, respecting NVD rate limits, and caches CVEs per product for 7 days. CISA KEV is refreshed every 12 hours. Matching confidence:

- **CONFIRMED** — vendor + product + version inside a CPE range
- **PROBABLE** — product + version match, vendor unverified
- **POSSIBLE** — product name match only, version range unknown
- **UNKNOWN** — installed version missing

## Reports

Generated server-side from persisted data (pdfkit / CSV), stored in `report_exports`, downloaded same-origin under `/api/reports/:id/download`. Every report carries the scope/limitations disclaimer.
