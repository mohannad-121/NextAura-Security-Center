# NextAura Security Center

**Visibility. Detection. Confidence.**

A read-only, multi-tenant endpoint security assessment service for small and medium businesses. A lightweight Go agent on each Windows or macOS device collects a fixed set of security facts; the dashboard turns them into evidence-backed findings, risk scores, CVE matches and reports.

What it deliberately is **not**: an EDR, a remote-management tool or a remediation engine. The agent never changes a setting, never executes operator-supplied commands and never reads user files.

## Repository layout

| Path                                                  | What                                                                                                                                                 |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `artifacts/security-center`                           | React + Vite dashboard (Clerk sign-in, English/Arabic)                                                                                               |
| `artifacts/api-server`                                | Express 5 API: dashboard API (`/api/*`, OpenAPI in `lib/api-spec`) and agent API (`/api/agent/v1/*`, Zod contract in `src/routes/agent/contract.ts`) |
| `lib/db`                                              | Drizzle schema for Supabase Postgres                                                                                                                 |
| `lib/api-spec`, `lib/api-zod`, `lib/api-client-react` | OpenAPI contract and generated client/validators                                                                                                     |
| `agent`                                               | Go agent (stdlib only), build scripts, service installers                                                                                            |
| `docs/`                                               | Architecture, security model, privacy, deployment, agent installation, platforms, known limitations                                                  |

## Quick start (development)

```bash
corepack pnpm install
pnpm --filter @workspace/db run push          # apply schema to the database in SUPABASE_DB_URL
pnpm --filter @workspace/api-server run dev   # API on $PORT
pnpm --filter @workspace/security-center run dev
./agent/scripts/build-agent.sh                # builds complete agent packages into agent/dist
go test ./...                                  # from ./agent
```

Required environment: see `.env.example`.

## Core guarantees

1. **Read-only agent.** Six compiled-in collectors; an allow-list of OS read-only commands; unknown collector IDs are refused by the agent _and_ the server.
2. **Evidence or UNKNOWN.** Every check carries its evidence string, data source, confidence and required permission. Anything not observed is `UNKNOWN`, `UNSUPPORTED` or `PERMISSION_DENIED` — never `PASS`.
3. **Tenant isolation.** Every table is scoped by `organization_id`; every dashboard query filters by the caller's active organization; device tokens are hashed and bound to one device.
4. **No fabricated data.** There is no demo seed. A fresh organization is empty until a real agent reports.

See `docs/` for details.
