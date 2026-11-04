# NextAura Security Center

Read-only, multi-tenant endpoint security assessment SaaS for SMBs: a Go agent on Windows/macOS devices reports fixed security facts; the dashboard shows evidence-backed findings, risk, CVE matches and reports. Tagline: "Visibility. Detection. Confidence."

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — API server (reads `PORT`)
- `pnpm --filter @workspace/security-center run dev` — dashboard
- `pnpm run typecheck` / `pnpm run typecheck:libs` (run libs first; artifacts depend on built lib d.ts)
- `pnpm --filter @workspace/api-spec run codegen` — regenerate hooks/Zod from `lib/api-spec/openapi.yaml`
- `pnpm --filter @workspace/db run push` — apply schema to Supabase (`SUPABASE_DB_URL`, falls back to `DATABASE_URL`)
- `./agent/scripts/build-agent.sh` — builds agent binaries into `agent/dist` (committed so they ship with the deployment); `cd agent && go test ./...`
- Env: see `.env.example`. Secrets: `SUPABASE_DB_URL`, `CLERK_*`, optional `NVD_API_KEY`.

## Stack

pnpm workspaces · React 19 + Vite + wouter + Clerk (dashboard) · Express 5 + Drizzle on Supabase Postgres (API) · Go 1.22 stdlib-only agent · pdfkit reports · NVD 2.0 + CISA KEV feeds.

## Where things live

- DB schema: `lib/db/src/schema/*` (organizations, devices, assessments, platform)
- Dashboard API contract: `lib/api-spec/openapi.yaml` → `lib/api-zod`, `lib/api-client-react`
- Agent API contract (not in OpenAPI): `artifacts/api-server/src/routes/agent/contract.ts` ⇄ `agent/internal/model/model.go` — keep in sync
- Rules engine: `artifacts/api-server/src/services/rules.ts`; ingestion: `services/assessments.ts`; CVE: `services/vulnerabilities.ts`
- Agent collectors: `agent/internal/collectors/platform_{windows,darwin}.go`, exec allow-list in `exec.go`
- Docs: `docs/*.md`, `README.md`

## Architecture decisions

- Agent routes mount before CORS/Clerk with per-device hashed bearer tokens; dashboard routes use Clerk session → `requireIdentity` → `requireOrg` → `requireRole`.
- Members are authorised by email; membership rows get `userId` claimed on first sign-in.
- UNKNOWN/UNSUPPORTED/PERMISSION_DENIED never count as PASS; they lower coverage and raise LOW/INFO "visibility gap" findings. Risk score is null at 0% coverage.
- Agent builds are served from `agent/dist` only if present; `manifest.json` `verified`/`signed` flags are set manually after real-device tests. No demo data anywhere.
- Reports stored base64 in `report_exports`; downloaded same-origin under `/api/reports/:id/download`.

## Gotchas

- `@swc/helpers` must stay a direct dependency of api-server (fontkit/pdfkit needs it at runtime in the esbuild bundle).
- Zod in api-server must be `catalog:` to match `@workspace/api-zod`.
- Linux (this workspace) cannot run the agent collectors; `collect` reports UNSUPPORTED. Cross-compile and test on real devices.
