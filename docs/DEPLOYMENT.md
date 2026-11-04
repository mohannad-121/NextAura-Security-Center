# Deployment

## Prerequisites

- Supabase project (Postgres). Set `SUPABASE_DB_URL` to the **pooler** connection string (port 6543, `sslmode=require`).
- Clerk application. Set `CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY`, `VITE_CLERK_PUBLISHABLE_KEY`. Enable MFA in the Clerk dashboard if your policy requires it.
- Optional: `NVD_API_KEY` (raises NVD rate limit from 5 to 50 requests / 30 s).

## Steps

1. `pnpm install`
2. `pnpm --filter @workspace/db run push` (or generate migrations with `drizzle-kit generate` for controlled rollouts).
3. Build agent binaries on a machine with Go 1.22+: `./agent/scripts/build-agent.sh`. Copy `agent/dist/*` to the server (or set `AGENT_DIST_DIR`). Until a binary exists the enrollment wizard shows "No binary has been built on this server" and offers the source-build command instead.
4. After a successful test enrollment from a real device, set `verified.<platform>: true` in `agent/dist/manifest.json` so the wizard stops labelling the build as untested.
5. Start the API (`pnpm --filter @workspace/api-server run dev` builds and runs `dist/index.mjs`; it reads `PORT`) and the web app.
6. Put both behind HTTPS. The agent refuses non-HTTPS servers.

## On Replit

Publishing uses the configured workflows; secrets live in the Replit Secrets panel. The agent download endpoint serves files from `agent/dist` inside the deployment image, so build the binaries before publishing.

## Operational notes

- Intelligence scheduler runs in-process; a single API instance is assumed. If you scale horizontally, run the scheduler on one instance only (`INTELLIGENCE_SCHEDULER=off` on the others is a straightforward extension).
- Reports are stored in the database (base64). For very large fleets move them to object storage.
