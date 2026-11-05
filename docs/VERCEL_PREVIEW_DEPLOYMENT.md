# Vercel Preview deployment

This repository deploys as one Vercel project containing two Vercel Services. Services is currently a Beta Vercel feature.

## Architecture

| Service           | Root                        | Runtime                                  | Public route           |
| ----------------- | --------------------------- | ---------------------------------------- | ---------------------- |
| `security-center` | `artifacts/security-center` | Vite static output                       | `/*` after API routing |
| `api-server`      | `artifacts/api-server`      | Express on the Node.js Functions runtime | `/api/*`               |

The API service imports `src/app.ts` directly. It does not run `src/index.ts`, open a listener, or start the local hourly intelligence scheduler. The SPA service rewrites unmatched paths to `index.html`, so direct navigation and browser refresh work.

## Required Preview environment variables

Configure values only in **Project Settings -> Environment Variables -> Preview**. Use an isolated staging Clerk instance and an isolated staging Supabase project. Do not copy production secrets.

| Name                         | Exposure            | Purpose                                                                                                                 |
| ---------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `SUPABASE_DB_URL`            | Secret, server only | PostgreSQL transaction-pooler connection for the isolated staging database. `DATABASE_URL` is the supported fallback.   |
| `CLERK_SECRET_KEY`           | Secret, server only | Validates Clerk sessions in the Express API.                                                                            |
| `CLERK_PUBLISHABLE_KEY`      | Config, server only | Lets the API resolve the matching Clerk Frontend API key.                                                               |
| `VITE_CLERK_PUBLISHABLE_KEY` | Public Config       | Browser key for the same staging Clerk instance. Vite embeds this value in the frontend bundle.                         |
| `AGENT_PUBLIC_BASE_URL`      | Config, server only | Exact HTTPS Preview origin embedded in enrollment commands. Set it after the first Preview URL is known, then redeploy. |

Do not put database URLs, Clerk secret keys, NVD keys, agent tokens, or any other secret in a `VITE_*` variable.

## Optional variables

| Name                   | Purpose                                                                                                                           |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `NVD_API_KEY`          | Raises the NVD request allowance. Vulnerability intelligence remains slower without it.                                           |
| `LOG_LEVEL`            | Pino logging level; defaults to `info`.                                                                                           |
| `APP_ORIGINS`          | Comma-separated CORS allowlist only when the SPA is hosted on a different origin. Omit for this same-origin Services deployment.  |
| `VITE_CLERK_PROXY_URL` | Clerk Frontend API proxy URL only for a deliberately configured proxy/custom-domain flow. Omit for the normal Vercel Clerk setup. |
| `AGENT_DIST_DIR`       | Filesystem override for packaged agent artifacts. Omit on Vercel; the function bundle includes tracked `agent/dist` files.        |

## Missing configuration behavior

- `/api/healthz` remains a liveness endpoint and does not touch the database.
- Agent routes return HTTP 503 until the staging database connection name is configured.
- Operator API routes return HTTP 503 until both staging database and Clerk server variables are configured.
- The frontend shows a configuration-required screen instead of fabricating a signed-in session or loading production data when the public staging Clerk key is absent.

## Runtime limitations

- The API is stateless and may scale to zero. PostgreSQL connections use a small per-instance pool; use the Supabase transaction pooler rather than a direct session connection.
- The local hourly vulnerability-intelligence scheduler is not started in a Vercel Function. Manual refresh and durable scheduling require a separately reviewed Vercel Cron/Workflow design before production.
- Vercel deployment does not verify installation, enrollment, service startup, or scanning by the separate Go endpoint agent.
- Agent packages remain unavailable for trusted download unless their exact SHA-256/build identity has an independent native verification record. Deployment never changes that status.

## Import settings

- Team: select the intended Vercel team explicitly.
- Repository: `mohannad-121/NextAura-Security-Center`
- Root Directory: repository root (`.`)
- Framework Preset: Services (normally detected from `vercel.json`)
- Production Branch: leave the existing repository production branch unchanged; this work is Preview-only.
- Do not override the service-local install, build, or output settings from `vercel.json`.
