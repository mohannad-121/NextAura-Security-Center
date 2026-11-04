# Deployment

## Required services and configuration

- Supabase PostgreSQL pooler URL in `SUPABASE_DB_URL` with `sslmode=verify-full`.
- Clerk operator identity: `CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY`, and `VITE_CLERK_PUBLISHABLE_KEY`.
- `AGENT_PUBLIC_BASE_URL`: the canonical HTTPS origin embedded into enrollment commands. It is required in production and must not contain a path.
- Optional `APP_ORIGINS`: comma-separated explicit frontend origins only when the SPA and API are on different origins. Same-origin deployment needs no CORS.
- Optional `NVD_API_KEY` for higher NVD rate limits.

## Database rollout

The historical project used `drizzle-kit push` and did not contain versioned migrations. The new history contains a complete greenfield baseline followed by the security hardening migration.

For a new/local database, start Docker Desktop and validate from the repository root:

```bash
supabase start
supabase db reset --local --no-seed
supabase db lint --local --schema public --level error --fail-on error
```

For an existing database whose tables already match the Drizzle schema:

1. Back up and validate the current schema in a staging branch/project.
2. Diff the live schema against `20261104171732_base_schema.sql`; do not mark the baseline applied unless they are compatible.
3. Check for duplicate replay keys:
   `select device_id, request_id, count(*) from public.agent_request_replay group by 1,2 having count(*) > 1;`
4. After review, record only the pre-existing baseline in staging migration history with `supabase migration repair 20261104171732 --status applied --linked`.
5. Review and apply `20261104171734_lock_down_data_api_and_replay.sql` to staging with the pinned CLI, then run the Supabase security/performance advisors.
6. Run enrollment, reuse, expiry, revocation, heartbeat, assessment, and tenant-isolation integration tests.
7. Repeat the reviewed migration-history repair and migration push in production only with explicit change approval.

The hardening migration revokes Data API roles because this application uses a database-owner, server-side PostgreSQL connection. A future least-privilege application role needs explicit grants and suitable RLS policies before use. Also disable the Data API in the Supabase dashboard if it is not needed. No migration was applied to a linked or production database during this audit.

## Agent artifact rollout

`.github/workflows/agent-build.yml` builds on native Windows amd64, macOS Intel, and macOS arm64 runners; runs tests and the binary entry point; creates complete packages; computes checksums; and uploads short-lived development artifacts. It never creates a GitHub Release.

To connect a build to the website:

1. Download the CI artifact for the intended platform.
2. Verify its workflow provenance and SHA-256.
3. Perform a real installation, enrollment, initial assessment, heartbeat, restart, and uninstall test on that target OS.
4. Complete production signing/notarization when distributing as trusted software.
5. Copy the package into `agent/dist` (or the protected `AGENT_DIST_DIR`).
6. After the native test, add `nativeVerification` beneath the exact platform artifact in `manifest.json`. Its `sha256` and `buildId` must exactly repeat that artifact's generated values, and `testedAt` plus a durable `evidence` reference are required. Never copy approval metadata to a rebuilt artifact.
7. Deploy the API image with the package directory included and immutable.

The manifest writer derives each `buildId` from version, platform, and package SHA-256 and clears all native approvals on every rebuild. The API recomputes the package checksum and build identity at runtime and refuses missing, mismatched, legacy-boolean, or unapproved packages. The API always reports `signed: false`; editable manifest metadata is not accepted as proof of Authenticode, Developer ID signing, or notarization. Production signing must be cryptographically verified outside this manifest flow.

## Application build

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm run typecheck
PORT=3000 BASE_PATH=/ corepack pnpm run build
corepack pnpm --filter @workspace/api-server test
```

Run the API and SPA behind HTTPS. The repository still requires a platform-specific process definition or reverse proxy that routes the SPA and `/api` to their respective processes; Replit metadata alone is not a portable deployment configuration.

## Operational notes

- The intelligence scheduler is in-process and assumes a single active scheduler instance.
- Enrollment and agent rate limiting is process-local. Use trusted edge/shared rate limiting for horizontally scaled production.
- Reports are stored as base64 in PostgreSQL; move large-fleet report storage to protected object storage.
