# Codex Initial Engineering and Security Audit

Date: 2026-11-04 (Asia/Dubai)
Scope: repository snapshot supplied for NextAura Security Center
Status: pre-remediation evidence baseline

## A. Executive Summary

The repository contains a substantial but incomplete endpoint assessment product: a React/Vite dashboard, an Express/TypeScript API, a Drizzle/PostgreSQL data layer hosted on Supabase, Clerk operator authentication, and a dependency-free Go agent with read-only Windows and macOS collectors.

The agent protocol itself is mostly coherent: enrollment uses a single-use hashed code, creates a per-device token whose hash is stored server-side, and supports authenticated heartbeats and assessment ingestion. The installation experience fails before or around that protocol because the delivery mechanism is incomplete. The dashboard downloads only a raw architecture-specific executable, but the service installation scripts and launchd plist are separate repository files and are not delivered. The generated command uses `nextaura-agent`, which is not the downloaded filename and is not placed on `PATH`. The page also permits users to continue when no verified build is downloadable. There is no GitHub Actions release-build workflow, no complete installer package, no deployment automation that installs release artifacts into `AGENT_DIST_DIR`, and no native installation test evidence in the manifest.

The supplied `agent/dist` contains non-empty Windows amd64 and macOS amd64/arm64 binaries whose SHA-256 values match `SHA256SUMS`. The Windows executable runs its `version` entry point natively in this environment. It is unsigned. The two macOS files have Mach-O magic, but cannot be executed or installation-tested on this Windows host. The manifest marks every platform unverified and unsigned.

Production readiness is further blocked by absent schema migrations, no Data API lockdown/RLS migration for tables created in Supabase's exposed `public` schema, permissive CORS, disabled PostgreSQL certificate verification, weak replay uniqueness, only two Go unit-test files, and no backend/API test harness.

## B. Actual Project Architecture

- Dashboard: React 19, Vite, TypeScript, Tailwind CSS, Radix UI/shadcn-derived components, TanStack Query, Wouter, Clerk React.
- API: Express 5, TypeScript bundled with esbuild, Clerk Express middleware, Zod validation, Pino logging.
- API contract: OpenAPI at `lib/api-spec/openapi.yaml`; generated React Query and Zod clients under `lib/api-client-react` and `lib/api-zod`.
- Database: PostgreSQL through `pg` and Drizzle ORM. `SUPABASE_DB_URL` is a direct server-side Postgres connection; the frontend does not use Supabase Auth or the Supabase Data API.
- Identity and authorization: Clerk authenticates operators. API middleware resolves Clerk users, loads email/user-id organization memberships, selects a current organization, and enforces role ranks.
- Agent: Go 1.22 standard-library module. It supports Windows amd64, macOS amd64, and macOS arm64. It makes outbound HTTPS calls to `/api/agent/v1` and rejects non-HTTPS except loopback development.
- Agent authentication: one-time enrollment code -> device record -> random bearer token; only SHA-256 token hashes are stored server-side.
- Assessment model: six fixed collectors. The agent rejects unknown collector IDs. Collection is read-only and subprocess execution is restricted to an explicit OS-binary allowlist.
- Build delivery: local files under `agent/dist` are enumerated by the API and downloaded through authenticated operator routes. No external release registry or object storage is integrated.
- Deployment: Replit metadata exists, but the snapshot has no complete deployment workflow that starts and routes both the SPA and API, and no GitHub Actions directory.

## C. Implemented Features

- Confirmed: Clerk identity middleware and organization role checks.
- Confirmed: organization-scoped dashboard, device, finding, report, settings, and enrollment queries on reviewed routes.
- Confirmed: hashed, expiring, single-use enrollment codes with an atomic `PENDING` -> `CONSUMED` claim.
- Confirmed: per-device bearer tokens with stored hashes, expiry, revocation checks, and last-used timestamps.
- Confirmed: authenticated heartbeat and assessment endpoints.
- Confirmed: fixed collector allowlist; no remote shell or arbitrary dashboard-supplied script execution.
- Confirmed: Windows collectors for system information, Defender/Security Center, threat history, firewall, BitLocker, software inventory via registry uninstall keys, startup inventory, and security posture.
- Confirmed: macOS collectors for system information, FileVault, firewall, SIP, Gatekeeper, updates, XProtect, software, launchd inventory, and safe network summaries.
- Confirmed: honest UNKNOWN/UNSUPPORTED/PERMISSION_DENIED status model in collector code.
- Confirmed: artifact existence, size, runtime checksum, version, signed and verified metadata are exposed to the dashboard.
- Confirmed: checked-in Windows binary executes `version` on Windows amd64.

## D. Missing Features

### HIGH — Complete installers/packages

- Affected: `agent/dist`, `agent/scripts/*`, `artifacts/security-center/src/pages/enroll.tsx`
- Component: artifact packaging and installation wizard
- Evidence: only raw binaries are served; service scripts and the launchd plist are not included in the download.
- Reproduction: download the Windows or macOS artifact from the wizard; follow the displayed command. The downloaded filename is not `nextaura-agent`, and no service installer accompanies it.
- Proposed correction: create complete per-platform packages containing the binary, integrated install/uninstall scripts, service metadata, checksums, and instructions; serve only explicitly verified packages.

### HIGH — Release CI

- Affected: repository root (missing `.github/workflows`)
- Component: build/release pipeline
- Evidence: no GitHub Actions files exist.
- Reproduction: inspect `rg --files .github`; directory is absent.
- Proposed correction: native Windows and macOS jobs, Go verification/tests, target build, entry-point smoke test, package creation, checksums, and safe artifact upload. Do not auto-publish a release.

### HIGH — Versioned database migrations

- Affected: `lib/db/package.json`, repository root
- Component: database deployment
- Evidence: schema deployment uses `drizzle-kit push`; there is no migration directory or migration history in the snapshot.
- Proposed correction: add a reviewed Supabase migration and document local/staging validation and production application steps.

### MEDIUM — Backend and UI automated tests

- Affected: `artifacts/api-server`, `artifacts/security-center`
- Evidence: no API/UI test files or test scripts; only two Go test files exist.
- Proposed correction: add unit/contract tests and a database-backed integration-test procedure for enrollment, reuse, expiry, revocation, tenant isolation, heartbeat, and assessment persistence.

## E. Broken Features

### CRITICAL — Installation workflow is disconnected from delivered artifact

- Affected: `artifacts/security-center/src/pages/enroll.tsx`
- Function: `Install`, `CodeStep`
- Evidence: download name is `nextaura-agent-windows-amd64.exe` or `nextaura-agent-darwin-*`; generated enrollment command is always `nextaura-agent enroll ...`; no copy/chmod/PATH step is displayed.
- Reproduction: download the file into a normal Downloads directory and paste the generated command. The shell cannot resolve `nextaura-agent`.
- Correction: deliver an installer package and generate exact, platform-specific commands that invoke the package installer with the canonical server URL and one-time code.

### CRITICAL — Service installation files are not delivered

- Affected: `agent/scripts/install-service-windows.ps1`, `agent/scripts/install-service-macos.sh`, `agent/scripts/com.nextaura.agent.plist`, `artifacts/api-server/src/services/agentBuilds.ts`
- Evidence: API platform mapping points only to raw binary filenames.
- Reproduction: download from `/api/agent-builds/:platform/download`; archive/service files are absent.
- Correction: package all required files and make install scripts perform copy, enrollment, credential-directory hardening, service registration, start, and status reporting.

### HIGH — Wizard advances without a usable build

- Affected: `artifacts/security-center/src/pages/enroll.tsx`
- Function: `Install`
- Evidence: `<Nav ... onNext={onNext} />` is always enabled, including missing/unverified build state.
- Reproduction: remove an artifact or use an unverified manifest and click Continue.
- Correction: block continuation until a verified package is available and show a recoverable “Build not available” state.

### HIGH — macOS guidance bypasses platform security

- Affected: `docs/AGENT_INSTALLATION.md`
- Evidence: documentation recommends removing the quarantine attribute with `xattr -d`.
- Correction: remove this instruction; document Developer ID signing, hardened runtime, notarization, stapling, and legitimate Gatekeeper verification.

### HIGH — Production base URL derived from request headers

- Affected: `artifacts/api-server/src/routes/enrollments.ts`
- Function: `serverUrl`
- Evidence: enrollment server URL trusts `x-forwarded-host`/`host` and falls back to localhost.
- Reproduction: send an authenticated enrollment request with a manipulated forwarded host in a deployment that does not sanitize it.
- Correction: require a configured canonical `AGENT_PUBLIC_BASE_URL` in production and validate HTTPS; allow request-derived loopback only in development.

### MEDIUM — Windows installer does not install the downloaded binary

- Affected: `agent/scripts/install-service-windows.ps1`
- Evidence: default target is `C:\Program Files\NextAura\nextaura-agent.exe`, but the script only checks that it already exists.
- Correction: accept a source binary, copy it to the controlled destination, enroll, harden ACLs, then register/start the service.

### MEDIUM — macOS installer depends on repository-relative plist

- Affected: `agent/scripts/install-service-macos.sh`
- Evidence: script reads `$(dirname "$0")/com.nextaura.agent.plist`, but neither file is served with the raw binary.
- Correction: ship both in one package and validate they are co-located.

## F. Installation Workflow Analysis

1. Administrator: authenticated by Clerk; ADMIN or OWNER required to create enrollment.
2. Enrollment page: organization and OS selection are implemented.
3. Build lookup: API checks fixed filenames in a local directory. This works only if deployment happens to contain those files.
4. Download: raw binary only; current manifest is unverified and unsigned.
5. Execution: displayed command does not refer to the downloaded filename/location.
6. Service installation: separate scripts exist but are neither downloaded nor invoked by the wizard.
7. Enrollment protocol: code hash lookup, expiry/status/OS policy validation, atomic redemption, device/token creation are implemented.
8. Credential persistence: state is written to a system-wide directory. Unix modes are requested; Windows ACL enforcement is not demonstrated by code and must be performed by the installer.
9. Initial assessment: agent enroll command runs all six collectors and uploads results.
10. Heartbeat: only begins continuously if the separate service/LaunchDaemon installation succeeds.
11. Persistence/dashboard: API writes device, credential, heartbeat, assessment, inventory, and finding tables; dashboard polls enrollment then device state.

## G. Root Cause of Installation Failure

Confirmed root cause: artifact delivery and installation orchestration are incomplete and mutually inconsistent. The repository contains agent binaries and service scripts, but the web/API delivery path exposes only the binaries; the UI command assumes a different filename and installation state; and there is no native CI packaging/release pipeline or deployment artifact synchronization. Therefore a user cannot reliably move from “Download” to an installed background service using the dashboard alone.

Contributing defects are an untrusted/possibly localhost server URL, unverified unsigned artifacts, missing credential ACL hardening in the Windows installer path, and the ability to continue the wizard without a usable build.

The core enrollment database transaction is not the primary failure found in static tracing. It still lacks database-backed automated coverage, so production behavior remains unverified until tested against a migrated staging database.

## H. Security Issues

### CRITICAL — Supabase public-schema exposure is not controlled

- Affected: all `lib/db/src/schema/*.ts`; missing migrations
- Evidence: tables are created in `public`; no RLS, grant revocation, or Data API lockdown exists in the repository. Current Supabase documentation states that existing projects may automatically grant public-schema tables to Data API roles.
- Correction: because this app uses only a direct server-side database connection, revoke `anon`/`authenticated` access, revoke default privileges, and enable RLS as defense in depth. Alternatively disable the Data API in the Supabase dashboard. Do not apply to production without review/approval.

### HIGH — PostgreSQL TLS certificate verification disabled

- Affected: `lib/db/src/index.ts`, `lib/db/drizzle.config.ts`
- Evidence: `rejectUnauthorized: false` is forced for `SUPABASE_DB_URL`.
- Correction: require certificate verification and a `verify-full` connection configuration.

### HIGH — Credentialed CORS reflects arbitrary origins

- Affected: `artifacts/api-server/src/app.ts`
- Evidence: `cors({ credentials: true, origin: true })`.
- Correction: same-origin by default; explicit normalized allowlist only when separate frontend origins are required.

### HIGH — Replay table lacks uniqueness

- Affected: `lib/db/src/schema/devices.ts`
- Function: `agentRequestReplayTable`, `replaySeen`
- Evidence: `(device_id, request_id)` has a non-unique index; select-then-insert races can admit duplicate requests.
- Correction: unique composite index and atomic insert-on-conflict replay claim.

### MEDIUM — Rate limiting is process-local

- Affected: `artifacts/api-server/src/lib/rateLimit.ts`
- Evidence: in-memory `Map`; limits reset per instance/restart.
- Correction: use trusted edge throttling or a shared store in multi-instance production; increment enrollment attempt counters transactionally.

### MEDIUM — Installer uses PowerShell execution-policy bypass

- Affected: documentation and current workflow
- Evidence: `-ExecutionPolicy Bypass` is recommended.
- Correction: signed scripts for trusted releases; for controlled testing, document hash verification and an explicit one-process policy invocation without presenting it as production trust.

### MEDIUM — Agent token at rest on Windows is not proven ACL-restricted

- Affected: `agent/internal/config/config.go`, Windows installer
- Evidence: Go mode `0600` does not itself demonstrate a restrictive Windows DACL.
- Correction: installer creates the state directory with inheritance removed and grants only LocalSystem and Administrators.

### LOW — Enrollment code modulo bias

- Affected: `artifacts/api-server/src/lib/crypto.ts`
- Function: `generateEnrollmentCode`
- Evidence: random bytes are reduced with `% 32`; because alphabet length is exactly 32, there is no modulo bias. This item was investigated and is **not a defect**.

## I. Database and API Issues

- Confirmed: no committed migrations or local schema-validation setup.
- Confirmed: server-side routes generally scope operator data by organization; reviewed device child queries first load an organization-scoped device.
- Confirmed: agent credentials join to their device and organization, and revoked devices/tokens are rejected.
- Confirmed: assessment requests are restricted to six fixed collector IDs at dashboard schema, server schema, and agent execution layers.
- Confirmed defect: replay claim is not atomic/unique.
- Confirmed defect: enrollment `attemptCount` exists but is never incremented.
- Unverified: real Supabase grants/RLS state, because no production database inspection or mutation was authorized and no linked project context was supplied.
- Unverified: production Clerk custom-domain proxy behavior.

## J. Build and Deployment Issues

- No Git repository metadata is present in this extracted snapshot, so branch/history and tracked-file assertions cannot be verified.
- No `.github/workflows` exists.
- Replit metadata names an autoscale deployment but does not define a complete start workflow in the snapshot.
- API build bundles only the server entry point; agent artifacts remain external filesystem dependencies.
- Frontend Vite build and API server are separate artifacts with no documented production reverse-proxy/static-serving topology.
- Existing macOS binaries are not proven signed, notarized, stapled, or executable on native targets.
- Existing Windows binary is unsigned but its entry point runs on this Windows amd64 host.

## K. Test Coverage

- Present: Go tests for URL validation, fixed collector registry, unknown collector rejection, exec allowlist, and UNKNOWN-not-PASS semantics.
- Missing: backend route tests, database integration tests, authentication/tenant tests, UI tests, installer tests, release workflow, and migration tests.
- Baseline command results:
  - `agent/dist/nextaura-agent-windows-amd64.exe version`: PASS (`0.1.0`, windows/amd64).
  - SHA-256 recomputation vs `SHA256SUMS`: PASS for all three supplied binaries.
  - Windows Authenticode: `NotSigned`.
  - macOS header inspection: Mach-O magic present for amd64 and arm64; native execution not tested.
  - `go test ./...`: BLOCKED because Go is not installed on this host.
  - pnpm TypeScript/build tests: BLOCKED initially because pnpm/dependencies are not installed.
  - Supabase CLI: present at 2.122.0; current changelog warns that CLI v3 changes hosted/local defaults, so automation must pin/discover commands.

## L. Prioritized Fix Plan

1. Package each platform build with exact install/uninstall tooling and service metadata.
2. Gate downloads and wizard progression on an explicitly verified manifest entry.
3. Add canonical public API URL configuration and strict HTTPS validation.
4. Add native Windows/macOS CI jobs, smoke tests, checksums, version metadata, and artifact uploads without automatic release publication.
5. Integrate safe platform-specific UI instructions, OS detection/manual override, recovery errors, expiration, consent, and confirmed enrollment/heartbeat states.
6. Add a Supabase migration that locks the unused Data API surface and makes replay claims unique; do not apply it to production.
7. Make replay protection atomic and increment invalid enrollment attempts.
8. Restore PostgreSQL certificate verification and restrict CORS.
9. Add unit/contract tests and document database-backed end-to-end tests.
10. Run TypeScript checks, production builds, Go tests/builds, artifact integrity checks, and native tests available in this environment; explicitly record remaining native macOS and production-database gaps.

## Supplemental Defects Confirmed During Remediation

These defects were uncovered only after the pre-change trace was complete:

### HIGH — Windows state updates cannot replace the existing state file

- Affected: `agent/internal/config/config.go`, function `Save`.
- Evidence: the implementation wrote a temporary file and called `os.Rename` over `state.json`. On Windows, that operation fails when the destination exists.
- Reproduction: save an enrolled state twice on Windows; the second save fails. Scheduler timestamps therefore cannot persist reliably and assessments may repeat.
- Correction: use `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` on Windows and retain atomic rename on Unix; add a two-save regression test.

### MEDIUM — Windows dependency installation is blocked by a Unix-only preinstall command

- Affected: root `package.json` preinstall command.
- Evidence: the package-manager check used Unix shell syntax and failed before pnpm could install dependencies on Windows.
- Correction: replace it with a cross-platform Node script and use current pnpm `allowBuilds` configuration.

### MEDIUM — Workspace overrides remove native web-build dependencies

- Affected: `pnpm-workspace.yaml`.
- Evidence: overrides replaced every Rollup, esbuild, Tailwind oxide, and Lightning CSS native optional package with `-`; the Windows production build failed to load `@rollup/rollup-win32-x64-msvc`, and the same configuration would break native macOS/Linux builds.
- Correction: retain normal platform optional-dependency resolution and update the frozen lockfile.
