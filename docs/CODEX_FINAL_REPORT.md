# Codex Final Engineering and Security Report

Date: 2026-11-04 (Asia/Dubai)
Scope: supplied NextAura Security Center repository snapshot
Final classification: **CONDITIONALLY READY**

This classification means the codebase and package flow are ready for a controlled staging exercise, but not for production distribution. Production remains gated on a database-backed integration run, native installation/enrollment/restart/uninstall tests on all three targets, code signing/notarization, and deployment of reviewed migrations and artifacts.

## 1. Initial system status

The snapshot contained a coherent React/Express/PostgreSQL product and a constrained, read-only Go agent, but no usable dashboard-to-service installation path. The API served raw binaries while the required installer scripts and macOS plist remained separate. The UI displayed a command for a different filename, allowed progress without a verified build, and could embed a request-controlled host in agent configuration. There was no native CI, migration history, API test suite, or evidence that checked-in packages had completed native enrollment.

The agent protocol was stronger than the delivery path: one-time enrollment codes were hashed, a successful claim was transactional, per-device bearer tokens were stored as hashes, agent routes checked device/token expiry and revocation, and collector execution was limited to six predefined read-only collectors.

## 2. Confirmed installation root cause

The primary failure was a disconnected build/package/install chain, not a single database or Go protocol defect:

1. The build output was a raw architecture-specific executable.
2. The API exposed that executable without the service installer, uninstaller, or launchd plist.
3. The UI instructed the user to invoke `nextaura-agent`, although the download had another filename and was not installed on `PATH`.
4. The Windows script expected an already-installed binary; the macOS script expected a repository-relative plist.
5. No native CI created and checked complete packages.
6. Missing/unverified files did not prevent the wizard from continuing.

A second Windows-only runtime defect would have appeared after enrollment: `os.Rename` could not replace an existing `state.json`, so subsequent scheduler timestamps/state saves could fail and cause repeated full assessment work.

## 3. Confirmed problems and disposition

| Severity | Confirmed problem                                                                    | Disposition                                                                                           |
| -------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| CRITICAL | Raw binary delivery was incompatible with displayed install command                  | Fixed with complete per-platform packages and exact commands                                          |
| CRITICAL | Service/LaunchDaemon files were not delivered                                        | Fixed; included in archives                                                                           |
| CRITICAL | Supabase public-schema exposure had no repository-controlled grants/RLS boundary     | Fixed in an unapplied hardening migration; production review still required                           |
| HIGH     | Wizard advanced when no verified build existed                                       | Fixed; download path and progression require `available && verified`                                  |
| HIGH     | Agent server URL trusted forwarded/host headers in production                        | Fixed; production requires canonical HTTPS `AGENT_PUBLIC_BASE_URL`                                    |
| HIGH     | Credentialed CORS accepted arbitrary origins                                         | Fixed; same-origin default plus explicit `APP_ORIGINS` allowlist                                      |
| HIGH     | PostgreSQL TLS certificate validation was disabled                                   | Fixed; forced bypass removed and `sslmode=verify-full` documented                                     |
| HIGH     | Replay protection used select-then-insert with a non-unique index                    | Fixed with a unique index and atomic insert-on-conflict claim                                         |
| HIGH     | No migration history or greenfield baseline                                          | Fixed with ordered baseline and hardening migrations                                                  |
| HIGH     | No native package-validation workflow                                                | Fixed with Windows amd64, macOS Intel, and macOS arm64 jobs                                           |
| HIGH     | Windows state replacement failed after the first save                                | Fixed with `MoveFileExW` replace/write-through and regression coverage                                |
| HIGH     | Existing platform-support checks could become misleading as OS support dates changed | Updated to a dated, fail-closed Windows/macOS support table; future unknown releases remain `UNKNOWN` |
| MEDIUM   | Windows installer did not copy its source binary or prove state ACL restriction      | Fixed; it copies, ACL-hardens, enrolls, registers, and starts the service                             |
| MEDIUM   | macOS installer depended on a repository-relative plist                              | Fixed by packaging all required files and validating co-location                                      |
| MEDIUM   | Documentation advised a Gatekeeper quarantine bypass                                 | Removed; legitimate signing/notarization steps documented                                             |
| MEDIUM   | Known invalid/expired/reused code attempts were not counted                          | Fixed for matched records                                                                             |
| MEDIUM   | Windows dependency install used Unix-only shell syntax                               | Fixed with a cross-platform Node preinstall check                                                     |
| MEDIUM   | Workspace overrides removed native Rollup/esbuild/CSS packages                       | Fixed; native optional dependencies resolve normally on each host                                     |
| MEDIUM   | API development command used Unix-only `export` syntax                               | Fixed with a cross-platform command                                                                   |
| MEDIUM   | API/enrollment protocol had no automated tests                                       | Partially fixed with 15 pure contract/security tests; DB integration remains pending                  |
| MEDIUM   | Rate limits are process-local                                                        | Open; requires edge or shared-store enforcement before horizontal production scaling                  |
| LOW      | Enrollment alphabet modulo bias was suspected                                        | Closed as not a defect: the alphabet contains exactly 32 symbols                                      |

No arbitrary command, remote shell, file retrieval, remediation, screen/camera/microphone, credential extraction, or inbound control port was added. Collector IDs remain fixed at the schema, API, and agent layers.

## 4. Fixes implemented

- Built complete Windows ZIP and macOS tar packages with installer, uninstaller, instructions, and service metadata.
- Added integrated Windows and macOS installation/uninstallation scripts with explicit elevation, enrollment, credential-directory protection, service startup, and diagnostics.
- Changed artifact mapping and downloads from raw executables to packages; unverified packages have no download URL and the route rejects direct requests.
- Reworked the seven-step enrollment UI for OS detection/manual override, architecture selection, availability/verification states, consent before command display, expiry/polling, confirmed enrollment, and authenticated-heartbeat confirmation.
- Added semantic current-step and live status announcements for assistive technology.
- Added canonical origin validation, strict production HTTPS, restricted CORS, and verified PostgreSQL TLS defaults.
- Made replay claims atomic and enrollment state decisions independently testable.
- Fixed atomic state replacement on Windows.
- Added fail-closed current OS-support checks and native-target tests.
- Added a native GitHub Actions package pipeline that uploads development artifacts only and never creates a release.
- Added a complete database baseline and deny-by-default Supabase Data API/RLS hardening migration.
- Restored cross-platform package installation/build behavior and a frozen lockfile.

## 5. Files modified

The supplied snapshot has no `.git` metadata, so this is the audited change set rather than a Git diff:

- Root/tooling: `.env.example`, `.gitignore`, `README.md`, `package.json`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`.
- API: `artifacts/api-server/package.json`, `src/app.ts`, `src/routes/agent/contract.ts`, `src/routes/agent/index.ts`, `src/routes/agentBuilds.ts`, `src/routes/enrollments.ts`, `src/services/agentBuilds.ts`.
- UI: `artifacts/security-center/src/pages/enroll.tsx`.
- Database: `lib/db/drizzle.config.ts`, `lib/db/src/index.ts`, `lib/db/src/schema/devices.ts`.
- Agent: `agent/internal/config/config.go`, `agent/internal/client/client_test.go`, both platform collector implementations/tests, build scripts, Windows/macOS installers, plist, package metadata, checksums, and manifest.
- Documentation: `AGENT_INSTALLATION.md`, `DEPLOYMENT.md`, `KNOWN_LIMITATIONS.md`, `SECURITY_MODEL.md`, and `SUPPORTED_PLATFORMS.md`.

## 6. New files created

- `.github/workflows/agent-build.yml`
- `scripts/verify-package-manager.mjs`
- `agent/scripts/uninstall-agent-windows.ps1`
- `agent/scripts/uninstall-agent-macos.sh`
- `agent/scripts/PACKAGE_README.txt`
- `agent/internal/config/replace_windows.go`
- `agent/internal/config/replace_unix.go`
- `agent/internal/config/config_test.go`
- API tests/helpers: `crypto.test.ts`, `publicBaseUrl.ts`, `publicBaseUrl.test.ts`, `routes/agent/enrollmentState.ts`, `enrollmentState.test.ts`, `contract.test.ts`, `services/agentBuilds.test.ts`
- Drizzle generation state: `lib/db/drizzle/0000_base_schema.sql` and `lib/db/drizzle/meta/*`
- Supabase: `supabase/config.toml`, `20261104171732_base_schema.sql`, `20261104171734_lock_down_data_api_and_replay.sql`
- Audit reports: `docs/CODEX_INITIAL_AUDIT.md`, `docs/CODEX_FINAL_REPORT.md`
- Development packages under `agent/dist` for all three targets.

## 7. Dependency and build-tool updates

- Added `tsx` as an API development dependency for Node's test runner.
- Replaced the legacy pnpm build-dependency allowlist with current `allowBuilds` configuration.
- Removed platform-native dependency exclusions that broke Rollup and would break web builds across host operating systems.
- Regenerated `pnpm-lock.yaml`; `corepack pnpm install --frozen-lockfile` passes.
- No runtime framework migration or agent third-party dependency was introduced. The Go agent remains standard-library only.

## 8. Database migration requirements

No linked, staging, or production database was changed.

- `20261104171732_base_schema.sql` creates the complete 23-table schema for an empty database.
- `20261104171734_lock_down_data_api_and_replay.sql` revokes `public`/Data API role access and default privileges, enables RLS without public policies, and relies on the baseline's unique replay index.
- Local reset/lint could not run because Docker Desktop's Linux engine was not running on this host.
- For an existing database, first diff it against the baseline and check replay duplicates. Only after confirming compatibility should an operator mark the baseline as already applied, then deploy the hardening migration to staging. Exact commands and safeguards are in `docs/DEPLOYMENT.md`.
- The current direct connection must be the database owner. A future least-privilege application role requires explicit grants and RLS policies.

## 9. Test results

| Command/check                                                 | Result        | Scope                                                                   |
| ------------------------------------------------------------- | ------------- | ----------------------------------------------------------------------- |
| `corepack pnpm install --frozen-lockfile`                     | PASS          | reproducible workspace install                                          |
| `corepack pnpm --filter @workspace/api-server test`           | PASS, 15/15   | mocked/pure crypto, URL, contract, enrollment-state, build-gating tests |
| `corepack pnpm run typecheck`                                 | PASS          | all library/artifact TypeScript projects                                |
| `PORT=3000 BASE_PATH=/ corepack pnpm run build`               | PASS          | API, dashboard, and mockup production builds                            |
| Go 1.22.12 `go mod verify`                                    | PASS          | module integrity                                                        |
| Go 1.22.12 `go test ./...` on Windows                         | PASS          | client, collectors, config including double-save regression             |
| Go 1.22.12 `go vet ./...` on Windows                          | PASS          | native Windows source set                                               |
| Go cross-builds for windows/amd64, darwin/amd64, darwin/arm64 | PASS          | compilation only for macOS targets                                      |
| Windows binary `version`                                      | PASS          | native entry point, reports `0.1.0 (windows/amd64)`                     |
| PowerShell parser for Windows build/install/uninstall scripts | PASS          | syntax only; policy was not bypassed                                    |
| Archive member inspection                                     | PASS          | all packages contain required files                                     |
| Recomputed SHA-256 vs `SHA256SUMS`                            | PASS          | final three packages                                                    |
| Windows Authenticode check                                    | `NotSigned`   | accurately retained as untrusted development artifact                   |
| ESLint                                                        | NOT AVAILABLE | no ESLint configuration or lint script exists in the supplied workspace |
| `docker info` / local Supabase reset                          | BLOCKED       | Docker Linux engine unavailable                                         |

The successful API tests do not exercise Clerk, PostgreSQL transactions, tenant isolation, heartbeat persistence, assessment persistence, or revocation against a live database. Those remain staging integration tests, not silently mocked successes.

The production build emits a non-fatal warning for a roughly 1.07 MB minified dashboard JavaScript chunk. Route-level splitting is recommended before large-scale deployment.

## 10. Final package evidence

| Package                              | SHA-256                                                            | Trust state                                                    |
| ------------------------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------- |
| `nextaura-agent-windows-amd64.zip`   | `9d11c6912d477cddaf461fc4700a082155facc780bf17927dbcc29eca076a280` | native entry point passed; unsigned; enrollment unverified     |
| `nextaura-agent-darwin-amd64.tar.gz` | `3589b3dd0fabac45a2728ca3e5b1c3cf65746560d61ccfae523d05baed435e1a` | cross-built; unsigned/unnotarized; native execution unverified |
| `nextaura-agent-darwin-arm64.tar.gz` | `9bf4220fd0339574337d4544175b2c42b5b353079edee1ef5fbc33fc750089da` | cross-built; unsigned/unnotarized; native execution unverified |

`agent/dist/manifest.json` intentionally contains empty `verified` and `signed` maps. Consequently, the dashboard reports the packages but the API exposes no download path. This is the required fail-closed state until native enrollment evidence exists.

## 11. Native OS testing status

- Windows amd64: compiled, unit-tested, vetted, and the final executable's entry point ran natively. No administrator service installation or real enrollment was performed because no disposable elevated endpoint and migrated staging backend were available.
- macOS Intel/arm64: compiled by Go cross-build only in this environment. The workflow uses native Intel and Apple-silicon GitHub runners for tests, build, and entry-point execution. Real launchd installation, enrollment, restart, uninstall, Developer ID signing, notarization, and stapling remain unverified.

## 12. Remaining limitations and recommendations

- Run database-backed tests for valid/invalid/expired/reused enrollment, token expiry/revocation, cross-tenant denial, heartbeat persistence, assessment persistence, and agent-request replay.
- Move process-local rate limiting to an edge policy or shared store before multi-instance production.
- Pin GitHub Actions to reviewed commit SHAs for stronger CI supply-chain control.
- Sign Windows binaries/scripts; sign the macOS binary and installer, enable hardened runtime, notarize, staple, and verify. Never bypass SmartScreen, Gatekeeper, SIP, or TCC.
- Move large report payloads from base64 PostgreSQL storage to protected object storage.
- Add route-level frontend code splitting and performance budgets.
- Define the production process/reverse-proxy topology that serves the SPA and API and immutably includes `AGENT_DIST_DIR`.
- Keep OS support tables tied to a documented review date; future releases intentionally return `UNKNOWN` until reviewed.

## 13. Deployment steps

1. Start Docker Desktop and pass the local migration reset/lint procedure in `docs/DEPLOYMENT.md`.
2. Create an isolated Supabase staging project, review/diff the baseline, apply migration history safely, and deploy the hardening migration.
3. Configure Clerk staging keys, `SUPABASE_DB_URL` with `sslmode=verify-full`, canonical HTTPS `AGENT_PUBLIC_BASE_URL`, and an explicit `APP_ORIGINS` only if origins differ.
4. Build and deploy the SPA/API behind HTTPS with immutable agent artifact storage.
5. Run the native CI workflow. Download artifacts and verify provenance/checksums.
6. Complete target-OS test installations and production signing/notarization.
7. Set `verified.<platform>` only after a full native test; set `signed.<platform>` only after cryptographic verification; redeploy artifacts.
8. Repeat database tests and security/advisor checks, then obtain explicit production change approval.

## 14. Controlled installation test plan

For each target architecture on a disposable, supported endpoint:

1. Create a staging enrollment and confirm the UI-selected architecture and displayed checksum.
2. Extract the complete package and run the exact installer command with administrator authorization.
3. Confirm one-time code redemption, device creation, token redaction, initial assessment persistence, inventory/findings, and first authenticated heartbeat.
4. Restart the endpoint and verify service/LaunchDaemon startup plus continued state persistence.
5. Attempt code reuse, an expired code, an invalid request, a replayed agent request, and a revoked device token; all must fail safely.
6. Verify another organization cannot access the device or its findings.
7. Review collector evidence: unknown/permission-denied/unsupported conditions must never become `PASS`.
8. Revoke the device, uninstall the agent, confirm service removal, and remove local state only after revocation.

## 15. Overall readiness

**CONDITIONALLY READY** for a controlled staging/native-test campaign.

It is **not production-ready today** because the final packages are intentionally unverified/unsigned, no real database-backed enrollment was run, the Supabase migration could not be locally reset without Docker, and neither Windows service installation nor macOS launchd installation completed end to end. The application now fails closed at those trust boundaries instead of presenting unavailable or unverified software as installable.
