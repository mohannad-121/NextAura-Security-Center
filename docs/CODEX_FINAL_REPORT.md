# Codex Final Engineering and Security Report

Date: 2026-11-05 (Asia/Dubai; updated after independent PR review)
Scope: supplied NextAura Security Center repository snapshot
Final classification: **CONDITIONALLY READY**

This classification means the codebase and package flow are ready for a controlled staging exercise, but not for production distribution. The migration chain now passes isolated local reset, lint, and pgTAP security tests. Production remains gated on application-level database integration, native installation/enrollment/restart/uninstall tests on all three targets, code signing/notarization, and deployment of reviewed migrations and artifacts.

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

| Severity | Confirmed problem                                                                    | Disposition                                                                                                                        |
| -------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| CRITICAL | Raw binary delivery was incompatible with displayed install command                  | Fixed with complete per-platform packages and exact commands                                                                       |
| CRITICAL | Service/LaunchDaemon files were not delivered                                        | Fixed; included in archives                                                                                                        |
| CRITICAL | Supabase public-schema exposure had no repository-controlled grants/RLS boundary     | Fixed in an unapplied hardening migration; production review still required                                                        |
| HIGH     | Wizard advanced when no verified build existed                                       | Fixed; download path and progression require `available && verified`                                                               |
| HIGH     | Agent server URL trusted forwarded/host headers in production                        | Fixed; production requires canonical HTTPS `AGENT_PUBLIC_BASE_URL`                                                                 |
| HIGH     | Credentialed CORS accepted arbitrary origins                                         | Fixed; same-origin default plus explicit `APP_ORIGINS` allowlist                                                                   |
| HIGH     | PostgreSQL TLS certificate validation was disabled                                   | Fixed; forced bypass removed and `sslmode=verify-full` documented                                                                  |
| HIGH     | Replay protection used select-then-insert with a non-unique index                    | Fixed with a unique index and atomic insert-on-conflict claim                                                                      |
| HIGH     | No migration history or greenfield baseline                                          | Fixed with ordered baseline and hardening migrations                                                                               |
| HIGH     | No native package-validation workflow                                                | Fixed with Windows amd64, macOS Intel, and macOS arm64 jobs                                                                        |
| HIGH     | Windows state replacement failed after the first save                                | Fixed with `MoveFileExW` replace/write-through and regression coverage                                                             |
| HIGH     | Existing platform-support checks could become misleading as OS support dates changed | Updated to a dated, fail-closed Windows/macOS support table; future unknown releases remain `UNKNOWN`                              |
| MEDIUM   | Windows installer did not copy its source binary or prove state ACL restriction      | Fixed; it copies, ACL-hardens, enrolls, registers, and starts the service                                                          |
| MEDIUM   | macOS installer depended on a repository-relative plist                              | Fixed by packaging all required files and validating co-location                                                                   |
| MEDIUM   | Documentation advised a Gatekeeper quarantine bypass                                 | Removed; legitimate signing/notarization steps documented                                                                          |
| MEDIUM   | Known invalid/expired/reused code attempts were not counted                          | Fixed for matched records                                                                                                          |
| MEDIUM   | Windows dependency install used Unix-only shell syntax                               | Fixed with a cross-platform Node preinstall check                                                                                  |
| MEDIUM   | Workspace overrides removed native Rollup/esbuild/CSS packages                       | Fixed; native optional dependencies resolve normally on each host                                                                  |
| MEDIUM   | API development command used Unix-only `export` syntax                               | Fixed with a cross-platform command                                                                                                |
| MEDIUM   | API/enrollment protocol had no automated tests                                       | Partially fixed with 17 contract/security tests plus six migration security assertions; application DB integration remains pending |
| HIGH     | Rebuilds inherited editable verification/signing booleans from previous artifacts    | Fixed; rebuilds clear approvals and runtime approval is bound to exact SHA-256 plus build identity                                 |
| HIGH     | Enrollment codes appeared in shell history and process arguments                     | Fixed; installers request hidden input and pass the code to the agent only over stdin                                              |
| HIGH     | Checked-in macOS archives could lack executable mode bits when packaged on Windows   | Fixed in artifacts and enforced by native CI extraction checks                                                                     |
| MEDIUM   | GNU-only tar mode flags failed on GitHub's BSD-tar macOS runners                      | Fixed with GNU/BSD portable archive-mode handling                                                                                   |
| MEDIUM   | Windows CI treated checkout CRLF as unformatted Go source                            | Fixed with repository LF attributes for Go/shell/workflow files                                                                    |
| MEDIUM   | Rate limits are process-local                                                        | Open; requires edge or shared-store enforcement before horizontal production scaling                                               |
| LOW      | Enrollment alphabet modulo bias was suspected                                        | Closed as not a defect: the alphabet contains exactly 32 symbols                                                                   |

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
- Replaced boolean artifact trust with deterministic, hash-bound build identities and native-test records; signing is never inferred from editable manifest metadata.
- Removed enrollment codes from generated commands and process arguments; Windows and macOS installers now use hidden interactive entry and stdin.
- Made service installation retry-safe, created missing macOS installation directories, narrowed uninstall deletion targets, and added package permission checks.
- Added isolated Supabase reset/lint plus six pgTAP grant/RLS/index integration assertions.

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
- `.github/workflows/database-validation.yml`
- `.gitattributes`
- `scripts/verify-package-manager.mjs`
- `agent/scripts/uninstall-agent-windows.ps1`
- `agent/scripts/uninstall-agent-macos.sh`
- `agent/scripts/PACKAGE_README.txt`
- `agent/scripts/write-manifest.mjs` and `write-manifest.test.mjs`
- `agent/internal/config/replace_windows.go`
- `agent/internal/config/replace_unix.go`
- `agent/internal/config/config_test.go`
- API tests/helpers: `crypto.test.ts`, `publicBaseUrl.ts`, `publicBaseUrl.test.ts`, `routes/agent/enrollmentState.ts`, `enrollmentState.test.ts`, `contract.test.ts`, `services/agentBuilds.test.ts`
- Drizzle generation state: `lib/db/drizzle/0000_base_schema.sql` and `lib/db/drizzle/meta/*`
- Supabase: `supabase/config.toml`, `20261104171732_base_schema.sql`, `20261104171734_lock_down_data_api_and_replay.sql`
- Database integration: `supabase/tests/database/security.test.sql`
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
- Isolated local validation passed on Docker Desktop 29.8.0: both migrations replayed in order, migration history matched, public-schema lint returned no errors, and all six pgTAP security assertions passed.
- For an existing database, first diff it against the baseline and check replay duplicates. Only after confirming compatibility should an operator mark the baseline as already applied, then deploy the hardening migration to staging. Exact commands and safeguards are in `docs/DEPLOYMENT.md`.
- The current direct connection must be the database owner. A future least-privilege application role requires explicit grants and RLS policies.

## 9. Test results

| Command/check                                                 | Result        | Scope                                                                      |
| ------------------------------------------------------------- | ------------- | -------------------------------------------------------------------------- |
| `corepack pnpm install --frozen-lockfile`                     | PASS          | reproducible workspace install                                             |
| `corepack pnpm --filter @workspace/api-server test`           | PASS, 17/17   | crypto, URL, contract, enrollment-state, and hash-bound build-gating tests |
| `corepack pnpm run typecheck`                                 | PASS          | all library/artifact TypeScript projects                                   |
| `PORT=3000 BASE_PATH=/ corepack pnpm run build`               | PASS          | API, dashboard, and mockup production builds                               |
| Go 1.22.12 `go mod verify`                                    | PASS          | module integrity                                                           |
| Go 1.22.12 `go test ./...` on Windows                         | PASS          | client, collectors, config including double-save regression                |
| Go 1.22.12 `go vet ./...` on Windows                          | PASS          | native Windows source set                                                  |
| Go cross-builds for windows/amd64, darwin/amd64, darwin/arm64 | PASS          | compilation only for macOS targets                                         |
| Rebuilt Windows binary `version`                              | BLOCKED       | Windows Application Control blocked execution; policy was not bypassed     |
| `node --test agent/scripts/write-manifest.test.mjs`           | PASS, 1/1     | rebuild changes hash/build identity and clears native approval             |
| PowerShell parser for Windows build/install/uninstall scripts | PASS          | syntax only; policy was not bypassed                                       |
| Archive member inspection                                     | PASS          | all packages contain required files                                        |
| Recomputed SHA-256 vs `SHA256SUMS`                            | PASS          | final three packages                                                       |
| Windows Authenticode check                                    | `NotSigned`   | accurately retained as untrusted development artifact                      |
| ESLint                                                        | NOT AVAILABLE | no ESLint configuration or lint script exists in the supplied workspace    |
| `supabase db reset --local --no-seed`                         | PASS          | empty-database replay of baseline then hardening                           |
| `supabase db lint --local --schema public`                    | PASS          | no schema errors                                                           |
| `supabase test db --local ...security.test.sql`               | PASS, 6/6     | RLS, grants, schema access, replay uniqueness, owner access, policies      |

The successful API tests do not exercise Clerk, application PostgreSQL transactions, tenant isolation, heartbeat persistence, assessment persistence, or revocation against a live application database. Those remain staging integration tests, not silently mocked successes. The new pgTAP suite validates migration security boundaries only.

The production build emits a non-fatal warning for a roughly 1.07 MB minified dashboard JavaScript chunk. Route-level splitting is recommended before large-scale deployment.

## 10. Final package evidence

| Package                              | SHA-256                                                            | Trust state                                                                 |
| ------------------------------------ | ------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `nextaura-agent-windows-amd64.zip`   | `16588e1b4c78131f05c6b351b74653daa2f4130a5b2a66e6bf47b92cd051161e` | cross-built; unsigned; native execution and enrollment unverified            |
| `nextaura-agent-darwin-amd64.tar.gz` | `7e0536b0044588ea2bfc9373d5ba96c41b8d717362ae6fa1d336039b24037640` | cross-built; executable archive modes verified; native execution unverified |
| `nextaura-agent-darwin-arm64.tar.gz` | `6063fd467f0ffc098a97c162aeb5204b0756b92354648aef4cb693e0127b8074` | cross-built; executable archive modes verified; native execution unverified |

`agent/dist/manifest.json` uses schema version 2. Each artifact records its generated SHA-256 and deterministic build identity with `nativeVerification: null`. Rebuilds always reset that field. The API recomputes both values and ignores legacy booleans; it exposes no download path until a matching native-test record exists. It always reports signing as false because editable metadata is not cryptographic evidence.

## 11. Native OS testing status

- Windows amd64: compiled, unit-tested, and vetted. Windows Application Control blocked the rebuilt final executable's entry point, and that policy was not bypassed. No administrator service installation or real enrollment was performed because no disposable elevated endpoint and migrated staging backend were available.
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
7. Add a hash/build-identity-matching `nativeVerification` record only after a full native test. Do not represent signing through manifest flags; cryptographically verify signing/notarization in the controlled release process.
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

It is **not production-ready today** because the final packages are intentionally unverified/unsigned, no application-level database-backed enrollment was run, and neither Windows service installation nor macOS launchd installation completed end to end. The migration chain itself now passes isolated local validation. The application fails closed at package trust boundaries instead of presenting modified, unavailable, or unverified software as installable.
