# تقرير Codex للفحص المركزي

## ملخص عربي موجز

تم تنفيذ مسار فحص مركزي دفاعي للأنظمة المسجّلة دون إضافة تحكم عن بُعد أو أوامر عشوائية. يستطيع محلل مصرح له اختيار جهاز أو عدة أجهزة، وطلب مجمّعات أمنية ثابتة أو فحص ملفات ضمن نطاق محلي وافق عليه مسؤول الجهاز. لا يرسل الخادم مسارات ملفات، ولا يرفع الوكيل محتوى الملفات، ولا ينفذها أو يحذفها أو يعزلها.

تُعرض الحالات الفعلية فقط، ولا تظهر حالة `RUNNING` إلا بعد تأكيد الوكيل. أضيف ابتلاع تلقائي موثّق لأدلة الملفات، ومنع إعادة الإرسال والانتحال، وعزل المؤسسات، وسجل تدقيق، وتقارير PDF. تم توسيع التحليل الساكن المحدود لملفات ZIP المتداخلة وISO9660 وPE مع حدود صارمة ونتائج صريحة عند نقص الرؤية.

أكد التحقيق المحلي أن ملف Windows الحالي غير موقّع، وأن سياسة Windows Code Integrity/WDAC ذات المعرّف `{0283ac0f-fff1-49ae-ada1-8a933130cad6}` منعته لعدم استيفاء مستوى التوقيع المؤسسي. لم يتم تعطيل أو تجاوز أي حماية. لذلك يبقى التثبيت الأصلي والإنتاج محجوبين إلى حين توقيع موثوق واختبارات Windows وmacOS فعلية.

---

# Technical Engineering Report

## 1. Executive summary

Branch `codex/centralized-threat-scanning` extends PR #2 with an evidence-driven dashboard-to-agent scan path. It preserves the outbound-only authenticated agent channel and read-only endpoint model. No existing PR was merged, no deployment or release was created, and no production Supabase project was contacted.

## 2. Previous limitations

The platform could request fixed collectors for one device, but had no fleet scan model, local scope registry, authenticated file-evidence ingestion, genuine multi-device lifecycle, Scan Center, or scan report. File metadata required analyst JSON import. ISO and nested archive coverage was shallow. Windows blocking was recorded but not tied to the exact enforcing policy.

## 3. Implemented functionality

- Transactional individual, multi-device and organization-wide scan jobs.
- Fixed assessment and approved-scope operations over the existing agent poll channel.
- Local administrator scope add/list/revoke commands with consent and personal-directory guard.
- Agent-reported scope ID/label state without transmitting paths.
- Bounded folder scanning, sanitized metadata ingestion and five-attempt network backoff.
- Genuine job stages, safe pending cancellation, expiry, partial-result and visibility-gap reporting.
- Scan Center history, per-device comparison, evidence provenance, incident links and PDF export.
- Windows application-control event-count collector and independent signing verification scripts.

## 4. Centralized scanning architecture

The Clerk-authenticated operator API creates `scan_jobs`, `scan_job_devices` and fixed `agent_requests` in one PostgreSQL transaction. The agent pulls requests after heartbeat, validates compiled operation/collector allowlists and local scope state, acknowledges before execution, and submits evidence using its device credential. The API derives organization/device identity and never trusts client-supplied tenancy.

## 5. Agent-to-server communication

The only network client remains `agent/internal/client`. Requests use outbound HTTPS except explicit localhost development, reject redirects, bound time and response size, and authenticate with a revocable hashed device token. No inbound port, remote shell, dashboard script, arbitrary path, arbitrary SQL or secondary control channel was introduced.

## 6. File analysis capabilities

Implemented static coverage includes hashes, magic/type mismatch, double extensions, ZIP/Office containers, encrypted flags, traversal names, bounded nested ZIPs, read-only ISO9660 metadata, PE imports/sections/certificate-table metadata, MSI/OLE, LNK, PDF, RTF and scripts. Scope evidence records detector ID/version, source, timestamp, severity, confidence, classification and limitations. File content and plaintext paths are not uploaded.

## 7. Windows App Control investigation

The inspected development artifact SHA-256 is `ce0ff80b3b1bc6717fb79522fcd21fffce355d25745f949f067d887b333e30ef` and Authenticode status is `NotSigned`. Code Integrity events 3033 and 3077 name failure of Enterprise signing-level requirements; event 3077 identifies enforced policy `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`. This confirms WDAC/App Control for Business enforcement for the observed block. No matching AppLocker or Defender event established a different cause.

## 8. Windows signing status

Unsigned and blocked. `verify-windows-signing.ps1` provides independent checksum, Authenticode, signer, timestamp and certificate evidence after an external organization-controlled signer is available. It does not sign or consume credentials. Production and native testing remain blocked.

## 9. macOS signing/notarization status

Builds are development artifacts only. Developer ID signing, hardened-runtime review, notarization, stapling and Gatekeeper installation evidence are unavailable. `verify-macos-signing.sh` fails closed unless strict codesign, Gatekeeper and stapler checks succeed.

## 10. Database migration status

`20261105040345_centralized_scan_jobs.sql` was generated with the pinned Supabase CLI. It adds scan enums, local-scope metadata, scan jobs/targets, agent request operation binding and file evidence. All exposed-schema tables have RLS enabled and privileges revoked from Data API roles. Validation was local only.

## 11. API security results

The implementation validates RBAC, device ownership, scope ownership/state, fixed operations, collector allowlists, request/device/scope binding, known detector provenance, sanitized filenames, revoked credentials, expiry, cross-tenant targets and transactional idempotency. Agent, analyst and future vendor evidence remain distinct trust classes.

## 12. Tests executed

- TypeScript project typecheck.
- API unit and isolated PostgreSQL integration tests.
- Production workspace build.
- Go unit tests and vet in Go 1.22 Linux container.
- Windows amd64 and macOS amd64/arm64 cross-build checks.
- Supabase empty reset, schema lint and pgTAP security tests.
- Installer/release manifest tests, signing-script syntax, checksum and secret scans.

## 13. Tests passed

TypeScript typecheck passed; the API suite passed 21/21 with the isolated PostgreSQL integration active; Go tests and vet passed; Windows amd64, macOS amd64 and macOS arm64 cross-builds passed; the production build passed with existing sourcemap notices and a large-chunk warning; migration reset and schema lint passed; pgTAP passed 7/7; installer/manifest regressions passed 3/3. Final GitHub Actions results are recorded in the pull request summary.

## 14. Tests skipped or blocked

- Windows host execution remains blocked by enterprise Code Integrity; policy was not bypassed.
- Actual Windows install/enroll/service/restart/upgrade/uninstall is blocked on trusted signing and a disposable native endpoint.
- Actual macOS Intel/Apple Silicon installation is blocked on Developer ID/notarization credentials and endpoints.
- SmartScreen and Gatekeeper user flows were not tested.
- Full YARA, ClamAV, Sysmon and vendor EDR integrations are unsupported rather than silently installed.

## 15. Files changed

Changes cover the Go agent model/client/scheduler/config/analyzer/collectors, Express contracts/routes/services/integration tests, Drizzle schemas and Supabase migration/tests, Scan Center React page/navigation/translations, signing verification scripts, CI validation inputs and the documentation set requested by this assignment. Use `git diff --name-status 7a3acac...HEAD` for the final authoritative inventory.

## 16. Security limitations

No product guarantees complete detection. Static analysis cannot observe runtime behavior, encrypted content, unsupported archive variants, memory-only threats or vendor telemetry that is unavailable. Absence of selected events or indicators is not a clean verdict. The current literal rules are not full YARA. Remote forced cancellation of running scans is intentionally absent.

## 17. Performance constraints

Scope scans are limited to 500 supported candidate files, 2,000 directories, 15 minutes, 128 MiB per file, archive entry/expansion/compression limits, nested depth two, 16 MiB per nested ZIP and 64 MiB total nested budget. The agent serializes requests and the server permits one active request per device.

## 18. Remaining blockers

Trusted Windows signing accepted by the enterprise policy; Apple Developer ID/notarization; disposable native endpoints; staging identity/provider configuration; complete native lifecycle evidence; UX/accessibility acceptance; optional production-grade shared rate limiting; and formal release ownership remain outstanding.

## 19. Production readiness

Not production-ready. The branch is suitable for independent code review and isolated staging/database testing. Unsigned packages must not be presented as trusted installers, and successful builds must not be labeled native-tested, signed or production-approved.

## 20. Exact next steps

1. Review and merge prerequisite PRs only through normal approval; keep this PR draft until review findings are resolved.
2. Deploy the migration/API/dashboard to an isolated staging environment, not production.
3. Enroll disposable devices with non-production credentials and configure explicitly consented scopes locally.
4. Complete organization-controlled Windows signing and Apple signing/notarization, then independently verify exact hashes.
5. Execute `docs/CONTROLLED_TESTING_PLAN.md` on Windows amd64, macOS Intel and macOS Apple Silicon.
6. Attach immutable native evidence to the exact build identity; any rebuild clears approval.
7. Repeat security, database, API, artifact and secret checks before any production change request.
