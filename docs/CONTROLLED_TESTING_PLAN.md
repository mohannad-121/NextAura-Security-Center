# Controlled Testing Plan

Use an isolated non-production API and Supabase/PostgreSQL database, disposable enrolled endpoints, synthetic harmless files, and organization-approved signing identities.

## Database and API

1. Replay migrations into an empty isolated database.
2. Run database lint, pgTAP, API integration, tenant-isolation, replay, revocation, scan lifecycle, and evidence provenance tests.
3. Confirm no production project reference or credential is configured.

## Windows amd64

1. Obtain an Authenticode-signed candidate allowed by the applicable enterprise policy.
2. Verify package SHA-256 and run the independent signing verifier.
3. Download, extract, consent, enter enrollment code through hidden input, install, and verify protected state ACLs.
4. Confirm initial assessment, heartbeat, scope reporting, centralized posture request, approved-scope request, evidence ingestion, dashboard state, and PDF report.
5. Restart, verify service persistence, test retry/offline recovery, perform an upgrade, revoke credentials, uninstall, and optionally remove local state.
6. Capture Code Integrity, AppLocker, SmartScreen, Defender, service, and application logs. Stop rather than bypass any block.

## macOS Intel and Apple Silicon

1. Use Developer ID signed, notarized, stapled candidates and independently verify them.
2. Confirm Gatekeeper acceptance, checksum, protected state ownership/mode, LaunchDaemon bootstrap, initial evidence, restart persistence, upgrade, revocation, and uninstall.
3. Record TCC/permission-denied collector gaps rather than marking them passed.

## Security cases

- Unknown/revoked scope, traversal and symlink escape, file replacement, nested archive limits, encrypted archive, malformed ZIP/ISO/PE, forged detector, duplicate evidence, expired request, revoked token, cross-tenant target, cancellation before pickup, cancellation after start, and offline expiry.
- Confirm files are not uploaded, executed, mounted, deleted, or quarantined.
- Confirm a rebuild changes SHA/build identity and clears approval.

Passing compilation or package construction is never recorded as native installation success.
