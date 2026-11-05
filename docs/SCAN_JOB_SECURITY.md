# Scan Job Security

## Authorization and isolation

- Operator endpoints require Clerk identity, active organization membership, and `SECURITY_ANALYST` or higher for mutation.
- Every selected device and reported scope is checked against the active organization.
- Job, per-device request, and target rows are created in one PostgreSQL transaction.
- Agent identity comes from a hashed, expiring, revocable device token. Organization and device IDs are derived server-side.
- Revoked or expired device credentials cannot poll or submit evidence.

## Fixed protocol

Only `ASSESSMENT` and `FILE_SCOPE_SCAN` are accepted. Collector IDs use a compiled enum; file requests contain a scope ID only. The agent rejects unknown operations, collectors, scopes, and revoked scopes. No dashboard-supplied command, path, environment variable, SQL, or executable payload is present.

## Replay and forgery resistance

- Assessment idempotency is unique per device.
- File evidence idempotency is inserted transactionally with evidence.
- Evidence keys are unique per request.
- Request ID, device ID, operation, scope ID, and detector allowlist must all agree.
- The detector allowlist currently accepts only `NEXTAURA_STATIC_FILE_ANALYZER` from `LOCAL_APPROVED_SCOPE_STATIC_ANALYSIS`.
- Analyst JSON imports remain tagged as analyst evidence and cannot use the agent endpoint.

## Lifecycle semantics

`RUNNING` is set only after agent acknowledgement. The UI deliberately shows stages instead of invented percentages. Cancellation expires work that has not started; already-running read-only collectors are allowed to finish. Expired requests are terminal and cannot accept new evidence.

## Database exposure

All scan tables have RLS enabled. `public`, `anon`, `authenticated`, and `service_role` receive no table privileges; the server uses its protected PostgreSQL connection. There are no permissive RLS policies. A future least-privilege server role requires explicit grants and reviewed policies.
