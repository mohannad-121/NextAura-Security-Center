# Security model

## Trust boundaries

| Actor | Trusts | Must not be able to |
|---|---|---|
| Agent | The server URL it was enrolled with (HTTPS only) | Receive arbitrary commands; be pointed at another server without re-enrollment |
| Server | Clerk for operator identity; device tokens for devices | Cross tenant boundaries; execute anything on a device |
| Operator | The dashboard | See other organizations; change device state |

## Agent

- Six compiled-in collectors. `collectors.Run` refuses any other ID; the server's Zod contract refuses any other ID; the scheduler rejects (and ACKs as REJECTED) any request containing one.
- Every external command goes through `exec.run`, which checks a static allow-list of OS binaries and uses read-only arguments. No shell is ever spawned.
- The state file (device token) is written `0600` in an admin-only directory. Tokens are never logged; `status` prints a redacted copy.
- HTTP redirects are not followed; response bodies are capped at 1 MiB; `http://` is accepted only for `localhost`.
- Clock skew > 15 minutes is rejected by the server to limit replay windows.

## Server

- Device tokens: 32 random bytes, prefix `nxa_`, stored as sha256. Revocation sets `revokedAt` and the device to `REVOKED`; the agent clears its local token on 403.
- Enrollment codes: 25 chars from an unambiguous alphabet (~125 bits), hashed, single-use, expire per organization policy, rate-limited 10/10 min per IP.
- Agent routes are mounted before CORS/Clerk with their own 2 MB body limit and per-device rate limit (60/min).
- Dashboard routes: `requireOrg` resolves the active organization from the caller's memberships only; role gates (`requireRole`) on every mutating route. All queries filter by `organization_id`.
- Audit log for every security-relevant action (enrollment, revocation, finding status changes, settings, members, reports, data deletion, intelligence refresh).
- Security headers (`nosniff`, `DENY` framing, `no-referrer`, `no-store`).

## Authentication & MFA

Operators sign in through Clerk. MFA, password policy and session lifetime are configured in the Clerk dashboard; the organization setting `requireMfa` records the policy and is surfaced in the UI.

## What the system cannot verify

Any value the agent could not observe is reported as `UNKNOWN` / `UNSUPPORTED` / `PERMISSION_DENIED` and feeds a low-severity "visibility gap" finding rather than a pass. See `KNOWN_LIMITATIONS.md`.
