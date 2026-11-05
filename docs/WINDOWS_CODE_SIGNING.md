# Windows Code Signing

## Status

Development artifacts are unsigned and are not approved for production. The repository contains no signing key or certificate. Compilation and GitHub artifact provenance do not equal Authenticode trust.

## Controlled process

1. Build a versioned Windows amd64 package from a reviewed commit on a protected runner.
2. Submit `nextaura-agent.exe` to an organization-controlled trusted signing service or hardware-backed certificate process. Never export the private key into the repository or ordinary CI logs.
3. Repackage after signing, regenerate SHA-256 and build identity, and leave native approval empty because the bytes changed.
4. On an independent Windows verifier, run:

```powershell
.\agent\scripts\verify-windows-signing.ps1 `
  -Package .\nextaura-agent-windows-amd64.zip `
  -ExpectedSha256 <64-hex-package-sha256>
```

5. Preserve the JSON verification output, signer subject/thumbprint, timestamp authority, certificate expiry, workflow/commit provenance, package hash, and build identity.
6. Confirm the signer is permitted by the applicable WDAC/App Control policy.
7. Perform the controlled native installation plan. Only then may a hash-bound `nativeVerification` record approve controlled testing.

Production approval additionally requires release-owner review, valid timestamping, certificate-chain/revocation verification, incident response ownership, and an organization policy decision. Editable manifest flags never prove signing.

## Missing prerequisites

- Organization-owned signing identity accepted by the enforced enterprise policy.
- Protected signing environment/service and authorization workflow.
- Independent Windows verifier and disposable native test endpoint.
- Durable evidence storage and release approval ownership.
