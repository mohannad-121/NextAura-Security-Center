# File Analysis Engine

## Security model

The engine performs static, read-only inspection. It never executes, mounts, extracts to disk, deletes, quarantines, uploads, or password-cracks content. `NO_FINDINGS_OBSERVED` means only that configured detectors observed no indicator within their coverage.

## Implemented formats

- ZIP and Office-compatible ZIP containers: entry names, sizes, encryption flags, risky extensions, traversal names, compression ratio, expanded-byte and entry limits.
- Nested ZIP: in-memory only, maximum depth two, 16 MiB per nested archive and 64 MiB total nested budget, with the global time/entry budget.
- ISO9660: read-only primary-volume and directory-record parsing to depth two. No mounting. Joliet, UDF, boot images, and file-content inspection are explicitly unsupported.
- PE EXE/DLL/SCR/COM: header type, machine, timestamp, imports (maximum 100), section count, writable+executable section indicators, and certificate-table presence.
- MSI/OLE, LNK, PDF, RTF, Office containers, BAT/CMD/PowerShell/JavaScript/VBScript and other recognized scripts.
- SHA-256 exact local intelligence and bounded literal offline rules. This is not a full YARA engine.

Certificate-table presence is reported as `PRESENT_NOT_VALIDATED`; it is never described as trusted Authenticode. Actual Windows trust is verified only by `Get-AuthenticodeSignature` in the controlled signing verifier. Encrypted ZIP contents remain `INCONCLUSIVE`; passwords are neither requested remotely nor persisted.

## Classifications

`CONFIRMED_DETECTION`, `SUSPICIOUS_INDICATOR`, `INCONCLUSIVE`, `NO_FINDINGS_OBSERVED`, and `UNSUPPORTED` are evidence classes, not remediation instructions. Every centralized record includes detector ID/version, source, timestamp, severity, confidence, classification, and limitations.

## Race and boundary handling

The analyzer resolves root and target links, rejects paths outside the real root, rejects non-regular files, opens the file, compares file identity, rechecks resolution, and then uses that open handle for hashing and ZIP/ISO/PE reads. Directory symlinks are not traversed. Hard-linked content is read only; no mutation occurs. Files that change before open are rejected. Files already opened remain bound to that handle.

## Harmless test fixtures

Automated tests cover extension mismatches, double extensions, traversal names, encrypted ZIP flags, expansion limits, nested ZIP limits, ISO9660 metadata, scope symlink skipping, scope file limits, exact hashes, and synthetic literal rules. No malware is included or executed.
