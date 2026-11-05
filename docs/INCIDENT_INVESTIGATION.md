# Incident Investigation

## Analyst workflow

1. Preserve the suspicious attachment without opening it. Record where it came from and who received it outside NextAura according to company procedure.
2. On an approved analysis endpoint, run:

   ```text
   nextaura-agent inspect-file --path <file> --approved-root <authorized-directory>
   ```

   Optional `--hash-feed` and `--rules` inputs must be approved local JSON files. The command never uploads the file.

3. Review the classification and every limitation. Password-protected ZIP entries are `INCONCLUSIVE`; NextAura does not attempt password recovery.
4. Create an incident in **Incident investigations** and associate relevant endpoint findings and devices through the API.
5. Import only the analyzer JSON metadata. Do not paste document contents, credentials, archive passwords, or confidential file data.
6. Add timeline events from actual evidence: message receipt time, antivirus detection time, assessment time, and authorized response actions.
7. Record confidence, visibility gaps, and manual next actions. Export the incident PDF for review.

## Incident evidence model

Each incident stores:

- title, severity, confidence, owner, and investigation status;
- organization-scoped device and finding references;
- file name, SHA-256, detected type, size, evidence classification, signature metadata, reputation metadata, archive summary, and limitations;
- timestamped evidence events and their sources;
- recommended manual response actions;
- an evidence-focused PDF report.

The database does not store suspicious file contents. SHA-256 reputation is empty unless an approved local feed supplied a match.

## API controls

- Read access requires an active organization membership.
- Incident creation, updates, evidence import, and timeline changes require `SECURITY_ANALYST` or higher.
- All incident IDs are resolved together with the active organization ID.
- Associated devices and findings are validated as belonging to the active organization before insertion.
- File evidence rejects malformed SHA-256 values and files larger than the analyzer's supported maximum.

## Status guidance

- `OPEN`: initial triage; evidence may be incomplete.
- `INVESTIGATING`: an analyst is correlating file, endpoint, and user-reported evidence.
- `CONTAINED`: authorized responders report containment; NextAura does not perform containment itself.
- `CLOSED`: review is complete and limitations are documented.

Closing an incident is not a declaration that a device is clean. Reopen or create a new incident when new evidence appears.

## WhatsApp invoice example

For a password-protected ZIP or an ISO disguised as an invoice:

- record the delivery channel and visible filename outside the file contents;
- inspect the container locally from an approved directory;
- expect encrypted ZIP content to remain inconclusive;
- treat an invoice double extension, nested executable/shortcut/script, type mismatch, suspicious persistence entry, Defender detection, or approved hash match as separate evidence points;
- do not mount the ISO, open the attachment, bypass its password, or upload it automatically;
- correlate the receiving device's Defender history, selected security event counts, startup inventory, and vulnerable software;
- escalate according to company policy for manual sandboxing or forensic analysis in a separately approved environment.
