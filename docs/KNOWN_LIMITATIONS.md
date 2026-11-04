# Known limitations

- **Not an EDR.** No process monitoring, no network capture, no behavioural detection. Threat history comes only from Microsoft Defender's own records.
- **Third-party antivirus on macOS** is detected by application bundle presence; its real-time state is `UNKNOWN`.
- **Screen-lock checks** read the interactive user's preferences. When the agent runs as a service/daemon they are usually `UNKNOWN`.
- **Windows 10 ESU** enrollment cannot be verified; Windows 10 is reported as end-of-support.
- **CVE matching is inventory-based.** It depends on vendor/product names as installed packages report them. Confidence is stated per match; `POSSIBLE` matches need human review. No NVD key means slow initial population (5 requests / 30 s).
- **Email security audit** is DNS-only (SPF/DMARC/DKIM/MX records). It cannot confirm that mail actually passes alignment; DKIM requires the selector names.
- **Single-instance scheduler** for intelligence refresh.
- **Agent binaries are unsigned** unless you sign them. The wizard shows this explicitly.
- **Linux endpoints** are out of scope.
- **Agent binaries built on this server have not been executed on a real Windows/macOS device by the build itself.** The `verified` flag in `manifest.json` is set manually after a real test enrollment; until then the wizard labels them "not yet tested".
