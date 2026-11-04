# Known limitations

- **Not an EDR.** No process monitoring, no network capture, no behavioural detection. Threat history comes only from Microsoft Defender's own records.
- **Third-party antivirus on macOS** is detected by application bundle presence; its real-time state is `UNKNOWN`.
- **Screen-lock checks** read the interactive user's preferences. When the agent runs as a service/daemon they are usually `UNKNOWN`.
- **Windows 10 ESU** enrollment cannot be verified; Windows 10 is reported as end-of-support.
- **CVE matching is inventory-based.** It depends on vendor/product names as installed packages report them. Confidence is stated per match; `POSSIBLE` matches need human review. No NVD key means slow initial population (5 requests / 30 s).
- **Email security audit** is DNS-only (SPF/DMARC/DKIM/MX records). It cannot confirm that mail actually passes alignment; DKIM requires the selector names.
- **Single-instance scheduler** for intelligence refresh.
- **Checked-in packages are unsigned and unverified.** The wizard refuses their download until a native enrollment test is recorded; production trust additionally requires Windows signing or macOS signing/notarization.
- **Linux endpoints** are out of scope.
- **No native macOS installation was executed in this Windows audit environment.** CI performs native compile/test/entry-point checks, but `verified` remains a separate manual end-to-end enrollment assertion.
