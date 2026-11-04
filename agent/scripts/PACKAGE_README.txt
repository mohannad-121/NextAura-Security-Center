NextAura Security Agent - controlled testing package

This package performs a transparent, read-only endpoint security assessment.
It does not provide remote shell, arbitrary commands, file retrieval, screen
capture, credential extraction, or automated remediation.

Before installation:
1. Obtain the package from your authorized NextAura administrator.
2. Compare its SHA-256 checksum with the value in the enrollment wizard.
3. Confirm the displayed server URL and data-collection consent notice.

Windows: open an elevated PowerShell in the extracted package and run:
  .\install-agent.ps1 -ServerUrl https://YOUR-SERVER

macOS: open Terminal in the extracted package and run:
  sudo ./install-agent.sh --server https://YOUR-SERVER

The installer then requests the one-time enrollment code with hidden input. Do
not put the code directly in a shell command, script, log, or support ticket.

Do not disable SmartScreen, Gatekeeper, SIP, TCC, or other OS protections.
Production macOS packages must be Developer ID signed, notarized, and stapled.
Production Windows packages should be Authenticode signed.

Revoke the device in the dashboard before uninstalling it. Uninstall scripts
preserve local enrollment state unless the explicit removal option is used.
