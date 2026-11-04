# Supported platforms

| Platform                                     | Architecture | Status                 | Notes                                                                                  |
| -------------------------------------------- | ------------ | ---------------------- | -------------------------------------------------------------------------------------- |
| Windows 11 25H2 / 26H1 / 26H2                | x64          | Supported              | PowerShell 5.1+, CIM, Defender cmdlets                                                 |
| Windows 11 24H2                              | x64          | Edition-dependent      | Home/Pro support ended; Enterprise/Education remains supported at the audit date       |
| Windows 11 23H2                              | x64          | Upgrade immediately    | Only Enterprise/Education remains supported and reaches end of servicing on 2026-11-10 |
| Windows 10                                   | x64          | Collects, flagged      | OS reported as end-of-support (ESU not verifiable)                                     |
| Windows Server 2019+                         | x64          | Best effort            | Same collectors; no screen-lock policy                                                 |
| macOS 27 Golden Gate / 26 Tahoe / 15 Sequoia | arm64, x64   | Supported              | Current Apple security-update set as of 2026-11-04                                     |
| macOS 14 Sonoma and older                    | arm64, x64   | Collects, flagged FAIL | Not in the current three routinely updated releases                                    |
| Linux                                        |              | Not supported          | All collectors report `UNSUPPORTED`; the binary refuses to enroll                      |

## Per-check availability

| Check                                | Windows                                                   | macOS                                                                |
| ------------------------------------ | --------------------------------------------------------- | -------------------------------------------------------------------- |
| Firewall                             | Get-NetFirewallProfile                                    | socketfilterfw                                                       |
| Disk encryption                      | Get-BitLockerVolume (admin)                               | fdesetup (root)                                                      |
| OS updates                           | Get-HotFix                                                | softwareupdate --list --no-scan                                      |
| OS support                           | build number table                                        | major version table                                                  |
| Screen lock                          | HKCU screen saver values (interactive user only)          | com.apple.screensaver (interactive user only)                        |
| Secure Boot                          | Confirm-SecureBootUEFI (admin)                            | SPiBridgeDataType (T2/Apple silicon only)                            |
| UAC / SIP / Gatekeeper               | registry EnableLUA                                        | csrutil, spctl                                                       |
| Guest account                        | Get-LocalUser RID 501                                     | loginwindow GuestEnabled                                             |
| Remote access                        | fDenyTSConnections                                        | sshd / screensharing loaded                                          |
| AV product / real-time / definitions | SecurityCenter2 + Get-MpComputerStatus                    | bundle detection + XProtect (third-party real-time state is UNKNOWN) |
| Threat history                       | Get-MpThreatDetection                                     | UNSUPPORTED                                                          |
| SMBv1                                | Get-SmbServerConfiguration                                | smbd loaded (informational)                                          |
| Software inventory                   | Uninstall registry keys                                   | system_profiler SPApplicationsDataType                               |
| Startup inventory                    | Run keys, Startup folders, scheduled tasks, auto services | LaunchDaemons / LaunchAgents                                         |

Support tables are dated and fail closed for unknown future releases. Verification status of complete install packages is shown per platform in the enrollment wizard, driven by `agent/dist/manifest.json`.
