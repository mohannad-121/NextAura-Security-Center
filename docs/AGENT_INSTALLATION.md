# Agent installation

The agent is a single binary with no dependencies. Enrollment requires a one-time code generated in **Devices → Enroll device** by an ADMIN or OWNER.

## Windows (x64)

1. Download `nextaura-agent-windows-amd64.exe` from the enrollment wizard (compare the SHA-256 shown) or build it with `agent\scripts\build-agent.ps1`.
2. Open an **elevated** PowerShell and copy the binary to `C:\Program Files\NextAura\nextaura-agent.exe`.
3. Enroll:
   ```powershell
   & "C:\Program Files\NextAura\nextaura-agent.exe" enroll --server https://<your-server> --code XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
   ```
   This collects system identification, registers the device and uploads the first assessment.
4. Install the service (runs as LocalSystem so BitLocker and Secure Boot can be read):
   ```powershell
   powershell -ExecutionPolicy Bypass -File agent\scripts\install-service-windows.ps1
   ```
5. State and logs: `C:\ProgramData\NextAura\Agent\`.

Running without elevation works but BitLocker, Secure Boot and some AV details will be reported as `PERMISSION_DENIED`.

## macOS (Intel and Apple silicon)

1. Download the matching binary (`darwin-arm64` for Apple silicon, `darwin-amd64` for Intel) or build with `./agent/scripts/build-agent.sh`.
2. `chmod +x nextaura-agent && sudo ./nextaura-agent enroll --server https://<your-server> --code ...`
3. `sudo ./agent/scripts/install-service-macos.sh ./nextaura-agent` installs `/usr/local/bin/nextaura-agent` and the LaunchDaemon `com.nextaura.agent`.
4. State and logs: `/Library/Application Support/NextAura/Agent/`.

Binaries are not notarized by default. Gatekeeper may require `xattr -d com.apple.quarantine nextaura-agent` for a downloaded file, or sign/notarize with your own Developer ID and set `signed.<platform>: true` in `manifest.json`.

## Commands

| Command | Description |
|---|---|
| `enroll --server --code` | Register this device (one time) |
| `run` | Foreground service loop (used by the service/daemon) |
| `assess [--collectors A,B]` | Run collectors now and upload |
| `collect [--collectors A,B]` | Run collectors and print JSON locally — useful to see exactly what would be sent |
| `status` | Show enrollment (token redacted) |
| `unenroll` | Delete local token (revoke in the dashboard too) |

## Uninstall

Windows: `Stop-Service NextAuraAgent; sc.exe delete NextAuraAgent`, delete the binary and `C:\ProgramData\NextAura`.
macOS: `sudo launchctl bootout system/com.nextaura.agent`, remove the plist, binary and state directory. Then revoke the device in the dashboard.
