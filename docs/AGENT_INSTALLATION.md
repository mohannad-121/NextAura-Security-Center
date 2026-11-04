# Agent installation

The enrollment wizard serves complete, architecture-specific install packages only after a release operator records a successful native test enrollment in `agent/dist/manifest.json`. A package that merely exists is not downloadable.

Before installing, the device user must review the consent notice, confirm the canonical HTTPS server URL, and compare the package SHA-256 with the value displayed by the wizard.

## Windows x64

1. Download and extract `nextaura-agent-windows-amd64.zip`.
2. Open PowerShell with **Run as administrator** in the extracted directory.
3. Run the exact command displayed by the enrollment wizard:

   ```powershell
   .\install-agent.ps1 -ServerUrl "https://security.example.com" -EnrollmentCode "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
   ```

The installer copies the binary to `C:\Program Files\NextAura`, restricts `C:\ProgramData\NextAura\Agent` to LocalSystem and Administrators, redeems the one-time code, uploads the initial assessment, creates the visible `NextAuraAgent` service, and starts it. It does not disable Defender, change firewall rules, or modify security settings.

Diagnostics:

```powershell
Get-Service NextAuraAgent
& "C:\Program Files\NextAura\nextaura-agent.exe" status
Get-Content "C:\ProgramData\NextAura\Agent\agent.log" -Tail 100
```

Uninstall: first revoke the device in the dashboard, then run `uninstall-agent.ps1` as administrator. It preserves local state by default. Use `-RemoveLocalState` only after revocation.

## macOS Intel and Apple silicon

Choose `darwin-amd64` for an Intel Mac or `darwin-arm64` for Apple silicon. Confirm the chip in **Apple menu → About This Mac**; browsers cannot reliably detect Mac CPU architecture.

1. Download and extract the matching `.tar.gz` package.
2. Open Terminal in the extracted directory.
3. Run the exact command displayed by the wizard:

   ```bash
   sudo ./install-agent.sh --server 'https://security.example.com' --code 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'
   ```

The installer copies the binary to `/usr/local/bin`, protects `/Library/Application Support/NextAura/Agent`, enrolls and assesses the device, installs `com.nextaura.agent.plist`, and starts a LaunchDaemon. It does not bypass Gatekeeper, SIP, TCC, or Full Disk Access.

Diagnostics:

```bash
sudo launchctl print system/com.nextaura.agent
sudo /usr/local/bin/nextaura-agent status
sudo tail -100 '/Library/Application Support/NextAura/Agent/launchd.err.log'
```

Uninstall: first revoke the device in the dashboard, then run `sudo ./uninstall-agent.sh`. It preserves local state by default. Add `--remove-local-state` only after revocation.

## Signing and notarization

The checked-in packages are development artifacts and the current manifest marks them unsigned/unverified. Never present them as production-trusted installers.

- Windows production distribution requires an organization-controlled code-signing certificate and Authenticode signing, for example `signtool sign /fd SHA256 /td SHA256 /tr <trusted-RFC3161-timestamp-url> /sha1 <certificate-thumbprint> <binary>`, followed by `signtool verify /pa /v <binary>`.
- macOS production distribution should use a signed installer package (`productbuild --sign "Developer ID Installer: ..."`), a Developer ID Application-signed binary with hardened runtime and secure timestamp (`codesign --options runtime --timestamp --sign "Developer ID Application: ..."`), Apple notarization (`xcrun notarytool submit ... --keychain-profile ... --wait`), and stapling/validation (`xcrun stapler staple` and `xcrun stapler validate`) on a supported staplable container.
- Signing identities and notarization credentials must live in protected CI secrets/keychains. They are not present in this repository.

Do not remove quarantine attributes or instruct users to bypass OS security warnings.

## Agent commands

| Command                      | Description                                                |
| ---------------------------- | ---------------------------------------------------------- |
| `enroll --server --code`     | Redeem a one-time code and store a per-device token        |
| `run`                        | Foreground service loop                                    |
| `assess [--collectors A,B]`  | Run fixed collectors and upload                            |
| `collect [--collectors A,B]` | Print fixed collector results locally without upload       |
| `status`                     | Show enrollment with token redacted                        |
| `unenroll`                   | Remove only the local token; server revocation is separate |
