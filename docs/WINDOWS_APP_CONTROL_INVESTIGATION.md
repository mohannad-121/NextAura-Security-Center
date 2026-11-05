# Windows Application Control Investigation

## Confirmed local evidence — 2026-11-05

The existing development executable was inspected without running it:

- Path: `agent/dist/nextaura-agent-windows-amd64.exe`
- SHA-256: `ce0ff80b3b1bc6717fb79522fcd21fffce355d25745f949f067d887b333e30ef`
- Authenticode: `NotSigned`
- Publisher/signer: none available because the artifact has no Authenticode signature.
- Code Integrity event 3077: the executable failed the Enterprise signing level and violated policy ID `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`.
- Code Integrity event 3033 independently reported failure to meet the Enterprise signing level.
- The same policy blocked generated `nextaura-agent.test.exe` binaries.
- Matching AppLocker and Defender events were not present in the queried 30-day windows.

This evidence confirms an enforced Code Integrity / App Control for Business (WDAC) signing-level policy. It does not support describing the failure as merely SmartScreen reputation or antivirus detection. Smart App Control can also emit Code Integrity events, but the explicit enterprise policy identifier and signing-level message are the controlling evidence here.

No protection was disabled, bypassed, excluded, or weakened.

## Reproduce the read-only investigation

```powershell
$file = Resolve-Path .\agent\dist\nextaura-agent-windows-amd64.exe
Get-FileHash -LiteralPath $file -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $file | Format-List Status,StatusMessage,SignerCertificate
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-CodeIntegrity/Operational'
  Id=3033,3034,3076,3077,3089
  StartTime=(Get-Date).AddDays(-30)
} | Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-AppLocker/EXE and DLL'
  Id=8003,8004,8028,8029
  StartTime=(Get-Date).AddDays(-30)
} | Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Windows Defender/Operational'
  Id=1116,1117,1121,5001
  StartTime=(Get-Date).AddDays(-30)
} | Select-Object TimeCreated,Id,Message
```

The Windows posture collector now reports bounded event counts only. It intentionally states that event IDs alone cannot distinguish WDAC, Smart App Control, AppLocker, SmartScreen, and antivirus reputation.

## Blocker

Native Windows execution, installation, enrollment, service startup, restart, upgrade, and uninstall testing must remain blocked until the exact candidate is signed by an identity allowed by policy `{0283ac0f-fff1-49ae-ada1-8a933130cad6}` or the organization explicitly approves that publisher/hash through its normal App Control governance. Disabling policy is not an acceptable test method.
