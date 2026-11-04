# Installs the already-enrolled agent as a Windows service running as LocalSystem.
# Run from an elevated PowerShell after `nextaura-agent.exe enroll ...`.
param([string]$BinaryPath = "C:\Program Files\NextAura\nextaura-agent.exe")
$ErrorActionPreference = "Stop"
if (-not (Test-Path $BinaryPath)) { throw "Binary not found at $BinaryPath" }
sc.exe create NextAuraAgent binPath= "`"$BinaryPath`" run" start= auto DisplayName= "NextAura Security Agent" obj= LocalSystem | Out-Null
sc.exe description NextAuraAgent "Read-only endpoint security assessment agent for NextAura Security Center." | Out-Null
sc.exe failure NextAuraAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
Start-Service NextAuraAgent
Get-Service NextAuraAgent
