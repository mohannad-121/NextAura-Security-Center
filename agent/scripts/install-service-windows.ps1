# Installs, enrolls, and starts the NextAura Windows service.
# Run from an elevated PowerShell. The package is intentionally transparent:
# it copies one binary, writes enrollment state, and creates one Windows service.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^https://')][string]$ServerUrl,
  [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$EnrollmentCode,
  [string]$SourceBinary = (Join-Path $PSScriptRoot 'nextaura-agent.exe'),
  [string]$InstallDirectory = "$env:ProgramFiles\NextAura"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'NextAuraAgent'
$destination = Join-Path $InstallDirectory 'nextaura-agent.exe'
$stateDirectory = Join-Path $env:ProgramData 'NextAura\Agent'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Administrator privileges are required. Open PowerShell with Run as administrator.'
}
if (-not (Test-Path -LiteralPath $SourceBinary -PathType Leaf)) {
  throw "Agent binary not found: $SourceBinary"
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  throw 'NextAuraAgent is already installed. Use uninstall-agent.ps1 before reinstalling.'
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null
& icacls.exe $stateDirectory '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent state directory ACL.' }

Copy-Item -LiteralPath $SourceBinary -Destination $destination -Force
Write-Host 'Enrolling this device with the authorized NextAura server...'
& $destination enroll --server $ServerUrl --code $EnrollmentCode
if ($LASTEXITCODE -ne 0) { throw "Enrollment failed with exit code $LASTEXITCODE." }

& sc.exe create $serviceName binPath= "`"$destination`" run" start= auto DisplayName= 'NextAura Security Agent' obj= LocalSystem | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create the NextAuraAgent service.' }
& sc.exe description $serviceName 'Read-only endpoint security assessment agent for NextAura Security Center.' | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
Start-Service -Name $serviceName

$service = Get-Service -Name $serviceName
Write-Host "Installed $destination"
Write-Host "State: $stateDirectory (LocalSystem and Administrators only)"
$service
