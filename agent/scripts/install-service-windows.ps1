# Installs, enrolls, and starts the NextAura Windows service.
# Run from an elevated PowerShell. The enrollment code is read without echo and
# sent over stdin; it is never placed in shell history or process arguments.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^https://')][string]$ServerUrl,
  [string]$SourceBinary = (Join-Path $PSScriptRoot 'nextaura-agent.exe'),
  [string]$InstallDirectory = "$env:ProgramFiles\NextAura"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'NextAuraAgent'
$destination = Join-Path $InstallDirectory 'nextaura-agent.exe'
$stateDirectory = Join-Path $env:ProgramData 'NextAura\Agent'
$statePath = Join-Path $stateDirectory 'state.json'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Administrator privileges are required. Open PowerShell with Run as administrator.'
}
if (-not (Test-Path -LiteralPath $SourceBinary -PathType Leaf)) {
  throw "Agent binary not found: $SourceBinary"
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
  Stop-Service -Name $serviceName -Force
  $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null
& icacls.exe $stateDirectory '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent state directory ACL.' }

Copy-Item -LiteralPath $SourceBinary -Destination $destination -Force

if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
  $secureCode = Read-Host 'Enrollment code (input hidden)' -AsSecureString
  $plainCode = [Net.NetworkCredential]::new('', $secureCode).Password
  if ([string]::IsNullOrWhiteSpace($plainCode)) {
    $secureCode.Dispose()
    throw 'Enrollment code cannot be empty.'
  }
  try {
    Write-Host 'Enrolling this device with the authorized NextAura server...'
    $plainCode | & $destination enroll --server $ServerUrl --code-stdin
    if ($LASTEXITCODE -ne 0) { throw "Enrollment failed with exit code $LASTEXITCODE." }
  } finally {
    $plainCode = $null
    $secureCode.Dispose()
    $secureCode = $null
  }
} else {
  Write-Host "Existing protected enrollment state found at $statePath; reusing it for this repair/retry."
}

if ($service) {
  & sc.exe config $serviceName binPath= "`"$destination`" run" start= auto obj= LocalSystem | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not update the NextAuraAgent service.' }
} else {
  & sc.exe create $serviceName binPath= "`"$destination`" run" start= auto DisplayName= 'NextAura Security Agent' obj= LocalSystem | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not create the NextAuraAgent service.' }
}
& sc.exe description $serviceName 'Read-only endpoint security assessment agent for NextAura Security Center.' | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

try {
  Start-Service -Name $serviceName
  $service = Get-Service -Name $serviceName
  $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
} catch {
  throw "Agent files and protected enrollment state are present, but the service did not start. Re-run this installer after checking Event Viewer. $($_.Exception.Message)"
}

Write-Host "Installed $destination"
Write-Host "State: $stateDirectory (LocalSystem and Administrators only)"
Get-Service -Name $serviceName
