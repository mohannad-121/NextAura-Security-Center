# Removes the Windows service and binary. Server-side revocation must be done
# from the dashboard. Local enrollment state is preserved unless explicitly requested.
[CmdletBinding()]
param(
  [switch]$RemoveLocalState,
  [string]$InstallDirectory = "$env:ProgramFiles\NextAura"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'NextAuraAgent'
$stateDirectory = Join-Path $env:ProgramData 'NextAura\Agent'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Administrator privileges are required.'
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
  if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
  & sc.exe delete $serviceName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not delete the NextAuraAgent service.' }
}
if (Test-Path -LiteralPath $InstallDirectory) {
  Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
}
if ($RemoveLocalState -and (Test-Path -LiteralPath $stateDirectory)) {
  Remove-Item -LiteralPath $stateDirectory -Recurse -Force
  Write-Host 'Removed local enrollment state. Also revoke the device in the dashboard.'
} else {
  Write-Host "Preserved local state at $stateDirectory. Use -RemoveLocalState only after dashboard revocation."
}
Write-Host 'NextAura Agent service and binary removed.'
