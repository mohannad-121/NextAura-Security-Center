# Verifies an externally signed Windows package. This script never signs files
# and never reads signing credentials. Run it on a trusted Windows verifier.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Package,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256
)
$ErrorActionPreference = 'Stop'
$resolved = Resolve-Path -LiteralPath $Package
$actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $ExpectedSha256.ToLowerInvariant()) { throw "Package SHA-256 mismatch. Expected $ExpectedSha256, received $actual." }
$stage = Join-Path ([IO.Path]::GetTempPath()) ("nextaura-trust-" + [guid]::NewGuid().ToString('N'))
try {
  Expand-Archive -LiteralPath $resolved -DestinationPath $stage
  $binary = Join-Path $stage 'nextaura-agent.exe'
  if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Package does not contain nextaura-agent.exe.' }
  $signature = Get-AuthenticodeSignature -LiteralPath $binary
  if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
    throw "Authenticode verification failed: $($signature.Status) $($signature.StatusMessage)"
  }
  [pscustomobject]@{
    schemaVersion = 1
    packageSha256 = $actual
    binarySha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    authenticodeStatus = [string]$signature.Status
    signerSubject = $signature.SignerCertificate.Subject
    signerThumbprint = $signature.SignerCertificate.Thumbprint
    certificateNotAfter = $signature.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')
    timestampSubject = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { $null }
    verifiedAt = [DateTime]::UtcNow.ToString('o')
  } | ConvertTo-Json -Depth 3
} finally {
  if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
