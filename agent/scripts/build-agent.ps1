# Builds and packages the NextAura agent for Windows amd64 on Windows.
# Requires Go 1.22+ on PATH.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:CGO_ENABLED = "0"; $env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -trimpath -ldflags "-s -w" -o dist\nextaura-agent-windows-amd64.exe .\cmd\nextaura-agent
& .\dist\nextaura-agent-windows-amd64.exe version
if ($LASTEXITCODE -ne 0) { throw "Windows agent smoke test failed." }

$stage = Join-Path $env:TEMP "nextaura-agent-windows-amd64-package"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item .\dist\nextaura-agent-windows-amd64.exe (Join-Path $stage 'nextaura-agent.exe')
Copy-Item .\scripts\install-service-windows.ps1 (Join-Path $stage 'install-agent.ps1')
Copy-Item .\scripts\uninstall-agent-windows.ps1 (Join-Path $stage 'uninstall-agent.ps1')
Copy-Item .\scripts\PACKAGE_README.txt (Join-Path $stage 'README.txt')
$archive = '.\dist\nextaura-agent-windows-amd64.zip'
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
$version = [regex]::Match((Get-Content .\internal\config\config.go -Raw), 'const Version = "([^"]+)"').Groups[1].Value
if (-not $version) { throw 'Could not read agent version.' }
node .\scripts\write-manifest.mjs $version ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
if ($LASTEXITCODE -ne 0) { throw 'Could not generate the hash-bound artifact manifest.' }
Write-Host "Package created: $archive"
