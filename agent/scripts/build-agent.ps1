# Builds the NextAura agent for Windows (amd64) from a Windows machine.
# Requires Go 1.22+ on PATH. Output: agent\dist\nextaura-agent-windows-amd64.exe
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:CGO_ENABLED = "0"; $env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -trimpath -ldflags "-s -w" -o dist\nextaura-agent-windows-amd64.exe .\cmd\nextaura-agent
Get-FileHash dist\nextaura-agent-windows-amd64.exe -Algorithm SHA256 | Format-List
Write-Host "Copy the binary and its hash into agent/dist on the server to make it downloadable from the dashboard."
