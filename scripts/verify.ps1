# scripts/verify.ps1
# Independent verification script
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$exe = "$PSScriptRoot\..\build\$Configuration\sha-research.exe"
if (-not (Test-Path $exe)) {
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
}

Write-Host "Running Independent Verification..." -ForegroundColor Cyan
& $exe verify
