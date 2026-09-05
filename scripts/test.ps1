# scripts/test.ps1
# Test execution script
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$exe = "$PSScriptRoot\..\build\$Configuration\sha_tests.exe"
if (-not (Test-Path $exe)) {
    Write-Host "Test binary not found. Building project first..." -ForegroundColor Yellow
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
}

Write-Host "Executing SHA-256 Test Suite..." -ForegroundColor Cyan
& $exe
if ($LASTEXITCODE -ne 0) {
    throw "Test suite failed with exit code $LASTEXITCODE"
}
