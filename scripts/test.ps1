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

$adv = "$PSScriptRoot\..\build\$Configuration\sha_adversarial_tests.exe"
if (Test-Path $adv) {
    Write-Host "Executing Adversarial & Tamper Detection Suite..." -ForegroundColor Cyan
    & $adv
    if ($LASTEXITCODE -ne 0) {
        throw "Adversarial tests failed with exit code $LASTEXITCODE"
    }
}

$mil = "$PSScriptRoot\..\build\$Configuration\test_million_a.exe"
if (Test-Path $mil) {
    Write-Host "Executing NIST Million 'a' Vector..." -ForegroundColor Cyan
    & $mil
    if ($LASTEXITCODE -ne 0) {
        throw "Million 'a' test failed with exit code $LASTEXITCODE"
    }
}
