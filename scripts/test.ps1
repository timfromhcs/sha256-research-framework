# scripts/test.ps1
# Test execution script
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

function Find-Binary([string]$name, [string]$config) {
    $p1 = "$PSScriptRoot\..\build\$config\$name.exe"
    if (Test-Path $p1) { return $p1 }
    $p2 = "$PSScriptRoot\..\build\$name.exe"
    if (Test-Path $p2) { return $p2 }
    return $null
}

$exe = Find-Binary "sha_tests" $Configuration
if (-not $exe) {
    Write-Host "Test binary not found. Building project first..." -ForegroundColor Yellow
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
    $exe = Find-Binary "sha_tests" $Configuration
    if (-not $exe) { throw "sha_tests.exe not found after build." }
}

Write-Host "Executing SHA-256 Test Suite..." -ForegroundColor Cyan
& $exe
if ($LASTEXITCODE -ne 0) {
    throw "Test suite failed with exit code $LASTEXITCODE"
}

$adv = Find-Binary "sha_adversarial_tests" $Configuration
if (-not $adv) { throw "sha_adversarial_tests.exe not found." }
Write-Host "Executing Adversarial & Tamper Detection Suite..." -ForegroundColor Cyan
& $adv
if ($LASTEXITCODE -ne 0) {
    throw "Adversarial tests failed with exit code $LASTEXITCODE"
}

$mil = Find-Binary "test_million_a" $Configuration
if (-not $mil) { throw "test_million_a.exe not found." }
Write-Host "Executing NIST Million 'a' Vector..." -ForegroundColor Cyan
& $mil
if ($LASTEXITCODE -ne 0) {
    throw "Million 'a' test failed with exit code $LASTEXITCODE"
}

$det = Find-Binary "test_determinism" $Configuration
if (-not $det) { throw "test_determinism.exe not found." }
Write-Host "Executing Deterministic Behavior & Reproducibility Suite..." -ForegroundColor Cyan
& $det
if ($LASTEXITCODE -ne 0) {
    throw "Determinism tests failed with exit code $LASTEXITCODE"
}

Write-Host "Executing Python Canonicalization & Evidence Verification..." -ForegroundColor Cyan
& python "$PSScriptRoot\..\reproducibility\verify_evidence.py"
if ($LASTEXITCODE -ne 0) {
    throw "Evidence verification failed with exit code $LASTEXITCODE"
}
& python "$PSScriptRoot\..\reproducibility\test_determinism.py"
if ($LASTEXITCODE -ne 0) {
    throw "Python determinism tests failed with exit code $LASTEXITCODE"
}

Write-Host "All Tests Passed Successfully!" -ForegroundColor Green
