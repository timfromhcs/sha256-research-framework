# scripts/verify.ps1
# Independent verification script
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$exe = "$PSScriptRoot\..\build\$Configuration\sha-research.exe"
$verifier = "$PSScriptRoot\..\build\$Configuration\sha-verifier.exe"
if (-not (Test-Path $exe) -or -not (Test-Path $verifier)) {
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
}

Write-Host "Running Framework Verification..." -ForegroundColor Cyan
& $exe verify
if ($LASTEXITCODE -ne 0) { throw "sha-research verify failed with exit code $LASTEXITCODE" }

Write-Host "Running Standalone Independent Verifier KATs..." -ForegroundColor Cyan
& $verifier test-vectors
if ($LASTEXITCODE -ne 0) { throw "sha-verifier test-vectors failed with exit code $LASTEXITCODE" }

Write-Host "Running Standalone Independent Verifier Hostile Rejection Gate..." -ForegroundColor Cyan
& $verifier test-negative
if ($LASTEXITCODE -ne 0) { throw "sha-verifier test-negative failed with exit code $LASTEXITCODE" }

Write-Host "Verifying Evidence Manifests & Artifacts..." -ForegroundColor Cyan
& python "$PSScriptRoot\..\reproducibility\verify_evidence.py"
if ($LASTEXITCODE -ne 0) { throw "Evidence verification failed with exit code $LASTEXITCODE" }

Write-Host "All Independent Verification Checks Passed!" -ForegroundColor Green
