# scripts/verify.ps1
# Independent verification script
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

$exe = Find-Binary "sha-research" $Configuration
$verifier = Find-Binary "sha-verifier" $Configuration

if (-not $exe -or -not $verifier) {
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
    $exe = Find-Binary "sha-research" $Configuration
    $verifier = Find-Binary "sha-verifier" $Configuration
    if (-not $exe -or -not $verifier) {
        throw "Required binaries missing after build."
    }
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

Write-Host "Verifying Evidence Manifests, Artifacts & Release Manifest..." -ForegroundColor Cyan
& python "$PSScriptRoot\..\reproducibility\verify_evidence.py"
if ($LASTEXITCODE -ne 0) { throw "Evidence verification failed with exit code $LASTEXITCODE" }

& python "$PSScriptRoot\..\tools\generate_release_manifest.py" --verify
if ($LASTEXITCODE -ne 0) { throw "Release manifest verification failed with exit code $LASTEXITCODE" }

Write-Host "All Independent Verification Checks Passed!" -ForegroundColor Green
