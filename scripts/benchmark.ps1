# scripts/benchmark.ps1
# Performance benchmarking runner
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$exe = "$PSScriptRoot\..\build\$Configuration\sha-research.exe"
if (-not (Test-Path $exe)) {
    $exe = "$PSScriptRoot\..\build\sha-research.exe"
}
if (-not (Test-Path $exe)) {
    Write-Host "Binary not found. Building project first..." -ForegroundColor Yellow
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
    $exe = "$PSScriptRoot\..\build\$Configuration\sha-research.exe"
    if (-not (Test-Path $exe)) { $exe = "$PSScriptRoot\..\build\sha-research.exe" }
}

Write-Host "Running Benchmark Suite..." -ForegroundColor Cyan
& $exe benchmark
if ($LASTEXITCODE -ne 0) {
    throw "Benchmark suite failed with exit code $LASTEXITCODE"
}
