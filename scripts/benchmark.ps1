# scripts/benchmark.ps1
# Performance benchmarking runner
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$exe = "$PSScriptRoot\..\build\$Configuration\sha-research.exe"
if (-not (Test-Path $exe)) {
    Write-Host "Binary not found. Building project first..." -ForegroundColor Yellow
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
}

Write-Host "Running Benchmark Suite..." -ForegroundColor Cyan
& $exe benchmark
