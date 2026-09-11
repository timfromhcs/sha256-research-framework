# scripts/clean.ps1
# Clean temporary build artifacts while preserving immutable research evidence
param(
    [switch]$All = $false
)

$ErrorActionPreference = "Continue"

Write-Host "Cleaning build directory..." -ForegroundColor Yellow
$dirsToClean = @("build", "build-cpuonly", "build_cpu", "build_debug", "build_fresh", "Testing")
foreach ($d in $dirsToClean) {
    $p = "$PSScriptRoot\..\$d"
    if (Test-Path $p) {
        Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue
    }
}

if ($All) {
    Write-Host "Cleaning temporary test files..." -ForegroundColor Yellow
    Get-ChildItem -Path $env:TEMP -Filter "sha_*" | Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Host "Clean completed." -ForegroundColor Green
