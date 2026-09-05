# scripts/clean.ps1
# Clean temporary build artifacts while preserving immutable research evidence
param(
    [switch]$All = $false
)

$ErrorActionPreference = "Continue"

Write-Host "Cleaning build directory..." -ForegroundColor Yellow
if (Test-Path "$PSScriptRoot\..\build") {
    Remove-Item -Recurse -Force "$PSScriptRoot\..\build"
}

if ($All) {
    Write-Host "Cleaning temporary test files..." -ForegroundColor Yellow
    Get-ChildItem -Path $env:TEMP -Filter "sha_*" | Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Host "Clean completed." -ForegroundColor Green
