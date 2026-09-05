# scripts/build.ps1
# Idempotent and clean build script for the SHA-256 research framework
param(
    [string]$Configuration = "Release",
    [switch]$Clean = $false,
    [switch]$RunTests = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "     SHA-256 Research Framework Build System     " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

$buildDir = "$PSScriptRoot\..\build"

if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "Cleaning build directory: $buildDir" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $buildDir
}

if (-not (Test-Path $buildDir)) {
    Write-Host "Configuring CMake (Visual Studio 2022 x64)..." -ForegroundColor Yellow
    & cmake -B $buildDir -G "Visual Studio 17 2022" -A x64
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }
}

Write-Host "Building target ($Configuration)..." -ForegroundColor Yellow
& cmake --build $buildDir --config $Configuration --parallel 8
if ($LASTEXITCODE -ne 0) { throw "Build failed." }

Write-Host "Build succeeded!" -ForegroundColor Green

if ($RunTests) {
    Write-Host "Executing test suite..." -ForegroundColor Yellow
    & "$buildDir\$Configuration\sha_tests.exe"
}
