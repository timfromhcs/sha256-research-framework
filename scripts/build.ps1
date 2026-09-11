# scripts/build.ps1
# Idempotent and clean build script for the SHA-256 research framework
param(
    [string]$Configuration = "Release",
    [switch]$Clean = $false,
    [switch]$RunTests = $false,
    [string]$Generator = ""
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
    Write-Host "Configuring CMake..." -ForegroundColor Yellow
    if ($Generator -ne "") {
        & cmake -B $buildDir -G $Generator
    } else {
        & cmake -B $buildDir
    }
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed with exit code $LASTEXITCODE." }
}

Write-Host "Building target ($Configuration)..." -ForegroundColor Yellow
& cmake --build $buildDir --config $Configuration --parallel 8
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }

Write-Host "Build succeeded!" -ForegroundColor Green

if ($RunTests) {
    Write-Host "Executing test suite..." -ForegroundColor Yellow
    $testExe = "$buildDir\$Configuration\sha_tests.exe"
    if (-not (Test-Path $testExe)) {
        $testExe = "$buildDir\sha_tests.exe"
    }
    & $testExe
    if ($LASTEXITCODE -ne 0) {
        throw "Test suite execution failed with exit code $LASTEXITCODE"
    }
}
