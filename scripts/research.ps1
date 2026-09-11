# scripts/research.ps1
# Autonomous research workflow runner
param(
    [int]$Rounds = 8,
    [string]$Solver = "cadical",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$exe = "$PSScriptRoot\..\build\$Configuration\sha-research.exe"
if (-not (Test-Path $exe)) {
    $exe = "$PSScriptRoot\..\build\sha-research.exe"
}
if (-not (Test-Path $exe)) {
    & "$PSScriptRoot\build.ps1" -Configuration $Configuration
    $exe = "$PSScriptRoot\..\build\$Configuration\sha-research.exe"
    if (-not (Test-Path $exe)) { $exe = "$PSScriptRoot\..\build\sha-research.exe" }
}

Write-Host "Running Autonomous Experiment: $Rounds rounds with $Solver..." -ForegroundColor Cyan
& $exe experiment run $Rounds $Solver
if ($LASTEXITCODE -ne 0) {
    throw "Research experiment failed with exit code $LASTEXITCODE"
}
