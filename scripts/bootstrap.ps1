# scripts/bootstrap.ps1
# Idempotent environment setup and verification script
param(
    [switch]$SkipWSL = $false,
    [switch]$SkipGPU = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "    SHA-256 Research Framework Bootstrapper      " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# 1. Check Python
Write-Host "[Check 1/6] Python environment..." -ForegroundColor Yellow
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    throw "Python not found in PATH."
}
$pyVer = & python --version
Write-Host "  Found Python: $pyVer" -ForegroundColor Green

# 2. Check CMake & Ninja
Write-Host "[Check 2/6] Build system (CMake & Ninja)..." -ForegroundColor Yellow
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
$ninja = Get-Command ninja -ErrorAction SilentlyContinue
if (-not $cmake) { throw "CMake not found." }
if (-not $ninja) { throw "Ninja not found." }
Write-Host "  Found CMake: $((& cmake --version | Select-Object -First 1))" -ForegroundColor Green
Write-Host "  Found Ninja: $((& ninja --version))" -ForegroundColor Green

# 3. Check C++ Toolchain (MSVC / Clang)
Write-Host "[Check 3/6] C++ Compilers..." -ForegroundColor Yellow
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msvcFound = $false
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
    if ($vsPath) {
        $msvcFound = $true
        Write-Host "  Found MSVC toolset at: $vsPath" -ForegroundColor Green
    }
}
$clang = Get-Command clang -ErrorAction SilentlyContinue
if ($clang) {
    Write-Host "  Found Clang: $((& clang --version | Select-Object -First 1))" -ForegroundColor Green
}
if (-not $msvcFound -and -not $clang) {
    throw "No supported C++ compiler (MSVC or Clang) found."
}

# 4. Check Vulkan SDK & Runtime
Write-Host "[Check 4/6] Vulkan compute environment..." -ForegroundColor Yellow
if (-not $SkipGPU) {
    if ($env:VULKAN_SDK -and (Test-Path $env:VULKAN_SDK)) {
        Write-Host "  Found Vulkan SDK: $env:VULKAN_SDK" -ForegroundColor Green
    } else {
        Write-Host "  Warning: VULKAN_SDK environment variable not set, but vulkaninfo will be checked." -ForegroundColor Yellow
    }
    $vk = Get-Command vulkaninfo -ErrorAction SilentlyContinue
    if ($vk) {
        Write-Host "  Found vulkaninfo runtime loader." -ForegroundColor Green
    } else {
        Write-Host "  Vulkan runtime loader not found." -ForegroundColor Yellow
    }
}

# 5. Check Solvers
Write-Host "[Check 5/6] SAT / SMT Solvers..." -ForegroundColor Yellow
# Test Z3 in Python
$z3Test = & python -c "import z3; print(z3.get_version_string())" 2>$null
if ($z3Test) {
    Write-Host "  Found native Python Z3 SMT solver: v$z3Test" -ForegroundColor Green
} else {
    Write-Host "  Native Python Z3 solver not found. Installing via pip..." -ForegroundColor Yellow
    & python -m pip install z3-solver
}

# Test WSL solvers if available
if (-not $SkipWSL) {
    $wsl = Get-Command wsl -ErrorAction SilentlyContinue
    if ($wsl) {
        Write-Host "  WSL2 is available. Checking solver binaries in WSL..." -ForegroundColor Yellow
        $cadical = & wsl -d Ubuntu-22.04 -e bash -c "cadical --version 2>/dev/null || true"
        if ($cadical) { Write-Host "  WSL CaDiCaL: $($cadical.Trim())" -ForegroundColor Green }
        $kissat = & wsl -d Ubuntu-22.04 -e bash -c "kissat --version 2>/dev/null || true"
        if ($kissat) { Write-Host "  WSL Kissat: $($kissat.Trim())" -ForegroundColor Green }
        $cms = & wsl -d Ubuntu-22.04 -e bash -c "cryptominisat5 --version 2>/dev/null || true"
        if ($cms) { Write-Host "  WSL CryptoMiniSat: $($cms.Trim())" -ForegroundColor Green }
    }
}

# 6. Run Environment Doctor
Write-Host "[Check 6/6] Generating system inventory via doctor.ps1..." -ForegroundColor Yellow
& pwsh -File "$PSScriptRoot\doctor.ps1"

Write-Host "Bootstrap completed successfully!" -ForegroundColor Green
