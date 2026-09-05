# Complete Framework Reproduction Guide

Follow these verified steps to reproduce the entire environment, compile binaries, and execute research workflows.

## Prerequisites
- Windows 11 x64
- Visual Studio 2022 Community (Desktop development with C++)
- Vulkan SDK (1.4.x)
- Python 3.10+ (with PyTorch and Z3-solver)
- PowerShell Core 7+
- Optional: WSL2 with Ubuntu 22.04 (for CaDiCaL and Kissat SAT solvers)

## Step-by-Step Execution

### 1. Environmental Verification
```powershell
pwsh -File scripts/doctor.ps1
```
Generates `docs/machine_inventory.md` and raw output files in `evidence/environment/`.

### 2. Dependency Bootstrap
```powershell
pwsh -File scripts/bootstrap.ps1
```
Smoke tests all compilers, Python libraries, and solver executables.

### 3. Build Release Target
```powershell
pwsh -File scripts/build.ps1 -Configuration Release
```
Compiles `sha256_core.lib`, `sha-research.exe`, `sha_tests.exe`, and SPIR-V shaders (`sha256.spv`, `differential.spv`, `search.spv`).

### 4. Run Test Suite
```powershell
pwsh -File scripts/test.ps1
```
Verifies KATs, CPU equivalence, negative verifier gates, and Vulkan smoke test.

### 5. Run Performance Benchmarks
```powershell
pwsh -File scripts/benchmark.ps1
```
Outputs throughput metrics for CPU scalar, multicore unrolled CPU, Vulkan GPU, and SAT encoding.

### 6. Run Reduced-Round Inversion Experiment
```powershell
pwsh -File scripts/research.ps1 -Rounds 10 -Solver kissat
```
Executes automated inversion, generates immutable experiment directory under `evidence/experiments/`, and verifies the solution independently.
