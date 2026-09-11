# Reproducibility Report

**Generated**: 2026-09-11 20:15:31

## Reproduction Steps
To reproduce the complete research framework on a clean machine:

1. **Clone Repository & Enter Directory**:
   ```powershell
   git clone <repo_url>
   cd SHA256Solver
   ```

2. **Run Doctor & Bootstrap**:
   ```powershell
   pwsh -File scripts/doctor.ps1
   pwsh -File scripts/bootstrap.ps1
   ```

3. **Compile Release Binaries**:
   ```powershell
   pwsh -File scripts/build.ps1 -Configuration Release
   ```

4. **Run Verification & Test Suite**:
   ```powershell
   pwsh -File scripts/test.ps1
   ```

5. **Execute Performance Benchmarks**:
   ```powershell
   pwsh -File scripts/benchmark.ps1
   ```

6. **Run Cryptanalysis Experiment**:
   ```powershell
   pwsh -File scripts/research.ps1 -Rounds 10 -Solver kissat
   ```

## Immutability & Evidence
- Every experiment run is assigned an immutable timestamped ID under `evidence/experiments/<id>/`.
- Artifacts are recorded with their SHA-256 hashes in `manifest.json`.
- Historical runs are preserved and recorded in `evidence/knowledge_base.sqlite`.
