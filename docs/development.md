# Developer Guide & Contributor Workflows

## Coding Standards
- Modern C++20 standard (`/std:c++20`).
- No unchecked buffer access; all byte loaders and memory copies are bounds-checked.
- Target-based CMake configuration without global mutable compile flags.
- Complete documentation of all public API symbols in headers under `include/sha256_research/`.

## Workflow Cycle
1. **Self-Healing Build Loop**:
   - Make code edits in `src/` or `include/`.
   - Recompile: `pwsh -File scripts/build.ps1`
   - Run tests: `pwsh -File scripts/test.ps1`
   - If tests fail, diagnose root cause and patch.
2. **Adding a New Solver**:
   - Inherit from `ISolver` in `src/solver/solver_interface.cpp`.
   - Implement `solve_cnf` and register in `SolverFactory`.
3. **Adding a New Differential Characteristic**:
   - Define step differences in `src/differential/diff_trail.cpp`.
   - Verify pair evaluation with unit tests in `tests/test_main.cpp`.
