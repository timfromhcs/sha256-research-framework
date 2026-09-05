# Contributing to SHA-256 Cryptanalysis Framework

## Core Principles
1. **Never claim success without machine-verifiable evidence.**
2. **Never weaken or disable the independent verifier.**
3. **Preserve negative results and failed experiments.**
4. **All C++ code must adhere to C++20 standards with zero compiler warnings.**

## Development Workflow
1. Create a feature branch: `git checkout -b feature/your-feature`
2. Implement your changes in `src/` or `include/`
3. Run the local build: `pwsh -File scripts/build.ps1`
4. Run all tests including negative verification gates: `pwsh -File scripts/test.ps1`
5. Run the evidence integrity check: `python reproducibility/verify_evidence.py`
6. Submit a Pull Request targeting `main`. All CI status checks must pass before merge.
