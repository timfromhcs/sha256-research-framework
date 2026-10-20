# Final Build Report

## Release v5.1.0 Validation Build (Current Candidate)

**Generated**: 2026-10-20
**Source Commit**: `050cff7b254078f5c4e35aadb995a2be5a4bfe87`
**Version**: 5.1.0
**Status**: SUCCESS (Exit Code: 0)

### Current Build Matrix
| Target / Platform | Compiler | Architecture | Build Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Native Windows x64 (Full + Vulkan)** | MSVC 19.51 (VS 2026 BuildTools) | x86_64 / AVX2 | Release | **PASSED** |
| **Native Windows x64 (CPU-Only)** | MSVC 19.51 (VS 2026 BuildTools) | x86_64 / AVX2 | Release | **PASSED** |
| **Vulkan Compute Pipeline** | glslc (Vulkan SDK 1.4.357) | SPIR-V (v450) | Compute Pipeline | **PASSED** |

### Artifacts Verified
- `build/Release/sha256_core.lib` (Static Core Cryptanalysis Library)
- `build/Release/sha-research.exe` (Unified CLI Framework, version 5.1.0)
- `build/Release/sha_tests.exe` (Automated Test Runner)
- `build/Release/sha-verifier.exe` (Standalone Independent Verifier, version 5.1.0)
- `build/Release/sha_adversarial_tests.exe` (Adversarial & Tamper Detection Suite)
- `build/Release/test_million_a.exe` (NIST Million 'a' Target)
- `build/Release/test_determinism.exe` (Determinism & Reproducibility Suite)
- `build/Release/context_shaping.exe` (Context Shaping 19-Round Search Engine, version 5.1.0)
- `build/Release/c3_spectrum.exe` (Fourier Residual Spectral Analysis Tool, version 5.1.0)
- `shaders/sha256.spv` (10,216 bytes)
- `shaders/differential.spv` (11,892 bytes)
- `shaders/search.spv` (11,528 bytes)

### Verification
Clean rebuilds executed for both full and CPU-only configurations. All 9 binary targets linked cleanly with zero unresolved externals.

---

## Historical Build Record (v2.0.0 Baseline)

**Generated**: 2026-09-21 19:05:40
**Status**: SUCCESS (Exit Code: 0)

### Build Matrix
| Target / Platform | Compiler | Architecture | Build Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Native Windows x64** | MSVC 19.44 (VS 2022 Community) | x86_64 / AVX2 | Release | **PASSED** |
| **Vulkan Compute Pipeline** | glslc (Vulkan SDK 1.4.357) | SPIR-V (v450) | Compute Pipeline | **PASSED** |
| **WSL2 Linux Environment** | GCC 11.4.0 / Make | x86_64 | Native POSIX | **PASSED** |
