# SHA-256 Cryptanalysis Research Framework (v2.0.0)

[![Build (Windows MSVC)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-build.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-build.yml)
[![Tests (Windows)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-test.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-test.yml)
[![Independent Verifier & Adversarial Gate](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-verifier.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-verifier.yml)
[![Evidence Integrity & Anti-Tamper](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-evidence.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-evidence.yml)
[![Security & Anti-Cheating Controls](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-security.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-security.yml)
[![Documentation & Reproducibility Check](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-documentation.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-documentation.yml)

A reproducible, high-performance cryptographic research framework for Windows 11 with native CPU execution, Vulkan compute acceleration, WSL2 solver backends, SAT/SMT cryptanalysis, independent verification, and ML-guided search.

---

## Scientific Integrity & Cryptanalysis Status

> [!IMPORTANT]
> **No standard full SHA-256 collision demonstrated.**
> Full SHA-256 remains computationally secure and unbroken. All candidate preimages, differential trails, or collision claims are strictly validated by an independent reference verifier prior to acceptance.

- **Standard Full SHA-256 (64 rounds)**: **UNBROKEN**. No standard collision or full preimage has ever been discovered or claimed.
- **Reduced-Round Demonstrations**: Inversions verified on toy/reduced rounds (e.g. 8-round CaDiCaL, 10-round Kissat) for research validation only.
- **Classification Non-Negotiables**: Reduced-round experiments are never conflated with full SHA-256. Modified or custom-IV experiments are categorized strictly as `SemiFreeStart` or rejected. Near-collisions are triage heuristics, not cryptographic breaks.

---

## Release v2.0.0 Architecture & Hardening

1. **Segregated Independent Reference Verifier Engine**:
   - `IndependentVerifier` no longer shares implementation code with `Sha256Scalar`, eliminating common-mode software failure.
   - Contains an isolated, self-contained FIPS 180-4 reference engine with independent state, independent round execution, independent padding logic, and independent constant tables.
2. **Explicit Anti-Clamping Policy**:
   - Replaced silent input clamping (`std::min(rounds, 64)`) with strict, explicit validation in both CLI options and SAT encoders.
   - Any request with `rounds < 1` or `rounds > 64` throws an explicit invalid argument exception.
3. **Comprehensive Layered Test Suite (5 CTest Targets, 100% Pass Rate)**:
   - **`sha-tests` (21 tests)**: Exhaustive primitives, padding boundary sweep (0..130 bytes, 55, 56, 64, 65, 119, 120, 128 bytes), streaming chunked hashing, backend equivalence, exact search partitioning, Tseitin SAT semantics, solver replay, and verifier differential cross-checks.
   - **`sha-adversarial-tests` (8 tests)**: 1-bit tampering detection, identical input spoofing rejection, artifact hash tampering, custom-IV misclassification prevention, reduced-round conflation rejection, zero-round rejection, over-claimed rounds rejection, and forged metadata override rejection.
   - **`test-million-a`**: NIST CAVP long message test (1,000,000 `'a'` characters) verifying both scalar and optimized CPU backends against `cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0`.
   - **`verifier-kat`**: NIST Known-Answer Test suite executed via standalone `sha-verifier.exe`.
   - **`verifier-negative`**: Negative guardrail and hostile rejection test suite.
4. **Hardened Shaders & Pipelines**:
   - Corrected 32-bit shift in SPIR-V `search.comp` when target zero bits is 0.
   - Recompiled SPIR-V shaders embedded for Vulkan GPU acceleration.
5. **CI Automation & Deterministic Failure Propagation**:
   - Hardened all GitHub Actions PowerShell workflows with `$LASTEXITCODE` checks to guarantee failure propagation.

---

## Test & Validation Matrix

| Target Name | Test Count | Description | Status |
| :--- | :--- | :--- | :--- |
| `sha-tests` | 21 Unit Tests | Primitives, padding sweep, differential, Tseitin SAT, solver replay | **PASS** |
| `sha-adversarial-tests` | 8 Adversarial Tests | Hostile tamper detection, fake claims, metadata forgery guardrails | **PASS** |
| `test-million-a` | 1 NIST KAT | NIST 1,000,000 `'a'` character vector verification | **PASS** |
| `verifier-kat` | 4 Vectors | Standalone independent FIPS 180-4 reference engine KATs | **PASS** |
| `verifier-negative` | 3 Hostile Vectors | Negative rejection gates for $M_1 = M_2$, altered digests, custom IVs | **PASS** |
| `verify_evidence.py` | Full Evidence DB | SHA-256 hash manifest verification across all experiment artifacts | **PASS** |

---

## Key Capabilities

- **FIPS 180-4 Standard Compliance**: Exact reference scalar implementation cross-checked against NIST CAVP test vectors (`sha-verifier test-vectors`, `sha_tests`).
- **Multicore CPU Backend**: Portable unrolled compression path plus scalar reference fallback, validated for identical digests across padding-boundary lengths. Example measured throughput: ~27.18M hashes/sec across 16 threads on AMD Ryzen 7 7735HS.
- **Vulkan GPU Compute Acceleration (optional)**: SPIR-V compute shaders for batched compression, independently verified against CPU state when a compute device is present. CPU-only builds (`-DSHA256_ENABLE_VULKAN=OFF`) work without any Vulkan SDK.
- **Pluggable SAT/SMT Cryptanalysis (optional, environment-dependent)**: Tseitin SAT encoding for reduced-round SHA-256 with native-vs-model differential oracle tests. External solvers (CaDiCaL, Kissat, CryptoMiniSat, MiniSat, Z3) are used only when installed; solver claims are always re-verified by the independent verifier.
- **Non-Negotiable Independent Verifier**: Cryptographic results are strictly verified by an independent component before entering evidence storage. Enforces distinct inputs ($M_1 \neq M_2$) and exact FIPS padding.
- **Immutable Evidence Storage & SQLite DB**: Every experiment receives an immutable ID, SHA-256 hashed artifact manifest, and entry in `evidence/knowledge_base.sqlite`. Manifests record git commit, environment, solver version, command, seed, timing, and verification status; "executed" and "independently verified" are distinct states.
- **ML-Guided Search (research prototype)**: PyTorch neural ranking prototype trained on synthetic trail features with a reported heuristic baseline (see `ml/models/metrics.json`).

---

## Quick Start (PowerShell on Windows 11)

### 1. Environment Doctor & Dependency Verification
```powershell
pwsh -File scripts/doctor.ps1
pwsh -File scripts/bootstrap.ps1
```

### 2. Build Framework (Release)
```powershell
pwsh -File scripts/build.ps1 -Configuration Release
```

### 3. Run Automated Tests via CTest
```powershell
ctest --test-dir build -C Release --output-on-failure
# Or run using the test runner script:
pwsh -File scripts/test.ps1 -Configuration Release
```

### 4. Run Performance Benchmarks
```powershell
pwsh -File scripts/benchmark.ps1
```

### 5. Run Cryptanalysis Experiment (e.g. 10 rounds with Kissat)
```powershell
pwsh -File scripts/research.ps1 -Rounds 10 -Solver kissat
```

### 6. Query Framework Status via CLI
```powershell
.\build\Release\sha-research.exe status
```

---

## CLI Reference (`sha-research.exe`)

```
Usage: sha-research <command> [options]

Core Commands:
  doctor                  Probe environment, hardware, and toolchains
  bootstrap               Verify/setup dependencies and solvers
  build                   Configure and build framework binaries
  test                    Execute test suite (unit, KAT, differential, verifier)
  benchmark               Run CPU, Vulkan, and SAT benchmark suite
  verify                  Verify known answer vectors and negative tests
  status                  Display framework status, devices, and solvers

Research & Experimentation:
  hypothesis list         List active and evaluated research hypotheses
  experiment run [r] [s]  Execute cryptanalysis experiment with [r] rounds and solver [s]
  campaign start          Start autonomous research campaign
  analyze                 Analyze solver statistics and differential characteristics
  train                   Train ML search guidance models
  report                  Generate comprehensive markdown reports
```

---

## Architecture Overview

```
├── CMakeLists.txt              # Modern CMake build configuration (v2.0.0)
├── CMakePresets.json           # Native Windows MSVC & Ninja presets
├── include/sha256_research/    # C++ Public Headers
│   ├── core/                   # Word rotations, bitwise functions, FIPS constants
│   ├── sha256/                 # Scalar reference implementation with round tracing
│   ├── cpu/                    # Portable unrolled batching + CPUID info (no intrinsics)
│   ├── vulkan/                 # Vulkan context, SPIR-V pipeline, GPU compute
│   ├── differential/           # Differential trails and bit condition modeling
│   ├── sat/                    # Full Tseitin SAT CNF encoder
│   ├── solver/                 # Pluggable solver abstraction (CaDiCaL, Kissat, CMS, Z3)
│   ├── verifier/               # Independent verifier and integrity gate
│   ├── storage/                # Immutable runs, artifact SHA-256 manifests
│   └── benchmark/              # Benchmark suite
├── shaders/                    # GLSL compute shaders & compiled SPIR-V
│   ├── sha256.comp / .spv      # Batched 64-round SHA-256 compute shader
│   ├── differential.comp / .spv# Differential pair evaluation shader
│   └── search.comp / .spv      # Nonce and target condition search shader
├── src/                        # C++ Implementation sources
│   └── verifier/               # Segregated FIPS 180-4 reference engine
├── tests/                      # Automated test suite (KATs, Equivalence, Million 'a')
│   └── adversarial/            # Tamper detection, anti-spoofing, hostile tests
├── verifier/standalone/        # Standalone verifier CLI
├── scripts/                    # Automation scripts (doctor, bootstrap, build, test, etc.)
├── tools/                      # Python utilities (train.py, analyze.py, report.py, init_db.py)
├── evidence/                   # Immutable logs, manifests, and SQLite knowledge base
├── reports/                    # Machine-generated build, test, and benchmark reports
└── docs/                       # Complete engineering and cryptanalysis documentation
```

---

## License & Integrity Non-Negotiables

This framework strictly upholds cryptographic integrity:
1. The agent is never an authority for cryptographic validity; an independent verifier arbitrates all claims.
2. Reduced-round results, semi-free-start collisions, or differential trails are never misrepresented as standard full SHA-256 collisions.
3. Failed experiments are preserved as first-class scientific evidence.
4. Input constraints are strictly validated and never silently clamped.
