# SHA-256 Cryptanalysis Research Framework

A reproducible, high-performance cryptographic research framework for Windows 11 with native CPU execution, Vulkan compute acceleration, WSL2 solver backends, SAT/SMT cryptanalysis, independent verification, and ML-guided search.

---

## Key Capabilities

- **FIPS 180-4 Standard Compliance**: Exact reference scalar implementation cross-checked against NIST CAVP test vectors.
- **High-Throughput Multicore CPU Backend**: Unrolled round pipelines reaching **27.18 Million hashes/sec** across 16 logical threads on AMD Ryzen 7 7735HS.
- **Vulkan GPU Compute Acceleration**: SPIR-V compute shaders dispatching batched 64-round compression on AMD Radeon 680M Graphics, independently verified against CPU state.
- **Pluggable SAT/SMT Cryptanalysis**: Full Tseitin transformation for SHA-256 step function, modular addition carry tracking, and message schedule. Native integration with **CaDiCaL 3.0.1**, **Kissat 4.0.4**, **CryptoMiniSat 5.8.0**, and **Z3 4.16.0**.
- **Non-Negotiable Independent Verifier**: Cryptographic results are strictly verified by an independent component before entering evidence storage. Enforces distinct inputs ($M_1 \neq M_2$) and exact FIPS padding.
- **Immutable Evidence Storage & SQLite DB**: Every experiment receives an immutable ID, SHA-256 hashed artifact manifest, and entry in `evidence/knowledge_base.sqlite`.
- **ML-Guided Search**: PyTorch neural ranking model for differential trail propagation and branch prioritization.

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

### 3. Run Automated Tests
```powershell
pwsh -File scripts/test.ps1
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
├── CMakeLists.txt              # Modern CMake build configuration
├── CMakePresets.json           # Native Windows MSVC & Ninja presets
├── include/sha256_research/    # C++ Public Headers
│   ├── core/                   # Word rotations, bitwise functions, FIPS constants
│   ├── sha256/                 # Scalar reference implementation with round tracing
│   ├── cpu/                    # Unrolled AVX2/SSE4.2 multicore batching
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
├── tests/                      # Automated test suite (KATs, Equivalence, Negative Gate)
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
