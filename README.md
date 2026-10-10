# SHA-256 Cryptanalysis Research Framework (v4.1.0)

[![Build (Windows MSVC)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-build.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-build.yml)
[![Tests (Windows)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-test.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-test.yml)
[![Independent Verifier & Adversarial Gate](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-verifier.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-verifier.yml)
[![Evidence Integrity & Anti-Tamper](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-evidence.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-evidence.yml)
[![Security & Anti-Cheating Controls](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-security.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-security.yml)
[![Documentation & Reproducibility Check](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-documentation.yml/badge.svg?branch=main)](https://github.com/timfromhcs/sha256-research-framework/actions/workflows/ci-documentation.yml)

A headless, local-first autonomous research platform for SHA-256 cryptanalysis with native CPU execution, Vulkan compute acceleration, SAT/SMT solvers, local LLM/VLM runtimes, tool-restricted autonomous agent orchestration, independent verification, and tamper-evident evidence packages.

---

## Scientific Integrity & Cryptanalysis Status

> [!IMPORTANT]
> **No standard full SHA-256 collision demonstrated.**
> Full SHA-256 remains computationally secure and unbroken. All candidate preimages, differential trails, or collision claims are strictly validated by an independent reference verifier prior to acceptance.
>
> **Epistemic Trust Model (L0-L5)**:
> - **L0**: Model Suggestion (Hypothesis)
> - **L1**: Unverified Observation (Visual/Empirical)
> - **L2**: Experiment Output (Solver Raw Result)
> - **L3**: Independently Verified (Arbitrated by IndependentVerifier)
> - **L4**: Reproduced (Locally replicated with identical parameters)
> - **L5**: Cross-Environment Reproduced (Independently validated across platforms)
>
> Neither LLM, VLM, nor agent output is ever treated as cryptographic proof. Only the segregated `IndependentVerifier` arbitrates truth.

- **Standard Full SHA-256 (64 rounds)**: **UNBROKEN**. No standard collision or full preimage has ever been discovered or claimed.
- **Reduced-Round Demonstrations**: Inversions are verified by the independent reference engine. The deepest preimage this framework has confirmed is **18 rounds** of the compression function (see [`reports/preimage_scaling.md`](reports/preimage_scaling.md)). Round 19 did not resolve within the measured budget — that is a statement about this encoding and this budget, **not** a proof of impossibility.
- **Why full SHA-256 is out of reach**: A full preimage costs 2^256 ≈ 1.16e77 compression-function evaluations. All Bitcoin mining combined (~1e21 H/s) would need roughly 1e56 years. This is a physical bound, not an implementation gap.
- **Classification Non-Negotiables**: Reduced-round experiments are never conflated with full SHA-256. Modified or custom-IV experiments are categorized strictly as `SemiFreeStart` or rejected. Near-collisions are triage heuristics, not cryptographic breaks.

---

## Release v4.1.0: Advanced Search Strategies (measured, including what failed)

Implements the techniques from Zaikin, *Constraints* 2026, which reached 19
rounds of SHA-256 via a parameterised CDCL solver plus parallel
Cube-and-Conquer. Both were implemented and **measured to be worse on this
instance**, which is reported rather than hidden.

### Parallel Cube-and-Conquer

```bash
sha-research preimage --rounds N --cube-bits K --cube-round R \
                      [--cube-register a|e] [--jobs J]
```

Disjoint cubes over selected state bits, each solved independently under
assumptions; a cube proven `UNSAT` yields a blocking clause that prunes it
permanently. Because the cubes are disjoint and total, exhausting them with
`UNSAT` is a **proof** of nonexistence, not a timeout.

Safety properties: cubes are processed in batches so the master formula is
never written concurrently; a cube that merely times out is never pruned.

### Message-word pinning

```bash
sha-research preimage --rounds N --fix-words 0:7 --fix-seed S
```

`fixed_words` uses explicit `(index, value)` pairs, so pinning `W[3]` does not
silently pin `W[0..2]`.

### Measured at 18 rounds (XOR + carry-save, 300 s budget)

| Strategy | Solve time | Outcome |
| :--- | ---: | :--- |
| unrestricted | **13.3 s** | VERIFIED |
| pin `W[0..3]` | 293 s | TIMEOUT |
| pin `W[0..7]` | 292 s | TIMEOUT |
| Cube-and-Conquer (12 bits) | 296 s | VERIFIED |

At 19 rounds, 10-bit Cube-and-Conquer left **1024/1024 cubes inconclusive**
after 3860 s and learned no blocking clauses.

**Why both lose.** A one-block preimage is overdetermined by 2^256 — 512 free
message bits map onto a 256-bit digest — so the instance is satisfiable by a
wide margin and is hard only because the search cannot thread one of many
solutions through a deep circuit. Pinning removes the solver's room to
manoeuvre without making propagation easier, and partitioning gives each worker
a strictly harder subproblem. Shrinking the search space does not help an
overdetermined problem. See
[`docs/research/advanced-strategies.md`](docs/research/advanced-strategies.md)
and [`reports/preimage_strategies.md`](reports/preimage_strategies.md).

### Why 19 rounds still needs a programmable solver

The published result depends on a CDCL implementation whose branching heuristic
is specialised to intermediate inverse problems, which is not reachable through
a solver binary's command-line flags. The practical 19/20-round record (Basra
2026) uses table-based context shaping instead of SAT inversion.

---

## Release v4.0.0: Verification Integrity & Encoding Depth

### 1. Single Trust Boundary (no fallback verdicts)

Previous versions of the Python platform could report a verification result that no
verifier had produced. All of those paths are removed:

- `workers/worker.py` inferred success by substring-matching C++ stdout
  (`"[VERIFIED]" in stdout`) and, when the binary was missing, **fabricated** a
  passing result. It now parses a machine-readable result contract and re-verifies
  every candidate through `sha-verifier`.
- `agent/tools.py` declared a collision valid purely because two inputs differed.
  That fallback is deleted; a missing verifier is now a hard error.
- `agent/loop.py` recorded stage VERIFY as `L3` *before* verification ran. Promotion
  is now earned, never assumed.
- A missing or unparseable verifier raises `VerificationUnavailable`. There is no
  code path from "no evidence" to "verified". A missing research binary is recorded
  as `INFRA_FAILURE`, which is explicitly not a scientific result.

`EpistemicTrustManager` additionally requires the verdict to name the segregated
`IndependentVerifier` engine; a bare `is_valid: true` is no longer sufficient.

### 2. Leaner SAT Encodings

`src/sat/sat_encoder.cpp` gained two first-class encoding dialects:

- **XOR dialect** — native XOR constraints in CryptoMiniSat's extended DIMACS, so
  the solver can run Gaussian elimination over the GF(2) subsystem instead of
  clause-level propagation. SHA-256's σ/γ functions and adder sum bits are
  XOR-dominated, which makes this the single largest win.
- **Carry-save T1** — `T1 = h + Σ1 + Ch + W + K` is reassociated into one
  carry-save (3:2 compressor) tree instead of four serial ripple adders.

Measured at 17 rounds (`reports/preimage_encoding_compare.md`):

| Configuration | CNF vars | CNF clauses | vs. baseline |
| :--- | ---: | ---: | :--- |
| `tseitin` / CaDiCaL | 21128 | 68552 | baseline |
| `tseitin+cs` / CaDiCaL | 20550 | 72171 | −3% vars |
| `xor` / CryptoMiniSat | 16616 | 29256 | −21% vars, −57% clauses |
| `xor+cs` / CryptoMiniSat | **15511** | 30835 | **−27% vars, −55% clauses** |

New CLI surface:

```
sha-research preimage --rounds N [--solver S] [--encoding xor|tseitin]
                       [--carry-save] [--timeout T] [--out DIR]
```

It emits a machine-readable result contract (`RESULT_CANDIDATE`,
`RESULT_TARGET_DIGEST`, `RESULT_SOLVER_STATUS`, `RESULT_CNF_*`, …) that the Python
platform consumes instead of scraping prose.

### 3. Hybrid Research Loop

Two planes with a hard trust boundary:

- **Proposal plane** (`agent/proposals.py`) — an LLM may emit candidate
  configurations. They are schema-validated against a closed allowlist, are
  permanently capped at trust level **L0**, and the rationale is stored verbatim
  for audit. A deterministic proposer guarantees forward progress if no model is
  loaded, so the loop can never stall.
- **Decision plane** (`agent/scheduler.py`) — the *only* component that executes
  work and the *only* path to L3. Escalation follows measured depth, not model
  optimism. A solver/model-extraction disagreement is flagged as a **bug** and
  halts progression. A timeout grows the budget instead of being recorded as a
  wall. A solver `UNSAT` is distinguished from a solver give-up, because only the
  former is a proof.

Each cycle writes a deterministic, timestamp-free manifest to
`evidence/cycles/`, with timestamps in a sidecar so replays hash identically.

### 4. Honest Measurement

`tools/measure_scaling.py` produces `reports/preimage_scaling.md` purely from
executed runs. It states the 2^256 bound explicitly, labels every unresolved
round as unresolved rather than disproven, and reports the measured per-round
growth factor without extrapolating a complexity-theoretic bound.

---

## Release v2.0.0 Architecture & Hardening

1. **Segregated Independent Reference Verifier Engine**:
   - `IndependentVerifier` no longer shares implementation code with `Sha256Scalar`, eliminating common-mode software failure.
   - Contains an isolated, self-contained FIPS 180-4 reference engine with independent state, independent round execution, independent padding logic, and independent constant tables.
2. **Explicit Anti-Clamping Policy**:
   - Replaced silent input clamping (`std::min(rounds, 64)`) with strict, explicit validation in both CLI options and SAT encoders.
   - Any request with `rounds < 1` or `rounds > 64` throws an explicit invalid argument exception.
3. **Comprehensive Layered Test Suite (6 CTest Targets, 100% Pass Rate)**:
   - **`sha-tests` (30 tests)**: Exhaustive primitives, padding boundary sweep, streaming chunked hashing, backend equivalence, exact search partitioning, SAT gate and adder semantics, **encoding-dialect semantic equivalence**, solver replay, and verifier differential cross-checks.
   - **`sha-adversarial-tests` (11 tests)**: 1-bit tampering detection, identical input spoofing rejection, artifact hash tampering, custom-IV misclassification prevention, reduced-round conflation rejection, zero-round rejection, over-claimed rounds rejection, forged metadata override rejection (collision and preimage), and preimage tamper rejection.
   - **`test-million-a`**: NIST CAVP long message test (1,000,000 `'a'` characters) verifying both scalar, optimized, and independent verifier backends against `cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0`.
   - **`test-determinism`**: Dedicated determinism test verifying bit-for-bit output invariance across repeated runs (runs A, B, C) across all engines, parallel batch hashing, SAT encodings, and differential trails.
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
| `sha-tests` | 30 Unit Tests | Primitives, padding sweep, differential, SAT dialects, adder semantics, solver replay | **PASS** |
| `sha-adversarial-tests` | 11 Adversarial Tests | Hostile tamper detection, fake claims, metadata forgery guardrails | **PASS** |
| `test-million-a` | 1 NIST KAT | NIST 1,000,000 `'a'` character vector verification | **PASS** |
| `test-determinism` | 8 Invariance Tests | Multi-run (A/B/C) determinism for CPU, threads, SAT, verifier | **PASS** |
| `verifier-kat` | 4 Vectors | Standalone independent FIPS 180-4 reference engine KATs | **PASS** |
| `verifier-negative` | 7 Hostile Vectors | Negative rejection gates: identical inputs, altered digests, custom IVs, round-count abuse | **PASS** |
| `tests/test_v3_platform.py` | 15 Tests | Platform entities, anti-clamping, trust validation, verification integrity, REST API | **PASS** |
| `tests/test_scheduler.py` | 25 Tests | Proposal envelope, LLM output parsing, scheduler escalation rules, trust boundary | **PASS** |
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
