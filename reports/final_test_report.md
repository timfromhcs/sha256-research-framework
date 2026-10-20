# Final Test Report

## Release v5.1.0 Full Validation (Current Candidate)

**Generated**: 2026-10-20
**Source Commit**: `2e04195d6012fa68441817407f66f67ba51c9e0a`
**Version**: 5.1.0
**Results**:
- **CTest Suite**: 17 / 17 Targets PASSED (100%)
- **Python Platform & Unit Suite**: 82 / 82 Tests PASSED (100%)
- **Framework Core Suite**: 39 / 39 Tests PASSED (100%)
- **Adversarial & Tamper Suite**: 11 / 11 Tests PASSED (100%)
- **Deterministic Manifest Check**: 12 / 12 Tests PASSED (100%)
- **Independent Verifier Rejection Gate**: All NIST vectors verified; hostile spoofing, custom IV, and altered digests rejected

### CTest Target Execution (17 / 17)
| # | Target | Description | Status |
| :--- | :--- | :--- | :--- |
| 1 | `sha-tests` | Core framework unit, differential, SAT, solver & concurrency suite (39 tests) | **PASS** |
| 2 | `sha-adversarial-tests` | Anti-tamper, spoofing, IV alteration, and metadata forgery rejection (11 tests) | **PASS** |
| 3 | `test-million-a` | NIST FIPS 180-4 1,000,000 'a' character boundary vector | **PASS** |
| 4 | `test-determinism` | C++ bitwise reproducibility and determinism test | **PASS** |
| 5 | `verifier-kat` | Segregated independent verifier known-answer vectors | **PASS** |
| 6 | `verifier-negative` | Segregated verifier hostile negative controls | **PASS** |
| 7 | `context-shaping-selftest` | Context shaping backward chain & 10 algebraic identities on planted states | **PASS** |
| 8 | `context-shaping-multifibre` | Verification of $\sigma_0/\sigma_1$ bit sensitivities against closed forms | **PASS** |
| 9 | `context-shaping-table-roundtrip` | Disk persistence roundtrip and brute-force root verification for compact CST3 table | **PASS** |
| 10 | `cli-version` | `sha-research --version` CLI contract check | **PASS** |
| 11 | `cli-help` | `sha-research --help` CLI contract check | **PASS** |
| 12 | `verifier-version` | `sha-verifier --version` CLI contract check | **PASS** |
| 13 | `verifier-help` | `sha-verifier --help` CLI contract check | **PASS** |
| 14 | `context-shaping-version` | `context_shaping --version` CLI contract check | **PASS** |
| 15 | `context-shaping-help` | `context_shaping --help` CLI contract check | **PASS** |
| 16 | `c3-spectrum-version` | `c3_spectrum --version` CLI contract check | **PASS** |
| 17 | `c3-spectrum-help` | `c3_spectrum --help` CLI contract check | **PASS** |

### Python Test Suite Summary (82 / 82)
- `tests/test_context_shaping.py` (13 tests): Context shaping parameter handling, memory budget guards, algebraic identities
- `tests/test_evidence_verifier.py` (7 tests): Fail-closed validation on empty manifests, path traversal rejection, schema enforcement
- `tests/test_published_witnesses.py` (8 tests): External 19- and 20-round witness verification and negative rejection
- `tests/test_python_reference_kat.py` (7 tests): Independent reference Python implementation KATs
- `tests/test_scheduler.py` (25 tests): Job scheduling, prioritization, worker concurrency, and timeout handling
- `tests/test_v3_platform.py` (15 tests): SQLite persistence, REST API, recovery, tool registration, anti-clamping
- `tests/test_z3_cross_check.py` (7 tests): Z3 bit-vector cross-check agreement and missing solver contracts

---

## Historical Test Record (v2.0.0 Baseline)

**Generated**: 2026-09-21 19:05:40
**Results**: 21 / 21 Unit/Differential Tests PASSED | 8 / 8 Adversarial Tests PASSED | 6 / 6 CTest Targets PASSED (100% Pass Rate)

### Historical Test Suite Execution
| Test Case | Category | Verification Method | Status |
| :--- | :--- | :--- | :--- |
| `test_nist_known_answer_vectors` | Standards (KAT) | Exact hash comparison against FIPS 180-4 vectors | **PASS** |
| `test_sha256_edge_lengths` | Padding Boundaries | Boundary sweep (0..130 bytes) cross-checked | **PASS** |
| `test_streaming_chunked_hashing` | Core Library | Incremental buffer update vs. one-shot hash | **PASS** |
| `test_cpu_backend_equivalence` | Backend Integrity | Randomized messages cross-checked | **PASS** |
| `test_search_partition_exact_cover` | Concurrency | Exact partition cover across multiple thread counts | **PASS** |
| `test_search_early_termination_sane` | Concurrency | Early termination on zero-target prefix search | **PASS** |
| `test_differential_trail_verification` | Cryptanalysis | Single-block MSB difference propagation check | **PASS** |
| `test_sat_gates_exhaustive` | SAT Encoding | Unit propagation truth table verification | **PASS** |
| `test_sat_add32_semantics` | SAT Encoding | 32-bit modular addition carry propagation semantics | **PASS** |
| `test_sat_sigma_gamma_semantics` | SAT Encoding | FIPS Sigma0, Sigma1, Gamma0, Gamma1 consistency | **PASS** |
| `test_sat_encoder_tseitin_basic` | SAT Encoding | Full Tseitin round transform for 1-round reduced CNF | **PASS** |
| `test_sat_invalid_round_rejection` | Input Validation | Explicit rejection of impossible round counts (0, 65) | **PASS** |
| `test_sat_end_to_end_with_solver` | Solver Replay | End-to-end SAT preimage inversion replayed | **PASS** |
| `test_independent_verifier_rejection_gate` | Negative Integrity | Strict rejection of identical messages, altered hashes | **PASS** |
| `test_independent_verifier_differential` | Verifier Isolation | Segregated independent reference engine | **PASS** |
| `test_verifier_metadata_forgery` | Security | Forged metadata override rejection | **PASS** |
| `test_primitive_exhaustive` | Cryptographic Math | Exhaustive truth testing of rotr32, ch, maj, sigma | **PASS** |
| `test_concurrency_hash_batch` | Multithreading | Concurrent batch hashing across threads | **PASS** |
| `test_concurrency_search` | Multithreading | Multi-threaded prefix search | **PASS** |
| `test_vulkan_smoke` | GPU Compute | 256-block GPU compute batch compared against CPU | **PASS** |
| `test_million_a` | Standards (KAT) | NIST 1,000,000 'a' character long message vector | **PASS** |
