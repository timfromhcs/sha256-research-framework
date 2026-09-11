# Final Test Report

**Generated**: 2026-09-11 20:15:31
**Results**: 21 / 21 Unit/Differential Tests PASSED | 8 / 8 Adversarial Tests PASSED | 5 / 5 CTest Targets PASSED (100% Pass Rate)

## Test Suite Execution
| Test Case | Category | Verification Method | Status |
| :--- | :--- | :--- | :--- |
| `test_nist_known_answer_vectors` | Standards (KAT) | Exact hash comparison against FIPS 180-4 vectors (Empty, 'abc', 56B, 112B) | **PASS** |
| `test_sha256_edge_lengths` | Padding Boundaries | Boundary sweep (0..130 bytes, 55, 56, 64, 65, 119, 120, 128) cross-checked | **PASS** |
| `test_streaming_chunked_hashing` | Core Library | Incremental buffer update vs. one-shot hash | **PASS** |
| `test_cpu_backend_equivalence` | Backend Integrity | Randomized messages cross-checked across Scalar & Optimized CPU | **PASS** |
| `test_search_partition_exact_cover` | Concurrency | Exact partition cover across multiple thread counts | **PASS** |
| `test_search_early_termination_sane` | Concurrency | Early termination on zero-target prefix search | **PASS** |
| `test_differential_trail_verification` | Cryptanalysis | Single-block MSB difference propagation check through round steps | **PASS** |
| `test_sat_gates_exhaustive` | SAT Encoding | Unit propagation truth table verification for AND, OR, XOR, MAJ, CH gates | **PASS** |
| `test_sat_add32_semantics` | SAT Encoding | 32-bit modular addition carry propagation semantics check | **PASS** |
| `test_sat_sigma_gamma_semantics` | SAT Encoding | FIPS Sigma0, Sigma1, Gamma0, Gamma1 transformation consistency | **PASS** |
| `test_sat_encoder_tseitin_basic` | SAT Encoding | Full Tseitin round transform for 1-round reduced CNF | **PASS** |
| `test_sat_invalid_round_rejection` | Input Validation | Explicit rejection of impossible round counts (0, 65) | **PASS** |
| `test_sat_end_to_end_with_solver` | Solver Replay | End-to-end SAT preimage inversion replayed via reference hasher | **PASS** |
| `test_independent_verifier_rejection_gate` | Negative Integrity | Strict rejection of identical messages, altered hashes, fake claims | **PASS** |
| `test_independent_verifier_differential` | Verifier Isolation | Segregated independent reference engine cross-checked with core backends | **PASS** |
| `test_verifier_metadata_forgery` | Security | Forged metadata override rejection and round bounds verification | **PASS** |
| `test_primitive_exhaustive` | Cryptographic Math | Exhaustive truth testing of rotr32, ch, maj, sigma, gamma without NDEBUG dependency | **PASS** |
| `test_concurrency_hash_batch` | Multithreading | Concurrent batch hashing across 1, 2, 4, 8, 16 worker threads | **PASS** |
| `test_concurrency_search` | Multithreading | Multi-threaded prefix search with thread counts up to 16 | **PASS** |
| `test_vulkan_smoke` | GPU Compute | 256-block GPU compute batch compared against independent CPU state | **PASS** |
| `test_million_a` | Standards (KAT) | NIST 1,000,000 'a' character long message vector verification | **PASS** |

## Adversarial & Tamper Detection Suite
| Test Case | Adversarial Vector | Expected Guardrail | Status |
| :--- | :--- | :--- | :--- |
| Test 1 | 1-bit tampered candidate digest | Rejection as non-collision | **PASS** |
| Test 2 | Identical input spoofing ($M_1 == M_2$) | Rejection of trivial candidate | **PASS** |
| Test 3 | Evidence artifact byte tampering | Immediate SHA-256 hash mismatch detection | **PASS** |
| Test 4 | Modified/Custom IV claiming standard collision | Downgraded from StandardFullCollision to SemiFreeStart | **PASS** |
| Test 5 | Reduced round (10 rounds) claimed as 64-round | Segregated from full collision claim | **PASS** |
| Test 6 | Zero-round configuration (claimed_rounds = 0) | Explicit rejection as Invalid | **PASS** |
| Test 7 | Over-claimed rounds (claimed_rounds > 64) | Explicit rejection as Invalid | **PASS** |
| Test 8 | Forged generator metadata claiming verified status | Metadata ignored; verification fails closed | **PASS** |

## Integrity Gate Check
Independent verifier successfully rejected all malformed and corrupted candidate structures. No false positives recorded.
