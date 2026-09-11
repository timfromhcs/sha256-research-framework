# Changelog

All notable changes to the SHA-256 Research Framework will be documented in this file.

## [2.0.0] - 2026-09-11

### Added
- **Segregated Independent Reference Engine**: Fully decoupled FIPS 180-4 hashing engine in `IndependentVerifier` with separate constants, IVs, round compression, and padding to completely eliminate common-mode failure between research and verification paths.
- **Strict Input Validation & Anti-Clamping**: Security-sensitive inputs with invalid round counts (`rounds < 1 || rounds > 64`) are explicitly rejected with fatal exit codes instead of silently clamped.
- **Hardened Adversarial Test Suite**: Expanded to 8 comprehensive test vectors covering 1-bit tampered candidates, identical inputs ($M_1 == M_2$), corrupted artifacts, modified IV claims, reduced rounds claimed as 64-round, zero-round configurations, over-claimed rounds, and forged metadata authority rejection.
- **Dedicated NIST Million 'a' Target**: Added standalone `test_million_a` executable and CTest target validating OpenSSL-identical digests on long 1MB boundary inputs.
- **Padding Boundary Verification Sweep**: Comprehensive differential sweep covering 0 to 130 byte messages, explicitly checking critical single/multi-block transitions (55, 56, 64, 65, 119, 120, 128 bytes).
- **CI Failure Propagation Hardening**: Added `$LASTEXITCODE` checks across all workflow execution steps in GitHub Actions.

### Changed
- Refactored `test_primitive_exhaustive` from `assert()` macros to exception-throwing validations for build resilience under `/DNDEBUG`.
- Fixed GLSL compute shader edge case in `search.comp` avoiding undefined 32-bit shift behavior when `target_zero_bits == 0`.
- Integrated all test suites into unified CTest suite with 100% pass rate.

## [1.0.0] - 2026-09-05

### Added
- **Core FIPS 180-4 SHA-256 Reference**: Fully validated scalar implementation with streaming support and NIST KAT vectors.
- **Multicore CPU Backend**: Unrolled compression round loops reaching 27.18 MH/s across 16 logical threads.
- **Vulkan 1.4 Compute Acceleration**: SPIR-V compute pipeline running on AMD Radeon 680M Graphics, cross-verified against CPU reference.
- **SAT/SMT Cryptanalysis**: Full Tseitin transform encoder for round steps and modular addition carry chains; native support for CaDiCaL 3.0.1, Kissat 4.0.4, CryptoMiniSat 5.8.0, and Z3 4.16.0.
- **Independent Verifier**: Segregated verification gate with strict collision definition and hostile negative test validation.
- **Adversarial Tamper Suite**: Automated detection of modified candidates, altered digests, and tampered manifest hashes.
- **Evidence Storage & Knowledge Base**: Content-addressed manifests with SHA-256 hashing and SQLite database tracking.
- **Machine Learning Search Guidance**: PyTorch neural ranker for differential trail survivability scoring.
- **Unified CLI (`sha-research`)**: Full command family for doctor, build, test, benchmark, verify, status, and autonomous research campaigns.
