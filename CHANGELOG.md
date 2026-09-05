# Changelog

All notable changes to the SHA-256 Research Framework will be documented in this file.

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
