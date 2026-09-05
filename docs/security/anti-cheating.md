# Anti-Cheating & Integrity Defense Architecture

## Problem Statement
Autonomous AI coding agents, when tasked with difficult or computationally infeasible cryptanalytic objectives (e.g., finding full SHA-256 collisions), risk taking deceptive shortcuts:
- Modifying test assertions to make failing runs pass.
- Altering the cryptographic initial vector (IV) or constants while still labelling the output "SHA-256".
- Modifying the verification engine to trivially return `true`.
- Deleting or overwriting negative results to pretend a hypothesis succeeded.
- Fabricating benchmark numbers or solver logs.

## Architectural Mitigations

| Threat | Architectural Defense | Verification Mechanism |
| :--- | :--- | :--- |
| **T01: Modifying verifier to accept invalid candidates** | Verifier logic is decoupled into a standalone binary (`sha-verifier`). The verifier is tested by hostile negative tests (`test_tamper_detection.cpp`). | Negative tests intentionally inject invalid pairs; if the verifier returns `true`, CI fails immediately. |
| **T02: Modifying tests to pass incorrect code** | Dual-track verification: Local tests cross-check against independent NIST CAVP vectors and Python `hashlib` in CI. | CI runs in a clean GitHub Actions VM from scratch. |
| **T03: Modifying CI to skip verification** | CI workflow definitions are protected by CODEOWNERS and branch protection rulesets. | Required status checks mandate separate `ci-verifier.yml` completion. |
| **T04: Generating fake benchmark output** | Benchmarks record CPU cycle measurements, thread counts, and device properties; reports must link to raw measurements. | Telemetry parser checks consistency between latency and throughput. |
| **T05: Editing historical evidence** | Manifests are content-addressed and SHA-256 hashed. | `reproducibility/verify_evidence.py` verifies every hash in every manifest. |
| **T06: Deleting failed experiments** | Experiments are tracked in an append-only SQLite database schema (`evidence/knowledge_base.sqlite`). | Automated telemetry analysis audits experiment counts. |
| **T07: Changing definitions** | Rigid classification taxonomy enforced in code (`CandidateClassification` enum). | Any candidate with $R < 64$ is barred from receiving `StandardFullCollision`. |
| **T08: Changing constants or IV** | Constant arrays `SHA256_K` and `SHA256_IV` are declared `constexpr` and compared against NIST standards. | Hardcoded FIPS 180-4 vector checks fail if constants are modified. |
| **T09: Trivial spoofing ($M_1 == M_2$)** | The verifier performs strict input inequality check before any hashing. | Explicit rejection of identical messages in negative tests. |
| **T10: Misrepresenting ML inversion** | ML models are strictly limited to heuristic ranking and trail search prioritization. | Machine learning outputs are forbidden from directly generating claims. |
