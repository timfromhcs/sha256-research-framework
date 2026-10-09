# Changelog

All notable changes to the SHA-256 Research Framework will be documented in this file.

## [4.0.0] - 2026-10-09

The headline: **the deepest independently verified preimage moved from 10 rounds to 18**, and the platform can no longer report a verification result that no verifier produced.

### Security Fixes (removal of fabricated verification)

These are correctness fixes, not refactors. Each removed a code path that could
report success without any cryptographic evidence.

- **`workers/worker.py` no longer fabricates results.** It previously inferred
  verification by substring-matching C++ stdout (`"[VERIFIED]" in stdout or
  exit_code == 0`) and, when `sha-research.exe` was absent, synthesised the
  string `"[VERIFIED] Candidate block matches target digest!"`. Both paths are
  deleted. The worker now parses a machine-readable result contract and
  re-verifies every candidate by invoking `sha-verifier` as a subprocess.
- **`agent/tools.py` no longer declares collisions from input inequality.** The
  fallback `is_valid = (msg_a_hex == msg_b_hex) is False` is removed; a missing
  verifier now raises `ToolValidationError`.
- **`agent/loop.py` no longer pre-assigns L3.** Stage VERIFY recorded trust level
  `L3` before verification ran. Promotion now happens only after a real
  `IndependentVerifier` verdict, through `EpistemicTrustManager`.
- **`agent/trust.py` requires verifier provenance.** A promotion payload must name
  the segregated `IndependentVerifier` engine; a bare `is_valid: true` is refused.
  `StandardFullPreimage` additionally requires `actual_rounds == 64`.
- **Missing toolchain is `INFRA_FAILURE`, not a result.** Distinct from both a
  verified result and a negative result.
- **Path sandbox operator-precedence bug fixed.** `read_artifact` used
  `a or b and c`, permitting traversal. Replaced with `Path.resolve()` plus
  `relative_to()` containment.
- **`benchmark_backend` and `analyze_results` no longer return hardcoded values.**
  Both now measure or derive from recorded data.
- **Tests that asserted the fabricated outcome were rewritten.** Coverage added for
  tampered-candidate rejection, missing-binary refusal, and anti-clamping through
  the verifier bridge.

### Added

- **XOR encoding dialect for the SAT encoder.** Native XOR constraints in
  CryptoMiniSat's extended DIMACS, with literal normalisation (repeated
  variables, opposite-sign cancellation, shared TRUE literal for false parity).
- **Carry-save multi-operand adder (`encode_add32_multi`).** 3:2 compressors that
  satisfy `a + b + c == sum + 2*carry`, letting `T1 = h + Σ1 + Ch + W + K`
  collapse from four serial ripple adders into one pass.
- **Constant folding in `encode_add32_const`.** Replaces a materialised 32-variable
  constant word plus 32 unit clauses with per-bit AND/OR/negation.
- **`sha-research preimage` command.** `--rounds --solver --encoding --carry-save
  --timeout --out`, emitting a machine-readable `RESULT_*` contract including
  `RESULT_SOLVER_STATUS` so a solver give-up is never confused with `UNSAT`.
- **`sha-verifier --json` output.** Single-line JSON verdict with a stable schema,
  so Python consumers parse structure instead of prose. Exit code and parsed
  verdict are cross-checked for self-consistency.
- **Hybrid research loop.** `agent/proposals.py` (LLM proposal plane, permanently
  capped at L0, schema-validated against a closed allowlist, deterministic
  fallback guaranteeing progress) and `agent/scheduler.py` (deterministic
  decision plane, sole path to L3).
- **`tools/measure_scaling.py`.** Emits `reports/preimage_scaling.md` purely from
  executed runs, with the 2^256 bound stated explicitly and unresolved rounds
  labelled as unresolved.
- **Replayable cycle manifests.** Deterministic, timestamp-free JSON under
  `evidence/cycles/`, with timestamps in a sidecar so replays hash identically.
- **`verify_preimage_candidate` tool**, symmetric with the collision path.
- **`tests/test_scheduler.py`** (25 tests) covering the proposal envelope,
  adversarial LLM output parsing, scheduler escalation rules, and the trust
  boundary.

### Changed

- **Deepest verified preimage: 10 -> 18 rounds.** Measured with the XOR +
  carry-save encoding on CryptoMiniSat; round 19 did not resolve within a 240 s
  budget, which is recorded as unresolved rather than disproven.
- **CNF size at 17 rounds: −27% variables, −55% clauses** versus pure Tseitin
  (15511 vars / 30835 clauses against 21128 / 68552).
- **Measured solve-time growth between 17 and 18 rounds: ~38x.** The report uses
  the last observed ratio as the asymptotic estimate rather than an average,
  since early rounds are dominated by solver warm-up.
- **Version unified at 4.0.0** across `CMakeLists.txt`, `README.md`, and
  `sha256_research_platform/__init__.py`, which previously disagreed.
- **Test counts corrected in documentation** to match the code: 30 `sha-tests`
  (was documented as 21), 11 adversarial (was 8), 7 verifier-negative vectors
  (was 3).
- **`verifications` table** gained `verified_by` and `engine_segregated`
  columns so provenance survives into the database.
- **`sha-research campaign`** is now dialect-aware and distinguishes exit codes:
  0 verified, 1 no solution, 2 verification failure.

### Known Limitations (unchanged, restated honestly)

- No full SHA-256 preimage or collision. 2^256 evaluations is a physical bound.
- No collision encoding, MITM, boomerang, or differential trail search. The
  `is_collision_problem` flag and `message2_vars` remain declared but unused.
- The `differential` module remains a placeholder and is not used by any attack
  path. Two GPU shaders are still not dispatched from C++.
- The `ml/` trail ranker is trained on synthetic data and is not connected to any
  attack path.

## [3.0.0] - 2026-09-13

### Added
- **Headless Local-First Autonomous Research Platform**: Complete transition to headless architecture exposing REST API and WebSocket live event streams, fully decoupled from user interfaces.
- **Strict Epistemic Trust Model (L0-L5)**: Formal epistemic levels separating model hypotheses (L0), unverified observations (L1), experiment outputs (L2), independently verified results (L3), reproduced findings (L4), and cross-environment reproduced claims (L5). AI models are strictly prohibited from verifying cryptographic truth.
- **Autonomous Research Campaign Loop**: 9-stage closed-loop orchestrator (`OBSERVE` -> `FORM HYPOTHESIS` -> `DESIGN EXPERIMENT` -> `VALIDATE PLAN` -> `EXECUTE` -> `VERIFY` -> `STORE EVIDENCE` -> `ANALYZE` -> `DECIDE NEXT STEP`).
- **Tool-Restricted Agent Registry**: 17 validated sandboxed tools covering system telemetry, model management, hypothesis tracking, experiment dispatch, verification, artifact retrieval, evidence search, and automated reporting.
- **Local Model Runtime & Task-Aware Routing**: Local inference runtime supporting GGUF/llama.cpp models with Vulkan acceleration and CPU fallback; integrated hardware probe, conservative iGPU shared memory budget, and strict single-model residency.
- **Local Vision-Language Model (VLM) Analysis**: Structured visual interpretation of solver heatmaps and differential trails producing tamper-evident L1 observations.
- **Local RAG & Epistemic Research Memory**: Lexical and semantic retrieval over codebase documentation, evidence manifests, and experiment outcomes with verification-status weighting.
- **Asynchronous Worker Pool & Job Scheduling**: Non-blocking worker queue capturing exit codes, stdout/stderr, wall time, and generating automated evidence packages.
- **Crash Recovery & Orphan Detection**: Automatic detection and recovery of dangling jobs (`RUNNING`, `PREPARING`, `VERIFYING`) upon platform reboot with deterministic recovery policies.
- **Persistent SQLite Research State**: Comprehensive schema extension supporting 19 relational entities including projects, hypotheses, experiments, candidates, verifications, artifacts, models, agent actions, tool calls, observations, and benchmarks.
- **Complete End-to-End Test Suite (`test_v3_platform.py`)**: 12 automated unit and integration tests verifying all architectural guarantees and anti-clamping contracts across every layer.
- **Web Dashboard Client**: Modern, responsive web frontend consuming the REST API and live WebSocket feed without containing any cryptographic logic.

### Changed
- Decoupled `IndependentVerifier` into standalone static library target `sha256_verifier_core`, eliminating unnecessary dependencies on SAT/solvers and external components.
- Recursively hardened anti-clamping across all C++ scalar engines, Vulkan compute pipelines, verifier APIs, worker queues, and REST endpoints. Invalid rounds (`rounds < 1 || rounds > 64`) are strictly rejected.
- Standardized evidence packages to include environment specs, raw input/output logs, deterministic evidence root hashes, and verification manifests.

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
