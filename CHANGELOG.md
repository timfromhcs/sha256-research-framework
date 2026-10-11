# Changelog

All notable changes to the SHA-256 Research Framework will be documented in this file.

## [5.0.0] - 2026-10-11

Published as a GitHub release with prebuilt archives for Windows x64, Linux x64
and macOS arm64. Each archive is built on a runner of the matching operating
system and ships with a `.sha256` digest; no binary is cross-labelled.

**This framework now solves 19 rounds of the SHA-256 compression function
itself.** In v4.3.0 it could only *verify* published 19- and 20-round
preimages. This release produces 19-round preimages in under a second on
commodity hardware, and documents precisely why 20 and 21 remain out of reach.

### Added

- **`tools/context_shaping.cpp` — context-shaping preimage search.** An
  independent reimplementation of the submask family (Basra 2026,
  `github.com/kamb-code/sha256-r19-preimage`); no code is shared with that
  repository, and the equations are derived from FIPS 180-4 plus the
  structural conditions of the construction.

  Works backwards from the target so the target fixes eight state words with no
  search, imposes `a4 = a5 = v` and `e8 = e9 = 0xFFFFFFFF` to exploit the
  saturations `Ch(0xFFFFFFFF, y, z) = y` and `Maj(x, x, y) = x`, and so makes
  the `W16, W17, W18` schedule constraints triangular in `(a1, a2, a3)`. Three
  inverse-table lookups replace a fixed-point iteration, and the residual
  collapses from a 32-bit modular equation to the bitwise condition
  `Maj(v, a3, a2) == a3`.

- **A verified 19-round preimage**, produced by this framework:

  ```
  1b2ffb528506b511c2db748f75d4fe52f
  7674fd48874e7b9b374812290818441f
  22f4d988399a64f2fbadc6a256f8ac32
  4e45a975978b51418a0375599cf2cd1
  ```

  Segregated `IndependentVerifier`: `is_valid=true`,
  `classification=ReducedRoundPreimage`, `hamming_distance=0`,
  `engine_segregated=true`; **rejected at 18 and at 20 rounds**.

  This is a round the direct SAT encoding could not reach at all (>3230 s
  unresolved). SAT still reaches 18 rounds in ~13.2 s; the two are
  complementary, not substitutes.

- **Lossless table reduction to fit ~11 GiB of RAM.** The published
  construction assumes a 16 GiB inverse table. Two reductions make it fit:
  store roots only for image values below `2^B` (yield falls by
  `(2^B/2^32)^3`, memory by `2^(32-B)`), and scan the *whole* 32-bit range of
  `u` regardless of storage width. The second matters: restricting the scan to
  the same range drops the image density from 0.6337 to 0.25 and costs a factor
  of 16 in yield, because all three lookups must hit.

- **20-round fourth constraint `C3`** plus a residual-measurement mode
  (`CS_MEASURE_C3=1`) that reports the cumulative low-`k` zero counts of
  `c3 = sigma0(W4) + W3 - kappa3`.

- **13 new tests** (`tests/test_context_shaping.py`) and a new CTest target
  `context-shaping-selftest`. Totals: 39 C++ unit, 11 adversarial, 87 Python,
  7 CTest.

### Fixed

Two derivation bugs, both of which produced *plausible* output rather than
failing loudly. Both were found by planted-state identity tests, not by running
the search and reading the digest:

- **`Maj(x, y, y) = y`, not `x`.** With `a5 = a4 = v` the saturated term
  `T2^(7) = Sigma0(a6) + Maj(a6, v, v)` equals `Sigma0(a6) + v`. Using `a6`
  silently corrupted `A_0` and `A_2`.
- **`W_0` is not a constant.** Round 0 gives `W_0 = a_0 - const`, so it
  carries the swept variable with coefficient +1. Treating it as constant broke
  `C0` only — `C1` and `C2` still passed, the worst possible failure shape for a
  hand-rolled search.

The ten algebraic identities are now checked on planted states in 0.05 s, so
this class of error cannot return silently.

### Fixed (robustness)

- **Hexadecimal option parsing caused a machine crash.** `--bits 28` was parsed
  as `0x28 = 40`, and the tool requested a 17 GiB allocation on a machine with
  ~11 GiB free, exhausting memory. Options are now decimal with validation, and
  a hard memory budget clamps the table width *before* allocating. Both are
  covered by regression tests.

### Measured

| Configuration | Rounds | Cost |
| --- | ---: | --- |
| Direct SAT, XOR + carry-save | 18 | ~13.2 s |
| Direct SAT | 19 | > 3230 s, unresolved |
| Context shaping, submask family | **19** | **~0.3 s** after a one-time table |

- Throughput ~1.4e7 swept `a0` per second on this machine; one 19-round
  preimage per ~6e6 swept values at `--bits 30`.
- 20 rounds projects to `2^45.4` swept values, about 15 h on one A100.
  **Not reproduced here.**
- 21 rounds projects to `2^77` swept values, about **5.6 million years on a
  single A100**. This is an arithmetic wall, not a missing implementation.

### Not achieved

- **No 20-round preimage was produced by this framework.** The deepest
  *confirmed* result remains the externally published 20-round witness from
  v4.3.0, which is not ours.
- **21 rounds is out of reach** with this construction on any plausible
  hardware. Basra's barrier analysis localises the obstruction to a single
  wire, with a falsification search over ~1.6e6 legal context conditions finding
  10.86 bits changed per flipped bit against a 2-bit absorption threshold.
- The `C3` residual measurement is **not** a validation of the `2^-32` model:
  24 candidates is far too small a sample. Basra himself reports that rate as a
  working extrapolation.
- Full SHA-256 remains unbroken at 2^256. Nothing here affects collision
  resistance, and a reduced-round preimage of a compression function is not a
  preimage of the padded hash.

## [4.3.0] - 2026-10-11

Adds **external witness verification** and a **second, independent solver core**.
The framework still cannot *solve* 19- or 20-round preimages on commodity
hardware, but it can now corroborate published ones and cross-check its own
encodings against a solver that shares none of its code.

### Added

- **`tools/verify_published.py` — external witness verification.** Confirms
  eight published reduced-round preimages with the segregated
  `IndependentVerifier`, each paired with a **negative control** at a
  neighbouring round count.
  - **8/8 verified.** P1–P7 at 19 rounds (Basra 2026,
    `github.com/kamb-code/sha256-r19-preimage`; P7 uses the all-ones target
    also used by Zaikin, Constraints 2026), plus R20 at 20 rounds.
  - Every positive witness verifies with Hamming distance 0; every negative
    control is rejected. **Deepest externally published preimage confirmed:
    20 rounds.**
  - A permissive verifier that accepted everything would fail the controls, so
    the result is meaningful rather than vacuous.
- **`tools/z3_bitvector_check.py` — Z3 bit-vector solver core.** An independent
  SAT path with a different search heuristic, used as a cross-check.
  - Four gates must agree before any result is reported: Z3 model, independent
    Python recomputation, the segregated C++ verifier, and a negative control.
    Disagreement between engines is reported as an error, not smoothed over.
- **22 new tests** (39 C++, 74 Python):
  - `tests/test_published_witnesses.py` — witness verification, negative
    controls, bit-flip tamper rejection, segregated-engine provenance, and
    failure when the verifier binary is missing.
  - `tests/test_python_reference_kat.py` — known-answer tests for the Python
    reference against the NIST vectors, `hashlib` across every padding
    boundary, the framework's own K/IV tables, and all eight published
    witnesses.
  - `tests/test_z3_cross_check.py` — cross-engine agreement, honest `UNKNOWN`
    reporting, and clean dependency handling.
- **C++ test for encoder completeness against conditioned projections**
  (Feng and Gao, ePrint 2026/1505). See *Fixed* below.

### Fixed

- **`tools/z3_bitvector_check.py` round constant.** `K[2]` was written as
  `0xb5c0fbbc` instead of the correct `0xb5c0fbcf` — a single transposed digit
  that produced plausible-looking but wrong digests in every run. Caught by
  disagreement with the C++ verifier, then pinned by
  `tests/test_python_reference_kat.py`.
- **`locate_verifier()` in `tools/verify_published.py`** silently fell back to
  a default binary when `SHA_VERIFIER_BIN` pointed at a missing file. An
  explicit override is now authoritative: on a trust boundary, "the verifier
  you asked for is not there" must not degrade into "I found another one".

### Measured

| Configuration | Deepest reduced-round preimage |
| --- | --- |
| CryptoMiniSat + XOR dialect + carry-save (native) | **18** |
| Z3 bit-vector (eager bit-blasting) | **7** |
| Unconstrained 18 rounds | ~13.2 s |
| Dobbertin E@12/24 bit, 18 rounds | ~115.7 s |

- The **11-round gap** between the native path and Z3 is not a defect in
  either. SHA-256 is XOR-dominated, and native XOR clauses let the solver apply
  Gaussian elimination; Z3 bit-blasts eagerly into plain CNF and loses that
  structure. This is independent support for the XOR-dialect decision.
- **Conditional-affine redundancy is unnecessary here.** Feng and Gao propose
  redundant Ch/Maj clauses so that conditioned projections are visible to BCP.
  The new C++ test checks our encodings directly against that criterion: every
  conditioned projection implied by the Ch and Maj truth tables is *already*
  entailed by the clauses we emit. The redundant clauses cannot therefore
  improve propagation, which is consistent with the measured slowdown from
  adding them. The paper's motivation remains sound for encodings that do not
  meet this bar; ours does.

### Not achieved

- 19-round preimages remain **unsolved** by this framework. The published
  19- and 20-round results rely on table-based context shaping and heavily
  parameterised search, not a direct SAT encoding.
- Z3 bit-vector does not scale to the round counts that matter; it is a
  cross-check, not a path forward.

### Documentation

- **README test matrix corrected**: the C++ unit-test count was still listed as
  30 (actual: 39), and the three new Python test modules were missing. The
  matrix now lists every target with its real count, plus totals (39 C++, 11
  adversarial, 74 Python, 6 CTest) and the seven CI checks.
- **Repository tree updated**: `tools/` and `tests/` now list the v4.3.0 files,
  and `CMakeLists.txt` no longer claims v2.0.0.
- Em-dash encoding damage in `docs/research/advanced-strategies.md` repaired;
  the file is clean UTF-8.

### CI

All seven checks pass on `main` @ `8e0b59d` — no bypass was required:
`build-windows-msvc`, `build-windows-cpuonly`, `tests-windows`,
`verifier-independent`, `security-audit`, `evidence-integrity`,
`documentation-check`.

## [4.2.0] - 2026-10-10

Implements **Dobbertin's state-register constraints** (Dobbertin 1998; applied
to SHA-2 by Davydov, Pikhtovnikov, Kiryanova and Zaikin 2025, who reported 17-
and 18-round preimages "for the first time") — the technique behind the
published 19-round result — and records its measured behaviour here.

### Added

- **Dobbertin-style state constraints.** Forces the top `B` bits of one state
  register at a round boundary to match a chosen constant `K`, then relaxes `B`
  one bit at a time on failure, following Algorithm 1 of Zaikin (IJCAI-ECAI
  2022).
  - Relaxation is sound in both directions: fewer constraint bits is a strict
    superset of the solution set, so a preimage found at a lower level is still
    genuine. Inconclusive levels relax rather than abort.
  - Only the unconstrained `B = 0` instance being `UNSAT` is reported as
    `ProvenNoPreimage`; every other outcome is `Unresolved`.
  - CLI: `--dobbertin-bits B --dobbertin-round R --dobbertin-register a|e
    --dobbertin-constant K`.
  - Encoder support pins the most-significant bits first and rejects
    out-of-range rounds and bit counts above 32.
- **2 new C++ tests** (38 total): the constraint pins exactly the requested
  bits (complement is UNSAT, lower bits stay free, 0 bits is a no-op), and
  invalid round / bit counts are rejected.

### Measured at 18 rounds (XOR + carry-save, 300 s budget)

| Strategy | Solve time | Outcome |
| :--- | ---: | :--- |
| **unrestricted** | **13.2 s** | VERIFIED |
| Dobbertin E@12, 24 bits, K=0 | 115.7 s | VERIFIED |
| pin `W[0..3]` | 285.5 s | TIMEOUT |
| pin `W[0..7]` | 285.2 s | TIMEOUT |
| Cube-and-Conquer, 12 bits | 287.0 s | VERIFIED |

Position sweep for the Dobbertin constraint at 18 rounds: E@8 and E@4 both
relax all the way to 0 bits (no constraint helped), A@8 found at 10 bits, and
**E@12 found at 24 bits with no relaxation at all**.

That is a real structural finding — constraining 24 bits of a middle-round
register still admits preimages — but it is ~9x slower than the plain search.

At 19 rounds nothing resolved: the unrestricted instance exceeds 3230 s, all
1024 Cube-and-Conquer cubes time out, and all 25 Dobbertin relaxation levels
time out.

### Solver tuning investigated and reported

CryptoMiniSat's `--maxmatrixrows` default (5000) sits below the 6189 XOR
constraints at 19 rounds, which looked like it might silently disable Gaussian
elimination. Verbose output shows it running normally, building 4892x10010 and
2249x4816 matrices with average XOR length 3.7–3.9. A six-configuration flag
sweep (`--maxmatrixrows 20000`, `--autodisablegauss 0`, `--maxxorsize 12
--varsperxorcut 1`, `--forcepreservexors 1`, `-m 1`) produced no verdict at 19
rounds.

A solver comparison confirms the existing default is the right choice:
CryptoMiniSat with the XOR dialect solves 18 rounds in 13.2 s, whereas Kissat
with the Tseitin dialect takes 47.6 s on the same instance.

### Honest summary

Four strategies were implemented — Dobbertin constraints, Cube-and-Conquer,
message-word pinning, and solver tuning. **All four are slower than the plain
search on this instance.** They are documented as measured regressions rather
than dropped, because a measured regression is a result.

The single lever that demonstrably worked remains **encoding quality**: the
XOR dialect and carry-save adder took this framework from 10 rounds to 18.

The deepest verified preimage remains **18 rounds**. No full SHA-256 preimage
or collision is claimed.

## [4.1.0] - 2026-10-10

Implements the search techniques published in Zaikin, *Constraints* 2026
("Preimage attacks on round-reduced MD5, SHA-1, and SHA-256 using
parameterized SAT solver"), which reached 19 rounds — and reports, honestly,
that **they make this instance harder**.

### Added

- **Parallel Cube-and-Conquer search.** The search space is partitioned into
  disjoint cubes over selected state bits at a chosen round boundary. Each cube
  is solved independently under assumptions, and a cube proven `UNSAT`
  contributes a blocking clause that prunes it permanently. Because the cubes
  are disjoint and total, exhausting them with `UNSAT` is a genuine proof of
  nonexistence rather than a timeout.
  - `ISolver::solve_under_assumptions`, with a default DIMACS implementation
    that pins assumptions as unit clauses.
  - `CubePartition::{enumerate, literals_for, blocking_clause}`.
  - Cubes are processed in **batches**: workers only read the master formula
    within a batch, and learned clauses are merged under a lock between
    batches. Writing to the formula from a worker would be a data race.
  - A cube that merely times out is never pruned.
  - CLI: `--cube-bits K --cube-round R --cube-register a|e --jobs J`.
- **Message-word pinning (`fixed_words`).** Replaces the positional
  `fixed_message_words` vector with explicit `(index, value)` pairs, so pinning
  `W[3]` no longer silently pins `W[0..2]`.
  CLI: `--fix-words FIRST:LAST --fix-seed S`.
- **`SolverStatus::to_string`** and `RESULT_SOLVER_STATUS`, so a solver give-up
  (`UNKNOWN`) is never conflated with a proof (`UNSAT`).
- **`docs/research/advanced-strategies.md`** documenting both techniques and
  their measured behaviour.
- **`reports/preimage_strategies.{json,md}`**, generated by
  `tools/measure_scaling.py --strategy-sweep`.
- **6 new C++ tests** (36 total): cube disjointness and total coverage, blocking
  clause excludes exactly its own cube, enumeration respects its cap, assumption
  solving pins literals and rejects contradictory ones, `fixed_words` pins
  listed indices only, and a fully pinned message proves `UNSAT`.

### Measured results (all reproduced by the committed reports)

| Strategy, 18 rounds | Solve time | Outcome |
| :--- | ---: | :--- |
| unrestricted | **13.3 s** | VERIFIED |
| pin `W[0..3]` | 293 s | TIMEOUT |
| pin `W[0..7]` | 292 s | TIMEOUT |
| Cube-and-Conquer, 12 bits | 296 s | VERIFIED |

At 19 rounds, 10-bit Cube-and-Conquer left **1024 / 1024 cubes inconclusive**
after 3860 s, so no blocking clause was ever learned.

**Why both techniques lose here.** A one-block preimage is overdetermined by
2^256: 512 free message bits map onto a 256-bit digest, so the instance is
satisfiable by a wide margin and is hard only because the CDCL search cannot
thread one of many solutions through a deep circuit. Removing free variables
removes the solver's room to manoeuvre without making propagation easier. And a
SAT instance of this kind is narrow-but-deep, so partitioning the space gives
each worker a strictly harder subproblem and destroys the global propagation
that makes the unrestricted run tractable. Parallelism cannot absorb a ~200x
per-round cost jump on 16 cores.

The intuition from underconstrained problems ("shrink the search space") is
simply false for overdetermined ones. The finding is recorded rather than
discarded because a measured regression is a result.

### Known limitations

- Reaching 19 rounds in the published work requires a **parameterised solver** —
  a CDCL implementation with branching heuristics specialised to intermediate
  inverse problems. That is not reachable by invoking a solver binary with
  command-line flags, so 19 rounds remains out of reach for this framework.
  The practical 19/20-round record (Basra 2026) uses table-based context
  shaping rather than SAT inversion.
- The deepest verified preimage remains **18 rounds**.

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
