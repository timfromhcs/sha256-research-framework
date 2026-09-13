# SHA-256 Research Framework — GEMINI.md
## v3.0 Headless Autonomous Research Platform Development Contract

**Repository:** `timfromhcs/sha256-research-framework`

**Stable branch:** `main`

**Development branch:** `dev/v3-local-autonomous-research`

**Target release:** `v3.0.0`

---

# 0. Mission

This development cycle transforms the existing SHA-256 Research Framework v2.x into a **headless, local-first, autonomous research platform** while preserving the scientific integrity and cryptographic trust model of the existing system.

The v2.x implementation on `main` is the stable baseline and MUST NOT be modified by this agent.

All v3 work MUST happen on:

```text
dev/v3-local-autonomous-research
```

The final objective is a fully working local headless platform with:

- Existing SHA-256 C++ core preserved and reusable
- Independent cryptographic verifier preserved and strengthened
- Headless research execution
- Structured experiment lifecycle
- Persistent SQLite research state
- Automatic evidence/artifact storage
- Research workers and job scheduling
- Local LLM support
- Local VLM support
- Local embedding/RAG support
- Vulkan-capable local model inference
- CPU fallback
- Model management
- Research-agent orchestration
- Tool-restricted agent operation
- REST API
- WebSocket live events
- Autonomous research campaigns
- Crash/recovery handling
- Automatic reports
- Deterministic/reproducible execution
- Complete local validation
- Complete cloud CI validation

The system MUST remain scientifically conservative:

```text
LLM proposes
Research engine executes
Verifier validates
Evidence system records
```

The LLM, VLM, planner, solver, frontend, and agent MUST NEVER become authorities for cryptographic truth.

---

# 1. Absolute Branch Protection Rule

Before making ANY modification:

1. Inspect repository state.
2. Confirm current branch.
3. Confirm `main` is clean and unchanged.
4. Create the v3 development branch from the current `main`.

Expected branch:

```text
dev/v3-local-autonomous-research
```

Rules:

- NEVER commit v3 work directly to `main`.
- NEVER force-push `main`.
- NEVER rewrite `main`.
- NEVER delete `main`.
- NEVER merge into `main`.
- NEVER alter v2 release artifacts for convenience.
- NEVER use `main` as a temporary scratch branch.
- NEVER "fix" v2 on `main` while implementing v3.

The final result of this task MUST be pushed only to:

```text
origin/dev/v3-local-autonomous-research
```

The v2 baseline remains intact.

---

# 2. Baseline Audit Before Development

Before architecture changes, inspect:

```text
README.md
CHANGELOG.md
CMakeLists.txt
CMakePresets.json
GEMINI.md
docs/
include/
src/
tests/
verifier/
reproducibility/
evidence/
tools/
scripts/
.github/workflows/
schemas/
```

Also inspect:

- existing CI workflows
- existing test targets
- existing evidence manifests
- existing release manifest
- existing SQLite schema
- existing CLI behavior
- current Vulkan implementation
- solver integration
- current IndependentVerifier implementation
- current benchmark system
- current deterministic test system

Record:

```text
baseline_commit
baseline_branch
compiler
CMake
Python
Vulkan
solver versions
test status
CI status
evidence status
```

Do not proceed if the repository baseline is ambiguous.

---

# 3. Existing Scientific Integrity Is Non-Negotiable

The following principles MUST remain true after v3:

### Full SHA-256 remains correctly classified

The framework MUST NOT claim a standard full SHA-256 collision, preimage, or break unless independently proven by the actual verifier.

Reduced-round results MUST remain distinct from standard 64-round SHA-256.

Modified/custom IV experiments MUST remain explicitly classified.

Near-collisions MUST remain heuristic classifications only.

Solver output MUST NOT be treated as cryptographic proof.

LLM output MUST NOT be treated as cryptographic proof.

VLM output MUST NOT be treated as cryptographic proof.

Agent metadata MUST NOT override verification.

---

# 4. v3 Architecture

Build the system as separated layers:

```text
                    WEB FRONTEND
                          |
                     REST/WebSocket
                          |
                    HEADLESS API
                          |
                RESEARCH ORCHESTRATOR
                          |
       +------------------+------------------+
       |                  |                  |
       v                  v                  v
   MODEL RUNTIME      JOB WORKERS       EVIDENCE STORE
       |                  |                  |
       v                  v                  v
 LLM / VLM / RAG     SHA/SAT/SOLVER     SQLite + Files
                          |
                          v
                  INDEPENDENT VERIFIER
```

The existing cryptographic core remains below this layer.

---

# 5. Core Separation

The cryptographic core MUST NOT depend on:

- frontend
- FastAPI
- React
- LLM
- VLM
- embeddings
- RAG
- agent prompts
- browser code

The cryptographic core MUST remain usable headlessly and independently.

The API and agent layers call the core through well-defined interfaces.

---

# 6. CLI Must Become a Client of the Application Layer

Do not keep research logic buried inside CLI command implementations.

Refactor toward:

```text
CLI
 |
 v
Application/Service Layer
 |
 v
Core
```

The same application interfaces MUST be usable by:

```text
CLI
API
Workers
Agent
Tests
```

The CLI may remain in v3, but it MUST NOT be the only path to execute research.

---

# 7. Experiment Model

Introduce a structured experiment representation.

Every experiment MUST contain at least:

```text
experiment_id
hypothesis_id
created_at
status
rounds
solver
backend
seed
timeout
parameters
source_commit
environment
```

Experiment states MUST be explicit.

Example lifecycle:

```text
QUEUED
PREPARING
RUNNING
VERIFYING
COMPLETED
FAILED
TIMEOUT
CANCELLED
REJECTED
```

State transitions MUST be persisted.

An agent restart MUST NOT destroy historical state.

---

# 8. SQLite Research State

Extend the existing database architecture instead of creating an unrelated second database.

At minimum support entities equivalent to:

```text
projects
research_goals
hypotheses
experiments
experiment_runs
candidates
verifications
artifacts
models
model_runs
agent_actions
tool_calls
observations
metrics
datasets
benchmarks
reports
jobs
events
```

Store structured metadata in SQLite.

Store potentially large artifacts on disk.

Link artifacts through deterministic paths and hashes.

---

# 9. Evidence Storage

Every completed experiment MUST automatically produce an auditable evidence package.

Expected conceptual structure:

```text
evidence/
  experiments/
    <experiment_id>/
      request.json
      environment.json
      stdout.log
      stderr.log
      result.json
      verification.json
      manifest.json
      report.md
```

The exact structure may differ if a better existing convention is already present.

Evidence MUST record:

```text
experiment
source commit
software versions
hardware
backend
solver
seed
parameters
result
verification state
artifact hashes
```

Never silently overwrite prior experiment evidence.

---

# 10. Correct Integrity Terminology

Do not describe a simple aggregate hash as a Merkle tree unless a real Merkle tree is implemented.

Prefer terminology such as:

```text
Evidence Root Hash
Deterministic Evidence Root
Content-Addressed Evidence
```

Do not call ordinary mutable repository files "immutable" unless the actual mechanism provides immutability.

Use precise terminology:

```text
integrity-checked
content-addressed
tamper-detectable
```

---

# 11. Independent Verifier

The IndependentVerifier MUST remain a separate trust boundary.

Strengthen isolation where practical.

Prefer:

```text
sha-verifier
    |
    +-- independent verifier implementation only
```

Avoid unnecessary linkage to:

```text
SAT
solver
search
benchmark
research orchestration
```

Do not let agent state modify verifier rules.

Do not let metadata override verification.

Do not let solver results bypass verification.

---

# 12. Anti-Clamping Requirement

No hidden parameter normalization may silently convert invalid cryptographic requests into valid requests.

Do NOT allow patterns such as:

```cpp
min(rounds, 64)
```

for validation-sensitive inputs.

Invalid round values MUST fail explicitly.

Required behavior:

```text
rounds < 1   -> reject
rounds > 64  -> reject
```

Audit all code paths, including low-level APIs.

The validation contract applies recursively, not only at CLI level.

---

# 13. Local Model Runtime

Add a local inference layer.

Primary design target:

```text
GGUF
+
llama.cpp
+
Vulkan
+
CPU fallback
```

The runtime MUST support:

- local execution
- no mandatory cloud inference
- Vulkan when available
- CPU fallback
- model discovery
- model loading/unloading
- configuration through manifests
- deterministic configuration capture

Do not build a second inference engine unless technically necessary.

---

# 14. Model Classes

The platform MUST conceptually support:

```text
Research LLM
Vision-Language Model
Embedding Model
```

Models MUST have manifests containing at least:

```text
model_id
name
format
quantization
context_length
runtime
backend
size
checksum
capabilities
```

Do not silently download or replace models without recording the source and checksum.

---

# 15. iGPU-First Requirements

Optimize for local integrated-GPU operation.

The system MUST detect:

```text
CPU
GPU
Vulkan availability
shared memory / approximate memory budget
supported backend
```

The model manager SHOULD use a conservative memory budget.

Do not automatically load several large models simultaneously.

Prefer:

```text
load
use
unload
```

over permanent multi-model residency on low-memory iGPU machines.

---

# 16. Model Routing

Implement task-aware routing.

Conceptually:

```text
simple planning      -> small LLM
research reasoning  -> research LLM
image/plot analysis  -> VLM
semantic retrieval   -> embedding model
cryptographic truth  -> verifier
```

Do not route cryptographic verification to an LLM.

---

# 17. Agent Design

Implement the autonomous research agent as a controlled planner.

The agent MAY:

```text
inspect research history
create hypotheses
design experiments
select valid parameters
request experiments
compare results
analyze evidence
generate follow-up hypotheses
generate reports
```

The agent MUST NOT directly receive unrestricted:

```text
shell
filesystem write
SQL
network
arbitrary process execution
```

unless explicitly mediated through validated tools.

---

# 18. Tool Interface

Implement an explicit tool registry.

Conceptual tools:

```text
get_system_status
list_models
load_model
unload_model
create_hypothesis
list_hypotheses
create_experiment
run_experiment
get_experiment
cancel_experiment
verify_candidate
compare_experiments
search_evidence
read_artifact
analyze_results
benchmark_backend
generate_report
```

Each tool MUST validate its arguments before execution.

The agent MUST never bypass the tool layer.

---

# 19. Research Loop

Implement an autonomous research cycle conceptually equivalent to:

```text
OBSERVE
  ->
FORM HYPOTHESIS
  ->
DESIGN EXPERIMENT
  ->
VALIDATE PLAN
  ->
EXECUTE
  ->
VERIFY
  ->
STORE EVIDENCE
  ->
ANALYZE
  ->
DECIDE NEXT STEP
```

Every stage MUST leave an auditable record.

No hidden agent state may be the only source of truth.

---

# 20. Trust Levels

Introduce explicit epistemic state.

Recommended levels:

```text
L0  Model Suggestion
L1  Unverified Observation
L2  Experiment Output
L3  Independently Verified
L4  Reproduced
L5  Cross-Environment Reproduced
```

The UI, database and agent memory SHOULD preserve these levels.

The agent MUST NOT promote L0/L1/L2 to L3 without actual verifier evidence.

---

# 21. VLM

Add VLM support for structured visual analysis.

Possible inputs:

```text
plots
graphs
research figures
solver visualizations
generated experiment images
```

VLM output MUST be stored as an observation.

Example:

```text
visual_observation
confidence
source_artifact
model
timestamp
```

VLM conclusions MUST NOT automatically become cryptographic claims.

---

# 22. Local RAG / Research Memory

Add local retrieval over:

```text
documentation
reports
experiments
evidence metadata
research notes
datasets
```

Keep evidence states separate from model-generated summaries.

Prefer verified evidence during retrieval when a fact is security-critical.

---

# 23. Worker Architecture

Long-running experiments MUST NOT block HTTP request handling.

Use:

```text
API
 |
 v
Job Queue
 |
 v
Worker
 |
 v
C++ / SAT / Solver
 |
 v
Verifier
 |
 v
Evidence
 |
 v
SQLite
```

Workers MUST capture exit codes.

Workers MUST capture stdout/stderr.

Workers MUST report terminal state reliably.

---

# 24. Crash Recovery

Jobs left in:

```text
RUNNING
PREPARING
VERIFYING
```

during an unexpected process termination MUST be detectable.

On restart:

```text
orphaned
```

jobs MUST become recoverable according to deterministic retry policy.

Never silently pretend a crashed experiment completed.

---

# 25. API

Implement a local-first REST API.

At minimum expose conceptual routes for:

```text
GET  /api/status
GET  /api/system
GET  /api/models

GET  /api/hypotheses
POST /api/hypotheses

GET  /api/experiments
POST /api/experiments
GET  /api/experiments/{id}
POST /api/experiments/{id}/cancel

GET  /api/jobs
GET  /api/evidence/{id}
POST /api/verify
```

Add WebSocket or equivalent event streaming for live status.

---

# 26. Frontend

The frontend MUST be a client of the headless API.

It MUST NOT contain the cryptographic business logic.

The backend MUST work completely without the frontend.

The frontend SHOULD expose:

```text
Dashboard
Research
Experiments
Hypotheses
Evidence
Models
Agent
System
Logs
Reports
```

---

# 27. Automatic Saving

The system MUST automatically persist:

```text
agent actions
tool calls
experiment requests
experiment outputs
verification outputs
model metadata
model calls
observations
artifacts
reports
errors
events
```

No important research state may exist only in memory.

---

# 28. Determinism

Where deterministic execution is possible, enforce it.

Capture:

```text
seed
commit
parameters
model
model checksum
solver version
backend
environment
```

Deterministic state MUST be included in reproducibility records.

Never fake determinism where external hardware scheduling makes strict determinism impossible.

Document unavoidable nondeterminism explicitly.

---

# 29. Local Verification Loop

After implementation work, perform a complete local validation loop.

This loop MUST NOT be considered complete until ALL relevant checks pass.

Minimum conceptual sequence:

```text
clean build
    ->
unit tests
    ->
adversarial tests
    ->
KATs
    ->
determinism tests
    ->
verifier negative tests
    ->
evidence verification
    ->
API tests
    ->
worker tests
    ->
model runtime smoke test
    ->
Vulkan smoke test when hardware exists
    ->
agent tool-policy tests
    ->
end-to-end research test
```

The exact commands MUST be derived from the actual repository.

Never invent successful output.

---

# 30. Local Loop Failure Rule

If ANY required local check fails:

```text
STOP
 |
diagnose
 |
fix
 |
rerun affected tests
 |
rerun complete local validation
```

Do not continue to the cloud phase while local validation is red.

Do not mark a failed test as expected unless the repository explicitly defines it as expected.

Do not weaken a test to make it pass.

Do not delete tests because they expose a regression.

---

# 31. Cloud Validation Loop

Only after the local validation loop is completely green:

```text
commit
push dev branch
```

Then inspect GitHub Actions.

The cloud loop MUST continue until:

```text
build = PASS
tests = PASS
verifier = PASS
security = PASS
evidence = PASS
documentation = PASS
all relevant v3 jobs = PASS
```

Use actual CI results.

Never infer success from local execution.

---

# 32. Cloud Loop Failure Rule

If cloud CI fails:

```text
inspect failing workflow
 |
inspect logs
 |
diagnose root cause
 |
fix on dev branch
 |
local validation again
 |
commit
 |
push
 |
cloud validation again
```

Cloud fixes MUST first survive the complete local validation loop before being accepted.

This creates:

```text
LOCAL LOOP
    ↓
PUSH
    ↓
CLOUD LOOP
    ↓
if failure -> LOCAL LOOP
```

Repeat until fully green.

---

# 33. No False Completion

Do NOT declare:

```text
complete
production ready
100% verified
perfect
```

unless the required local and cloud validation loops are actually green.

Do not manufacture proof.

Do not infer unavailable hardware validation.

Do not report tests that were not executed.

---

# 34. Final Branch Requirements

At successful completion:

```text
main
    remains unchanged
```

and:

```text
dev/v3-local-autonomous-research
    contains the complete v3 implementation
```

The dev branch MUST contain:

- source
- tests
- documentation
- manifests
- model runtime integration
- API
- worker system
- research orchestration
- evidence integration
- frontend
- CI updates
- reproducibility metadata

Do not merge the dev branch into `main`.

Do not delete the dev branch.

---

# 35. Final Verification Before Push

Immediately before the final push:

1. Verify current branch is the v3 dev branch.
2. Verify `main` was never modified.
3. Run the complete local validation loop.
4. Inspect `git diff`.
5. Inspect untracked files.
6. Ensure no secrets are present.
7. Ensure generated junk/build directories are excluded.
8. Ensure manifests reference the correct source commit semantics.
9. Ensure version metadata is internally consistent.
10. Ensure documentation matches implementation.
11. Ensure the repository remains buildable without optional components where promised.
12. Ensure tests reflect real behavior.

Then commit.

---

# 36. Commit Rules

Use explicit, meaningful commits.

Examples:

```text
feat(v3): introduce headless application layer
feat(v3): add persistent experiment state
feat(v3): add local Vulkan model runtime
feat(v3): add research agent tool registry
feat(v3): add autonomous campaign scheduler
feat(v3): add local research API
feat(v3): add live research events
test(v3): add end-to-end headless validation
fix(v3): ...
```

Do not create meaningless commits such as:

```text
update
fix
stuff
changes
```

---

# 37. Final Deterministic End

This task has a strict terminal condition.

The agent MUST end only after:

```text
v3 implementation complete
+
full local validation GREEN
+
cloud CI GREEN
+
final changes committed
+
final push completed
```

Final action:

```text
git push origin dev/v3-local-autonomous-research
```

After the successful final push:

```text
STOP.
```

No additional feature development.

No merge into `main`.

No speculative cleanup.

No extra refactor.

No endless optimization loop.

No automatic release of `main`.

No further commits after the final successful push.

The successful push to:

```text
origin/dev/v3-local-autonomous-research
```

is the deterministic end state.

---

# 38. Required Final Report

Before termination, output only a concise completion report containing:

```text
branch
final commit
local validation status
cloud validation status
major v3 components implemented
known limitations
final push status
```

The report MUST distinguish:

```text
implemented
tested locally
verified in CI
not verified
```

Do not claim anything beyond actual evidence.

---

# 39. Hard Prohibitions

NEVER:

- modify `main`
- force-push `main`
- merge v3 into `main`
- remove tests to obtain green CI
- silently clamp invalid crypto parameters
- trust LLM/VLM output as cryptographic truth
- bypass IndependentVerifier
- silently overwrite evidence
- fabricate benchmark results
- fabricate CI results
- fabricate model availability
- invent unsupported dependencies
- introduce cloud-only runtime requirements
- make local operation dependent on the frontend
- leave critical research state only in memory
- declare completion before both validation loops are green
- continue making changes after the final successful push

---

# 40. Definition of Done

v3 is DONE only when:

```text
[ ] main preserved
[ ] dev/v3-local-autonomous-research created
[ ] headless architecture implemented
[ ] core separated from UI
[ ] experiment lifecycle implemented
[ ] persistent SQLite research state implemented
[ ] automatic evidence storage implemented
[ ] worker execution implemented
[ ] API implemented
[ ] WebSocket/live events implemented
[ ] local LLM runtime implemented
[ ] Vulkan backend integrated where available
[ ] CPU fallback works
[ ] VLM support implemented
[ ] embedding/RAG layer implemented
[ ] agent tool boundary implemented
[ ] autonomous research loop implemented
[ ] crash recovery implemented
[ ] frontend consumes API only
[ ] local validation fully GREEN
[ ] cloud validation fully GREEN
[ ] documentation synchronized
[ ] final commit created
[ ] final push to dev branch succeeds
[ ] deterministic STOP executed
```

# END OF GEMINI DEVELOPMENT CONTRACT