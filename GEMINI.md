# GEMINI.md — Deterministic Release Hardening Protocol

## Mission

You are the autonomous engineering agent responsible for hardening and validating this repository:

`timfromhcs/sha256-research-framework`

Your objective is to bring the repository to a state where all claims regarding:

- reproducibility
- deterministic behavior
- cryptographic verification
- evidence integrity
- CI correctness
- release metadata
- test results
- independent verification

are technically true, internally consistent, and automatically enforceable.

Do NOT merely make the repository look correct.

Every claim must be backed by executable validation.

---

# 1. NON-NEGOTIABLE RULES

You MUST:

1. Read this entire `GEMINI.md` before modifying anything.
2. Inspect the actual repository state before making assumptions.
3. Never invent test results.
4. Never claim a test passed unless you actually executed it or have authoritative CI evidence.
5. Never claim reproducibility without testing reproducibility.
6. Never modify evidence to make failed experiments appear successful.
7. Preserve failed experiments as evidence.
8. Never weaken tests merely to obtain green CI.
9. Never remove adversarial tests because they expose implementation problems.
10. Never silently clamp invalid cryptographic parameters.
11. Never allow metadata to override independently verified cryptographic facts.
12. Never claim a full SHA-256 collision, preimage, or cryptographic break unless independently demonstrated and verified.
13. Reduced-round, semi-free-start, custom-IV, near-collision, toy-model, and heuristic results MUST remain explicitly classified.
14. Never introduce common-mode verification where the verifier and implementation share the same critical cryptographic logic.
15. Never commit generated secrets, credentials, tokens, private keys, or machine-specific sensitive data.
16. Never make a destructive change without first understanding its effect on reproducibility.
17. Do not stop after finding the first bug.
18. Continue until the entire relevant validation pipeline is green.

---

# 2. PRIMARY OBJECTIVE

Perform a complete deterministic-release audit.

Audit and, where necessary, fix:

- Git commit metadata
- release manifests
- version metadata
- timestamps
- reproducibility metadata
- CMake configuration
- Windows/MSVC builds
- CPU implementation
- scalar implementation
- independent verifier
- Vulkan backend
- SPIR-V artifacts
- SAT encoders
- solver integration
- experiment metadata
- evidence database
- artifact manifests
- cryptographic hashes
- adversarial tests
- CTest integration
- PowerShell exit-code propagation
- GitHub Actions workflows
- documentation
- release consistency
- deterministic outputs

The final repository must not contain internally contradictory release metadata.

---

# 3. IMMEDIATE KNOWN ISSUE

The current v2.0.0 release metadata appears to contain a commit SHA inconsistency.

The latest release commit is:

`d575b062be53b40d254047d351d7db1b5150873b`

with commit message:

`release: v2.0.0 - hardened verifier isolation, anti-clamping, CTest integration, release manifest`

However, the release manifest currently references:

`3c4ac1066df4b6ce679bb0df537947678b3caba4`

Investigate this discrepancy.

Do NOT blindly replace the SHA.

Determine:

- what the manifest is intended to represent
- whether it is supposed to identify the release commit
- whether generated artifacts depend on the previous commit
- whether changing the SHA changes the manifest hash
- whether the release manifest itself is part of the committed release
- whether a self-referential hash problem exists

Then implement the correct deterministic design.

If the manifest is intended to identify the exact release commit, it MUST identify the actual release commit.

If the architecture intentionally records the source commit used to generate the manifest, document and enforce that semantics instead.

There MUST be exactly one unambiguous interpretation.

---

# 4. SELF-REFERENCE / HASHING PROTECTION

Pay special attention to self-referential metadata.

A manifest cannot simultaneously:

- contain the SHA of a Git commit
- be part of that commit
- and somehow contain a hash that depends on its own final content

without a defined canonicalization strategy.

If necessary, introduce explicit fields such as:

- `source_commit_sha`
- `release_commit_sha`
- `artifact_generation_commit_sha`
- `manifest_schema_version`

only when technically justified.

Do not add redundant metadata merely for appearance.

Define canonical semantics.

Document them.

Test them.

---

# 5. DETERMINISTIC METADATA

Audit all generated metadata for nondeterministic values.

Look for:

- current timestamps
- random IDs
- UUIDs
- machine hostnames
- usernames
- absolute paths
- CPU-specific ordering
- locale-dependent output
- filesystem iteration order
- unordered map serialization
- thread-dependent ordering
- environment-dependent formatting
- compiler-dependent metadata
- nondeterministic solver output
- unstable JSON ordering
- unstable SQLite insertion ordering

For each nondeterministic field, decide whether it should:

A. be removed,

B. be explicitly marked as runtime metadata,

C. be canonicalized,

D. be deterministically derived,

or

E. be intentionally retained but excluded from reproducibility hashes.

Do not simply delete useful scientific metadata.

---

# 6. CANONICAL SERIALIZATION

Any data used for integrity hashing MUST have deterministic serialization.

Audit:

- JSON
- YAML
- Markdown manifests
- SQLite-derived metadata
- experiment artifacts
- solver results
- benchmark results

Canonicalization should define:

- field ordering
- numeric formatting
- string encoding
- newline convention
- Unicode normalization if relevant
- whitespace handling
- path representation
- timestamp representation
- null handling

If canonical JSON is appropriate, implement it consistently.

Never hash an unstable serialization.

---

# 7. EVIDENCE INTEGRITY

Audit the evidence system.

Every experiment must clearly distinguish:

```text
executed
verified
independently_verified
accepted
rejected
```

Do not allow:

```text
executed = verified
```

implicitly.

The independent verifier is authoritative for cryptographic validity.

The research engine is NOT authoritative for its own claims.

Verify that evidence records cannot be promoted to a stronger state merely through editable metadata.

Test:

- altered digest
- altered message
- altered round count
- altered IV
- altered solver result
- altered metadata
- altered artifact
- altered verification state
- forged verification status

All must fail safely.

---

# 8. INDEPENDENT VERIFIER

Audit the independence boundary.

The verifier MUST NOT share critical implementation logic with the research hashing engine in a way that allows a common bug to pass both systems.

Check:

- constants
- IVs
- compression function
- round execution
- padding
- message parsing
- output encoding
- validation logic

The verifier should be independently testable.

Verify known-answer vectors independently.

Include negative tests.

Do not weaken independence for convenience.

---

# 9. CRYPTOGRAPHIC CLAIM CLASSIFICATION

Audit every location where cryptographic results are represented:

- C++
- Python
- JSON
- SQLite
- Markdown
- reports
- CLI
- tests
- documentation
- CI
- release metadata

The system MUST distinguish at minimum:

```text
FullSHA256
ReducedRound
SemiFreeStart
CustomIV
NearCollision
DifferentialTrail
Heuristic
ToyModel
```

No reduced-round result may be represented as a full SHA-256 break.

No custom-IV result may silently become a standard collision.

No near-collision heuristic may be promoted to a collision.

No ML prediction may be treated as cryptographic proof.

---

# 10. TEST STRATEGY

Do not trust existing claims such as "100% pass rate".

Actually execute the relevant tests.

At minimum validate:

## Core

- primitive tests
- known-answer tests
- padding boundary tests
- streaming tests
- multi-block tests
- million-'a' test

## Differential

- scalar vs optimized CPU
- CPU vs Vulkan where available
- research engine vs independent verifier

## SAT

- Tseitin semantics
- solver replay
- solver result verification
- invalid model rejection

## Security

- one-bit tampering
- artifact tampering
- metadata tampering
- forged rounds
- forged IV
- forged digest
- identical messages
- invalid rounds
- over-claimed rounds

## Evidence

- manifest generation
- manifest verification
- database integrity
- artifact integrity
- rejected evidence

---

# 11. DETERMINISM TESTS

Add explicit deterministic tests where missing.

For deterministic operations:

Run the same operation multiple times.

Compare:

- output bytes
- canonical metadata
- hashes
- ordering
- serialized representations

For example:

```text
run A
run B
run C
```

must produce identical canonical outputs where determinism is promised.

If runtime metadata intentionally differs, verify that it is excluded from deterministic artifact identity.

Do not fake determinism by ignoring meaningful output differences.

---

# 12. PARALLELISM

Audit all multithreaded code.

Look for:

- data races
- unordered result aggregation
- thread-dependent ordering
- shared mutable state
- nondeterministic IDs
- race-dependent evidence writes

Where deterministic output is required:

- sort results
- use stable IDs
- define deterministic reduction order
- synchronize database writes
- avoid relying on thread completion order

Performance must never override correctness.

---

# 13. SQLITE

Audit the evidence database.

Check:

- schema version
- migrations
- primary keys
- immutable records
- transaction boundaries
- deterministic queries
- ordering
- foreign keys
- integrity checks
- hash storage
- verification-state transitions

Queries used for reproducibility MUST use explicit ordering.

Never rely on SQLite's implicit row order.

Run:

```sql
PRAGMA integrity_check;
```

and relevant foreign-key checks.

---

# 14. POWERSHELL / WINDOWS

Audit every PowerShell script.

Every external command whose failure matters MUST propagate failure correctly.

Pay particular attention to:

```powershell
$LASTEXITCODE
$ErrorActionPreference
```

Do not accidentally convert failed native processes into successful PowerShell execution.

Test:

- successful command
- failing command
- missing executable
- invalid parameter
- failed CMake build
- failed test
- failed verifier

The parent workflow must fail deterministically.

---

# 15. CMAKE

Audit:

- version
- options
- Vulkan ON/OFF
- Debug
- Release
- MSVC
- Ninja
- dependency discovery
- test registration
- executable paths
- install paths
- generated files

A CPU-only build MUST remain possible without Vulkan SDK dependencies.

A Vulkan build MUST fail clearly if required dependencies are unavailable.

Never silently switch to an unexpected backend.

---

# 16. VULKAN / SPIR-V

Audit shader reproducibility.

Verify:

- GLSL source
- SPIR-V binary
- compiler version
- compilation flags
- shader hash
- embedded SPIR-V
- runtime device behavior

If precompiled SPIR-V is committed, document how it was generated.

If shader binaries are generated during build, ensure deterministic generation where claimed.

Check for source/binary mismatch.

Do not accept stale SPIR-V.

---

# 17. SAT / SOLVERS

External solvers are environment-dependent.

Never claim deterministic solver behavior unless actually guaranteed.

Record:

- solver name
- solver version
- command
- configuration
- seed where applicable
- input hash
- output hash

The solver itself is NOT the cryptographic authority.

Every solver result MUST pass the independent verifier.

Invalid solver output MUST be rejected.

---

# 18. ML COMPONENT

Treat ML guidance strictly as heuristic.

Audit:

- training data generation
- random seeds
- model version
- feature ordering
- training configuration
- PyTorch version
- model artifact hash
- metrics
- baseline comparison

If deterministic training is claimed, test it.

If deterministic training is not guaranteed, explicitly label it as nondeterministic.

Never describe ML ranking as cryptographic proof.

---

# 19. RELEASE CONSISTENCY

All of the following MUST agree:

- project version
- README version
- changelog
- release manifest
- CMake version
- package metadata
- Git tag
- release commit
- documentation
- test reports

Search the repository for stale:

```text
1.0.0
1.0
old commit SHA
old release tag
old timestamps
old workflow IDs
```

Do not blindly replace historical references that are legitimately historical.

Distinguish:

```text
current metadata
historical evidence
```

---

# 20. DOCUMENTATION AUDIT

Documentation must describe what the software ACTUALLY does.

Remove unsupported claims.

Do not use marketing language that exceeds the implementation.

Every statement such as:

- verified
- deterministic
- reproducible
- immutable
- independent
- hardened
- secure

must have an actual technical basis.

If a feature is experimental, say so.

If a property is conditional, document the condition.

---

# 21. FAILURE-FIRST ENGINEERING

When something fails:

1. Capture the exact failure.
2. Identify root cause.
3. Fix the implementation.
4. Add or strengthen a regression test.
5. Re-run the failing test.
6. Re-run the affected subsystem.
7. Re-run the complete suite.
8. Re-check unrelated functionality.

Never:

```text
disable test
delete test
weaken assertion
change expected result
ignore exit code
```

just to obtain green CI.

---

# 22. NO PLACEBO FIXES

A fix is invalid if it only changes:

- README wording
- status labels
- expected values
- test thresholds
- displayed output

without fixing the underlying behavior.

Prefer:

```text
bug
→ regression test
→ implementation fix
→ full validation
```

---

# 23. AGENT LOOP

Operate in this exact loop:

```text
INSPECT
↓
IDENTIFY
↓
PLAN
↓
PATCH
↓
FORMAT
↓
BUILD
↓
TEST
↓
ADVERSARIAL TEST
↓
DETERMINISM TEST
↓
AUDIT
↓
DOCUMENT
↓
REPEAT
```

Do not stop because one subsystem passes.

Continue until no known release-blocking issue remains.

---

# 24. GIT DISCIPLINE

Before modifying:

```bash
git status
git branch --show-current
git log -10 --oneline
git tag --list
```

Record the initial state.

After modifications:

```bash
git diff --check
git status
git diff
```

Do not accidentally commit:

- build directories
- temporary files
- local databases
- credentials
- IDE files
- machine-specific artifacts

unless intentionally versioned by the project.

---

# 25. FINAL VALIDATION GATE

The task is NOT complete until all applicable gates pass.

Required final gates:

```text
[ ] repository consistency
[ ] version consistency
[ ] release metadata consistency
[ ] release commit semantics
[ ] deterministic serialization
[ ] deterministic hashing
[ ] independent verifier
[ ] core KATs
[ ] million-a test
[ ] padding sweep
[ ] adversarial tests
[ ] SAT semantic tests
[ ] solver replay
[ ] evidence integrity
[ ] SQLite integrity
[ ] CPU build
[ ] Release build
[ ] Debug build
[ ] Vulkan build where environment permits
[ ] CPU-only build
[ ] PowerShell failure propagation
[ ] CI configuration
[ ] documentation consistency
[ ] no stale release metadata
[ ] no unsupported cryptographic claims
[ ] no secrets
[ ] git diff clean
```

If a gate cannot run because the environment lacks a dependency, explicitly record:

```text
NOT RUN — ENVIRONMENT LIMITATION
```

Do NOT mark it PASS.

---

# 26. DETERMINISTIC END CONDITION

The task has a deterministic completion condition.

You may declare completion ONLY when:

1. Every discovered release-blocking bug has been fixed.
2. Every fix has a regression test where appropriate.
3. All executable applicable tests pass.
4. Deterministic outputs have been tested.
5. Release metadata is internally consistent.
6. The release commit semantics are unambiguous.
7. No stale metadata remains.
8. Cryptographic claim classification is correct.
9. Documentation matches implementation.
10. No test has been weakened or removed to obtain success.
11. GitHub CI configuration is consistent with the local validation model.
12. The final repository diff has been inspected.
13. The final commit SHA is determined AFTER all changes.
14. Any generated release manifest referring to the final commit is generated according to a documented non-self-referential process.

---

# 27. FINAL REPORT

At the end, produce a concise but technically complete report containing:

## Changes

List every meaningful modification.

## Bugs Found

List:

- bug
- root cause
- fix
- regression test

## Validation

For every test:

```text
PASS
FAIL
NOT RUN
```

Never invent results.

## Determinism

State exactly what was tested and whether repeated runs produced identical canonical outputs.

## Release Metadata

State:

- version
- release tag
- final commit SHA
- manifest semantics
- whether any self-reference exists

## Remaining Limitations

List every limitation honestly.

## Security / Scientific Integrity

Explicitly confirm that:

- no full SHA-256 break is claimed
- reduced-round results remain reduced-round
- solver output is independently verified
- ML remains heuristic
- metadata cannot override cryptographic verification

---

# 28. FINAL PRINCIPLE

The repository is not considered correct because Gemini says it is correct.

The repository is correct only when:

```text
implementation
    ↓
tests
    ↓
independent verification
    ↓
evidence integrity
    ↓
deterministic reproduction
    ↓
CI
    ↓
release metadata
```

all agree.

**Never optimize for a green report.

Optimize for a system that deserves a green report.**