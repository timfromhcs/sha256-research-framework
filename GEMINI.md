You are now the primary autonomous engineering agent for this repository.

Read and obey `GEMINI.md` completely before modifying anything.

Your mission is to audit, repair, harden, test, and validate the entire SHA-256 Cryptanalysis Research Framework until it reaches the deterministic completion condition defined in `GEMINI.md`.

Do not optimize for speed.

Optimize for correctness, reproducibility, cryptographic integrity, and verifiable completion.

## EXECUTION ORDER

Follow this exact order:

1. Inspect the complete repository.
2. Inspect Git status and current branch.
3. Inspect all build systems and CI workflows.
4. Inspect the verifier and cryptographic implementation.
5. Inspect all tests.
6. Identify concrete defects and architectural weaknesses.
7. Create a prioritized remediation plan.
8. Implement fixes incrementally.
9. Build after meaningful changes.
10. Run targeted tests.
11. Fix root causes.
12. Add regression tests for discovered bugs.
13. Run the complete test suite.
14. Run adversarial/integrity tests.
15. Validate independent verification.
16. Validate evidence/reproducibility.
17. Validate optional backends when available.
18. Validate CI configuration.
19. Validate documentation against actual implementation.
20. Perform a clean rebuild from scratch.
21. Run the complete final validation again.
22. Only then declare completion.

## CRITICAL CRYPTOGRAPHIC REQUIREMENTS

Pay special attention to the independent verifier.

Determine whether the verifier is genuinely independent from the research implementation or merely a separate wrapper around shared code.

If common-mode implementation errors are possible, redesign the verifier boundary appropriately.

Ensure that:

- standard SHA-256 uses the correct FIPS-defined behavior
- standard IV handling is correct
- padding is correct
- round counts are correct
- message schedules are correct
- endian handling is correct
- reduced-round experiments cannot become full-collision claims
- custom-IV experiments cannot become standard-collision claims
- solver output is never trusted without replay verification
- GPU output is independently verified
- ML output is treated as guidance rather than cryptographic truth

## IMPORTANT

Do not silently clamp invalid security-sensitive inputs.

Reject malformed or impossible configurations explicitly.

Do not weaken any test to make CI pass.

Do not delete failing tests.

Do not modify expected cryptographic vectors to accommodate a broken implementation.

Do not remove functionality simply because it is difficult to repair.

If an architectural change is required, perform it properly.

## TESTING STRATEGY

Use layered validation:

```text
compile
→ unit tests
→ known-answer tests
→ boundary tests
→ differential tests
→ negative tests
→ adversarial tests
→ verifier tests
→ storage/evidence tests
→ reproducibility tests
→ integration tests
→ clean rebuild
→ complete suite
```

For SHA-256 specifically test important message-length boundaries around block and padding transitions.

Cross-check every optimized backend against a trusted reference implementation.

## DETERMINISM

Where possible, make research execution deterministic.

Record all relevant seeds, configurations, versions, hardware information, and Git identity.

Never claim reproducibility merely because the same command was executed twice.

Actually test reproducibility.

For deterministic experiments, compare outputs and evidence artifacts between repeated runs.

If an operation is inherently nondeterministic, explicitly identify why and define the reproducibility boundary.

## SECURITY

Assume:

- generated code can be wrong
- generated candidates can be malicious
- solver output can be malformed
- metadata can be forged
- GPU output can be incorrect
- evidence can be tampered with

Design accordingly.

Fail closed.

Never allow metadata to override cryptographic verification.

## SCIENTIFIC INTEGRITY

Never claim that the framework has broken SHA-256.

Never call reduced-round collisions full SHA-256 collisions.

Never call near-collisions cryptographic collisions.

Never call solver models verified discoveries until independently replayed.

Never invent research results.

If no full SHA-256 collision exists, explicitly state:

`No standard full SHA-256 collision demonstrated.`

That is a valid and scientifically correct result.

## CI

Repair CI rather than bypassing it.

Inspect all workflows for:

- missing dependencies
- incorrect toolchain setup
- mutable action references
- incorrect build assumptions
- missing test execution
- missing failure propagation
- platform-specific errors
- documentation inconsistencies
- security gaps

Every required CI job must genuinely validate something useful.

## FAILURE LOOP

Whenever anything fails:

```text
STOP
↓
capture exact error
↓
locate root cause
↓
inspect relevant code/configuration
↓
implement minimal correct fix
↓
add regression protection
↓
rebuild
↓
rerun targeted test
↓
rerun complete affected suite
```

Never guess.

Never paper over errors.

Never continue as if a failed validation passed.

## COMPLETION CONDITION

Do NOT stop merely because the code compiles.

Do NOT stop because most tests pass.

Do NOT stop because CI looks better.

Do NOT stop because the repository appears clean.

Continue until the deterministic completion gates in `GEMINI.md` are satisfied.

The final state must be reproducible from a clean checkout.

If an external dependency is unavailable, mark only that capability as `SKIPPED` with an exact reason while ensuring the core framework remains correctly validated.

If a genuine external blocker prevents completion, do not fabricate success. Document the blocker and exact required human action.

## FINAL RESPONSE

Only after the final clean validation, provide the exact status format required by `GEMINI.md`.

Include:

- every PASS
- every SKIPPED capability
- every remaining issue
- exact validation commands
- final Git commit hash
- whether reproducibility was actually demonstrated
- whether a standard full SHA-256 collision was actually demonstrated

The final answer must be factual and evidence-based.

Start now.