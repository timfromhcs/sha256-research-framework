# Verification Integrity (v4.0.0)

This document records the trust boundary that v4.0.0 establishes, and the
specific defects it removed. It exists because a research platform that can
report a result nobody verified is worse than no platform at all.

## The rule

> **There is no code path from "no evidence" to "verified".**

Concretely, a result reaches trust level **L3** only when all of the following
hold:

1. The segregated `sha-verifier` binary was actually executed.
2. It returned a parseable verdict naming itself as the `IndependentVerifier`.
3. That verdict reports `is_valid: true`.
4. Its exit code agrees with the parsed verdict (self-consistency check).
5. `EpistemicTrustManager.validate_promotion` accepted the payload, which
   additionally requires verifier provenance and rejects a full-SHA-256
   classification whose round count is not 64.

If any of those fail, the outcome is `L1` and is recorded as a negative or an
infrastructure failure — never as a pass.

## Defects removed in v4.0.0

### 1. Worker fabricated results when the binary was missing

```python
# Removed
stdout = f"[Experiment] Running automated cryptanalysis experiment: {rounds} rounds\n" \
         f"Solver status: SAT\n[VERIFIED] Candidate block matches target digest!\n"
exit_code = 0
```

This ran whenever `sha-research.exe` was not present, producing a passing
result and a green evidence package. `tests/test_v3_platform.py` asserted this
fabricated state, so the suite was green while proving nothing.

**Now:** a missing binary records `INFRA_FAILURE` with classification
`InfrastructureError`, which is explicitly not a scientific outcome.

### 2. Verification inferred from stdout text

```python
# Removed
is_verified = "[VERIFIED]" in stdout or exit_code == 0
```

String matching on a subprocess's prose is not verification, and an exit code
of zero can mean anything.

**Now:** the worker parses the `RESULT_CANDIDATE` / `RESULT_TARGET_DIGEST`
contract, reads the candidate bytes, and invokes `sha-verifier` itself.

### 3. A collision was "verified" because its inputs differed

```python
# Removed
is_valid = (msg_a_hex == msg_b_hex) is False
```

**Now:** `agent/tools.py` raises `ToolValidationError` when the verifier is
unreachable.

### 4. L3 was recorded before verification ran

The VERIFY stage of the autonomous loop inserted its `agent_actions` row with
`trust_level = "L3"` before consulting any result.

**Now:** the row starts at `L1` and is promoted only via
`EpistemicTrustManager.validate_promotion` on a real verdict.

### 5. Trust promotion accepted a bare boolean

A payload of `{"is_valid": true, "classification": "ReducedRoundPreimage"}` was
enough to reach L3, because it could not be distinguished from a real verdict.

**Now:** promotion requires the payload to name the `IndependentVerifier` engine.

### 6. Path sandbox had an operator-precedence bug

```python
# Removed
if norm_path.startswith("..") or os.path.isabs(norm_path) and not os.path.exists(norm_path):
```

`and` binds tighter than `or`, so an absolute path that exists bypassed both
checks. **Now:** `Path.resolve()` plus `relative_to(workspace_root)`.

### 7. Hardcoded measurements

`benchmark_backend` returned `27.5` or `150.0` MH/s unconditionally;
`analyze_results` always reported "No anomaly detected". **Now:** both measure
or derive from recorded data, and raise if the measurement cannot be taken.

## Tests that hold the line

| Test | What it proves |
| :--- | :--- |
| `test_08c_tampered_candidate_is_rejected` | A wrong candidate gets `is_valid: false` with a non-zero Hamming distance |
| `test_08b_missing_binary_is_infrastructure_failure` | No binary yields `FAILED` / `INFRA_FAILURE`, never `CONFIRMED` |
| `test_08d_verifier_refuses_without_binary` | The bridge raises on missing binary, out-of-range rounds, wrong block length, malformed target |
| `test_10_epistemic_trust_validation` | Provenance is required; full-claim classifications require 64 rounds |
| `TestTrustBoundaryIsReal` | A proposal asserting its own success cannot promote |
| `test_missing_binary_is_infra_failure_not_a_result` | The scheduler reports infrastructure failure, not a negative result |

## Solver-status honesty

The framework distinguishes three things a careless pipeline conflates:

| Solver label | Meaning | Advances frontier? |
| :--- | :--- | :--- |
| `SAT` | A model exists | Yes, if the verifier confirms it |
| `UNSAT` | Proven unsatisfiable **for this encoding** | Yes |
| `TIMEOUT` / `UNKNOWN` | No verdict | **No** |

A timeout is never recorded as "no preimage exists". The escalation policy grows
the budget on a timeout precisely because exhausting a budget proves nothing.
See [`reports/preimage_scaling.md`](../../reports/preimage_scaling.md) for a
measured example: round 19 is labelled `TIMEOUT`, not `UNSAT`.