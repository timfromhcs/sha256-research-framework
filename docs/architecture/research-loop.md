# The Autonomous Research Loop (v4.0.0)

Two planes with a hard trust boundary. The split exists so that a language model
can influence *what gets tried* without ever influencing *what counts as true*.

```
                    PROPOSAL PLANE  (untrusted, capped at L0)
                    agent/proposals.py
                              |
        LLM proposes  ------+------  deterministic proposer
        (schema-validated,          (always present, guarantees progress)
         allowlisted, rationale               |
         stored verbatim)                     v
                              +---------------------------+
                              |   DETERMINISTIC SCHEDULER  |  agent/scheduler.py
                              |   the only executor         |
                              |   the only path to L3       |
                              +---------------------------+
                                              |
                                   sha-research preimage
                                              |
                                   IndependentVerifier  (L3 only here)
```

## Proposal plane

`agent/proposals.py` may never exceed trust level **L0**. Proposals are validated
against a closed envelope before they can be queued:

- `rounds` must be an `int` in `[1, 64]` (`bool` is rejected explicitly)
- `solver` must be one of `cadical`, `kissat`, `cryptominisat`, `minisat`
- `encoding` must be `tseitin` or `xor`
- `timeout` must be an `int` in `[1, 3600]`
- `xor` requires the XOR-capable solver `cryptominisat`

Anything outside the envelope is dropped, never executed. Model output is parsed
tolerantly (markdown fences, prose, JSON arrays) but validated strictly.

The **deterministic proposer** is always included, so a missing or broken model
degrades throughput but never stalls the loop. Every proposal's rationale is
stored verbatim — the reasoning is auditable, not just the outcome.

## Decision plane

`agent/scheduler.py` is the only component that executes work and the only path
to L3. Its rules, in order:

1. **The verifier decides everything.** Nothing else counts.
2. **A solver/model-extraction disagreement is a bug.** If the solver reports SAT
   but the verifier rejects the candidate, the scheduler flags
   `bug_suspected`, records it, and halts. That is a defect in the pipeline, not
   a scientific finding.
3. **A timeout is not a wall.** The budget grows (2.5×, capped at 3600 s) rather
   than being recorded as "no preimage exists".
4. **A solver give-up is not a proof.** `UNKNOWN` and `ERROR` are treated as
   inconclusive, exactly like `TIMEOUT`.
5. **A clean `UNSAT` is conclusive** for that encoding, so the same round is
   cross-checked with an independent solver and encoding before conceding.
6. **Escalation follows measured depth**, never model optimism.

### Frontier semantics

The loop tracks two numbers:

- `best_verified_rounds` — deepest round with a verifier-confirmed preimage
- `conclusive_rounds` — deepest round with a definitive answer (verified **or**
  proven `UNSAT`)

`next_target_rounds()` is `conclusive_rounds + 1`. Timeouts and infrastructure
failures never advance it, so the loop cannot escalate past a wall it merely
failed to probe.

## Replayable manifests

Each cycle writes `evidence/cycles/cycle_NNNN.json` containing the plan, every
step's configuration, measured metrics, and verdicts. **It contains no
timestamps**, which would break deterministic hashing; those live in a sibling
`cycle_NNNN.meta.json`. `test_manifest_is_deterministic_and_timestamp_free`
asserts that replaying a cycle produces byte-identical output.

## What this deliberately does not do

The loop does not let an LLM:
- mark anything verified,
- choose whether to escalate,
- influence the verifier,
- or produce a claim without measured backing.

Following the discipline that made OpenAI's 2026 mathematics release auditable:
publish the reasoning, but let a mechanical checker decide truth. The verifier is
the ground truth, not the model.