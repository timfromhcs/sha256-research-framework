# Advanced Search Strategies (v4.1.0)

This document records the techniques implemented beyond the direct SAT
encoding, and — more importantly — **what they actually measured**. Two of the
three turned out to make things worse on this hardware, and that is reported
here rather than quietly dropped.

Every number below was produced by `sha-research preimage` on the machine
described in [`preimage_scaling.md`](../../reports/preimage_scaling.md). No
figure is estimated.

## Why a one-block preimage is unusual

A single SHA-256 block gives 512 free message bits mapping onto a 256-bit
digest. The system is overdetermined by 2^256: roughly 2^256 distinct blocks
share any given target. The instance is therefore *satisfiable by a wide
margin* and is hard purely because the CDCL search cannot find one of the many
solutions through a deep, well-mixed circuit.

That observation drives everything below, and it is why the intuition from
underconstrained problems ("shrink the search space") does **not** apply here.

## 1. Cube-and-Conquer

Follows Zaikin, *Constraints* 2026, which inverted 19 rounds of SHA-256 using
a parameterised CDCL solver plus a parallel Cube-and-Conquer search.

```bash
sha-research preimage --rounds N --cube-bits K --cube-round R \
                      [--cube-register a|e] [--jobs J]
```

Mechanism:

1. Choose `K` bits of a state word at round boundary `R`.
2. Partition the search space into 2^K **disjoint** cubes that together cover
   every assignment.
3. Solve `F AND cube` for each cube, in parallel, under assumptions.
4. A cube proven `UNSAT` contributes a **blocking clause** that prunes it from
   the master formula permanently.
5. Because the cubes are disjoint and total, exhausting them with `UNSAT` is a
   genuine proof that no preimage exists.

Implementation notes:

- `ISolver::solve_under_assumptions` pins each cube literal as a unit clause,
  which is semantically identical to passing assumptions to an incremental
  solver and works with any DIMACS-reading solver.
- Cubes are processed in **batches**. Within a batch every worker only reads the
  master formula; between batches the learned clauses are merged under a lock.
  Writing to the formula from inside the worker loop would be a data race.
- A cube that merely times out is **never** pruned. Only a proven `UNSAT` may
  add a blocking clause.

### Measured result: does not help here

| Configuration | Solve time | Outcome |
| :--- | ---: | :--- |
| 18 rounds, unrestricted | **14.1 s** | SAT, verified |
| 18 rounds, 12 cube bits, 16 threads | 244.1 s | SAT, verified |
| 19 rounds, 10 cube bits, 60 s/cube | 3860 s | **1024 / 1024 cubes inconclusive** |

Cube-and-Conquer is *slower* at 18 rounds and *useless* at 19. The reason is
that a SAT instance of this kind is narrow-but-deep, not wide-but-shallow.
Partitioning the space gives each worker a strictly harder subproblem (most
bits unconstrained inside each cube) and removes the global propagation that
makes the unrestricted instance tractable. Parallelism cannot recover a
200x per-round cost jump on 16 cores.

The blocking-clause learning never even engaged at 19 rounds: no cube could be
decided, so nothing was learned.

## 2. Free-variable reduction (message-word pinning)

The overdetermination argument suggests that up to 8 of the 16 message words
could be pinned while keeping the instance satisfiable (`2^512-32k` free bits
still exceeds 256 down to k=8). `fixed_words` implements this as explicit
`(index, value)` pairs, so pinning `W[3]` does not silently pin `W[0..2]`.

```bash
sha-research preimage --rounds N --fix-words 0:7 --fix-seed S
```

### Measured result: substantially worse

18 rounds, XOR + carry-save, 300 s budget:

| Pinned words | Solve time | Status |
| :--- | ---: | :--- |
| none | **14.1 s** | SAT |
| `W[0..3]` (128 bits) | > 294 s | TIMEOUT |
| `W[0..5]` (192 bits) | > 294 s | TIMEOUT |
| `W[0..7]` (256 bits) | > 294 s | TIMEOUT |
| `W[0..15]` (512 bits) | 0.12 s | UNSAT (correct) |

Pinning four words already costs more than 20x. Pinning all sixteen makes the
message fully determined and the instance trivially unsatisfiable — correctly
proved in 0.12 s, and a good sanity check that the proof path works.

The intuition failure is worth stating plainly: removing free variables does
not make the constraint system easier to propagate through, it only removes
the solver's room to manoeuvre. For an overdetermined problem, constraint
hurts.

## 3. What is actually needed to reach 19 rounds

The published 19-round result depends on a **parameterised solver** — a CDCL
implementation whose branching heuristic is specialised to the structure of
intermediate inverse problems. That is not reachable by invoking a solver
binary with command-line flags.

The 19- and 20-round *practical* record (Basra 2026) uses a different technique
entirely: table-based context shaping rather than SAT inversion.

So the honest position is:

| Rounds | Status of this framework |
| ---: | :--- |
| 18 | **Verified**, reproducible, `reports/preimage_scaling.md` |
| 19 | Unresolved; all strategies tried exhaust their budget |
| 20+ | Not attempted; out of reach for a direct SAT encoding |

Reproduce the negative results with:

```bash
# Cube-and-Conquer at the wall
sha-research preimage --rounds 19 --solver cryptominisat --encoding xor \
    --carry-save --cube-bits 10 --cube-round 6 --timeout 60

# Free-variable reduction regression
sha-research preimage --rounds 18 --solver cryptominisat --encoding xor \
    --carry-save --fix-words 0:3 --timeout 300
```
