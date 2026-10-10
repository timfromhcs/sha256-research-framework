# Advanced Search Strategies (v4.2.0)

This document records the search techniques implemented beyond the direct SAT
encoding, and — more importantly — **what they actually measured**. Four were
implemented; all four are *worse* than the plain search on this instance. That
is reported here rather than quietly dropped, because a measured regression is
a result.

Every number was produced by `sha-research preimage` on the machine described
in [`preimage_scaling.md`](../../reports/preimage_scaling.md). Nothing is
estimated.

## Why a one-block preimage is unusual

A single SHA-256 block gives 512 free message bits mapping onto a 256-bit
digest. The system is overdetermined by 2^256: roughly 2^256 distinct blocks
share any given target. The instance is *satisfiable by a wide margin* and is
hard purely because the CDCL search cannot thread one of the many solutions
through a deep, well-mixed circuit.

That observation drives everything below, and it is why the intuition from
underconstrained problems ("shrink the search space") does not apply.

## Summary of measured outcomes (18 rounds)

| Strategy | Solve time | Outcome |
| :--- | ---: | :--- |
| **unrestricted** | **13.3 s** | VERIFIED |
| Dobbertin state constraint, E@12, 24 bits | 119.6 s | VERIFIED |
| pin `W[0..3]` (128 bits) | > 300 s | TIMEOUT |
| pin `W[0..7]` (256 bits) | > 300 s | TIMEOUT |
| Cube-and-Conquer, 12 bits | 236 s | VERIFIED |

At 19 rounds, **nothing resolved**: the unrestricted instance exceeds 3230 s,
all 1024 Cube-and-Conquer cubes time out, and all 25 Dobbertin relaxation
levels time out.

---

## 1. Dobbertin state constraints

Dobbertin (1998) constrained an intermediate **state register** to a constant,
rather than constraining the input. Applied to SHA-2 by Davydov, Pikhtovnikov,
Kiryanova and Zaikin (2025), which reported 17- and 18-round preimages "for the
first time" and a weakened 19-round one.

```bash
sha-research preimage --rounds N --dobbertin-bits B --dobbertin-round R \
                      [--dobbertin-register a|e] [--dobbertin-constant K]
```

Mechanism:

1. Force the top `B` bits of register `R` at round boundary `Rr` to match the
   top `B` bits of a constant `K`.
2. Solve. On success, verify and stop.
3. On failure, relax to `B - 1` and repeat, down to 0.

Relaxation is sound in both directions: fewer constraint bits is a strict
superset of the solution set, so any preimage found at a lower level is still
genuine. Only the unconstrained `B = 0` instance being `UNSAT` would constitute
a proof, and that case is reported explicitly as `ProvenNoPreimage`.

### Measured result: works, but slower

| Register / round | Found at | Total |
| :--- | ---: | ---: |
| E @ 8, K=0 | 0 bits (no constraint helped) | 603 s |
| E @ 4, K=0 | 0 bits | 599 s |
| **E @ 12, K=0** | **24 bits** | **119.6 s** |
| A @ 8, K=0 | 10 bits | 362 s |

The technique genuinely works — the 24-bit constraint on E after round 12 was
`SAT` directly, no relaxation needed, and the candidate passed independent
verification. That is a real structural finding: constraining 24 bits of a
middle-round register still admits preimages.

It is nevertheless ~9x slower than the unrestricted search. At 19 rounds every
relaxation level times out, so it does not reach the wall either.

**Why it does not help here.** The benefit in the literature comes from turning
a "wide and shallow" problem into an anchor that propagates both ways. On this
instance the unrestricted problem is already only 13 s deep, so the anchor adds
a constraint without removing the hardness that makes the search hard.

---

## 2. Cube-and-Conquer

Follows Zaikin (JAIR 2024 / Constraints 2026).

```bash
sha-research preimage --rounds N --cube-bits K --cube-round R \
                      [--cube-register a|e] [--jobs J]
```

Disjoint cubes over selected state bits, each solved independently under
assumptions; a cube proven `UNSAT` contributes a blocking clause that prunes it
permanently. Because the cubes are disjoint and total, exhausting them with
`UNSAT` is a genuine proof of nonexistence.

Implementation notes:

- `ISolver::solve_under_assumptions` pins each cube literal as a unit clause,
  semantically identical to passing assumptions to an incremental solver.
- Cubes are processed in **batches**. Within a batch every worker only reads
  the master formula; between batches the learned clauses are merged under a
  lock. Writing to the formula from inside the worker loop would be a data
  race.
- A cube that merely times out is **never** pruned.

### Measured result: does not help

| Configuration | Solve time | Outcome |
| :--- | ---: | :--- |
| 18 rounds, unrestricted | **14.1 s** | SAT, verified |
| 18 rounds, 12 cube bits, 16 threads | 244–296 s | SAT, verified |
| 19 rounds, 10 cube bits, 60 s/cube | 3860 s | **1024/1024 cubes inconclusive** |

A SAT instance of this kind is narrow-but-deep, not wide-but-shallow.
Partitioning gives each worker a strictly harder subproblem and destroys the
global propagation that makes the unrestricted instance tractable. Parallelism
cannot absorb a ~200x per-round cost jump on 16 cores.

The blocking-clause learning never engaged at 19 rounds: no cube could be
decided, so nothing was learned.

---

## 3. Free-variable reduction (message-word pinning)

Overdetermination suggests pinning up to 8 of the 16 message words while
keeping the instance satisfiable. `fixed_words` implements this with explicit
`(index, value)` pairs, so pinning `W[3]` does not silently pin `W[0..2]`.

```bash
sha-research preimage --rounds N --fix-words 0:7 --fix-seed S
```

### Measured result: substantially worse

| Pinned words | Solve time | Status |
| :--- | ---: | :--- |
| none | **13.3 s** | SAT |
| `W[0..3]` (128 bits) | > 300 s | TIMEOUT |
| `W[0..5]` (192 bits) | > 300 s | TIMEOUT |
| `W[0..7]` (256 bits) | > 300 s | TIMEOUT |
| `W[0..15]` (512 bits) | 0.12 s | UNSAT (correct) |

Pinning all sixteen fixes the message entirely, so the instance is trivially
unsatisfiable — correctly proved in 0.12 s, which is a good check that the
proof path works.

Removing free variables does not make the constraint system easier to propagate
through; it only removes the solver's room to manoeuvre. For an overdetermined
problem, constraint hurts.

---

## 4. Solver tuning

CryptoMiniSat exposes `--maxmatrixrows`, `--autodisablegauss`, `--maxxorsize`,
`--forcepreservexors`, and `-m` (simplification multiplier). The 19-round
formula emits 6189 XOR constraints, which is above the default
`--maxmatrixrows=5000`, so Gaussian elimination looked like it might be getting
disabled.

**It is not.** Verbose output shows the solver building matrices
(4892x10010 and 2249x4816, average XOR length 3.7–3.9) and running Gaussian
elimination normally.

Flag sweep at 19 rounds, 60 s each — no configuration produced a verdict:

| Configuration | Result |
| :--- | :--- |
| default | no verdict |
| `--maxmatrixrows 20000` | no verdict |
| `--autodisablegauss 0` | no verdict |
| `--maxxorsize 12 --varsperxorcut 1` | no verdict |
| `--forcepreservexors 1` | no verdict |
| `-m 1` | no verdict |

Solver comparison at 18 rounds also confirms the existing default is the right
choice: CryptoMiniSat with the XOR dialect solves in 13.3 s, whereas Kissat with
the Tseitin dialect takes 47.6 s on the same instance.

---

## What is actually needed to reach 19 rounds

The published 19-round result depends on a **parameterised solver** — a CDCL
implementation whose branching heuristic is specialised to the structure of
intermediate inverse problems, and which is tuned on easier instances of the
same family. That is not reachable by invoking a solver binary with
command-line flags.

The 19- and 20-round *practical* record (Basra 2026) uses table-based context
shaping rather than SAT inversion.

So the honest position:

| Rounds | Status of this framework |
| ---: | :--- |
| 18 | **Verified**, reproducible |
| 19 | Unresolved; every strategy tried exhausts its budget |
| 20+ | Not attempted; out of reach for a direct SAT encoding |

The one lever that demonstrably worked was **encoding quality** — the XOR
dialect and carry-save adder took this framework from 10 rounds to 18.

Reproduce any negative result with:

```bash
# Dobbertin
sha-research preimage --rounds 18 --solver cryptominisat --encoding xor \
    --carry-save --dobbertin-bits 24 --dobbertin-round 12 --timeout 300

# Cube-and-Conquer at the wall
sha-research preimage --rounds 19 --solver cryptominisat --encoding xor \
    --carry-save --cube-bits 10 --cube-round 6 --timeout 60

# Free-variable reduction
sha-research preimage --rounds 18 --solver cryptominisat --encoding xor \
    --carry-save --fix-words 0:3 --timeout 300
```
