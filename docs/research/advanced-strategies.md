# Advanced Search Strategies (v5.0.0)

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

---

## v4.3.0: External witnesses and a second solver core

Two additions, both aimed at the same question: *how much can be trusted, and
by what?*

### External witness verification

`tools/verify_published.py` confirms eight published reduced-round preimages
using the segregated `IndependentVerifier`.

| Witness | Rounds | Target | Positive | Negative control |
| :--- | ---: | :--- | :--- | :--- |
| P1 | 19 | Basra | verified, Hamming 0 | rejected @18 |
| P2 | 19 | Basra | verified, Hamming 0 | rejected @18 |
| P3 | 19 | Basra | verified, Hamming 0 | rejected @18 |
| P4 | 19 | Basra | verified, Hamming 0 | rejected @18 |
| P5 | 19 | Basra | verified, Hamming 0 | rejected @18 |
| P6 | 19 | Basra | verified, Hamming 0 | rejected @18 |
| P7 | 19 | all-ones (Zaikin) | verified, Hamming 0 | rejected @18 |
| R20 | 20 | all-ones | verified, Hamming 0 | rejected @19 |

**8/8 verified. Deepest externally published preimage confirmed: 20 rounds.**

The negative controls are what make this meaningful. Each witness is also run
at a neighbouring round count and *must* be rejected; a verifier that returned
`true` unconditionally would pass the positive cases and fail the controls.

Note on semantics: for rounds < 64 the verifier requires an exact 64-byte block
and calls `independent_compress_block` directly, **without** SHA-256 padding.
Padding applies only on the full 64-round path. Modelling a padded block would
target a different problem from the one the witnesses describe.

### Z3 bit-vector as a second solver core

`tools/z3_bitvector_check.py` runs the same problem through Z3's bit-vector
engine: a different search heuristic, different simplification pipeline, and no
shared code with the CDCL path.

| Rounds | Z3 bit-vector | Native CDCL path |
| ---: | ---: | ---: |
| 4 | 0.0 s | 0.0 s |
| 5 | 0.0 s | 0.0 s |
| 6 | 0.1 s | 0.0 s |
| 7 | **27.2 s** | 0.0 s |
| 8 | UNKNOWN @ 240 s | 0.0 s |
| 18 | not attempted | **~13.2 s** |

Z3's ceiling is **7 rounds** against our **18** — an 11-round gap.

This is not a defect in either engine. SHA-256 is XOR-dominated: emitting the
`Ch`, `Maj`, and `Sigma` relations as native XOR clauses lets the solver apply
Gaussian elimination across hundreds of variables at once. Z3 bit-blasts
eagerly into plain CNF and loses that structure entirely. The measurement is
independent support for the XOR-dialect decision made back in v4.0.

Z3 is retained as a **cross-check, not a path forward**.

#### Four gates

No Z3 result is reported unless all four agree:

1. **Z3** returns a model.
2. An **independent Python** recomputation reproduces the target.
3. The **segregated C++ verifier** confirms it (`is_valid=True`).
4. A **negative control** at `rounds - 1` is rejected.

Disagreement is surfaced as an error, not smoothed over.

#### What the gates caught

Gate 2 earned its place immediately. Z3 returned models that satisfied its own
constraints but whose digest did not reproduce — `K[2]` had been written as
`0xb5c0fbbc` instead of `0xb5c0fbcf`. One transposed digit, invisible on
inspection, wrong in every single run. The C++ verifier was right; the new
Python reference was wrong.

A bug found only by cross-checking two independent implementations is the
entire argument for having them, and it is now pinned by
`tests/test_python_reference_kat.py`.

### Conditional-affine redundancy: not needed here

Feng and Gao (ePrint 2026/1505) argue that Tseitin encodings of SHA-256's
nonlinear functions can hide conditioned differential projections from BCP,
and propose redundant CNF clauses to expose them — four for `Ch` and twelve for
`Maj` per bit.

The new C++ test `test_nonlinear_encodings_are_conditioned_projection_complete`
checks our encodings against that criterion directly. It enumerates every
assignment consistent with the `Ch` and `Maj` truth tables and asserts that each
conditioned projection holds on all of them:

- `Ch(e,f,g)`: four projections under `e = 1 -> out = f` and `e = 0 -> out = g`.
- `Maj(a,b,c)`: six projections for each of the three control variables, under
  `x = 1 -> out = OR(rest)` and `x = 0 -> out = AND(rest)`.

**All are already entailed by the clauses we emit.** The redundant clauses
therefore cannot add propagation, which is consistent with the measured
slowdown from adding them. The paper's motivation is sound for encodings that
fail this bar; ours does not fail it, so the remedy buys nothing here and costs
clause count.

This is a case where a negative result is the useful output: the technique can
now be ruled out on grounds other than "we tried it and it was slower".

## Still open

- **19-round preimages remain unsolved** by this framework. Published 19- and
  20-round results rely on table-based context shaping and heavily
  parameterised search rather than a direct SAT encoding.
- Reproducing the published results independently still requires a
  programmable, structurally parameterised CDCL search, or a table-based
  method such as context shaping.
- Full SHA-256 preimage resistance stands at 2^256. Nothing in this document
  changes that.

---

## v5.0.0: Context Shaping � 19 rounds solved by this framework

### The result

This framework now **produces** a 19-round SHA-256 compression-function
preimage itself, rather than only verifying published ones.

| Path | Rounds | Cost on this machine |
| --- | ---: | --- |
| Direct SAT encoding (CryptoMiniSat, XOR, carry-save) | **18** | ~13.2 s |
| Direct SAT encoding | 19 | > 3230 s, unresolved |
| **Context shaping (submask family)** | **19** | **~0.3 s**, after a one-time 4 GiB table |

Witness produced by `context_shaping`, all-ones target:

```
1b2ffb528506b511c2db748f75d4fe52f
7674fd48874e7b9b374812290818441f
22f4d988399a64f2fbadc6a256f8ac32
4e45a975978b51418a0375599cf2cd1
```

Confirmed by the segregated `IndependentVerifier`:
`is_valid=true`, `classification=ReducedRoundPreimage`, `hamming_distance=0`,
`engine_segregated=true`. Rejected at 18 and at 20 rounds.

### Why this works when the SAT encoding does not

A one-block preimage gives 512 free message bits against a 256-bit digest:
the instance is satisfiable by a margin of 2^256. That is the problem. CDCL
has to thread one solution through a deep, well-mixed circuit, and at 19 rounds
it cannot. This is why v4.1 and v4.2 measured cube-and-conquer, message pinning
and Dobbertin constraints as *regressions* � none of them remove the
overdetermination.

The submask family (Basra 2026) removes it algebraically instead:

1. **Work backwards.** Subtracting the IV from the target fixes `a_15..a_18`,
   and four inverted rounds extend the chain to `a_11`. No search.
2. **Choose the context, do not randomise it.** Imposing `a4 = a5 = v` and
   `e8 = e9 = 0xFFFFFFFF` uses the saturations `Ch(0xFFFFFFFF, y, z) = y` and
   `Maj(x, x, y) = x` to make the schedule constraints on `W16, W17, W18`
   *triangular* in `(a1, a2, a3)`.
3. **Three table lookups replace a fixed-point iteration.** Each constraint is
   `sigma0(u) - u = R`, solved from an inverse table.
4. **The residual collapses to a bitwise condition.** What was a 32-bit
   modular check becomes `Maj(v, a3, a2) == a3`, which holds for exactly
   `3^32` of the `2^64` pairs � probability `(3/4)^32 = 1.0045e-4`.

Measured on this machine: ~1.4e7 swept `a0` per second, one 19-round preimage
per ~6e6 swept values, matching the model
`1 / (0.6337^3 * (3/4)^32) = 39124` scaled by the reduced table width.

### Fitting the table to 11 GiB instead of 16 GiB

The published construction assumes a full 2^32 inverse table: 16 GiB. This
machine has ~11 GiB free, and a full table is not an option.

Two lossless reductions make it fit, and both are throughput trade-offs rather
than correctness changes:

- **Range truncation.** Store roots only for image values below `2^B`. A lookup
  outside that range simply misses, so the yield drops by `(2^B / 2^32)^3` while
  memory drops by `2^(32-B)`. At `B = 30` the table is 4 GiB and the sweep
  requirement rises from ~39k to ~2.5e6 � about 0.3 s of extra work.
- **Full-range scan.** Crucially, the *scan* over `u` must cover the whole
  32-bit range even when storage is truncated. Restricting the scan to the same
  range drops the image density from 0.6337 to 0.25 and costs a factor of 16 in
  yield, because all three lookups must hit.

A hard memory budget clamps the width before anything is allocated. This is not
hypothetical hardening: an earlier revision parsed its numeric options in hex,
so `--bits 28` became `40` and the tool attempted a 17 GiB allocation, which
exhausted memory and took the machine down. The parser is now decimal, the
budget is enforced, and both are covered by regression tests.

### What the derivation cost, and how the bugs were caught

Two real bugs were found and fixed during implementation. Both are worth
recording because both produced *plausible* output rather than crashing:

- **`Maj(x, y, y) = y`, not `x`.** With `a5 = a4 = v`, the saturated term
  `T2^(7) = Sigma0(a6) + Maj(a6, v, v)` equals `Sigma0(a6) + v`, not
  `Sigma0(a6) + a6`. This silently corrupted `A_0` and `A_2`.
- **`W_0` is not a constant.** Round 0 gives `W_0 = a_0 - const`, so it carries
  the swept variable with coefficient +1. Treating it as constant broke `C_0`
  only � `C_1` and `C_2` still passed, which is the worst possible failure
  shape for a hand-rolled search.

Neither was found by running the search and looking at the digest. Both were
found by **planted-state identity tests**: for arbitrary `a0..a3`, check that
`W_{j+1} = a_{j+1} + B_j`, that `W_{10} = A_1 - a_2` and `W_{11} = A_2 - a_3`
hold for every `a_3`, and that the `A_0` residual is exactly
`Maj(v, a3, a2) - a_3`. These ten identities run in 0.05 s and are now a
CTest target. The search itself independently reported the failure as
`C0=FAIL C1=ok C2=ok`, which is what localised it.

### Twenty rounds: measured cost model, not a result

At 20 rounds a fourth schedule constraint `C3` on `W19` appears. It is not
solved by a lookup; it reduces to a residual
`c3 = sigma0(W4) + W3 - kappa3` that must vanish, contributing a further factor
of `2^-32`.

The tool implements `C3` and can measure its residual distribution
(`CS_MEASURE_C3=1`). The honest reading of what that shows:

- The cumulative low-`k` zero counts on 24 candidates are consistent with the
  uniform model, but **24 candidates is far too small a sample to say
  anything** about an exact-zero rate.
- Basra himself reports `P(c3 = 0) = 2^-32` as a *working extrapolation, not a
  measured exact-zero rate*. This framework does not improve on that.

Projected cost with a full-width table: about `2^45.4` swept `a0`. At the
`8.5e8` per second Basra reports on an A100 that is ~15 h of one GPU. **This
framework did not reproduce a 20-round preimage.** The v4.3.0 external
witnesses still stand as the deepest confirmed 20-round result, and they are
someone else's witnesses, not ours.

### Twenty-one rounds: an arithmetic wall, not a missing idea

21 rounds adds two more exact 32-bit constraints. Under the independence model
that is a factor `2^64` over 19 rounds, i.e. about `2^77` swept `a0`. At
`8.5e8` per second:

```
2^77 / 8.5e8  ~  1.8e14 s  ~  5.6 million years on one A100
```

With a million A100s it is still ~5.6 years. Basra's own barrier analysis
localises the obstruction to a single wire � the `a5 -> C1` edge through
`Sigma0(a5)` � and reports a falsification search over ~1.6e6 legal context
conditions finding a minimum of 10.86 bits changed per flipped bit, against the
2-bit threshold at which absorption would become possible.

**21 rounds is not reachable with this method on any hardware that plausibly
exists.** Reporting it as an engineering gap would be misleading. It is a
genuine open research problem, and the useful thing this framework can do
about it is state the wall precisely, which is what the numbers above do.

### What this changes, and what it does not

- Changes: the framework solves 19 rounds itself, in under a second, on
  commodity hardware. The 19/20-round gap in v4.3.0 was a *verification* claim;
  it is now a *production* claim at 19 rounds.
- Does not change: full SHA-256 stands at 2^256. Nothing here touches
  collision resistance, and a reduced-round preimage of a compression function
  is not a preimage of the padded hash.
- Does not change: the direct SAT encoder still tops out at 18 rounds. The
  algebraic method is a different tool for a different shape of problem, and
  the two results are complementary rather than one replacing the other.
