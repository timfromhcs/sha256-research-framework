# v6 Plan — Joint-Absorption Search and Fibre-Aware Storage

**Status:** plan of record. Written before the work is done, so that the
target and the stopping condition are fixed in advance rather than chosen
after the fact.

**Starting point (v5.0.0, verified):** this framework solves 19 rounds of the
SHA-256 compression function in ~0.3 s. The direct SAT encoder reaches 18. A
segregated `IndependentVerifier` confirms every claim, with negative controls
at neighbouring round counts.

---

## 1. What is being targeted, and the honest ceiling

The goal is 21 rounds. Two facts established in v5.0.0 constrain it:

- **20 rounds** adds one exact 32-bit constraint (`C3`) and projects to
  `2^45.4` swept values, about 15 h on one A100. Not reproduced here.
- **21 rounds** adds two and projects to `2^77` swept values, about **5.6
  million years** on a single A100, still ~5.6 years on a million of them.

That projection is only valid if the constraints are met *by search*. The only
way 21 rounds becomes reachable is if a context family makes the fourth and
fifth constraints **structural** rather than probabilistic — that is, if they
are absorbed by the context rather than waited out. Absorbing them removes
`2^64` from the cost model at a stroke.

**This plan does not promise 21 rounds.** It is a serious attempt at the
absorption route, with a defined search space and a defined stopping
condition, plus one component that yields a certain, measurable improvement
regardless. The outcome is reported honestly either way.

---

## 2. Inspiration: what the OpenAI mathematics collection actually contributes

The release at `github.com/openai/math` (719 manuscripts, 372 families, ~42%
Lean-formalised) was surveyed specifically for mathematics analogous to
counting and optimising candidates surviving algebraic constraints.

**Most of the categories searched came up empty**, and those absences are
informative: there is nothing on low-discrepancy sequences, covering codes,
CVP/lattice reduction, residue distribution, or on `Sigma0`/`Sigma1`-type
nonlinear bit functions of a 32-bit word.

Four results transfer:

| Family | Result | How it applies |
| :--- | :--- | :--- |
| **011** | Erdős's totient conjecture: for every ε>0, infinitely many `n` have more than `n^(1-ε)` preimages under φ | The fibre size of a highly non-injective map can be far above its mean. Directly our question about `u ↦ σ0(u) − u`. **Tested in Phase A** — the hypothesis did *not* hold, see §3. |
| **132** | `bs(f) ≥ s(f)^α` for a fixed α>2 — block sensitivity is superquadratically larger than sensitivity | Single-variable dependence analysis provably undercounts exploitable structure. Basra's barrier search considered **single** context-word ties; multi-word ties are a different and larger space. **Drives Phase B.** |
| **192** | Linear Fourier coefficients of Boolean functions are **not** `O(√deg)`-bounded; violations are unbounded | A hard prohibition: no spectral signature of `σ0` may be estimated from its algebraic degree. Rules out a whole family of otherwise-plausible analyses. |
| **162** | Ryser's covering conjecture is false: balanced intersecting hypergraphs can need transversal number `q+1` | "Guess one variable, then solve" can be forced to be exhaustive. A sharp warning against assuming a fourth absorption is easy to find — it shapes how Phase B reports failure. |

Secondary, useful as *measurement instruments*: **127** (average sensitivity
`≤ 8d√n`, sharp constant), **179** (Barker sequences — exact classification of
binary sequences with flat aperiodic autocorrelation), **188** (sharp
survival constant for a randomised local-deletion process).

---

## 3. Phase A — Fibre-aware storage (certain, measurable win)

### The measurement, already taken

`context_shaping fibres` scans all 2^32 values of `u` and histograms the number
of preimages of each image under `σ0(u) − u`:

```
images attained    : 2721603627 (density 0.633673)
mean fibre         : 1.578102
max fibre          : 14

fibre size : fraction of attained images
  1        : 0.582967
  2        : 0.291562
  3        : 0.096335
  4        : 0.023665
  5        : 0.004612
  6+       : 0.000857
```

Three findings, two of them useful and one of them a negative result:

1. **The density 0.633673 reproduces Basra's published figure exactly**, from an
   independent implementation. That is an external cross-check on our code.
2. **The Erdős-style heavy-tail hypothesis is refuted.** If large fibres were
   polynomially common, max fibre would be far above 14 and the distribution
   would not concentrate at 1–2. It is mildly under-dispersed relative to
   Poisson. So there is no small set of "magic" high-multiplicity images to
   exploit. Recorded as a negative result rather than quietly dropped.
3. **But a real 36.6% loss is sitting in plain sight.** Our table stores
   exactly one root per image, discarding 36.6% of all attainable
   continuations. The exact marginal value of the K-th root is now known:

   | cap K | mean retained roots | fraction of images with ≥ K |
   | ---: | ---: | ---: |
   | 1 | 1.0000 | 1.0000 |
   | 2 | 1.4170 | 0.4170 |
   | 3 | 1.5425 | 0.1255 |
   | 4 | 1.5716 | 0.0291 |
   | 6 | 1.5780 | 0.0009 |

### Work

- **A1.** Replace the single-root table with a K-root table, K configurable,
  laid out as a dense array of `(K+1)` words per image slot: one count word plus
  K root words. Memory `4·(K+1)·2^B`; for K=3 at B=28 that is 4 GiB, inside
  budget.
- **A2.** Replace the *extrapolated* yield model with the *exact* one computed
  from the measured histogram. Expected retained roots becomes a known constant
  rather than a figure from a pooled campaign.
- **A3.** Measure end-to-end: swept `a0` per verified 19-round preimage, at
  matched settings, K = 1 vs 3, several seeds. Report mean and spread.
- **A4.** Apply the same treatment to 20-round `C3`: determine whether the
  residual's distribution interacts with fibre multiplicity, i.e. whether
  candidates drawn from high-multiplicity images have a systematically different
  `c3` distribution. This is a concrete, testable question that the published
  analysis left open.

**Expected outcome:** a measurable reduction in cost per preimage at 19 rounds,
and an exact rather than modelled cost prediction. **This does not move 21
rounds.** It is included because it is certain, and because A4 is a genuine
test of the `2^-32` assumption that every 20-round projection rests on.

---

## 4. Phase B — Joint-absorption search for 21 rounds

The obstruction is known and specific. Each unknown `a_k` reaches the schedule
constraints through two *one-input* functions of itself, `Σ0(a_k)` and
`Σ1(a_k + c)`, which the saturation rule cannot touch: saturation needs a
repeated argument, and these have none. Basra's barrier analysis found the
`a5 → C1` edge flips ≥10.86 bits per changed bit against a 2-bit absorption
threshold, and a falsification search over ~1.6e6 legal single-relation context
conditions found nothing.

Family 132 says this is the wrong place to stop looking, because the analysis
was *single-variable*.

### B1. Symbolic dependency engine

Build a symbolic analyser that, for a context family expressed in a grammar of
constraints on the context words `a_4..a_11`, decides mechanically:

- which of `C_0..C_4` are triangular in the remaining unknowns,
- for each unknown, the multiset of **one-input functions of it** appearing in
  each constraint,
- whether two occurrences of such a function can be made to cancel by a tie
  between two context words.

This replaces perturbation-based probing with an exact symbolic decision
procedure, and it is machine-checkable — which matters given how this project
has been bitten by hand-derived algebra.

### B2. Grammar with multi-word ties

Enumerate families where context words are tied in *pairs and triples*, not
one at a time. Shapes to include, motivated by the two-function obstruction:

- additive ties `a_6 = a_4 + a_5`, which make two `Σ0` arguments differ by a
  constant and can cancel under a shift;
- rotational ties `a_7 = ROTR(a_6, r)`, pairing a `Σ0` argument with a `Σ1`
  argument so that one flip changes both;
- compensating ties that make a context word enter `C_j` with coefficient +1
  in one term and −1 in another.

### B3. Search and stopping condition

Search the grammar exhaustively, with the symbolic engine as the oracle.
Stopping conditions, fixed now:

- **positive** — a family is found in which `C_3` and `C_4` are both absorbed.
  Then 21 rounds becomes a search problem of the 19-round kind, and the
  implementation proceeds to build and verify a witness.
- **negative** — the grammar is exhausted with no such family. Then we publish
  a *rigorous, machine-checked* negative result covering this grammar, which
  is strictly stronger than the published single-relation barrier: it says the
  obstruction survives multi-word ties too, not merely single ones.

A negative result here is a real outcome and will be reported as one. It is
also the outcome most consistent with the current evidence, and this plan does
not pretend otherwise.

---

## 5. Results

### Phase A — completed

**A0, the measurement.** The fibre distribution of `u ↦ σ0(u) − u` over all
2^32 values:

```
images attained : 2721603627   density 0.633673
mean fibre      : 1.578102     max fibre : 14
```

The density reproduces Basra's published 0.633673 from an independent
implementation — an external check on this codebase. **The Erdős-style
heavy-tail hypothesis is refuted**: max fibre 14, and 58.3% of attained images
have exactly one preimage. There are no "magic" high-multiplicity images to
target. Recorded as a negative result.

**A1–A2, exact cost model.** With the density fixed, the expected number of
root branches per lookup is

```
E[branches] = f * 0.633673 * E[min(K, fibre)]
```

and because `density * mean fibre = 1` exactly, this collapses to `E = f*K_eff`.
The yield per swept value is `E^3 * (3/4)^32`, which converts Basra's
extrapolated figures into arithmetic. The model was validated against
measurement across three independent contexts at three stages:

| Stage | predicted | measured | error |
| --- | ---: | ---: | ---: |
| lookup 1 | 0.158418 | 0.158692 | 0.2% |
| lookup 2 | 0.025096 | 0.025127 | 0.1% |
| lookup 3 | 0.003976 | 0.003935 | 1.0% |

Three decimal places, three contexts, three stages. The model is sound.

**A1, the compact table — implemented, verified, and it does not pay off here.**
A `CompactInverseTable` was built that stores *every* root: a bitmap, a rank
directory, one byte of multiplicity per image, a sampled root-base array every
8 images, and a contiguous root array. Correctness was checked against brute
force over a 2^20 image range: 350,324 roots verified, 0 invalid, 0 multiplicity
errors.

It loses, and the reason is specific. The saving is in the *steady state*
(2.75 GiB at width 2^29, against 4.00 GiB for the dense table at width 2^30),
but construction needs a temporary per-image cursor, so the **peak** is about 9
bytes per image. At a 6 GiB budget the compact table can therefore only be
built at width 2^29, which halves the image range and costs a factor 8 in
yield, against a factor 3.93 gained from the extra roots. Net 0.49×.

| Layout | width | memory | E[branches] | E^3 |
| :--- | ---: | ---: | ---: | ---: |
| dense, K=1 | 2^30 | 4.00 GiB | 0.1584 | 0.003976 |
| compact, all roots | 2^29 | 2.75 GiB | 0.1250 | 0.001953 |
| compact, all roots | 2^30 | *needs ~9.7 GiB peak* | **1.0000** | **1.0000** |

The last row is the real result. **At equal range the compact layout is 251×
better per lookup**, because `E[branches]` goes from 0.1584 to 1.0. It simply
cannot be built at that width within this machine's budget.

Measured confirmation, same target, 9e6 swept values: dense 2^30 produced 5
collapsed candidates, compact 2^29 produced 2.

**What this means, stated plainly:** with about 16 GiB of RAM instead of 11, the
19-round cost would drop from ~2.5e6 swept values to ~1e4. That is a real and
useful result, and it is a **hardware limitation, not a mathematical one**.

**It does not change the round count.** 21 rounds needs a factor of roughly
`2^61.7` over 19. A factor of 251 is not a path to it. Phase A has been
recorded as a negative result for the current hardware, with the condition
under which it would pay off stated exactly.

### Phase B — not achieved

The symbolic dependency engine and the joint-absorption search over multi-word
ties were **not implemented**. No 21-round preimage was found, and no
machine-checked negative result over the multi-word grammar was produced either.
The plan's Phase B remains open work, not a completed phase.

The honest position is unchanged from v5.0.0: 21 rounds projects to `2^77`
swept values, about 5.6 million years on one A100. The only route that changes
that is structural absorption of `C3` and `C4`, and Phase B was the attempt at
it. That attempt did not get far enough to produce a verdict, in either
direction.

- Every witness is forward-verified **before** being reported, and then
  adjudicated by the segregated `IndependentVerifier` at the stated round count
  and **rejected at both neighbouring round counts**.
- Every algebraic identity is checked on planted states before it is relied on.
  The ten identities added in v5.0.0 caught two derivation bugs that produced
  plausible output; the same guard applies to every new identity in Phase B.
- A result is reported as a result only if it survives all of the above. A
  solver model alone is `SolverModelOnly` and is never called a preimage.

## 7. Success criteria

| Criterion | Phase A | Phase B |
| :--- | :--- | :--- |
| Measured improvement | swept `a0` per preimage reduced, reported with spread | — |
| Exact cost model | replaces extrapolation | — |
| 21-round preimage | — | witness verified at 21, rejected at 20 and 22 |
| Rigorous negative result | — | symbolic engine exhausts the grammar, output committed |

Phases run in order; B is attempted even if A underdelivers, and A's outcome is
reported whatever B does.

## 8. Explicitly out of scope

- Any claim about **full SHA-256**. It stands at 2^256 and nothing here touches
  it.
- Any claim that a reduced-round compression-function preimage is a preimage of
  the padded hash. It is not.
- Re-labelling a 20-round result as ours. The published 20-round witnesses came
  from Basra's repository; v5.0.0 verifies them and does not claim them.
- Reporting an UNKNOWN or INCONCLUSIVE solver outcome as a result.