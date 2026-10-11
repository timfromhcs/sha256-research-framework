# v6 Plan, Revision 5 — Making 20 Rounds Tractable

**Status:** local only, nothing pushed. Rev 4 was a projection; this revision
replaces its numbers with measurements.

---

## 1. What changed since Revision 4

Rev 4 assumed the inner loop ran at 1.0e7 swept/s and projected 20 rounds eight
years out. Measuring first, before optimising, was the right instinct — but the
assumption was wrong by a factor of nine, and the loop was not where Rev 4
thought it was.

Three defects surfaced while establishing the baseline. All three are fixed.

### 1.1 The table cache returned a corrupt table

`save_table` wrote a 32-byte header; `load_table` read the arrays from offset
**64**. Every array was skewed by 32 bytes. The reloaded table loaded cleanly,
reported correct-looking statistics (mean 1.5781 roots/image), and returned
roots that were roots of nothing.

Nothing caught it because nothing ever verified a *cached* table — only freshly
built ones, which were always correct. The earlier "224.9 s → 84.1 s" cache
measurement timed the load and never checked its output.

Fixed: a named `TABLE_HDR_BYTES` used by both sides, the magic bumped to `CST2`
so existing corrupt files are rejected rather than misread, and the root count
recorded in the header is cross-checked against the stored count.

`tabletest` now accepts a path to verify a cached table, and `--roundtrip` to
build, write, read back and verify the reloaded copy. Wired into CTest as
`context-shaping-table-roundtrip`. Against the 2^30 cached table it reports
45969 multiplicity errors and 100178 invalid roots before the fix, zero after.

### 1.2 A genuine root was discarded as a sentinel

`root()` returns `0xFFFFFFFF` for "no such slot". But `0xFFFFFFFF` is itself a
legitimate root: `u = 0xFFFFFFFF` maps to image `0x20000000`. `branches()`
tested the returned value against the sentinel and silently dropped that
branch. One lost candidate in 2^30 — small, but a real wrong answer. Callers now
bound their loop by the multiplicity and never test the value.

### 1.3 The batch pipeline never advanced

The first batching implementation computed `a0` from the *slot* index rather
than the candidate index, so every window re-processed the same first `batch`
candidates. It reported a stage-1 hit rate of exactly zero. The debug that found
it was worth the detour: an independent recomputation over the same `a0`
sequence produced exactly the predicted 0.2503 / 0.1593, which localised the
fault to the plumbing rather than to the maths.

---

## 2. Where the time actually goes (measured)

Two sweeps of the same code at two widths, single-threaded:

| width | table | stage-1 hit rate | rate |
| --- | --- | ---: | ---: |
| 2^28 dense | 1.00 GiB | 0.0396 | 9.0e7 swept/s |
| 2^30 compact | 5.50 GiB | 0.1585 | 8.6e6 swept/s |

Ten times slower, for four times the lookup rate. Solving the two rate equations
for the per-lookup cost:

```
1/8.6e6 = C + 0.1585·L
1/9.0e7 = C + 0.0396·L      →  L ≈ 8.4e-7 s ≈ 840 ns per stage-1 hit
```

840 ns is 8x a DRAM cache miss. The cause is structural: the stage-1 lookup is a
**dependent chain of four random accesses** into a 5.5 GiB table — `cnt`, then
`rootbase`, then the `cnt` bytes of the enclosing block, then the root — over
4 KiB pages, so every one of them is also a TLB miss.

**The loop is latency-bound, not throughput-bound.** That is the fact the whole
plan rests on, and it is why both threading and batching should help and why
they should partly overlap.

---

## 3. O1 + O2, measured

`--threads` and `--batch` were added. Thread counts partition contexts, so the
context count must be at least the thread count or the pool silently idles — an
earlier run with `--contexts 2` capped at 2.10x and looked like a hardware
ceiling. Width 2^30 compact, 16 contexts, 3e6 swept each:

| threads \ batch | 1 | 16 | 64 | 256 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 8.3e6 | 1.07e7 | 1.07e7 | 1.04e7 |
| 2 | 1.45e7 | 2.09e7 | 2.18e7 | 2.18e7 |
| 4 | 2.8e7 | 4.36e7 | 4.36e7 | 4.36e7 |
| 8 | 6.0e7 | 8.0e7 | 8.0e7 | 8.0e7 |
| 16 | 9.6e7 | **1.20e8** | 1.20e8 | 1.20e7 |

Best configuration: **16 threads, batch 16, 1.20e8 swept/s — 14.5x over
single-threaded.**

Against the Rev 4 kill criteria:

- **O2 (batching), 1 thread: 1.29x.** Below the 2x kill threshold. Batch size
  beyond 16 buys nothing.
- **O1 (threads), batch 1: 11.6x.** Above the 8x kill threshold.
- **Combined: 14.5x, not 16 × 1.29 = 20.6x.** The two overlap, as anticipated —
  both fill the same memory-level parallelism slots. Worth having measured the
  grid rather than multiplying.

On 8 physical cores, 16 logical threads beats 8. Prefetching with `_mm_prefetch`
and `_MM_HINT_T0`.

---

## 4. The corrected cost model

Rev 4's projection rested on a predicted stage-1 hit rate of 0.25. That
prediction was wrong. `R0` is uniform over the full 32-bit space, and the table
stores only the attained images, which are 0.633673 of it, so the real rate is
`0.25 × 0.633673 = 0.1585` — exactly what is measured. The tool's own
`f * 0.633673 * mean_roots` formula already encodes this; only its label was
wrong.

Measured stage-2 and stage-3 rates (0.0396, 0.0099) exceed the independent-stage
prediction by 1.58x and 3.99x — that is, by 1.578 and 1.578². The stages are
positively correlated, because `a1` being a genuine root constrains what `R1`
can be. The measured collapsed rate is therefore **1.89e-6**, against 3.99e-7
from the independent model — 4.7x better.

```
expected swept per collapsed candidate  =  1 / 1.89e-6  =  5.3e5
19 rounds                                =  5.3e5 swept          (measured: 31,877)
20 rounds                                =  5.3e5 x 2^32 = 2.27e15
```

At the measured 1.20e8 swept/s:

| width | E[branches] | swept | projected wall clock |
| --- | ---: | ---: | ---: |
| 2^30 (now measured) | 0.25 | 2.27e15 | **219 days** |
| 2^31 | 0.50 | 1.14e15 | 110 days |
| 2^32 | 1.00 | 5.7e14 | 55 days |

Width 2^31 needs ~11 GiB resident and fits in this machine's 21 GiB, subject to
the OOM guard. Width 2^32 needs ~17 GiB for the roots array alone and does not
fit without the mapping work (O4), which is why that row is listed as
unreachable rather than merely slow.

**So: 20 rounds is about seven months on this laptop at width 2^30, or roughly
four months at 2^31.** Rev 4 said eight years. The error was the baseline rate
and the hit-rate prediction, not the mathematics.

---

## 5. What is left

| # | Item | Effort | Expected | Status |
| :--- | :--- | :--- | ---: | :--- |
| P1 | baseline profile | — | — | done, §2 |
| O2 | batched prefetch | 0.5 d | 4x predicted | done, **1.29x** |
| O1 | multithreaded sweep | 0.5 d | 16x | done, **11.6x / 14.5x combined** |
| O5 | adaptive width and exit code | 0.25 d | — | open |
| O4 | zero-copy roots mapping | 1 d | reach width 2^32 | open |
| O3 | SIMD arithmetic chain | 0.5 d | 1.2x | open, low value |

O3 is now last in priority and probably not worth doing: with batching and
threading in place the loop is still memory-bound, so removing arithmetic
instructions buys little.

O5 is the one that still matters, and not for speed. Every 20-round attempt so
far has been killed by an external timeout, which destroys the evidence. A
search that reports its own projection and exit code leaves a usable record.

---

## 6. Position

- **19 rounds** is solved, verified, and reproduces bit-identically
  (`1b2ffb52…cf2cd1`, `VERIFIED: yes`, 31,877 swept). It is now seconds and
  does not need optimising.
- **20 rounds** remains one `2^32` away. Seven months on this machine, four at
  width 2^31, both measured rather than guessed. The mathematics still offers
  nothing; every one of the six optimisation categories searched in the local
  OpenAI clone was empty, and the loop is memory-bound.
- **21 rounds** remains `2^77`.
- **Full SHA-256** stands at 2^256. Nothing here touches it.

The honest summary: this revision turned "eight years, optimistically" into
"four to seven months, measured". That is a real and large improvement, and it
still is not the difference between attempting 20 rounds and not attempting them.
The remaining lever with real leverage is O4 — reaching width 2^32 — and it
needs memory this machine does not have.