# SHA-256 Research Framework v5.0.0

**This release solves 19 rounds of the SHA-256 compression function.** In
v4.3.0 the framework could only *verify* published 19- and 20-round preimages;
it now produces 19-round preimages itself, in roughly 0.3 seconds on commodity
hardware.

Full SHA-256 remains unbroken. A reduced-round preimage of a *compression
function* is not a preimage of the padded hash, and nothing in this release
affects collision resistance.

## What changed

**New: context-shaping preimage search** (`tools/context_shaping.cpp`). An
independent reimplementation of the submask family (Basra 2026,
`github.com/kamb-code/sha256-r19-preimage`); no code is shared with that
repository and the equations are derived from FIPS 180-4 plus the
construction's structural conditions.

Working backwards from the target fixes eight state words with no search at
all. Imposing `a4 = a5 = v` together with `e8 = e9 = 0xFFFFFFFF` exploits the
saturations `Ch(0xFFFFFFFF, y, z) = y` and `Maj(x, x, y) = x`, which makes the
`W16`, `W17` and `W18` message-schedule constraints *triangular* in
`(a1, a2, a3)`. Three inverse-table lookups then replace a fixed-point
iteration, and the residual collapses from a 32-bit modular equation to the
bitwise condition `Maj(v, a3, a2) == a3`.

## Verified 19-round preimage

Produced by this framework, all-ones target:

```
1b2ffb528506b511c2db748f75d4fe52f
7674fd48874e7b9b374812290818441f
22f4d988399a64f2fbadc6a256f8ac32
4e45a975978b51418a0375599cf2cd1
```

Confirmed by the segregated `IndependentVerifier`:

- `is_valid = true`
- `classification = ReducedRoundPreimage`
- `hamming_distance = 0`
- `engine_segregated = true`
- **rejected at 18 rounds and at 20 rounds** (negative controls)

The direct SAT encoding could not reach 19 rounds at all (>3230 s,
unresolved). It still reaches 18 rounds in about 13 seconds, so the algebraic
method is complementary rather than a replacement.

## Measured

| Configuration | Rounds | Cost |
| --- | ---: | --- |
| Direct SAT (CryptoMiniSat, XOR, carry-save) | 18 | ~13.2 s |
| Direct SAT | 19 | > 3230 s, unresolved |
| **Context shaping (submask family)** | **19** | **~0.3 s** |

Throughput is about 1.4e7 swept `a0` per second on a Ryzen 7 7735HS.

## Honest limits

- **No 20-round preimage was produced here.** The fourth schedule constraint
  adds a factor of `2^-32`, projecting to `2^45.4` swept values, roughly 15
  hours on one A100. The deepest *confirmed* result remains the externally
  published 20-round witness verified in v4.3.0, which was not produced by this
  project.
- **21 rounds is out of reach.** It projects to `2^77` swept values, about
  5.6 million years on a single A100 and still about 5.6 years on a million of
  them. This is an arithmetic wall rather than a missing implementation, and
  Basra's barrier analysis localises the obstruction to a single wire.

## Assets in this release

Each archive is built on a runner of the matching operating system. No binary
in this repository is ever cross-labelled.

- `sha256-research-framework-v5.0.0-windows-x64.zip`
- `sha256-research-framework-v5.0.0-linux-x64.tar.gz`
- `sha256-research-framework-v5.0.0-macos-arm64.tar.gz`
- Matching `.sha256` digest files for each archive

Every archive contains `bin/`, `tools/`, `docs/`, and the licence and
changelog. Builds are CPU-only: the Vulkan SDK is optional and is not present
on the release runners.

Source code for this release is attached in the auto-generated archives at the
bottom of the release page.

## Verifying a download

```bash
sha256sum -c sha256-research-framework-v5.0.0-<platform>.<archive>.sha256

# then check the binaries themselves
bin/sha-verifier test-vectors
bin/context_shaping selftest
```

`context_shaping selftest` proves the backward chain and all ten algebraic
identities of the construction on planted states in about 0.05 s.

## Two bugs worth recording

Both produced *plausible* output rather than failing loudly, and both were
caught by planted-state identity tests rather than by reading a digest:

- `Maj(x, y, y) = y`, not `x`. With `a5 = a4 = v` the saturated term
  `T2^(7) = Sigma0(a6) + Maj(a6, v, v)` equals `Sigma0(a6) + v`. Using `a6`
  silently corrupted `A_0` and `A_2`.
- `W_0` is not a constant: round 0 gives `W_0 = a_0 - const`, carrying the
  swept variable with coefficient +1. Treating it as constant broke `C0` only,
  while `C1` and `C2` still passed.

A third bug, in the tool's own option parsing, is documented in the changelog:
numeric options were parsed in hexadecimal, so `--bits 28` became `40` and the
tool requested a 17 GiB allocation on a machine with about 11 GiB free. Parsing
is now decimal with validation and a hard memory budget clamps the table width
before allocating.