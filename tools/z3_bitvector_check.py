#!/usr/bin/env python3
"""
Cross-check the SHA-256 reduced-round preimage search with a different solver
core: Z3's bit-vector engine.

Why
---
Every preimage search in this framework goes through a CDCL solver reading
DIMACS (CryptoMiniSat, CaDiCaL, Kissat). Those share a search core. Z3
bit-blasts eagerly and drives the same style of CDCL, but with a different
heuristic and simplification pipeline, so it is a genuinely independent check
on the encoder and on the target construction.

This script also serves as an independent reference implementation of the
reduced-round compression function in Python: if Z3's model satisfies *its*
constraints but fails *this* code's recomputation, the disagreement is caught
rather than silently believed.

Usage
-----
    python tools/z3_bitvector_check.py --rounds 12
    python tools/z3_bitvector_check.py --rounds 16 --timeout 600
"""

import argparse
import os
import sys
import time
from typing import List, Optional, Tuple

try:
    import z3
except ImportError:
    z3 = None

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

MASK32 = 0xFFFFFFFF


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def compress_python_block(state: List[int], block: List[int],
                          rounds: int) -> List[int]:
    """Compress one raw 64-byte block into `state`, in place of a digest.

    ``state`` is the chaining value (the SHA-256 IV for the first block).
    ``block`` is 16 big-endian words, raw -- no padding is applied here.
    """
    w = list(block) + [0] * max(0, rounds - len(block))
    for t in range(len(block), len(w)):
        s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK32

    a, b, c, d, e, f, g, h = state
    for t in range(rounds):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e & MASK32) & g)
        t1 = (h + s1 + ch + w[t] + K[t]) & MASK32
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & MASK32
        a, b, c, d, e, f, g, h = (
            (t1 + t2) & MASK32, a, b, c, (d + t1) & MASK32, e, f, g)

    return [(a + state[0]) & MASK32, (b + state[1]) & MASK32,
            (c + state[2]) & MASK32, (d + state[3]) & MASK32,
            (e + state[4]) & MASK32, (f + state[5]) & MASK32,
            (g + state[6]) & MASK32, (h + state[7]) & MASK32]


def compress_python(msg_words: List[int], rounds: int) -> List[int]:
    """One-block reduced-round compression from the standard SHA-256 IV."""
    return compress_python_block(list(IV), msg_words, rounds)


def message_words(n_free_blocks: int) -> List[Optional[int]]:
    """Message-schedule input: ``n_free_blocks`` free 64-byte blocks.

    ``None`` marks a solver-chosen word, an int a fixed word.

    The block is RAW -- no padding. That matches the framework's reduced-round
    semantics: IndependentVerifier::verify_preimage_candidate requires an exact
    64-byte block for rounds < 64 and runs independent_compress_block on it
    directly, without appending the 0x80/length tail (see
    src/verifier/verifier.cpp). Padding is applied only on the full 64-round
    path, so modelling a padded block here would target a different problem
    from the one the 19/20-round witnesses describe.
    """
    if not 1 <= n_free_blocks <= 64:
        raise ValueError("n_free_blocks must be in [1, 64]")
    return [None] * (16 * n_free_blocks)


def solve_with_z3(rounds: int, target: List[int], timeout_ms: int,
                  n_free_blocks: int):
    """Ask Z3 for a block whose reduced-round digest equals `target`."""
    s = z3.Solver()
    s.set("timeout", timeout_ms)

    schedule = []
    free_vars = []
    for i, fixed in enumerate(message_words(n_free_blocks)):
        if fixed is None:
            var = z3.BitVec(f"w{i}", 32)
            schedule.append(var)
            free_vars.append(var)
        else:
            schedule.append(z3.BitVecVal(fixed, 32))

    wl = list(schedule)
    for t in range(len(schedule), max(rounds, 1)):
        x15 = wl[t - 15]
        x2 = wl[t - 2]
        s0 = z3.LShR(x15, 3) ^ z3.RotateLeft(x15, 25) ^ z3.RotateLeft(x15, 14)
        s1 = z3.LShR(x2, 10) ^ z3.RotateLeft(x2, 15) ^ z3.RotateLeft(x2, 13)
        wl.append(wl[t - 16] + s0 + wl[t - 7] + s1)

    a, b, c, d, e, f, g, h = (z3.BitVecVal(v, 32) for v in IV)
    for t in range(rounds):
        # sigma1(e) = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
        #           = rotl(e,26) ^ rotl(e,21) ^ rotl(e,7)
        s1 = z3.RotateLeft(e, 26) ^ z3.RotateLeft(e, 21) ^ z3.RotateLeft(e, 7)
        ch = (e & f) ^ ((~e) & g)
        t1 = h + s1 + ch + wl[t] + z3.BitVecVal(K[t], 32)
        # sigma0(a) = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
        #           = rotl(a,30) ^ rotl(a,19) ^ rotl(a,10)
        s0 = z3.RotateLeft(a, 30) ^ z3.RotateLeft(a, 19) ^ z3.RotateLeft(a, 10)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = s0 + maj
        a, b, c, d, e, f, g, h = (t1 + t2, a, b, c, d + t1, e, f, g)

    iv = [z3.BitVecVal(v, 32) for v in IV]
    out = [a + iv[0], b + iv[1], c + iv[2], d + iv[3],
           e + iv[4], f + iv[5], g + iv[6], h + iv[7]]
    for i, want in enumerate(target):
        s.add(out[i] == z3.BitVecVal(want, 32))

    res = s.check()
    if res == z3.sat:
        m = s.model()
        vals = [m.evaluate(x, model_completion=True).as_long() for x in free_vars]
        return "sat", vals
    if res == z3.unsat:
        return "unsat", None
    return "unknown", None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--blocks", type=int, default=1,
                    help="number of free 64-byte message blocks")
    ap.add_argument("--timeout", type=int, default=300,
                    help="Z3 timeout in seconds")
    args = ap.parse_args()

    if z3 is None:
        print("ERROR: the z3 python package is not installed "
              "(pip install z3-solver).", file=sys.stderr)
        return 2
    if not 1 <= args.rounds <= 64:
        print("ERROR: rounds must be in [1, 64].", file=sys.stderr)
        return 2

    print(f"Z3 bit-vector cross-check, {args.rounds} rounds, "
          f"{args.blocks} free block(s), timeout {args.timeout}s")
    print(f"Z3 version: {z3.get_version_string()}")
    print()

    seed = [0] * (16 * args.blocks)
    tag = b"TEST1234"
    for i, ch in enumerate(tag):
        seed[i // 4] |= ch << (24 - 8 * (i % 4))
    target = compress_python(seed, args.rounds)
    target_hex = "".join(f"{v:08x}" for v in target)
    print(f"  target digest: {target_hex}")

    t0 = time.perf_counter()
    status, vals = solve_with_z3(args.rounds, target, args.timeout * 1000,
                                 args.blocks)
    elapsed = time.perf_counter() - t0

    if status == "unknown":
        print(f"  Z3 returned UNKNOWN after {elapsed:.1f}s -- no verdict.")
        print("  Not a proof of satisfiability or unsatisfiability.")
        return 1
    if status == "unsat":
        print(f"  Z3 proved UNSAT in {elapsed:.1f}s.")
        print("  A proof of nonexistence here would be a genuine finding.")
        return 0

    print(f"  Z3 returned SAT in {elapsed:.1f}s")
    print(f"  free words = {' '.join(f'{v:08x}' for v in vals)}")

    # Gate 2: an independent Python implementation of the compression function.
    recomputed = compress_python(vals, args.rounds)
    if recomputed != target:
        print("  independent Python recomputation: MISMATCH")
        print(f"    computed {''.join(f'{v:08x}' for v in recomputed)}")
        print(f"    expected {target_hex}")
        return 2
    print("  independent Python recomputation: MATCH")

    # Gate 3: the framework's segregated C++ verifier.
    from tools.verify_published import locate_verifier, run_verifier
    exe = locate_verifier()
    if exe is None:
        print("  sha-verifier not built; skipped the segregated cross-check.")
        return 0
    if args.blocks != 1:
        print("  sha-verifier requires exactly one 64-byte block for reduced "
              "rounds; skipped the segregated cross-check.")
        return 0

    msg_hex = "".join(f"{v:08x}" for v in vals)
    verdict = run_verifier(exe, msg_hex, target_hex, args.rounds)
    print(f"  sha-verifier: is_valid={verdict['is_valid']} "
          f"classification={verdict['classification']} "
          f"engine={verdict['verifier_engine']}")
    if not verdict["is_valid"]:
        print("    the three engines disagree; do not trust this result.")
        return 2

    # Gate 4: the same block must NOT verify at a neighbouring round count.
    control = run_verifier(exe, msg_hex, target_hex, args.rounds - 1)
    print(f"  negative control @{args.rounds - 1} rounds: "
          f"is_valid={control['is_valid']} "
          f"(hamming {control['hamming_distance']})")
    return 0 if not control["is_valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())