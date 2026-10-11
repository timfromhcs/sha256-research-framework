#!/usr/bin/env python3
"""
Verify published reduced-round SHA-256 preimage witnesses with this framework's
own independent verifier.

Why this exists
---------------
This framework cannot *solve* 19- or 20-round preimages on commodity
hardware (see `reports/preimage_strategies.md`). It can, however, *verify*
them, and that is a meaningful capability to demonstrate for two reasons:

1. **External validation of the verifier.** The witnesses below were produced
   by other researchers. Confirming them with `sha-verifier` — an engine that
   shares no code with the `Sha256Scalar` research path — is an independent
   check that this framework's verification machinery is correct.

2. **External validation of the published record.** If a segregated engine
   confirms the witnesses, the published 19/20-round results stand.

Every witness is checked together with a **negative control**: the same message
must be *rejected* at a different round count. Without that, a verifier that
accepted everything would also "pass".

Sources
-------
  Basra, K. S. (2026), "Practical preimages of the 19- and 20-round SHA-256
  compression function", github.com/kamb-code/sha256-r19-preimage.
  Witness P7 uses the all-ones target, which is also the target used by
  Zaikin (Constraints, 2026) for its 19-round inversion.

Usage
-----
    python tools/verify_published.py
    python tools/verify_published.py --json
Exit code 0 means every witness verified and every negative control was
correctly rejected.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# (label, rounds, target digest, W[0..15] as 16 hex words)
WITNESSES: List[Tuple[str, int, str, str]] = [
    (
        "P1", 19,
        "1e65261c54255188604f5375091839733de63e966b5e4715658226bf03588447",
        "22f091af ec52d67b 74c33819 a280dc6a "
        "b001ff1a 1f2356a5 3eccf108 bd9a2333 "
        "abe611d1 6d1e5a20 8041df25 e43d31af "
        "aa895a2e 69106ad2 7479fa3a 2a9abb91",
    ),
    (
        "P2", 19,
        "fb52f81baed24f8728faf5bbce82c67d510761172fb9876d9e3a72dda351b7ca",
        "37e6702f bc20efea 2dd42a3e 501dfbe9 "
        "3cacc578 ea2de1c1 11c0f066 0f22be47 "
        "2a447d2d 13f0080f 1f33df6b d655d8e6 "
        "15730eaa 9bf64950 9f129973 5a964edf",
    ),
    (
        "P3", 19,
        "1bd7ebbdc4d938fb26d19b5dd5caf333de397bd1c745727bd5556baf38ccf977",
        "3ce8fba4 e2fb9661 44730c59 e1cf4bc0 "
        "e1a18d93 97658983 67efe2a7 ef260ecb "
        "d4c6dbe0 13e9388e 95664a59 4d9e248b "
        "74137862 664815ac 89eae95a cd7dbef5",
    ),
    (
        "P4", 19,
        "c55aecafd68ac4f559bb2b940688f3bc1dabe3ff86a7d03447e8b11a637d7506",
        "3694ee67 a1d020b9 47f08ea3 dc873e2b "
        "1f41c8b1 39018970 d3a2afb2 23f6e6cf "
        "80c46545 f7b2b46c 2e44f333 2effe68b "
        "06d80cdf 8525e7d7 7ef008e5 13e56087",
    ),
    (
        "P5", 19,
        "a8241289b5980304e9dfd401b1370200ab32b5e8cfaff26c26aabcfc8be89df4",
        "3e0a7d67 df0944a3 4bfe156b bd344ac5 "
        "7b7d9587 8984e286 21c995d9 d8e53cdd "
        "0a0be79d e02dda1a e17e0f4a e3ff692b "
        "8c782631 97dc4811 5ed68656 dfce314f",
    ),
    (
        "P6", 19,
        "09156002031fed2899bc67d0e419b6ff81b9a0dd4e3fa417e000817adb85b143",
        "164084a5 f97bd8bd bff47431 a8e55b29 "
        "948d1160 10eb8f7d d0ea565e 7918b8b9 "
        "87527a3a 6baa5685 a1fbc5dc 7548adfc "
        "be3fb206 b9738756 b4ca33e3 b8354a95",
    ),
    (
        "P7 (Zaikin all-ones target)", 19,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "3c6ff45c a5b23f8d dc6b8089 4f232935 "
        "79578e14 9c2da339 b22ec37a 9554191b "
        "e69661f0 49a43b7a d8c60a2b 88d7588c "
        "6225084d 87c95c4e 23ee573d 8d8fedfa",
    ),
    (
        "R20 (all-ones target)", 20,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0b0187bf b9aea692 b66effa5 087dca3a "
        "0caea827 1d2f9916 739a224e a87c0eae "
        "7f9ef4a7 b318a7de a8848c61 a7a141a4 "
        "11ac114b 952299be 97aaa67f c6acfe57",
    ),
]


def locate_verifier() -> Optional[Path]:
    """Resolve the segregated verifier binary.

    An explicit ``SHA_VERIFIER_BIN`` override is authoritative: if it is set but
    does not point at a file, that is an error rather than a reason to silently
    fall back to a different engine. For a trust boundary, "you asked for a
    specific verifier and it is not there" must never degrade into "I found
    some other binary instead".
    """
    override = os.environ.get("SHA_VERIFIER_BIN")
    if override:
        p = Path(override)
        return p if p.is_file() else None
    for cand in (
        REPO_ROOT / "build" / "Release" / "sha-verifier.exe",
        REPO_ROOT / "build" / "sha-verifier.exe",
        REPO_ROOT / "build-cpu" / "Release" / "sha-verifier.exe",
        REPO_ROOT / "build-cpu" / "sha-verifier.exe",
    ):
        if cand.is_file():
            return cand
    return None


def run_verifier(exe: Path, message_hex: str, target: str, rounds: int) -> Dict:
    """Invoke the segregated verifier and return its parsed verdict."""
    proc = subprocess.run(
        [str(exe), "verify-preimage", message_hex, target, str(rounds), "--json"],
        capture_output=True, text=True, timeout=60,
    )
    raw = (proc.stdout or "").strip()
    if not raw:
        raise RuntimeError(f"verifier produced no output (exit {proc.returncode})")
    verdict = json.loads(raw.splitlines()[-1])
    # The verdict must agree with the process exit code, otherwise we are not
    # talking to the verifier we think we are.
    if bool(verdict.get("is_valid")) != (proc.returncode == 0):
        raise RuntimeError(
            f"verifier self-inconsistent: exit={proc.returncode} "
            f"is_valid={verdict.get('is_valid')}")
    if verdict.get("verifier_engine") != "IndependentVerifier":
        raise RuntimeError("verdict did not come from the segregated engine")
    return verdict


def check_witness(exe: Path, label: str, rounds: int, target: str,
                  words: str) -> Dict:
    message_hex = "".join(words.split())
    if len(message_hex) != 128:
        raise ValueError(f"{label}: expected 16 words, got {len(message_hex)//8}")

    positive = run_verifier(exe, message_hex, target, rounds)
    # Negative control: off-by-one round count must be rejected.
    control_rounds = rounds - 1 if rounds > 1 else rounds + 1
    negative = run_verifier(exe, message_hex, target, control_rounds)

    return {
        "label": label,
        "rounds": rounds,
        "target": target,
        "verified": bool(positive.get("is_valid")),
        "classification": positive.get("classification"),
        "hamming_distance": positive.get("hamming_distance"),
        "verified_by": positive.get("verifier_engine"),
        "engine_segregated": bool(positive.get("engine_segregated")),
        "control_rounds": control_rounds,
        "control_rejected": not bool(negative.get("is_valid")),
        "control_reason": negative.get("failure_reason", "")[:90],
        "pass": bool(positive.get("is_valid")) and not bool(negative.get("is_valid")),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = ap.parse_args()

    exe = locate_verifier()
    if exe is None:
        print("ERROR: sha-verifier binary not found. Build the project first.",
              file=sys.stderr)
        return 2

    if not args.json:
        print("=" * 70)
        print("  EXTERNAL WITNESS VERIFICATION")
        print("  Published reduced-round SHA-256 preimages, checked by this")
        print("  framework's segregated IndependentVerifier engine.")
        print("=" * 70)
        print()
        print("  Each witness is confirmed at its stated round count and must be")
        print("  REJECTED at a neighbouring round count (negative control).")
        print()

    results = []
    failures = 0
    for label, rounds, target, words in WITNESSES:
        try:
            r = check_witness(exe, label, rounds, target, words)
        except Exception as e:
            r = {"label": label, "rounds": rounds, "pass": False,
                 "error": str(e)}
        results.append(r)
        if not r.get("pass"):
            failures += 1
        if not args.json:
            if "error" in r:
                print(f"  {label:<30} ERROR: {r['error']}")
            else:
                status = "OK  " if r["pass"] else "FAIL"
                print(f"  {label:<30} {status} "
                      f"{r['rounds']}-round preimage verified, "
                      f"control@{r['control_rounds']} rejected "
                      f"(hamming {r['hamming_distance']})")

    deepest = max((r.get("rounds", 0) for r in results if r.get("verified")), default=0)
    summary = {
        "verifier": str(exe),
        "engine_segregated": all(r.get("engine_segregated", False) for r in results
                                 if "error" not in r),
        "witnesses_checked": len(results),
        "witnesses_passed": len(results) - failures,
        "deepest_verified_rounds": deepest,
        "all_passed": failures == 0,
        "results": results,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print()
        print("=" * 70)
        print(f"  {summary['witnesses_passed']}/{summary['witnesses_checked']} "
              f"published witnesses verified")
        print(f"  Deepest externally published preimage confirmed: "
              f"{deepest} rounds")
        print(f"  Segregated engine: {summary['engine_segregated']}")
        print("=" * 70)
        if failures:
            print(f"\n  {failures} witness(es) FAILED. This framework does not "
                  f"corroborate the published record.", file=sys.stderr)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())