"""
Context-shaping preimage search: correctness and safety tests.

The submask family (Basra 2026) reaches 19 rounds by working backwards from
the target, which the direct SAT encoding in this framework cannot do at all.
These tests pin three things:

  1. the algebraic identities of the construction,
  2. that a freshly produced 19-round witness is accepted by the framework's
     segregated IndependentVerifier and rejected at a neighbouring round,
  3. that the tool cannot be made to exhaust memory by a bad option.

Point 3 is not hypothetical: an earlier revision parsed its numeric options
in hex, so `--bits 28` became 40 and the tool tried to allocate a 17 GiB
table on a machine with 11 GiB free.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verify_published import locate_verifier, run_verifier  # noqa: E402


def _tool() -> Path | None:
    for name in ("context_shaping.exe", "context_shaping"):
        for base in ("Release", "."):
            p = REPO_ROOT / "build" / base / name
            if p.is_file():
                return p
    return None


TOOL = _tool()
VERIFIER = locate_verifier()

ALL_ONES = "f" * 64


class TestUnavailable(unittest.TestCase):
    def test_tool_is_built(self):
        self.assertIsNotNone(TOOL, "context_shaping binary not built")


@unittest.skipUnless(TOOL, "context_shaping binary not built")
class TestSelfTest(unittest.TestCase):
    """Every algebraic identity of the construction, on planted states."""

    def test_selftest_reports_no_failures(self):
        proc = subprocess.run([str(TOOL), "selftest"], capture_output=True,
                              text=True, cwd=str(REPO_ROOT), timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("FAILED", proc.stdout)

    def test_selftest_covers_the_expected_identities(self):
        proc = subprocess.run([str(TOOL), "selftest"], capture_output=True,
                              text=True, cwd=str(REPO_ROOT), timeout=300)
        for expected in ["backward chain", "message-word recovery",
                         "family conditions", "A_0 residual", "A_2 identity"]:
            self.assertIn(expected, proc.stdout)


@unittest.skipUnless(TOOL, "context_shaping binary not built")
class TestOptionSafety(unittest.TestCase):
    """A bad option must never be able to take the machine down."""

    def _run(self, args, timeout=600):
        return subprocess.run([str(TOOL)] + args, capture_output=True,
                              text=True, cwd=str(REPO_ROOT), timeout=timeout)

    def test_options_are_parsed_as_decimal_not_hex(self):
        """--bits 28 must mean 28. Reading it as hex gave 40 and a 17 GiB
        allocation that crashed the machine."""
        proc = self._run(["search", ALL_ONES, "--bits", "28",
                          "--contexts", "1", "--sweep", "1"])
        self.assertNotIn("0x1c", proc.stdout)   # 40 == 0x28
        self.assertRegex(proc.stdout, r"table: 2\^28 entries")

    def test_oversized_width_is_clamped_not_allocated(self):
        proc = self._run(["search", ALL_ONES, "--bits", "32",
                          "--contexts", "1", "--sweep", "1"])
        # Return code 1 means "searched, found nothing", which is expected with
        # a one-step sweep. What matters is that the width was clamped instead
        # of allocated, and that the tool still ran to completion.
        self.assertIn(proc.returncode, (0, 1), proc.stderr)
        self.assertIn("clamping", proc.stderr)
        self.assertIn("16.00 GiB", proc.stderr)
        self.assertNotIn("bad_alloc", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_out_of_range_width_is_rejected(self):
        proc = self._run(["search", ALL_ONES, "--bits", "40",
                          "--contexts", "1", "--sweep", "1"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("at most 32", proc.stderr)

    def test_non_numeric_option_is_rejected(self):
        proc = self._run(["search", ALL_ONES, "--bits", "wide",
                          "--contexts", "1", "--sweep", "1"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("decimal", proc.stderr)


@unittest.skipUnless(TOOL and VERIFIER, "context_shaping or verifier not built")
class TestNineteenRoundPreimage(unittest.TestCase):
    """Produce a real 19-round preimage and have the segregated verifier
    adjudicate it."""

    @classmethod
    def setUpClass(cls):
        cls.block = None
        out = REPO_ROOT / "reports" / "context_shaping_witness.txt"
        env = dict(os.environ, CS_OUT_BLOCK=str(out))
        cls.proc = subprocess.run(
            [str(TOOL), "search", ALL_ONES, "--bits", "30",
             "--contexts", "8", "--sweep", "3000000"],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
            env=env, timeout=3600)
        if out.is_file():
            text = out.read_text().strip()
            if len(text) == 128:
                cls.block = text

    def test_search_reports_a_preimage(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stdout[-2000:])
        self.assertIn("VERIFIED: yes", self.proc.stdout)

    def test_search_constraints_all_hold(self):
        self.assertIn("C0=ok C1=ok C2=ok", self.proc.stdout)
        self.assertNotIn("FAIL", self.proc.stdout)

    def test_witness_is_128_hex_characters(self):
        self.assertIsNotNone(self.block)
        self.assertEqual(len(self.block), 128)
        int(self.block, 16)

    def test_segregated_verifier_accepts_the_witness(self):
        verdict = run_verifier(VERIFIER, self.block, ALL_ONES, 19)
        self.assertTrue(verdict["is_valid"], verdict.get("failure_reason"))
        self.assertEqual(verdict["classification"], "ReducedRoundPreimage")
        self.assertEqual(verdict["hamming_distance"], 0)
        self.assertEqual(verdict["verifier_engine"], "IndependentVerifier")
        self.assertTrue(verdict["engine_segregated"])

    def test_neighbouring_round_counts_are_rejected(self):
        for rounds in (18, 20):
            with self.subTest(rounds=rounds):
                verdict = run_verifier(VERIFIER, self.block, ALL_ONES, rounds)
                self.assertFalse(verdict["is_valid"])
                self.assertGreater(verdict["hamming_distance"], 0)

    def test_block_is_deterministic_for_a_fixed_seed(self):
        """Same seed, same witness: the search must be reproducible.

        Only the search result is compared. Table-build and sweep timings are
        wall-clock measurements and legitimately vary between runs, so
        including them would make the test flaky rather than strict.
        """
        def result_of(stdout):
            keep = []
            for line in stdout.splitlines():
                if "table:" in line:
                    line = line.split(", density")[0]
                if " in " in line and ("swept" in line or "values" in line):
                    line = line.split(",")[0] + " <elapsed omitted>"
                keep.append(line)
            return "\n".join(keep)

        args = [str(TOOL), "search", ALL_ONES, "--bits", "28",
                "--contexts", "2", "--sweep", "500000", "--seed", "7"]
        a = subprocess.run(args, capture_output=True, text=True,
                           cwd=str(REPO_ROOT), timeout=1800)
        b = subprocess.run(args, capture_output=True, text=True,
                           cwd=str(REPO_ROOT), timeout=1800)
        self.assertEqual(result_of(a.stdout), result_of(b.stdout))


if __name__ == "__main__":
    unittest.main(verbosity=2)