"""
Cross-engine agreement tests for the Z3 bit-vector solver core.

The value of a second, independent solver core is that it can disagree with
the primary CDGL pipeline. These tests assert the two agree on results that
are cheap enough to run in CI, and that the tool reports UNKNOWN honestly
rather than claiming a verdict it did not reach.

Tests that need a large round count are skipped: Z3 bit-vector is roughly an
order of magnitude weaker than the native CDCL path (see
docs/research/advanced-strategies.md), so its ceiling is around 7 rounds.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import z3  # noqa: F401
    HAVE_Z3 = True
except ImportError:
    HAVE_Z3 = False

from tools.verify_published import locate_verifier  # noqa: E402

HAVE_VERIFIER = locate_verifier() is not None


def run_tool(rounds: int, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "z3_bitvector_check.py"),
         "--rounds", str(rounds), "--timeout", str(timeout)],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=timeout + 120,
    )


class TestZ3ToolContract(unittest.TestCase):
    """Behaviour that must hold whether or not Z3 is installed."""

    def test_reports_missing_z3_instead_of_crashing(self):
        """With z3 unimportable the tool must fail cleanly, not traceback."""
        import tempfile
        with tempfile.TemporaryDirectory() as shadow:
            # A module named `z3` that cannot be imported stands in for z3
            # not being installed.
            (Path(shadow) / "z3.py").write_text(
                "raise ImportError('simulated missing z3')\n", encoding="utf-8")
            env = dict(os.environ, PYTHONPATH=shadow + os.pathsep +
                       str(REPO_ROOT))
            proc = subprocess.run(
                [sys.executable,
                 str(REPO_ROOT / "tools" / "z3_bitvector_check.py"),
                 "--rounds", "4"],
                capture_output=True, text=True, cwd=str(REPO_ROOT),
                env=env, timeout=120)

        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback", combined)
        self.assertIn("z3", combined.lower())
        self.assertEqual(proc.returncode, 2)

    def test_rejects_out_of_range_rounds(self):
        proc = run_tool(0, timeout=10)
        self.assertNotEqual(proc.returncode, 0)

    def test_usage_help(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "z3_bitvector_check.py"),
             "--help"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--rounds", proc.stdout)


@unittest.skipUnless(HAVE_Z3, "z3-solver not installed")
class TestZ3Agreement(unittest.TestCase):
    """Where both engines can run, they must reach the same conclusion."""

    @unittest.skipUnless(HAVE_VERIFIER, "sha-verifier binary not built")
    def test_small_round_solve_agrees_across_four_gates(self):
        proc = run_tool(4, timeout=120)
        out = proc.stdout
        self.assertIn("Z3 returned SAT", out, out + proc.stderr)
        self.assertIn("independent Python recomputation: MATCH", out)
        self.assertIn("sha-verifier: is_valid=True", out)
        self.assertIn("negative control", out)
        self.assertEqual(proc.returncode, 0, out)

    def test_unknown_is_reported_as_unknown(self):
        """A timeout must not be dressed up as a result."""
        proc = run_tool(8, timeout=30)
        out = proc.stdout
        if "UNKNOWN" in out:
            self.assertNotIn("recomputation", out)
            self.assertNotIn("sha-verifier:", out)
            self.assertEqual(proc.returncode, 1)


@unittest.skipUnless(HAVE_Z3, "z3-solver not installed")
class TestZ3Constants(unittest.TestCase):
    """The Z3 encoding must use the same constants as everything else."""

    def test_uses_framework_k_table(self):
        import re
        from tools import z3_bitvector_check as z3c
        src = (REPO_ROOT / "include" / "sha256_research" /
               "core" / "types.hpp").read_text(encoding="utf-8")
        m = re.search(r"0x428a2f98U.*?\}", src, re.S)
        framework = [int(x, 16)
                     for x in re.findall(r"0x([0-9a-fA-F]{8})U", m.group(0))]
        self.assertEqual(list(z3c.K), framework)

    def test_message_is_a_raw_64_byte_block(self):
        """Reduced rounds operate on a raw block; the verifier requires 64 bytes."""
        from tools import z3_bitvector_check as z3c
        words = z3c.message_words(1)
        self.assertEqual(len(words), 16)
        self.assertTrue(all(w is None for w in words))


if __name__ == "__main__":
    unittest.main(verbosity=2)