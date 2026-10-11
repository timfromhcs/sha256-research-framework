"""
External witness verification.

The framework cannot *solve* 19- or 20-round preimages on commodity hardware,
but it can *verify* them. These tests confirm that its segregated verifier
correctly validates published results, with negative controls so that a
verifier which accepted everything would still fail.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

sys.path.insert(0, str(REPO_ROOT / "tools"))

from tools.verify_published import (  # noqa: E402
    WITNESSES, locate_verifier, run_verifier, check_witness,
)


def _verifier_available() -> bool:
    return locate_verifier() is not None


VERIFIER_AVAILABLE = _verifier_available()


@unittest.skipUnless(VERIFIER_AVAILABLE, "sha-verifier binary not built")
class TestExternalWitnesses(unittest.TestCase):
    """Published reduced-round preimages must verify; neighbours must not."""

    def test_all_published_witnesses_verify_with_negative_controls(self):
        exe = locate_verifier()
        failures = []
        for label, rounds, target, words in WITNESSES:
            r = check_witness(exe, label, rounds, target, words)
            if not r["pass"]:
                failures.append(f"{label}: {r}")
        self.assertEqual(
            failures, [],
            "published witnesses must verify at their stated round count and be "
            "rejected at a neighbouring round count",
        )

    def test_deepest_confirmed_witness_is_twenty_rounds(self):
        exe = locate_verifier()
        confirmed = []
        for label, rounds, target, words in WITNESSES:
            r = check_witness(exe, label, rounds, target, words)
            if r["verified"]:
                confirmed.append(r["rounds"])
        self.assertGreaterEqual(
            max(confirmed), 20,
            "the framework's verifier must corroborate the published "
            "20-round preimage",
        )

    def test_witnesses_are_rejected_at_the_wrong_round_count(self):
        """A permissive verifier would fail here."""
        exe = locate_verifier()
        for label, rounds, target, words in WITNESSES:
            message_hex = "".join(words.split())
            wrong = run_verifier(exe, message_hex, target, rounds - 1)
            self.assertFalse(
                wrong["is_valid"],
                f"{label}: a {rounds}-round witness must not verify at "
                f"{rounds - 1} rounds",
            )
            self.assertGreater(
                wrong["hamming_distance"], 0,
                f"{label}: wrong-round rejection should show a non-zero "
                f"Hamming distance",
            )

    def test_verdicts_come_from_the_segregated_engine(self):
        exe = locate_verifier()
        label, rounds, target, words = WITNESSES[0]
        verdict = run_verifier(exe, "".join(words.split()), target, rounds)
        self.assertEqual(verdict["verifier_engine"], "IndependentVerifier")
        self.assertTrue(verdict["engine_segregated"])

    def test_tampered_witness_is_rejected(self):
        """Flip one bit of a known-good witness; it must stop verifying."""
        exe = locate_verifier()
        label, rounds, target, words = WITNESSES[0]
        message_hex = "".join(words.split())
        # Flip the top bit of the first byte.
        first_byte = int(message_hex[0:2], 16) ^ 0x80
        tampered = f"{first_byte:02x}{message_hex[2:]}"

        original = run_verifier(exe, message_hex, target, rounds)
        self.assertTrue(original["is_valid"], "precondition: witness is valid")

        broken = run_verifier(exe, tampered, target, rounds)
        self.assertFalse(
            broken["is_valid"],
            "a one-bit tampered witness must be rejected",
        )
        self.assertEqual(broken["classification"], "Invalid")


class TestToolContract(unittest.TestCase):
    """The tool must fail loudly rather than silently reporting success."""

    def test_witness_table_is_well_formed(self):
        self.assertGreaterEqual(len(WITNESSES), 8)
        for label, rounds, target, words in WITNESSES:
            with self.subTest(label=label):
                self.assertIn(rounds, (19, 20))
                self.assertEqual(len(target), 64)
                self.assertEqual(len(words.split()), 16)
                for word in words.split():
                    self.assertEqual(len(word), 8)
                    int(word, 16)  # must parse

    def test_tool_reports_failure_when_binary_missing(self):
        original = os.environ.get("SHA_VERIFIER_BIN")
        os.environ["SHA_VERIFIER_BIN"] = str(REPO_ROOT / "no-such-verifier.exe")
        try:
            self.assertIsNone(locate_verifier())
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "tools" / "verify_published.py")],
                capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120,
            )
            self.assertNotEqual(proc.returncode, 0,
                                "missing verifier must not report success")
        finally:
            if original is None:
                os.environ.pop("SHA_VERIFIER_BIN", None)
            else:
                os.environ["SHA_VERIFIER_BIN"] = original

    @unittest.skipUnless(VERIFIER_AVAILABLE, "sha-verifier binary not built")
    def test_tool_exit_code_is_zero_on_success(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_published.py")],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])


if __name__ == "__main__":
    unittest.main(verbosity=2)