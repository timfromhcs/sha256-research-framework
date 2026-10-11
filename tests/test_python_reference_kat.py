"""
Known-answer tests for the independent Python SHA-256 reference.

tools/z3_bitvector_check.py carries its own implementation of the compression
function so that a Z3 model is checked against something that shares no code
with the C++ encoder. That independence is only worth anything if the Python
is actually correct -- an independent *wrong* reference would either mask real
bugs or, worse, make correct results look broken.

This module pins the Python reference against:
  1. the NIST/RFC 6234 SHA-256 known-answer vectors, and
  2. the framework's own authoritative K/IV tables.

A single transposed digit in the round constants is invisible to inspection but
silently corrupts every digest, so it gets an explicit regression test.
"""

import hashlib
import os
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import z3_bitvector_check as z3c  # noqa: E402

MASK32 = 0xFFFFFFFF


def _pad(message: bytes):
    """Standard SHA-256 padding: 0x80, zeros, 64-bit big-endian bit length."""
    bit_len = len(message) * 8
    padded = message + b"\x80"
    padded += b"\x00" * ((55 - len(message)) % 64)
    padded += bit_len.to_bytes(8, "big")
    return [int.from_bytes(padded[i:i + 4], "big")
            for i in range(0, len(padded), 4)]


def sha256_python(message: bytes) -> bytes:
    """Full 64-round SHA-256 using the module's round function."""
    words = _pad(message)
    state = list(z3c.IV)
    for i in range(0, len(words), 16):
        state = z3c.compress_python_block(state, words[i:i + 16], 64)
    return b"".join(s.to_bytes(4, "big") for s in state)


class TestPythonReferenceKAT(unittest.TestCase):
    """The Python reference must reproduce the standard SHA-256 exactly."""

    def test_nist_known_answers(self):
        vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039"
             "a33ce45964ff2167f6ecedd419db06c1"),
            (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
             b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
             "cf5b16a778af8380036ce59e7b049237"
             "0b249b11e8f07a51afac45037afee9d1"),
        ]
        for msg, expect in vectors:
            with self.subTest(length=len(msg)):
                self.assertEqual(sha256_python(msg).hex(), expect)

    def test_matches_hashlib_across_padding_boundaries(self):
        """Block-count boundaries are where padding logic breaks."""
        import random
        rng = random.Random(20260911)
        lengths = [0, 1, 2, 54, 55, 56, 57, 63, 64, 65,
                   111, 112, 119, 120, 127, 128, 129, 200, 1000]
        for n in lengths:
            msg = bytes(rng.randrange(256) for _ in range(n))
            with self.subTest(length=n):
                self.assertEqual(sha256_python(msg).hex(),
                                 hashlib.sha256(msg).hexdigest())

    def test_million_a_vector(self):
        self.assertEqual(
            sha256_python(b"a" * 1_000_000).hex(),
            hashlib.sha256(b"a" * 1_000_000).hexdigest(),
        )


class TestConstantsMatchFramework(unittest.TestCase):
    """The Python tables must agree with the framework's authoritative ones."""

    @staticmethod
    def _framework_table(first: str):
        src = (REPO_ROOT / "include" / "sha256_research" /
               "core" / "types.hpp").read_text(encoding="utf-8")
        m = re.search(re.escape(first) + r".*?\}", src, re.S)
        if m is None:
            raise unittest.SkipTest("framework constant table not found")
        return [int(x, 16)
                for x in re.findall(r"0x([0-9a-fA-F]{8})U", m.group(0))]

    def test_round_constants_match(self):
        self.assertEqual(len(z3c.K), 64)
        self.assertEqual(list(z3c.K), self._framework_table("0x428a2f98U"))

    def test_initial_state_matches(self):
        self.assertEqual(list(z3c.IV), self._framework_table("0x6a09e667U"))

    def test_k2_is_not_the_transposed_value(self):
        """Regression: K[2] was once 0xb5c0fbbc instead of 0xb5c0fbcf.

        The error is invisible to a reader and produced plausible-looking
        output, so it is pinned explicitly.
        """
        self.assertEqual(z3c.K[2], 0xB5C0FBCF)


class TestPublishedWitnessesReproduce(unittest.TestCase):
    """The Python reference must reproduce externally published witnesses.

    These targets were produced by other researchers and confirmed by the
    framework's segregated C++ verifier, so agreement here is a strong,
    genuinely external check on the Python path.
    """

    def test_all_published_witnesses(self):
        from tools.verify_published import WITNESSES
        for label, rounds, target, words in WITNESSES:
            with self.subTest(label=label):
                got = z3c.compress_python([int(w, 16) for w in words.split()],
                                          rounds)
                self.assertEqual("".join(f"{v:08x}" for v in got), target)


if __name__ == "__main__":
    unittest.main(verbosity=2)