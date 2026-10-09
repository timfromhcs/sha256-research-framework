"""
Tests for the hybrid decision plane.

The scheduler is the only path to an L3 result, so its rules are tested
directly and adversarially:

  * a proposal outside the envelope is rejected before execution
  * an LLM proposal can never be verified, only executed then verified
  * a solver/model-extraction disagreement is flagged as a BUG
  * a timeout escalates the budget instead of being called a wall
  * escalation tracks measured depth, not model optimism
"""

import os
import sys
import json
import time
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sha256_research_platform.storage.db import DatabaseManager
from sha256_research_platform.evidence.store import EvidenceStore
from sha256_research_platform.workers.worker import (
    VerifierBridge, BinaryResolution, VerificationUnavailable,
)
from sha256_research_platform.agent.proposals import (
    CandidateEncoding, ProposalValidationError, ProposalPlane,
    parse_proposal, propose_deterministic, ALLOWED_SOLVERS,
)
from sha256_research_platform.agent.scheduler import (
    DeterministicScheduler, StepOutcome,
)
from sha256_research_platform.agent.trust import (
    EpistemicTrustManager, EpistemicIntegrityError,
)


def _binaries_available():
    return (
        BinaryResolution.locate() is not None
        and VerifierBridge().locate() is not None
    )


BINARIES_AVAILABLE = _binaries_available()


class TestProposalEnvelope(unittest.TestCase):
    """The proposal envelope is the LLM's blast radius. It must be small."""

    def test_anti_clamping_on_rounds(self):
        for bad in (0, -1, 65, 1000):
            with self.assertRaises(ProposalValidationError):
                CandidateEncoding(
                    rounds=bad, solver="cadical", encoding="tseitin",
                    carry_save=False, timeout=60,
                ).validate()

    def test_solver_allowlist(self):
        for bad in ("rm", "sh -c 'echo pwned'", "cadical; whoami", "", "CADICAL "):
            with self.assertRaises(ProposalValidationError):
                CandidateEncoding(
                    rounds=8, solver=bad, encoding="tseitin",
                    carry_save=False, timeout=60,
                ).validate()

    def test_encoding_allowlist(self):
        with self.assertRaises(ProposalValidationError):
            CandidateEncoding(
                rounds=8, solver="cadical", encoding="raw_magic",
                carry_save=False, timeout=60,
            ).validate()

    def test_xor_requires_xor_capable_solver(self):
        with self.assertRaises(ProposalValidationError):
            CandidateEncoding(
                rounds=8, solver="cadical", encoding="xor",
                carry_save=False, timeout=60,
            ).validate()
        # The correct pairing is accepted.
        CandidateEncoding(
            rounds=8, solver="cryptominisat", encoding="xor",
            carry_save=False, timeout=60,
        ).validate()

    def test_timeout_bounds(self):
        for bad in (0, -5, 3601, 10**9):
            with self.assertRaises(ProposalValidationError):
                CandidateEncoding(
                    rounds=8, solver="cadical", encoding="tseitin",
                    carry_save=False, timeout=bad,
                ).validate()

    def test_bool_is_not_an_int(self):
        with self.assertRaises(ProposalValidationError):
            CandidateEncoding(
                rounds=True, solver="cadical", encoding="tseitin",
                carry_save=False, timeout=60,
            ).validate()

    def test_every_proposal_is_l0(self):
        p = propose_deterministic(8)[0]
        self.assertEqual(p.trust_level, "L0")


class TestProposalParsing(unittest.TestCase):
    """Malformed or hostile model output must degrade to nothing, not crash."""

    def test_parses_well_formed_output(self):
        text = '''Here you go:
        [{"rounds": 12, "solver": "cryptominisat", "encoding": "xor",
          "carry_save": true, "timeout": 300, "rationale": "leanest CNF"}]
        Hope this helps!'''
        out = parse_proposal(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rounds, 12)
        self.assertEqual(out[0].encoding, "xor")
        self.assertTrue(out[0].carry_save)

    def test_rejects_out_of_envelope_objects(self):
        text = '[{"rounds": 999, "solver": "cadical", "encoding": "tseitin"}]'
        self.assertEqual(parse_proposal(text), [])

    def test_ignores_garbage(self):
        for text in ("", "no json here", "{{{", None, "[1,2,3]"):
            self.assertEqual(parse_proposal(text), [])

    def test_drops_illegal_but_keeps_legal_in_mixed_output(self):
        text = (
            '[{"rounds": 10, "solver": "cadical", "encoding": "tseitin"},'
            ' {"rounds": 900, "solver": "cadical", "encoding": "tseitin"}]'
        )
        out = parse_proposal(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rounds, 10)

    def test_deterministic_proposer_always_available(self):
        props = propose_deterministic(8, timeout=300)
        self.assertTrue(props)
        self.assertTrue(all(p.source == "deterministic" for p in props))


class TestSchedulerDecisions(unittest.TestCase):
    """Escalation must follow measured depth, never model optimism."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sha_sched_test_")
        self.db = DatabaseManager(db_path=os.path.join(self.temp_dir, "kb.sqlite"))
        store = EvidenceStore(base_dir=os.path.join(self.temp_dir, "evidence"), db=self.db)
        self.sched = DeterministicScheduler(
            db=self.db, evidence_store=store,
            out_dir=os.path.join(self.temp_dir, "evidence"),
            manifest_dir=os.path.join(self.temp_dir, "cycles"),
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @staticmethod
    def make_outcome(status, rounds=8, solve=None, verified=False, bug=False):
        return StepOutcome(
            proposal=CandidateEncoding(
                rounds=rounds, solver="cryptominisat", encoding="xor",
                carry_save=True, timeout=300,
            ).validate(),
            status=status,
            trust_level="L3" if verified else "L1",
            classification="ReducedRoundPreimage" if verified else None,
            solve_seconds=solve,
            bug_suspected=bug,
        )

    def test_verified_result_advances_frontier(self):
        o = self.make_outcome("VERIFIED", rounds=18, solve=12.7, verified=True)
        self.sched.history = [o]
        # A verified outcome is both verified and conclusive.
        self.sched.best_verified_rounds = 18
        self.sched.conclusive_rounds = 18
        nxt = self.sched.choose_next([o])
        self.assertIsNotNone(nxt)
        self.assertEqual(nxt.rounds, 19)

    def test_timeout_grows_budget_instead_of_declaring_wall(self):
        o = self.make_outcome("TIMEOUT", rounds=19, solve=300.0)
        nxt = self.sched.choose_next([o])
        self.assertIsNotNone(nxt)
        self.assertEqual(nxt.rounds, 19, "must retry the same round with a bigger budget")
        self.assertGreater(nxt.timeout, 300, "timeout must grow, not reset")

    def test_clean_negative_cross_checks_with_other_encoding(self):
        o = self.make_outcome("NO_SOLUTION", rounds=19, solve=0.4)
        nxt = self.sched.choose_next([o])
        self.assertIsNotNone(nxt)
        self.assertEqual(nxt.rounds, 19)
        self.assertNotEqual(
            (nxt.solver, nxt.encoding),
            ("cryptominisat", "xor"),
            "a negative must be cross-checked with an independent configuration",
        )

    def test_bug_suspected_stops_the_frontier(self):
        o = self.make_outcome("REJECTED", rounds=12, bug=True)
        self.assertIsNone(
            self.sched.choose_next([o]),
            "a verifier rejection must halt progression rather than escalate",
        )

    def test_next_target_is_one_past_verified(self):
        # Nothing attempted yet.
        self.assertEqual(self.sched.next_target_rounds(), 1)
        self.sched.best_verified_rounds = 18
        self.sched.conclusive_rounds = 18
        self.assertEqual(self.sched.next_target_rounds(), 19)

    def test_timeout_does_not_advance_the_frontier(self):
        """An unresolved round must not be mistaken for a solved one."""
        o = self.make_outcome("TIMEOUT", rounds=19, solve=300.0)
        self.sched._record("t1", o)
        self.assertEqual(
            self.sched.conclusive_rounds, 0,
            "a timeout is inconclusive and must not advance the frontier",
        )
        self.assertEqual(self.sched.next_target_rounds(), 1)

    def test_negative_is_conclusive_but_not_verified(self):
        o = self.make_outcome("NO_SOLUTION", rounds=19, solve=0.4)
        self.sched._record("n1", o)
        self.assertEqual(self.sched.conclusive_rounds, 19)
        self.assertEqual(self.sched.best_verified_rounds, 0)
        self.assertEqual(self.sched.next_target_rounds(), 20)

    def test_manifest_is_deterministic_and_timestamp_free(self):
        o = self.make_outcome("VERIFIED", rounds=8, solve=1.0, verified=True)
        p1 = self.sched.write_manifest(1, [o])
        data1 = p1.read_text(encoding="utf-8")
        p2 = self.sched.write_manifest(1, [o])
        data2 = p2.read_text(encoding="utf-8")
        self.assertEqual(data1, data2, "manifest must be byte-identical on replay")
        self.assertNotIn("recorded_at", data1, "timestamps break deterministic hashing")
        self.assertTrue((p1.parent / "cycle_0001.meta.json").exists(),
                        "timestamps belong in the sidecar, not the manifest")


class TestSchedulerExecution(unittest.TestCase):
    @unittest.skipUnless(BINARIES_AVAILABLE, "C++ binaries not built")
    def test_real_execution_produces_verified_or_honest_negative(self):
        temp_dir = tempfile.mkdtemp(prefix="sha_sched_exec_")
        try:
            db = DatabaseManager(db_path=os.path.join(temp_dir, "kb.sqlite"))
            out_dir = os.path.join(temp_dir, "evidence")
            store = EvidenceStore(base_dir=out_dir, db=db)
            sched = DeterministicScheduler(
                db=db, evidence_store=store, out_dir=out_dir,
                manifest_dir=os.path.join(temp_dir, "cycles"),
            )
            proposal = CandidateEncoding(
                rounds=6, solver="cadical", encoding="tseitin",
                carry_save=False, timeout=120,
            ).validate()
            outcome = sched.execute(proposal)

            self.assertIn(
                outcome.status, {"VERIFIED", "NO_SOLUTION", "TIMEOUT", "INFRA_FAILURE"}
            )
            self.assertNotEqual(outcome.status, "REJECTED")
            self.assertFalse(outcome.bug_suspected)

            if outcome.status == "VERIFIED":
                self.assertEqual(outcome.trust_level, "L3")
                self.assertEqual(outcome.verified_by, "IndependentVerifier")
                self.assertEqual(outcome.hamming_distance, 0)
                self.assertEqual(outcome.computed_digest, outcome.target_digest)
            else:
                self.assertEqual(outcome.trust_level, "L1")

            # Metrics must be measured, never absent.
            self.assertIsNotNone(outcome.cnf_vars)
            self.assertGreater(outcome.cnf_vars, 0)
            self.assertIsNotNone(outcome.cnf_clauses)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_missing_binary_is_infra_failure_not_a_result(self):
        temp_dir = tempfile.mkdtemp(prefix="sha_sched_nobin_")
        original = os.environ.get("SHA_RESEARCH_BIN")
        os.environ["SHA_RESEARCH_BIN"] = os.path.join(temp_dir, "absent.exe")
        try:
            db = DatabaseManager(db_path=os.path.join(temp_dir, "kb.sqlite"))
            sched = DeterministicScheduler(
                db=db,
                evidence_store=EvidenceStore(base_dir=os.path.join(temp_dir, "e"), db=db),
                out_dir=os.path.join(temp_dir, "e"),
                manifest_dir=os.path.join(temp_dir, "c"),
            )
            outcome = sched.execute(
                CandidateEncoding(
                    rounds=4, solver="cadical", encoding="tseitin",
                    carry_save=False, timeout=30,
                ).validate()
            )
            self.assertEqual(outcome.status, "INFRA_FAILURE")
            self.assertEqual(outcome.trust_level, "L1")
            self.assertNotEqual(outcome.status, "VERIFIED")
        finally:
            if original is None:
                os.environ.pop("SHA_RESEARCH_BIN", None)
            else:
                os.environ["SHA_RESEARCH_BIN"] = original
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestTrustBoundaryIsReal(unittest.TestCase):
    """The scheduler must not be able to promote anything on its own say-so."""

    def test_proposal_claiming_verification_cannot_promote(self):
        verdict = CandidateEncoding(
            rounds=64, solver="cadical", encoding="tseitin",
            carry_save=False, timeout=60,
        ).to_dict()
        verdict.update({"is_valid": True, "classification": "StandardFullPreimage",
                        "actual_rounds": 64})
        # No IndependentVerifier provenance -> promotion must be refused.
        with self.assertRaises(EpistemicIntegrityError):
            EpistemicTrustManager.validate_promotion("L1", "L3", verdict)

    def test_full_preimage_claim_needs_64_rounds(self):
        with self.assertRaises(EpistemicIntegrityError):
            EpistemicTrustManager.validate_promotion("L1", "L3", {
                "is_valid": True, "classification": "StandardFullPreimage",
                "actual_rounds": 18, "verified_by": "IndependentVerifier",
            })
        # The genuinely-64-round form with provenance is accepted by the trust
        # layer; whether a verifier ever emits it is a separate question.
        EpistemicTrustManager.validate_promotion("L1", "L3", {
            "is_valid": True, "classification": "StandardFullPreimage",
            "actual_rounds": 64, "verified_by": "IndependentVerifier",
        })

    def test_reduced_round_is_not_a_full_claim(self):
        EpistemicTrustManager.validate_promotion("L1", "L3", {
            "is_valid": True, "classification": "ReducedRoundPreimage",
            "actual_rounds": 18, "verified_by": "IndependentVerifier",
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)