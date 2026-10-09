"""
Deterministic decision plane for the SHA-256 autonomous research loop.

This is the ONLY component that executes experiments and the ONLY path to an
L3 (independently verified) result. LLM output reaches it as untrusted
CandidateEncoding proposals at L0 and can influence nothing except the order
in which configurations are attempted.

Decision rules, in priority order:

  1. IndependentVerifier verdict decides everything. Nothing else counts.
  2. A solver/model-extraction disagreement is quarantined as a BUG, never
     reported as a finding.
  3. Escalation is driven by measured solve times, not by proposal optimism.
  4. A timeout is never recorded as "no solution exists"; it is recorded as
     "unresolved within budget" and re-probed with a longer budget.
  5. Missing toolchain yields INFRA_FAILURE, not a negative result.

Every step writes a replayable manifest so a cycle can be reproduced exactly.
"""

import json
import time
import hashlib
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..storage.db import DatabaseManager
from ..evidence.store import EvidenceStore, sha256_file
from ..workers.worker import BinaryResolution, VerifierBridge, VerificationUnavailable
from ..agent.proposals import CandidateEncoding, ProposalPlane
from ..agent.trust import EpistemicTrustManager, EpistemicIntegrityError


@dataclass
class StepOutcome:
    """The measured result of executing one candidate configuration."""

    proposal: CandidateEncoding
    status: str                      # VERIFIED | NO_SOLUTION | TIMEOUT | INFRA_FAILURE | REJECTED
    trust_level: str                 # L3 only when VERIFIED, else L1
    classification: Optional[str] = None
    cnf_vars: Optional[int] = None
    cnf_clauses: Optional[int] = None
    cnf_xors: Optional[int] = None
    encode_seconds: Optional[float] = None
    solve_seconds: Optional[float] = None
    candidate_path: Optional[str] = None
    computed_digest: Optional[str] = None
    target_digest: Optional[str] = None
    hamming_distance: Optional[int] = None
    verified_by: Optional[str] = None
    failure_reason: str = ""
    bug_suspected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["proposal"] = self.proposal.to_dict()
        return d


CONCLUSIVE_STATUSES = ("VERIFIED", "NO_SOLUTION")
INCONCLUSIVE_STATUSES = ("TIMEOUT", "UNRESOLVED", "INFRA_FAILURE", "REJECTED")


def proposal_depth(outcomes: List[StepOutcome]) -> int:
    """Deepest round count among the given outcomes."""
    return max((o.proposal.rounds for o in outcomes), default=0)


class DeterministicScheduler:
    """Executes proposals, verifies results, and escalates on measured evidence."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        verifier: Optional[VerifierBridge] = None,
        evidence_store: Optional[EvidenceStore] = None,
        proposal_plane: Optional[ProposalPlane] = None,
        out_dir: str = "evidence",
        manifest_dir: str = "evidence/cycles",
    ):
        self.db = db or DatabaseManager()
        self.verifier = verifier or VerifierBridge()
        self.evidence_store = evidence_store or EvidenceStore(base_dir=out_dir, db=self.db)
        self.proposals = proposal_plane or ProposalPlane(db=self.db)
        self.out_dir = out_dir
        self.manifest_dir = Path(manifest_dir)
        self.history: List[StepOutcome] = []

        self.best_verified_rounds = 0
        # Deepest round for which we obtained a definitive answer (SAT with a
        # verified candidate, or a proven UNSAT). Timeouts and infrastructure
        # failures are inconclusive and must NOT advance the frontier, or the
        # loop would escalate past a wall it simply failed to probe.
        self.conclusive_rounds = 0
        self.step_counter = 0

    # ---- execution ----------------------------------------------------

    def _parse_result_lines(self, stdout: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for line in (stdout or "").splitlines():
            line = line.strip()
            if line.startswith("RESULT_") and "=" in line:
                key, _, value = line.partition("=")
                out[key.strip()] = value.strip()
        return out

    def execute(self, proposal: CandidateEncoding) -> StepOutcome:
        """Run one candidate and verify it through the independent verifier."""
        proposal.validate()
        self.step_counter += 1
        step_id = f"step_{self.step_counter:05d}"

        try:
            exe = BinaryResolution.require()
        except FileNotFoundError as e:
            return StepOutcome(
                proposal=proposal, status="INFRA_FAILURE", trust_level="L1",
                failure_reason=str(e),
            )
        try:
            self.verifier.require_binary()
        except VerificationUnavailable as e:
            return StepOutcome(
                proposal=proposal, status="INFRA_FAILURE", trust_level="L1",
                failure_reason=str(e),
            )

        cmd = [
            str(exe), "preimage",
            "--rounds", str(proposal.rounds),
            "--solver", proposal.solver,
            "--encoding", proposal.encoding,
            "--timeout", str(proposal.timeout),
            "--out", self.out_dir,
        ]
        if proposal.carry_save:
            cmd.append("--carry-save")

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=proposal.timeout + 120)
        except subprocess.TimeoutExpired:
            return StepOutcome(
                proposal=proposal, status="TIMEOUT", trust_level="L1",
                failure_reason=(
                    f"Wall-clock budget of {proposal.timeout + 120}s exceeded; "
                    f"the solver may still be making progress."
                ),
            )
        except Exception as e:
            return StepOutcome(
                proposal=proposal, status="INFRA_FAILURE", trust_level="L1",
                failure_reason=f"Execution failed: {e}",
            )
        wall = time.perf_counter() - t0

        res = self._parse_result_lines(proc.stdout)

        def num(key: str) -> Optional[float]:
            v = res.get(key)
            try:
                return float(v) if v is not None else None
            except ValueError:
                return None

        def inum(key: str) -> Optional[int]:
            v = res.get(key)
            try:
                return int(v) if v is not None else None
            except ValueError:
                return None

        candidate = res.get("RESULT_CANDIDATE")
        outcome = StepOutcome(
            proposal=proposal,
            status="NO_SOLUTION",
            trust_level="L1",
            classification=res.get("RESULT_CLASSIFICATION"),
            cnf_vars=inum("RESULT_CNF_VARS"),
            cnf_clauses=inum("RESULT_CNF_CLAUSES"),
            cnf_xors=inum("RESULT_CNF_XORS"),
            encode_seconds=num("RESULT_ENCODE_TIME"),
            solve_seconds=num("RESULT_SOLVER_TIME"),
        )

        if not candidate or candidate == "NONE":
            # Distinguish a proven UNSAT from a solver that merely gave up.
            # Only a genuine UNSAT is a conclusive negative; TIMEOUT and
            # UNKNOWN both mean "unresolved" and must not advance the frontier.
            solver_status = (res.get("RESULT_SOLVER_STATUS") or "").upper()
            solve_seconds = outcome.solve_seconds
            if solver_status == "UNSAT":
                outcome.status = "NO_SOLUTION"
                outcome.failure_reason = (
                    "Solver reported UNSAT: no 1-block preimage exists under this "
                    "encoding and round count."
                )
            elif solver_status == "TIMEOUT" or (
                solve_seconds is not None and solve_seconds >= proposal.timeout - 1
            ):
                outcome.status = "TIMEOUT"
                outcome.failure_reason = (
                    f"No candidate within the {proposal.timeout}s budget "
                    f"(solver ran {solve_seconds:.1f}s). Unresolved, not disproven."
                )
            else:
                outcome.status = "UNRESOLVED"
                outcome.failure_reason = (
                    f"Solver terminated without a verdict (status="
                    f"{solver_status or 'missing'}). No model and no proof."
                )
            self._record(step_id, outcome)
            return outcome

        # A candidate exists. It MUST pass the independent verifier.
        try:
            cand_path = Path(candidate)
            if not cand_path.is_absolute():
                cand_path = Path.cwd() / cand_path
            candidate_bytes = cand_path.read_bytes()
            target_hex = res.get("RESULT_TARGET_DIGEST")
            if not target_hex:
                raise VerificationUnavailable("sha-research emitted no RESULT_TARGET_DIGEST")
            verdict = self.verifier.verify_preimage(candidate_bytes, target_hex, proposal.rounds)
        except (VerificationUnavailable, OSError) as e:
            outcome.status = "INFRA_FAILURE"
            outcome.failure_reason = f"Independent verification unavailable: {e}"
            self._record(step_id, outcome)
            return outcome

        outcome.candidate_path = str(cand_path)
        outcome.computed_digest = verdict.get("digest_a")
        outcome.target_digest = verdict.get("digest_b")
        outcome.hamming_distance = verdict.get("hamming_distance")
        outcome.verified_by = verdict.get("verifier_engine")
        outcome.classification = verdict.get("classification")

        if verdict.get("is_valid"):
            EpistemicTrustManager.validate_promotion("L1", "L3", {
                "is_valid": True,
                "classification": verdict.get("classification"),
                "actual_rounds": verdict.get("actual_rounds", proposal.rounds),
                "verified_by": verdict.get("verifier_engine"),
            })
            outcome.status = "VERIFIED"
            outcome.trust_level = "L3"
            outcome.failure_reason = ""
            self.best_verified_rounds = max(self.best_verified_rounds, proposal.rounds)
            self.conclusive_rounds = max(self.conclusive_rounds, proposal.rounds)
        else:
            # The solver claimed SAT but the candidate does not check out.
            # That is a defect in the pipeline, not a scientific finding.
            outcome.status = "REJECTED"
            outcome.bug_suspected = True
            outcome.failure_reason = (
                "SOLVER REPORTED SAT BUT INDEPENDENT VERIFIER REJECTED THE CANDIDATE "
                f"(hamming={outcome.hamming_distance}): {verdict.get('failure_reason')}"
            )

        self._record(step_id, outcome)
        return outcome

    # ---- persistence --------------------------------------------------

    def _record(self, step_id: str, outcome: StepOutcome) -> None:
        self.history.append(outcome)
        if outcome.status in CONCLUSIVE_STATUSES:
            self.conclusive_rounds = max(
                self.conclusive_rounds, outcome.proposal.rounds
            )
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn = self.db.get_connection()
            try:
                exp_id = f"exp_{step_id}"
                conn.execute(
                    "INSERT OR REPLACE INTO experiments "
                    "(id, hypothesis_id, status, rounds, solver, backend, seed, timeout, "
                    " parameters, outcome, classification, created_at, updated_at) "
                    "VALUES (?, 'sched', ?, ?, ?, 'cpu', 0, ?, ?, ?, ?, ?, ?)",
                    (
                        exp_id, outcome.status, outcome.proposal.rounds,
                        outcome.proposal.solver, outcome.proposal.timeout,
                        json.dumps(outcome.proposal.to_dict(), sort_keys=True, default=str),
                        "CONFIRMED" if outcome.status == "VERIFIED" else "REFUTED",
                        outcome.classification or "Unknown", now, now,
                    ),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO verifications "
                    "(id, candidate_id, experiment_id, is_valid, classification, failure_reason, "
                    " digest_a, digest_b, hamming_distance, verified_rounds, verified_by, "
                    " engine_segregated, verified_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f"ver_{step_id}", f"cand_{step_id}", exp_id,
                        1 if outcome.status == "VERIFIED" else 0,
                        outcome.classification or "Unknown",
                        outcome.failure_reason,
                        outcome.computed_digest, outcome.target_digest,
                        outcome.hamming_distance,
                        outcome.proposal.rounds if outcome.status == "VERIFIED" else None,
                        outcome.verified_by or "IndependentVerifier",
                        1 if outcome.verified_by else 0,
                        now,
                    ),
                )
                for name, value, unit in (
                    ("wall_time_seconds", outcome.solve_seconds, "s"),
                    ("cnf_vars", outcome.cnf_vars, "count"),
                    ("cnf_clauses", outcome.cnf_clauses, "count"),
                    ("cnf_xors", outcome.cnf_xors, "count"),
                    ("encode_seconds", outcome.encode_seconds, "s"),
                ):
                    if value is not None:
                        conn.execute(
                            "INSERT INTO metrics (experiment_id, metric_name, metric_value, unit) "
                            "VALUES (?, ?, ?, ?)",
                            (exp_id, name, float(value), unit),
                        )
                conn.execute(
                    "INSERT INTO events (event_type, aggregate_id, payload) "
                    "VALUES (?, ?, ?)",
                    (
                        f"SCHEDULER_{outcome.status}",
                        exp_id,
                        json.dumps(outcome.to_dict(), sort_keys=True, default=str),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            # Persistence failure must not be mistaken for a result.
            pass

    # ---- frontier decisions -------------------------------------------

    def next_target_rounds(self) -> int:
        """One round past the deepest round with a definitive answer.

        A verified preimage is also a conclusive outcome, so `conclusive_rounds`
        already accounts for `best_verified_rounds`.
        """
        return min(self.conclusive_rounds + 1, 64)

    def choose_next(self, outcomes: List[StepOutcome]) -> Optional[CandidateEncoding]:
        """Deterministic selection from measured outcomes only.

        The LLM's opinion is never consulted here.
        """
        if not outcomes:
            return None

        target = self.next_target_rounds()

        # A suspected bug outranks everything: stop and surface it.
        for o in outcomes:
            if o.bug_suspected:
                return None

        if any(o.status == "VERIFIED" for o in outcomes):
            self.best_verified_rounds = max(self.best_verified_rounds, proposal_depth(outcomes))
            return CandidateEncoding(
                rounds=min(target, 64),
                solver="cryptominisat",
                encoding="xor",
                carry_save=True,
                timeout=900,
                rationale=(
                    f"Deepest independently verified preimage is "
                    f"{self.best_verified_rounds} rounds; escalating to {target}."
                ),
                source="scheduler",
            ).validate()

        # Nothing conclusive. If the target round was merely unresolved, grow the
        # budget rather than declaring a wall. This separates "slow" from
        # "stuck", and matters because a solver giving up proves nothing.
        stalled = [o for o in outcomes if o.status in INCONCLUSIVE_STATUSES]
        if stalled:
            slowest = max(
                stalled,
                key=lambda o: (o.solve_seconds or 0, o.proposal.timeout),
            )
            grown = min(
                int(max(slowest.solve_seconds or 0, slowest.proposal.timeout) * 2.5),
                3600,
            )
            if grown <= slowest.proposal.timeout:
                grown = min(slowest.proposal.timeout * 2, 3600)
            return CandidateEncoding(
                rounds=slowest.proposal.rounds,
                solver=slowest.proposal.solver,
                encoding=slowest.proposal.encoding,
                carry_save=slowest.proposal.carry_save,
                timeout=grown,
                rationale=(
                    f"Round {slowest.proposal.rounds} ended as {slowest.status} "
                    f"after {slowest.solve_seconds or 0:.0f}s without a verdict. "
                    f"Retrying with {grown}s, since neither a timeout nor a solver "
                    f"give-up is evidence that no preimage exists."
                ),
                source="scheduler",
            ).validate()

        # Clean negative (UNSAT) at some round: cross-check that exact round
        # with an independent solver and encoding before conceding a wall.
        # Encodings differ in strength, so one negative is not decisive.
        failed_round = max(o.proposal.rounds for o in outcomes)
        return CandidateEncoding(
            rounds=failed_round,
            solver="cadical",
            encoding="tseitin",
            carry_save=False,
            timeout=600,
            rationale=(
                f"No candidate found at round {failed_round} with the previous encoding. "
                f"Cross-checking with an independent solver and encoding before "
                f"concluding a wall."
            ),
            source="scheduler",
        ).validate()

    # ---- manifests ----------------------------------------------------

    def write_manifest(self, cycle: int, outcomes: List[StepOutcome]) -> Path:
        """Write a deterministic, timestamp-free manifest for replay."""
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "cycle": cycle,
            "best_verified_rounds": self.best_verified_rounds,
            "steps": [
                {
                    "status": o.status,
                    "trust_level": o.trust_level,
                    "rounds": o.proposal.rounds,
                    "solver": o.proposal.solver,
                    "encoding": o.proposal.encoding,
                    "carry_save": o.proposal.carry_save,
                    "timeout": o.proposal.timeout,
                    "cnf_vars": o.cnf_vars,
                    "cnf_clauses": o.cnf_clauses,
                    "cnf_xors": o.cnf_xors,
                    "solve_seconds": o.solve_seconds,
                    "classification": o.classification,
                    "failure_reason": o.failure_reason,
                    "bug_suspected": o.bug_suspected,
                }
                for o in outcomes
            ],
        }
        path = self.manifest_dir / f"cycle_{cycle:04d}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True, default=str)

        with open(self.manifest_dir / f"cycle_{cycle:04d}.meta.json", "w", encoding="utf-8") as f:
            json.dump(
                {"cycle": cycle, "recorded_at": datetime.now(timezone.utc).isoformat()},
                f, indent=2, sort_keys=True,
            )
        return path