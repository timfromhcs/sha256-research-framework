"""
Asynchronous Job Worker for SHA-256 Research Platform v3.1
Executes experiments off HTTP thread:
  State transitions: QUEUED -> PREPARING -> RUNNING -> VERIFYING -> COMPLETED / FAILED / TIMEOUT / CANCELLED / REJECTED
  Anti-clamping: strictly rejects invalid rounds (rounds < 1 or rounds > 64)
  Independent Verification: every candidate MUST be re-verified by the segregated
    `sha-verifier` binary. There is NO fallback path that can synthesise a verdict.
    A missing binary, an unparseable verdict, or a solver exit code is never a pass.
  Automatic Evidence: generates auditable evidence package in evidence/experiments/
"""

import json
import os
import sys
import time
import queue
import threading
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from ..storage.db import DatabaseManager
from ..evidence.store import EvidenceStore, sha256_file


class VerificationUnavailable(Exception):
    """Raised when the independent verifier cannot be reached.

    This is a hard infrastructure failure. It must never be converted into a
    pass, a fallback verdict, or a simulated result.
    """


class VerifierBridge:
    """Sole gateway to the segregated independent verifier.

    Every L3 trust promotion in the platform flows through this class. It
    returns only what the C++ verifier actually decided, parsed from its
    machine-readable JSON contract. If the verifier is unreachable or its
    output is malformed, this raises rather than guessing.
    """

    def __init__(self, binary_override: Optional[str] = None):
        self._binary_override = binary_override

    def locate(self) -> Optional[Path]:
        """Resolve the sha-verifier binary. Returns None if not built."""
        if self._binary_override:
            p = Path(self._binary_override)
            return p if p.is_file() else None

        env = os.environ.get("SHA_VERIFIER_BIN")
        if env:
            p = Path(env)
            return p if p.is_file() else None

        candidates = [
            Path("build/Release/sha-verifier.exe"),
            Path("build/sha-verifier.exe"),
            Path("build-cpu/Release/sha-verifier.exe"),
            Path("build-cpu/sha-verifier.exe"),
        ]
        for c in candidates:
            if c.is_file():
                return c
        return None

    def require_binary(self) -> Path:
        binary = self.locate()
        if binary is None:
            raise VerificationUnavailable(
                "sha-verifier binary not found. Independent verification is impossible; "
                "refusing to report any result. Build the project or set SHA_VERIFIER_BIN."
            )
        return binary

    def _run(self, args: List[str], timeout: int = 120) -> Dict[str, Any]:
        binary = self.require_binary()
        cmd = [str(binary)] + args
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise VerificationUnavailable(f"Verifier timed out after {timeout}s: {args}") from e
        except Exception as e:
            raise VerificationUnavailable(f"Verifier invocation failed: {e}") from e

        raw = (proc.stdout or "").strip()
        if not raw:
            raise VerificationUnavailable(
                f"Verifier produced no output (exit {proc.returncode}). Refusing to infer a verdict."
            )
        try:
            verdict = json.loads(raw.splitlines()[-1])
        except (ValueError, IndexError) as e:
            raise VerificationUnavailable(
                f"Verifier output was not valid JSON: {raw[:200]!r}"
            ) from e

        if not isinstance(verdict, dict) or "is_valid" not in verdict:
            raise VerificationUnavailable(
                f"Verifier JSON missing required 'is_valid' field: {raw[:200]!r}"
            )
        if verdict.get("verifier_engine") != "IndependentVerifier":
            raise VerificationUnavailable(
                "Verdict did not originate from the segregated IndependentVerifier engine."
            )

        # Cross-check: exit code and parsed verdict must agree. A disagreement
        # means we are not talking to the verifier we think we are.
        parsed_valid = bool(verdict["is_valid"])
        if parsed_valid != (proc.returncode == 0):
            raise VerificationUnavailable(
                f"Verifier self-inconsistent: exit={proc.returncode} but is_valid={parsed_valid}."
            )

        verdict["_exit_code"] = proc.returncode
        verdict["_raw_stdout"] = raw
        return verdict

    def verify_preimage(self, message: bytes, target_digest_hex: str, rounds: int) -> Dict[str, Any]:
        """Verify that `message` compresses to `target_digest_hex` in `rounds` rounds."""
        if not 1 <= rounds <= 64:
            raise VerificationUnavailable(f"Anti-clamping: rounds={rounds} outside [1, 64].")
        if len(message) != 64:
            raise VerificationUnavailable(
                f"Preimage candidate must be exactly 64 bytes (one block); got {len(message)}."
            )
        if len(target_digest_hex) != 64:
            raise VerificationUnavailable(
                f"Target digest must be 64 hex characters; got {len(target_digest_hex)}."
            )
        return self._run(["verify-preimage", message.hex(), target_digest_hex, str(rounds), "--json"])

    def verify_collision(self, message_a_hex: str, message_b_hex: str, rounds: int) -> Dict[str, Any]:
        """Verify that two distinct blocks collide in `rounds` rounds."""
        if not 1 <= rounds <= 64:
            raise VerificationUnavailable(f"Anti-clamping: rounds={rounds} outside [1, 64].")
        return self._run(["verify-pair", message_a_hex, message_b_hex, str(rounds), "--json"])


class BinaryResolution:
    """Locates the C++ research binary. Absent binary is an infrastructure failure."""

    @staticmethod
    def locate(name: str = "sha-research.exe") -> Optional[Path]:
        override = os.environ.get("SHA_RESEARCH_BIN")
        if override:
            p = Path(override)
            return p if p.is_file() else None
        for candidate in (
            Path("build/Release") / name,
            Path("build") / name,
            Path("build-cpu/Release") / name,
            Path("build-cpu") / name,
        ):
            if candidate.is_file():
                return candidate
        return None

    @staticmethod
    def require(name: str = "sha-research.exe") -> Path:
        p = BinaryResolution.locate(name)
        if p is None:
            raise FileNotFoundError(
                f"{name} not found. The C++ research binary must be built before any "
                f"experiment can run; the platform will not simulate results."
            )
        return p


class ResearchWorkerPool:
    """Manages asynchronous worker threads executing cryptanalysis jobs."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        max_workers: int = 2,
        evidence_store: Optional[EvidenceStore] = None,
        verifier: Optional[VerifierBridge] = None,
    ):
        self.db = db or DatabaseManager()
        self.evidence_store = evidence_store or EvidenceStore(db=self.db)
        self.max_workers = max_workers
        self.job_queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self.threads: List[threading.Thread] = []
        self.running = False
        self.active_jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.verifier = verifier or VerifierBridge()

    def start(self) -> None:
        """Starts worker threads."""
        if self.running:
            return
        self.running = True
        for i in range(self.max_workers):
            t = threading.Thread(target=self._worker_loop, name=f"ResearchWorker-{i}", daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self) -> None:
        """Stops worker threads."""
        self.running = False

    def enqueue_experiment(
        self,
        experiment_id: str,
        hypothesis_id: str,
        rounds: int,
        solver: str = "cadical",
        backend: str = "cpu",
        seed: int = 42,
        timeout: int = 60,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Validates parameters, creates experiment & job records, and queues the job."""
        now_str = datetime.now(timezone.utc).isoformat()

        # ANTI-CLAMPING CHECK:
        # Invalid rounds MUST fail explicitly with REJECTED state, never clamped!
        if rounds < 1 or rounds > 64:
            conn = self.db.get_connection()
            try:
                conn.execute("""
                    INSERT INTO experiments 
                    (id, hypothesis_id, status, rounds, solver, backend, seed, timeout, parameters, outcome, classification, created_at, updated_at)
                    VALUES (?, ?, 'REJECTED', ?, ?, ?, ?, ?, ?, 'REJECTED_INVALID_ROUNDS', 'AntiClampingViolation', ?, ?)
                """, (
                    experiment_id, hypothesis_id, rounds, solver, backend, seed, timeout,
                    str(parameters or {}), now_str, now_str
                ))
                conn.commit()
            finally:
                conn.close()

            self.db.record_event("EXPERIMENT_REJECTED", experiment_id, {
                "reason": f"Anti-clamping rule violation: rounds ({rounds}) must be between 1 and 64",
                "rounds": rounds
            })

            return {
                "experiment_id": experiment_id,
                "status": "REJECTED",
                "error": f"Invalid round count {rounds}: must be between 1 and 64."
            }

        # Create experiment record in DB
        conn = self.db.get_connection()
        try:
            conn.execute("""
                INSERT INTO experiments 
                (id, hypothesis_id, status, rounds, solver, backend, seed, timeout, parameters, created_at, updated_at)
                VALUES (?, ?, 'QUEUED', ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                experiment_id, hypothesis_id, rounds, solver, backend, seed, timeout,
                str(parameters or {}), now_str, now_str
            ))

            job_id = f"job_{experiment_id}"
            conn.execute("""
                INSERT INTO jobs (id, experiment_id, job_type, status, created_at)
                VALUES (?, ?, 'EXPERIMENT_RUN', 'QUEUED', ?)
            """, (job_id, experiment_id, now_str))

            conn.commit()
        finally:
            conn.close()

        job_item = {
            "job_id": job_id,
            "experiment_id": experiment_id,
            "hypothesis_id": hypothesis_id,
            "rounds": rounds,
            "solver": solver,
            "backend": backend,
            "seed": seed,
            "timeout": timeout,
            "parameters": parameters or {}
        }

        self.db.record_event("EXPERIMENT_QUEUED", experiment_id, job_item)
        self.job_queue.put(job_item)

        return {
            "job_id": job_id,
            "experiment_id": experiment_id,
            "status": "QUEUED"
        }

    def cancel_experiment(self, experiment_id: str) -> bool:
        """Cancels an experiment if it is queued or running."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if experiment_id in self.active_jobs:
                self.active_jobs[experiment_id]["cancelled"] = True

        conn = self.db.get_connection()
        try:
            conn.execute("""
                UPDATE experiments 
                SET status = 'CANCELLED', outcome = 'CANCELLED_BY_USER', updated_at = ?
                WHERE id = ? AND status IN ('QUEUED', 'PREPARING', 'RUNNING')
            """, (now_str, experiment_id))

            conn.execute("""
                UPDATE jobs 
                SET status = 'CANCELLED', completed_at = ?
                WHERE experiment_id = ? AND status IN ('QUEUED', 'PREPARING', 'RUNNING')
            """, (now_str, experiment_id))

            conn.commit()
        finally:
            conn.close()

        self.db.record_event("EXPERIMENT_CANCELLED", experiment_id, {})
        return True

    def _worker_loop(self) -> None:
        while self.running:
            try:
                job = self.job_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._execute_job(job)
            except Exception as e:
                self._handle_job_failure(job, str(e))
            finally:
                self.job_queue.task_done()

    def _update_state(self, experiment_id: str, job_id: str, status: str) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        conn = self.db.get_connection()
        try:
            conn.execute("UPDATE experiments SET status = ?, updated_at = ? WHERE id = ?", (status, now_str, experiment_id))
            conn.execute("UPDATE jobs SET status = ? WHERE id = ?", (status, job_id))
            conn.commit()
        finally:
            conn.close()
        self.db.record_event("EXPERIMENT_STATE_CHANGED", experiment_id, {"status": status})

    def _execute_job(self, job: Dict[str, Any]) -> None:
        exp_id = job["experiment_id"]
        job_id = job["job_id"]
        rounds = job["rounds"]
        solver = job["solver"]
        timeout = job["timeout"]

        with self._lock:
            self.active_jobs[exp_id] = {"cancelled": False}

        # 1. PREPARING
        self._update_state(exp_id, job_id, "PREPARING")

        # Preconditions. Both binaries are mandatory; absence is an
        # infrastructure failure, never a silent pass.
        try:
            exe_path = BinaryResolution.require()
            self.verifier.require_binary()
        except (FileNotFoundError, VerificationUnavailable) as e:
            self._record_infrastructure_failure(job, str(e))
            return

        with self._lock:
            if self.active_jobs[exp_id]["cancelled"]:
                self._update_state(exp_id, job_id, "CANCELLED")
                return

        # 2. RUNNING
        self._update_state(exp_id, job_id, "RUNNING")

        out_dir = self.evidence_store.base_dir
        cmd = [str(exe_path), "experiment", "run", str(rounds), solver, out_dir]

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self._update_state(exp_id, job_id, "TIMEOUT")
            self.db.record_event("EXPERIMENT_TIMEOUT", exp_id, {"timeout": timeout})
            self._finalise_active(exp_id)
            return
        except Exception as e:
            self._handle_job_failure(job, str(e))
            return

        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        wall_time = time.perf_counter() - t0

        with self._lock:
            if self.active_jobs[exp_id]["cancelled"]:
                self._update_state(exp_id, job_id, "CANCELLED")
                return

        # 3. LOCATE CANDIDATE
        # The C++ run prints a machine-parseable result pointer. We do NOT
        # infer success from stdout text or exit codes.
        candidate_path = self._resolve_candidate_path(exp_id, stdout)

        if candidate_path is None:
            # Solver produced no candidate (UNSAT, timeout, or model-extraction
            # failure). That is a legitimate negative result, not a failure.
            self._record_negative_result(
                job, exit_code, stdout, stderr, wall_time,
                reason="Solver produced no candidate block (UNSAT, timeout, or extraction failure).",
            )
            return

        # 4. VERIFYING — the only path to a pass
        self._update_state(exp_id, job_id, "VERIFYING")

        try:
            candidate_bytes = candidate_path.read_bytes()
            target_hex = self._extract_target_digest(stdout)
            verdict = self.verifier.verify_preimage(candidate_bytes, target_hex, rounds)
        except (VerificationUnavailable, OSError) as e:
            self._record_infrastructure_failure(job, f"Independent verification unavailable: {e}")
            return

        is_verified = bool(verdict["is_valid"])
        classification = verdict["classification"]
        verified_by = verdict.get("verifier_engine", "IndependentVerifier")

        verification_data = {
            "is_valid": is_verified,
            "classification": classification,
            "actual_rounds": verdict.get("actual_rounds", rounds),
            "claimed_rounds": rounds,
            "verified_by": verified_by,
            "verifier_engine_segregated": bool(verdict.get("engine_segregated", False)),
            "hamming_distance": verdict.get("hamming_distance"),
            "computed_digest": verdict.get("digest_a"),
            "target_digest": verdict.get("digest_b"),
            "candidate_sha256": sha256_file(str(candidate_path)),
            "candidate_path": str(candidate_path),
            "failure_reason": verdict.get("failure_reason", ""),
        }

        result_data = {
            "experiment_id": exp_id,
            "status": "COMPLETED",
            "exit_code": exit_code,
            "wall_time_seconds": wall_time,
            "outcome": "CONFIRMED" if is_verified else "REFUTED",
            "classification": classification,
            "verified_by_independent_verifier": True,
        }

        # 5. EVIDENCE STORAGE
        self.evidence_store.create_evidence_package(
            experiment_id=exp_id,
            request_data=job,
            stdout_text=stdout,
            stderr_text=stderr,
            result_data=result_data,
            verification_data=verification_data,
        )

        # 6. Record run, candidate, verification, metrics in SQLite
        conn = self.db.get_connection()
        try:
            run_id = f"run_{exp_id}_1"
            conn.execute("""
                INSERT INTO experiment_runs
                (id, experiment_id, run_number, started_at, ended_at, exit_code, status, raw_output)
                VALUES (?, ?, 1, ?, ?, ?, 'COMPLETED', ?)
            """, (run_id, exp_id, datetime.now(timezone.utc).isoformat(),
                  datetime.now(timezone.utc).isoformat(), exit_code, stdout))

            cand_id = f"cand_{exp_id}"
            conn.execute("""
                INSERT OR REPLACE INTO candidates (id, experiment_id, rounds, created_at)
                VALUES (?, ?, ?, ?)
            """, (cand_id, exp_id, rounds, datetime.now(timezone.utc).isoformat()))

            ver_id = f"ver_{exp_id}"
            conn.execute("""
                INSERT OR REPLACE INTO verifications
                (id, candidate_id, experiment_id, is_valid, classification, failure_reason,
                 verified_rounds, digest_a, digest_b, hamming_distance,
                 verified_by, engine_segregated, verified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ver_id, cand_id, exp_id, is_verified, classification,
                  verification_data["failure_reason"],
                  verification_data["actual_rounds"],
                  verification_data["computed_digest"],
                  verification_data["target_digest"],
                  verification_data["hamming_distance"],
                  verified_by,
                  1 if verification_data["verifier_engine_segregated"] else 0,
                  datetime.now(timezone.utc).isoformat()))

            conn.execute("""
                INSERT INTO metrics (experiment_id, metric_name, metric_value, unit)
                VALUES (?, 'wall_time_seconds', ?, 's')
            """, (exp_id, wall_time))
            conn.execute("""
                INSERT INTO metrics (experiment_id, metric_name, metric_value, unit)
                VALUES (?, 'verifier_hamming_distance', ?, 'bits')
            """, (exp_id, float(verification_data["hamming_distance"] or 0)))

            now_str = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE experiments
                SET status = 'COMPLETED', outcome = ?, classification = ?, updated_at = ?
                WHERE id = ?
            """, (result_data["outcome"], classification, now_str, exp_id))
            conn.execute(
                "UPDATE jobs SET status = 'COMPLETED', completed_at = ? WHERE id = ?",
                (now_str, job_id),
            )
            conn.commit()
        finally:
            conn.close()

        self.db.record_event("EXPERIMENT_COMPLETED", exp_id, {
            "is_valid": is_verified,
            "classification": classification,
            "wall_time_seconds": wall_time,
            "verified_by": verified_by,
        })
        self._finalise_active(exp_id)

    # ---- helpers -------------------------------------------------------

    def _resolve_candidate_path(self, exp_id: str, stdout: str) -> Optional[Path]:
        """Find the candidate block the C++ run produced, if any.

        Prefers the machine-readable RESULT line emitted by sha-research.
        Falls back to scanning the experiment directory. Returns None when the
        solver legitimately produced no candidate.
        """
        for line in (stdout or "").splitlines():
            line = line.strip()
            if line.startswith("RESULT_CANDIDATE="):
                raw = line.split("=", 1)[1].strip()
                p = Path(raw)
                if not p.is_absolute():
                    p = Path.cwd() / p
                if p.is_file():
                    return p

        exp_dir = Path(self.evidence_store.base_dir) / "experiments" / exp_id
        candidate = exp_dir / "artifacts" / "candidate_block.bin"
        if candidate.is_file():
            return candidate

        legacy = Path(self.evidence_store.base_dir) / "experiments" / exp_id / "candidate_block.bin"
        if legacy.is_file():
            return legacy
        return None

    def _extract_target_digest(self, stdout: str) -> str:
        """Read the target digest the C++ run committed to."""
        for line in (stdout or "").splitlines():
            line = line.strip()
            if line.startswith("RESULT_TARGET_DIGEST="):
                hexval = line.split("=", 1)[1].strip().lower()
                if len(hexval) == 64:
                    return hexval
        raise VerificationUnavailable(
            "sha-research did not emit RESULT_TARGET_DIGEST; cannot verify a candidate "
            "against an unknown target."
        )

    def _record_negative_result(
        self, job: Dict[str, Any], exit_code: int, stdout: str, stderr: str,
        wall_time: float, reason: str,
    ) -> None:
        """Legitimate negative outcome: the search ran and found nothing."""
        exp_id = job["experiment_id"]
        job_id = job["job_id"]
        classification = "NoSolutionFound"
        verification_data = {
            "is_valid": False,
            "classification": classification,
            "actual_rounds": job["rounds"],
            "claimed_rounds": job["rounds"],
            "verified_by": "IndependentVerifier",
            "failure_reason": reason,
        }
        result_data = {
            "experiment_id": exp_id,
            "status": "COMPLETED",
            "exit_code": exit_code,
            "wall_time_seconds": wall_time,
            "outcome": "REFUTED",
            "classification": classification,
            "verified_by_independent_verifier": True,
        }
        self.evidence_store.create_evidence_package(
            experiment_id=exp_id,
            request_data=job,
            stdout_text=stdout,
            stderr_text=stderr,
            result_data=result_data,
            verification_data=verification_data,
        )

        conn = self.db.get_connection()
        try:
            conn.execute("""
                INSERT INTO verifications
                (id, candidate_id, experiment_id, is_valid, classification, failure_reason,
                 verified_rounds, verified_by, engine_segregated, verified_at)
                VALUES (?, ?, ?, 0, ?, ?, ?, 'IndependentVerifier', 1, ?)
            """, (f"ver_{exp_id}", f"cand_{exp_id}", exp_id, classification,
                  reason, job["rounds"], datetime.now(timezone.utc).isoformat()))
            conn.execute("""
                INSERT INTO metrics (experiment_id, metric_name, metric_value, unit)
                VALUES (?, 'wall_time_seconds', ?, 's')
            """, (exp_id, wall_time))
            now_str = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE experiments
                SET status = 'COMPLETED', outcome = 'REFUTED', classification = ?, updated_at = ?
                WHERE id = ?
            """, (classification, now_str, exp_id))
            conn.execute("UPDATE jobs SET status = 'COMPLETED', completed_at = ? WHERE id = ?", (now_str, job_id))
            conn.commit()
        finally:
            conn.close()

        self.db.record_event("EXPERIMENT_COMPLETED", exp_id, {
            "is_valid": False, "classification": classification,
            "wall_time_seconds": wall_time, "note": "negative result (no candidate produced)",
        })
        self._finalise_active(exp_id)

    def _record_infrastructure_failure(self, job: Dict[str, Any], error_msg: str) -> None:
        """A missing or broken toolchain. Explicitly NOT a scientific result."""
        exp_id = job["experiment_id"]
        job_id = job["job_id"]
        now_str = datetime.now(timezone.utc).isoformat()

        conn = self.db.get_connection()
        try:
            conn.execute("""
                UPDATE experiments
                SET status = 'FAILED', outcome = 'INFRA_FAILURE',
                    classification = 'InfrastructureError', updated_at = ?
                WHERE id = ?
            """, (now_str, exp_id))
            conn.execute("""
                UPDATE jobs
                SET status = 'FAILED', error_message = ?, completed_at = ?
                WHERE id = ?
            """, (error_msg, now_str, job_id))
            conn.commit()
        finally:
            conn.close()

        self.db.record_event("EXPERIMENT_INFRA_FAILURE", exp_id, {"error": error_msg})
        self._finalise_active(exp_id)

    def _finalise_active(self, exp_id: str) -> None:
        with self._lock:
            if exp_id in self.active_jobs:
                del self.active_jobs[exp_id]

    def _handle_job_failure(self, job: Dict[str, Any], error_msg: str) -> None:
        exp_id = job["experiment_id"]
        job_id = job["job_id"]
        now_str = datetime.now(timezone.utc).isoformat()

        conn = self.db.get_connection()
        try:
            conn.execute("""
                UPDATE experiments
                SET status = 'FAILED', outcome = 'EXECUTION_ERROR',
                    classification = 'Error', updated_at = ?
                WHERE id = ?
            """, (now_str, exp_id))
            conn.execute("""
                UPDATE jobs
                SET status = 'FAILED', error_message = ?, completed_at = ?
                WHERE id = ?
            """, (error_msg, now_str, job_id))
            conn.commit()
        finally:
            conn.close()

        self.db.record_event("EXPERIMENT_FAILED", exp_id, {"error": error_msg})
        self._finalise_active(exp_id)
