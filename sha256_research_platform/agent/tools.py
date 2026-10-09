"""
Agent Tool Registry for SHA-256 Research Platform v3.0
Defines the strictly mediated tool interface for the autonomous research agent:
  get_system_status, list_models, load_model, unload_model,
  create_hypothesis, list_hypotheses, create_experiment, run_experiment,
  get_experiment, cancel_experiment, verify_candidate, compare_experiments,
  search_evidence, read_artifact, analyze_results, benchmark_backend, generate_report.
Enforces anti-clamping and prevents arbitrary filesystem/shell/network access.
"""

import os
import re
import sys
import json
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..storage.db import DatabaseManager
from ..models.runtime import LocalModelRuntime
from ..models.hardware import probe_hardware
from ..workers.worker import ResearchWorkerPool, VerifierBridge, BinaryResolution, VerificationUnavailable
from ..rag.memory import LocalResearchMemory
from ..agent.trust import TrustLevel, EpistemicTrustManager, EpistemicIntegrityError


class ToolValidationError(Exception):
    """Raised when tool arguments fail validation or anti-clamping checks."""
    pass


class ToolRegistry:
    """Provides validated and auditable execution of tools for the autonomous agent."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        runtime: Optional[LocalModelRuntime] = None,
        worker_pool: Optional[ResearchWorkerPool] = None,
        rag_memory: Optional[LocalResearchMemory] = None,
        verifier: Optional[VerifierBridge] = None,
    ):
        self.db = db or DatabaseManager()
        self.runtime = runtime or LocalModelRuntime(self.db)
        self.worker_pool = worker_pool or ResearchWorkerPool(self.db)
        self.rag_memory = rag_memory or LocalResearchMemory(self.db, self.runtime)
        self.verifier = verifier or VerifierBridge()

        self.tools = {
            "get_system_status": self.get_system_status,
            "list_models": self.list_models,
            "load_model": self.load_model,
            "unload_model": self.unload_model,
            "create_hypothesis": self.create_hypothesis,
            "list_hypotheses": self.list_hypotheses,
            "create_experiment": self.create_experiment,
            "run_experiment": self.run_experiment,
            "get_experiment": self.get_experiment,
            "cancel_experiment": self.cancel_experiment,
            "verify_candidate": self.verify_candidate,
            "verify_preimage_candidate": self.verify_preimage_candidate,
            "compare_experiments": self.compare_experiments,
            "search_evidence": self.search_evidence,
            "read_artifact": self.read_artifact,
            "analyze_results": self.analyze_results,
            "benchmark_backend": self.benchmark_backend,
            "generate_report": self.generate_report,
        }

    def execute_tool(self, tool_name: str, args: Dict[str, Any], action_id: Optional[str] = None) -> Dict[str, Any]:
        """Validates arguments, executes tool, records execution in SQLite, and returns result."""
        if tool_name not in self.tools:
            raise ToolValidationError(f"Tool '{tool_name}' not recognized in tool registry.")

        t0 = time.perf_counter()
        is_error = False
        error_msg = ""
        result: Any = None

        try:
            result = self.tools[tool_name](args)
        except Exception as e:
            is_error = True
            error_msg = str(e)
            result = {"error": error_msg}

        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Persist tool call in SQLite
        conn = self.db.get_connection()
        try:
            call_id = f"tcall_{int(time.time()*1000)}"
            conn.execute("""
                INSERT INTO tool_calls (id, action_id, tool_name, arguments, result, is_error, execution_time_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                call_id, action_id, tool_name, json.dumps(args, sort_keys=True),
                json.dumps(result, sort_keys=True, default=str),
                is_error, latency_ms
            ))
            conn.commit()
        finally:
            conn.close()

        if is_error:
            raise ToolValidationError(error_msg)

        return result

    # 1. get_system_status
    def get_system_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        hw = probe_hardware()
        counts = self.db.get_system_counts()
        return {
            "hardware": hw.to_dict(),
            "entity_counts": counts,
            "active_workers": self.worker_pool.max_workers,
            "loaded_model": self.runtime.loaded_model_id
        }

    # 2. list_models
    def list_models(self, args: Dict[str, Any]) -> Dict[str, Any]:
        models = self.runtime.list_models()
        return {"models": models}

    # 3. load_model
    def load_model(self, args: Dict[str, Any]) -> Dict[str, Any]:
        model_id = args.get("model_id")
        if not model_id:
            raise ToolValidationError("Argument 'model_id' is required.")
        ok = self.runtime.load_model(model_id)
        return {"model_id": model_id, "loaded": ok}

    # 4. unload_model
    def unload_model(self, args: Dict[str, Any]) -> Dict[str, Any]:
        model_id = args.get("model_id")
        ok = self.runtime.unload_model(model_id)
        return {"unloaded": ok}

    # 5. create_hypothesis
    def create_hypothesis(self, args: Dict[str, Any]) -> Dict[str, Any]:
        title = args.get("title")
        description = args.get("description", "")
        falsification = args.get("falsification_criteria", "")
        if not title:
            raise ToolValidationError("Argument 'title' is required.")

        hyp_id = f"H{int(time.time()) % 100000}"
        conn = self.db.get_connection()
        try:
            conn.execute("""
                INSERT INTO hypotheses (id, project_id, title, description, falsification_criteria, trust_level)
                VALUES (?, 'proj_sha256_v3', ?, ?, ?, 'L0')
            """, (hyp_id, title, description, falsification))
            conn.commit()
        finally:
            conn.close()

        self.db.record_event("HYPOTHESIS_CREATED", hyp_id, {"title": title})
        return {"hypothesis_id": hyp_id, "title": title, "trust_level": "L0"}

    # 6. list_hypotheses
    def list_hypotheses(self, args: Dict[str, Any]) -> Dict[str, Any]:
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM hypotheses ORDER BY id")
            rows = [dict(r) for r in cur.fetchall()]
            return {"hypotheses": rows}
        finally:
            conn.close()

    # 7. create_experiment
    def create_experiment(self, args: Dict[str, Any]) -> Dict[str, Any]:
        rounds = args.get("rounds")
        hypothesis_id = args.get("hypothesis_id", "H1")
        solver = args.get("solver", "cadical")
        timeout = args.get("timeout", 60)

        if rounds is None:
            raise ToolValidationError("Argument 'rounds' is required.")

        # ANTI-CLAMPING CHECK
        rounds = int(rounds)
        if rounds < 1 or rounds > 64:
            raise ToolValidationError(
                f"Anti-clamping violation: rounds must be between 1 and 64 (got {rounds})."
            )

        exp_id = args.get("experiment_id") or f"exp_auto_{int(time.time()*1000)}"
        res = self.worker_pool.enqueue_experiment(
            experiment_id=exp_id,
            hypothesis_id=hypothesis_id,
            rounds=rounds,
            solver=solver,
            timeout=timeout,
            parameters=args
        )
        return res

    # 8. run_experiment
    def run_experiment(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return self.create_experiment(args)

    # 9. get_experiment
    def get_experiment(self, args: Dict[str, Any]) -> Dict[str, Any]:
        exp_id = args.get("experiment_id")
        if not exp_id:
            raise ToolValidationError("Argument 'experiment_id' is required.")

        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM experiments WHERE id = ?", (exp_id,))
            row = cur.fetchone()
            if not row:
                raise ToolValidationError(f"Experiment '{exp_id}' not found.")
            exp_data = dict(row)

            # Fetch verifications
            cur.execute("SELECT * FROM verifications WHERE experiment_id = ?", (exp_id,))
            exp_data["verifications"] = [dict(r) for r in cur.fetchall()]

            # Fetch artifacts
            cur.execute("SELECT * FROM artifacts WHERE experiment_id = ?", (exp_id,))
            exp_data["artifacts"] = [dict(r) for r in cur.fetchall()]

            return exp_data
        finally:
            conn.close()

    # 10. cancel_experiment
    def cancel_experiment(self, args: Dict[str, Any]) -> Dict[str, Any]:
        exp_id = args.get("experiment_id")
        if not exp_id:
            raise ToolValidationError("Argument 'experiment_id' is required.")
        ok = self.worker_pool.cancel_experiment(exp_id)
        return {"experiment_id": exp_id, "cancelled": ok}

    # 11. verify_candidate
    def verify_candidate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Submits a candidate to the segregated IndependentVerifier.

        There is no offline fallback. If the verifier binary cannot be reached,
        this raises: a cryptographic verdict must come from the independent
        engine, never from this process's own reasoning.
        """
        msg_a_hex = args.get("message_a_hex")
        msg_b_hex = args.get("message_b_hex")
        rounds = args.get("rounds", 64)

        if not msg_a_hex or not msg_b_hex:
            raise ToolValidationError("Arguments 'message_a_hex' and 'message_b_hex' are required.")

        # ANTI-CLAMPING CHECK
        rounds = int(rounds)
        if rounds < 1 or rounds > 64:
            raise ToolValidationError(f"Invalid rounds {rounds}: must be between 1 and 64.")

        try:
            verdict = self.verifier.verify_collision(msg_a_hex, msg_b_hex, rounds)
        except VerificationUnavailable as e:
            raise ToolValidationError(
                f"Independent verification unavailable: {e}. Refusing to issue a verdict."
            ) from e

        is_valid = bool(verdict["is_valid"])
        trust_level = "L3" if is_valid else "L1"

        result = {
            "is_valid": is_valid,
            "rounds": rounds,
            "actual_rounds": verdict.get("actual_rounds"),
            # Classification comes from the verifier, never synthesised here.
            "classification": verdict["classification"],
            "failure_reason": verdict.get("failure_reason", ""),
            "digest_a": verdict.get("digest_a"),
            "digest_b": verdict.get("digest_b"),
            "hamming_distance": verdict.get("hamming_distance"),
            "verified_by": verdict.get("verifier_engine"),
            "engine_segregated": verdict.get("engine_segregated"),
            "trust_level": trust_level,
        }

        # Epistemic validation
        EpistemicTrustManager.validate_promotion("L2", trust_level, result)

        return result

    # 11b. verify_preimage_candidate
    def verify_preimage_candidate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies a preimage candidate (message bytes + target digest)."""
        import base64

        message_hex = args.get("message_hex")
        target_digest = args.get("target_digest")
        rounds = args.get("rounds", 64)

        if not message_hex or not target_digest:
            raise ToolValidationError(
                "Arguments 'message_hex' and 'target_digest' are required."
            )

        rounds = int(rounds)
        if rounds < 1 or rounds > 64:
            raise ToolValidationError(f"Invalid rounds {rounds}: must be between 1 and 64.")

        try:
            message = bytes.fromhex(message_hex)
        except ValueError as e:
            raise ToolValidationError(f"message_hex is not valid hex: {e}") from e

        try:
            verdict = self.verifier.verify_preimage(message, target_digest, rounds)
        except VerificationUnavailable as e:
            raise ToolValidationError(
                f"Independent verification unavailable: {e}. Refusing to issue a verdict."
            ) from e

        is_valid = bool(verdict["is_valid"])
        trust_level = "L3" if is_valid else "L1"
        result = {
            "is_valid": is_valid,
            "rounds": rounds,
            "actual_rounds": verdict.get("actual_rounds"),
            "classification": verdict["classification"],
            "failure_reason": verdict.get("failure_reason", ""),
            "computed_digest": verdict.get("digest_a"),
            "target_digest": verdict.get("digest_b"),
            "hamming_distance": verdict.get("hamming_distance"),
            "verified_by": verdict.get("verifier_engine"),
            "engine_segregated": verdict.get("engine_segregated"),
            "trust_level": trust_level,
        }
        EpistemicTrustManager.validate_promotion("L2", trust_level, result)
        return result

    # 12. compare_experiments
    def compare_experiments(self, args: Dict[str, Any]) -> Dict[str, Any]:
        exp_ids = args.get("experiment_ids", [])
        if not exp_ids:
            raise ToolValidationError("Argument 'experiment_ids' list is required.")

        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            results = []
            for eid in exp_ids:
                cur.execute("SELECT id, status, rounds, solver, outcome, classification FROM experiments WHERE id = ?", (eid,))
                r = cur.fetchone()
                if r:
                    results.append(dict(r))
            return {"comparison": results}
        finally:
            conn.close()

    # 13. search_evidence
    def search_evidence(self, args: Dict[str, Any]) -> Dict[str, Any]:
        query = args.get("query", "")
        top_k = int(args.get("top_k", 5))
        results = self.rag_memory.search(query, top_k=top_k)
        return {"query": query, "results": [r.to_dict() for r in results]}

    # 14. read_artifact
    def read_artifact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        path = args.get("path")
        if not path:
            raise ToolValidationError("Argument 'path' is required.")

        resolved = self._resolve_within_workspace(path)
        if not resolved.is_file():
            raise ToolValidationError(f"Artifact not found: {path}")

        with open(resolved, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(16384)  # Read up to 16KB

        return {
            "path": str(resolved),
            "content": content,
            "size_bytes": resolved.stat().st_size,
        }

    def _resolve_within_workspace(self, path: str) -> Path:
        """Resolve `path` and confine it to the workspace root.

        Uses resolved-path containment rather than string prefix checks, so
        symlinks, `..` segments, and Windows drive-relative forms cannot escape.
        """
        root = Path(os.environ.get("SHA_WORKSPACE_ROOT", ".")).resolve()
        try:
            candidate = Path(path)
            if not candidate.is_absolute():
                candidate = root / candidate
            resolved = candidate.resolve()
        except (OSError, RuntimeError) as e:
            raise ToolValidationError(f"Path could not be resolved: {path}") from e

        try:
            resolved.relative_to(root)
        except ValueError as e:
            raise ToolValidationError(
                f"Path escapes the workspace root and is denied: {path}"
            ) from e

        return resolved

    # 15. analyze_results
    def analyze_results(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Derive an analysis from measured experiment data.

        Nothing here is hardcoded: every field is computed from the recorded
        run, verification, and metric rows.
        """
        exp_id = args.get("experiment_id")
        if not exp_id:
            raise ToolValidationError("Argument 'experiment_id' is required.")

        exp_info = self.get_experiment({"experiment_id": exp_id})

        conn = self.db.get_connection()
        try:
            metrics = conn.execute(
                "SELECT metric_name, metric_value, unit FROM metrics WHERE experiment_id = ?",
                (exp_id,),
            ).fetchall()
        finally:
            conn.close()

        metric_map = {m["metric_name"]: m["metric_value"] for m in metrics}
        verifications = exp_info.get("verifications", [])
        verified = [v for v in verifications if v.get("is_valid")]

        findings = []
        if not verifications:
            findings.append("No verification record exists for this experiment.")
        elif verified:
            for v in verified:
                findings.append(
                    f"Independent verifier confirmed a {v.get('classification')} candidate "
                    f"at {v.get('verified_rounds')} rounds."
                )
        else:
            for v in verifications:
                findings.append(
                    f"Independent verifier rejected the candidate: {v.get('failure_reason') or 'no reason recorded'}"
                )

        hamming = metric_map.get("verifier_hamming_distance")
        if hamming is not None:
            findings.append(f"Verifier Hamming distance: {hamming} bits (0 = exact match).")

        wall = metric_map.get("wall_time_seconds")
        if wall is not None:
            findings.append(f"Wall time: {wall:.3f} s.")

        return {
            "experiment_id": exp_id,
            "status": exp_info.get("status"),
            "outcome": exp_info.get("outcome"),
            "classification": exp_info.get("classification"),
            "rounds": exp_info.get("rounds"),
            "solver": exp_info.get("solver"),
            "metrics": metric_map,
            "verification_count": len(verifications),
            "verified_count": len(verified),
            "findings": findings,
            "analysis_source": "measured",
        }

    # 16. benchmark_backend
    def benchmark_backend(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Measure backend throughput by executing the real benchmark.

        No cached or hardcoded numbers. If the benchmark cannot run, this
        raises rather than reporting an invented figure.
        """
        backend = args.get("backend", "cpu")
        rounds = int(args.get("rounds", 16))
        if rounds < 1 or rounds > 64:
            raise ToolValidationError(f"Anti-clamping violation: rounds {rounds} out of range [1, 64]")

        try:
            exe = BinaryResolution.require()
        except FileNotFoundError as e:
            raise ToolValidationError(
                f"Cannot benchmark: research binary unavailable. {e}"
            ) from e

        proc = subprocess.run(
            [str(exe), "benchmark"],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            raise ToolValidationError(
                f"Benchmark failed (exit {proc.returncode}): {proc.stderr.strip()[:300]}"
            )

        throughput = self._parse_throughput(proc.stdout)
        return {
            "backend": backend,
            "rounds": rounds,
            "throughput_mhashes_sec": throughput,
            "measurement_source": "executed",
            "raw_output": proc.stdout.strip()[-2000:],
        }

    @staticmethod
    def _parse_throughput(stdout: str) -> Optional[float]:
        """Extract a measured throughput figure from benchmark output."""
        pattern = re.compile(
            r"([0-9]+(?:\.[0-9]+)?)\s*(MH/s|MH\/s|GH/s|M hashes|hashes/sec)",
            re.IGNORECASE,
        )
        values = []
        for m in pattern.finditer(stdout or ""):
            try:
                values.append(float(m.group(1)))
            except ValueError:
                continue
        return max(values) if values else None

    # 17. generate_report
    def generate_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        title = args.get("title", "Autonomous Cryptanalysis Report")
        content = args.get("content", "# Research Summary\nNo breakthroughs on 64-round SHA-256.")

        report_id = f"rep_{int(time.time())}"
        fname = f"reports/autonomous_campaign_{int(time.time())}.md"
        os.makedirs("reports", exist_ok=True)
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content)

        conn = self.db.get_connection()
        try:
            conn.execute("""
                INSERT INTO reports (id, title, report_type, markdown_content, file_path)
                VALUES (?, ?, 'campaign_summary', ?, ?)
            """, (report_id, title, content, fname))
            conn.commit()
        finally:
            conn.close()

        self.db.record_event("REPORT_GENERATED", report_id, {"file_path": fname})
        return {"report_id": report_id, "file_path": fname}
