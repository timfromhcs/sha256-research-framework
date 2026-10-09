"""
Autonomous Research Loop for SHA-256 Research Platform v3.1

Nine-stage cycle:
  OBSERVE -> FORM_HYPOTHESIS -> DESIGN_EXPERIMENT -> VALIDATE_PLAN ->
  EXECUTE -> VERIFY -> STORE_EVIDENCE -> ANALYZE -> DECIDE_NEXT_STEP

Integrity contract:
  * Stage VERIFY records L1 on entry. Promotion to L3 happens only via
    EpistemicTrustManager and only when an IndependentVerifier verdict is
    present. The loop never asserts a trust level it has not earned.
  * A missing or unverifiable experiment yields REFUTED / NoSolutionFound,
    never a pass. There is no code path from "no evidence" to "verified".
  * Every cycle emits a replayable manifest.
"""

import time
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..storage.db import DatabaseManager
from ..models.runtime import LocalModelRuntime
from ..workers.worker import ResearchWorkerPool, VerifierBridge, VerificationUnavailable
from ..agent.tools import ToolRegistry, ToolValidationError
from ..agent.trust import TrustLevel, EpistemicTrustManager


class AutonomousResearchCampaign:
    """Executes multi-stage autonomous cryptanalysis research campaigns."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        tool_registry: Optional[ToolRegistry] = None,
        worker_pool: Optional[ResearchWorkerPool] = None,
        verifier: Optional[VerifierBridge] = None,
    ):
        self.db = db or DatabaseManager()
        self.worker_pool = worker_pool or ResearchWorkerPool(
            self.db, verifier=verifier
        )
        self.verifier = self.worker_pool.verifier
        self.tools = tool_registry or ToolRegistry(
            db=self.db, worker_pool=self.worker_pool
        )
        self.worker_pool.start()
        self.is_active = False
        self.cycle_count = 0
        self.manifest_dir = Path("evidence/cycles")

    def run_cycle(self, target_rounds: int = 4, solver: str = "cadical") -> Dict[str, Any]:
        """Execute one complete 9-stage autonomous research cycle."""
        self.cycle_count += 1
        cycle_id = self.cycle_count
        summary: Dict[str, Any] = {"cycle": cycle_id, "stages": {}}

        # Stage 1: OBSERVE ------------------------------------------------
        action_id_obs = self._record_action(cycle_id, "OBSERVE", "get_system_status", "L1")
        sys_status = self.tools.execute_tool("get_system_status", {}, action_id=action_id_obs)
        summary["stages"]["OBSERVE"] = sys_status

        # Stage 2: FORM_HYPOTHESIS ----------------------------------------
        action_id_hyp = self._record_action(cycle_id, "FORM_HYPOTHESIS", "create_hypothesis", "L0")
        hyp_res = self.tools.execute_tool("create_hypothesis", {
            "title": f"SAT Inversion Bound for {target_rounds} Rounds",
            "description": (
                f"Test whether {solver} finds an independently verifiable 1-block "
                f"preimage for the {target_rounds}-round SHA-256 compression function."
            ),
            "falsification_criteria": (
                f"UNSAT, solver timeout, or a candidate that the IndependentVerifier "
                f"rejects at {target_rounds} rounds."
            ),
        }, action_id=action_id_hyp)
        summary["stages"]["FORM_HYPOTHESIS"] = hyp_res

        # Stage 3: DESIGN_EXPERIMENT --------------------------------------
        action_id_des = self._record_action(cycle_id, "DESIGN_EXPERIMENT", "plan_parameters", "L0")
        exp_plan = {
            "hypothesis_id": hyp_res["hypothesis_id"],
            "rounds": target_rounds,
            "solver": solver,
            "timeout": 60,
            "seed": 42,
        }
        self._record_action_output(action_id_des, exp_plan)
        summary["stages"]["DESIGN_EXPERIMENT"] = exp_plan

        # Stage 4: VALIDATE_PLAN (anti-clamping) ---------------------------
        action_id_val = self._record_action(cycle_id, "VALIDATE_PLAN", "validate_constraints", "L0")
        if target_rounds < 1 or target_rounds > 64:
            raise ToolValidationError(
                f"Invalid plan: rounds {target_rounds} violates anti-clamping [1, 64]."
            )
        validation_status = {"valid": True, "target_rounds": target_rounds}
        self._record_action_output(action_id_val, validation_status)
        summary["stages"]["VALIDATE_PLAN"] = validation_status

        # Stage 5: EXECUTE --------------------------------------------------
        action_id_exe = self._record_action(cycle_id, "EXECUTE", "run_experiment", "L2")
        exp_id = f"exp_cycle{cycle_id}_{int(time.time() * 1000)}"
        run_res = self.tools.execute_tool("run_experiment", {
            "experiment_id": exp_id,
            "hypothesis_id": hyp_res["hypothesis_id"],
            "rounds": target_rounds,
            "solver": solver,
            "timeout": 60,
        }, action_id=action_id_exe)
        summary["stages"]["EXECUTE"] = run_res

        self.worker_pool.job_queue.join()
        time.sleep(0.1)

        # Stage 6: VERIFY ---------------------------------------------------
        # Recorded as L1 on entry. Promotion is earned, not assumed.
        action_id_ver = self._record_action(cycle_id, "VERIFY", "get_experiment", "L1")
        exp_details = self.tools.execute_tool(
            "get_experiment", {"experiment_id": exp_id}, action_id=action_id_ver
        )

        verifications = exp_details.get("verifications", [])
        independent_verdicts = [
            v for v in verifications if v.get("verified_by") == "IndependentVerifier"
        ]
        verified = [v for v in independent_verdicts if v.get("is_valid")]

        trust_level = "L1"
        if verified:
            EpistemicTrustManager.validate_promotion("L1", "L3", dict(verified[0]))
            trust_level = "L3"

        ver_summary = {
            "verified": bool(verified),
            "verifications_recorded": len(verifications),
            "independent_verdicts": len(independent_verdicts),
            "trust_level": trust_level,
            "classification": exp_details.get("classification"),
            "experiment_status": exp_details.get("status"),
            "outcome": exp_details.get("outcome"),
            "promotion_basis": (
                "IndependentVerifier confirmed candidate digest"
                if verified else
                "No independent verification available; level remains L1"
            ),
        }
        summary["stages"]["VERIFY"] = ver_summary
        self._record_action_output(action_id_ver, ver_summary)

        # Stage 7: STORE_EVIDENCE ------------------------------------------
        action_id_sto = self._record_action(cycle_id, "STORE_EVIDENCE", "verify_evidence_package", "L1")
        artifacts = exp_details.get("artifacts", [])
        sto_summary = {
            "artifacts_count": len(artifacts),
            "status": "stored_and_hashed" if artifacts else "no_artifacts_recorded",
        }
        self._record_action_output(action_id_sto, sto_summary)
        summary["stages"]["STORE_EVIDENCE"] = sto_summary

        # Stage 8: ANALYZE --------------------------------------------------
        action_id_ana = self._record_action(cycle_id, "ANALYZE", "analyze_results", "L1")
        try:
            ana_res = self.tools.execute_tool(
                "analyze_results", {"experiment_id": exp_id}, action_id=action_id_ana
            )
        except ToolValidationError as e:
            ana_res = {"error": str(e), "analysis_source": "unavailable"}
        summary["stages"]["ANALYZE"] = ana_res

        # Stage 9: DECIDE_NEXT_STEP ----------------------------------------
        action_id_dec = self._record_action(cycle_id, "DECIDE_NEXT_STEP", "plan_next", "L0")
        next_step = self._decide_next_step(target_rounds, bool(verified), exp_details)
        self._record_action_output(action_id_dec, next_step)
        summary["stages"]["DECIDE_NEXT_STEP"] = next_step

        summary["trust_level"] = trust_level
        manifest_path = self._write_cycle_manifest(cycle_id, summary, exp_plan)
        summary["manifest_path"] = str(manifest_path)

        self.db.record_event("CAMPAIGN_CYCLE_COMPLETED", f"cycle_{cycle_id}", {
            "verified": bool(verified),
            "trust_level": trust_level,
            "next_step": next_step,
        })
        return summary

    def _decide_next_step(self, target_rounds: int, verified: bool, exp_details: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic escalation policy driven by measured outcomes only."""
        status = (exp_details.get("status") or "").upper()

        if status == "FAILED":
            decision = "abort_infrastructure"
            next_rounds = target_rounds
            rationale = (
                "Experiment failed at the infrastructure level (missing binary or "
                "verifier). Escalation is meaningless until the toolchain is repaired."
            )
        elif verified:
            decision = "escalate"
            next_rounds = min(target_rounds + 1, 64)
            rationale = (
                f"Round {target_rounds} produced an independently verified preimage. "
                f"Increase the round count by one to locate the empirical wall."
            )
        else:
            # Distinguish "no solution at this round" from "not actually run".
            if status in ("COMPLETED", "REJECTED"):
                decision = "hold_and_retry"
                next_rounds = target_rounds
                rationale = (
                    f"Round {target_rounds} completed without an independently verified "
                    f"candidate. The wall may be here, or the solver may simply need a "
                    f"longer timeout or a different encoding. Re-probe before escalating."
                )
            else:
                decision = "hold_and_retry"
                next_rounds = target_rounds
                rationale = (
                    f"Round {target_rounds} ended in state '{status}'. No promotion is "
                    f"possible without an IndependentVerifier verdict."
                )

        return {
            "decision": decision,
            "current_rounds": target_rounds,
            "next_target_rounds": next_rounds,
            "rationale": rationale,
        }

    def _write_cycle_manifest(
        self, cycle_id: int, summary: Dict[str, Any], plan: Dict[str, Any]
    ) -> Path:
        """Write a replayable, timestamp-free cycle manifest.

        Timestamps live in a sidecar so the manifest hash stays deterministic
        across replays of the same inputs.
        """
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "cycle": cycle_id,
            "plan": plan,
            "stages": {
                k: v for k, v in summary.get("stages", {}).items()
            },
            "trust_level": summary.get("trust_level"),
        }
        manifest_path = self.manifest_dir / f"cycle_{cycle_id:04d}.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True, default=str)

        sidecar = self.manifest_dir / f"cycle_{cycle_id:04d}.meta.json"
        with open(sidecar, "w", encoding="utf-8") as f:
            json.dump({
                "cycle": cycle_id,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2, sort_keys=True)

        return manifest_path

    def _record_action(self, cycle: int, step_type: str, action_name: str, trust_level: str) -> str:
        action_id = f"act_{cycle}_{step_type}_{int(time.time() * 1000)}"
        conn = self.db.get_connection()
        try:
            conn.execute("""
                INSERT INTO agent_actions (id, cycle_number, step_type, action_name, trust_level)
                VALUES (?, ?, ?, ?, ?)
            """, (action_id, cycle, step_type, action_name, trust_level))
            conn.commit()
        finally:
            conn.close()
        return action_id

    def _record_action_output(self, action_id: str, output: Any) -> None:
        conn = self.db.get_connection()
        try:
            conn.execute(
                "UPDATE agent_actions SET output_payload = ? WHERE id = ?",
                (json.dumps(output, default=str), action_id),
            )
            conn.commit()
        finally:
            conn.close()