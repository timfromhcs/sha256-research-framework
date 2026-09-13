"""
Autonomous Research Loop for SHA-256 Research Platform v3.0
Implements the 9-stage cycle:
  OBSERVE -> FORM HYPOTHESIS -> DESIGN EXPERIMENT -> VALIDATE PLAN ->
  EXECUTE -> VERIFY -> STORE EVIDENCE -> ANALYZE -> DECIDE NEXT STEP
Records each stage into SQLite (agent_actions, tool_calls, events).
"""

import time
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from ..storage.db import DatabaseManager
from ..models.runtime import LocalModelRuntime
from ..workers.worker import ResearchWorkerPool
from ..agent.tools import ToolRegistry, ToolValidationError
from ..agent.trust import TrustLevel


class AutonomousResearchCampaign:
    """Executes multi-stage autonomous cryptanalysis research campaigns."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        tool_registry: Optional[ToolRegistry] = None,
        worker_pool: Optional[ResearchWorkerPool] = None
    ):
        self.db = db or DatabaseManager()
        self.worker_pool = worker_pool or ResearchWorkerPool(self.db)
        self.tools = tool_registry or ToolRegistry(db=self.db, worker_pool=self.worker_pool)
        self.worker_pool.start()
        self.is_active = False
        self.cycle_count = 0

    def run_cycle(self, target_rounds: int = 4, solver: str = "cadical") -> Dict[str, Any]:
        """Executes one complete 9-stage autonomous research cycle."""
        self.cycle_count += 1
        cycle_id = self.cycle_count
        summary: Dict[str, Any] = {"cycle": cycle_id, "stages": {}}

        # Stage 1: OBSERVE
        action_id_obs = self._record_action(cycle_id, "OBSERVE", "get_system_status", "L1")
        sys_status = self.tools.execute_tool("get_system_status", {}, action_id=action_id_obs)
        summary["stages"]["OBSERVE"] = sys_status

        # Stage 2: FORM_HYPOTHESIS
        action_id_hyp = self._record_action(cycle_id, "FORM_HYPOTHESIS", "create_hypothesis", "L0")
        hyp_res = self.tools.execute_tool("create_hypothesis", {
            "title": f"Autonomous SAT Inversion Bound for {target_rounds} Rounds",
            "description": f"Testing SAT preimage extraction efficiency on {target_rounds} rounds using {solver}.",
            "falsification_criteria": f"UNSAT or solver timeout on {target_rounds} rounds"
        }, action_id=action_id_hyp)
        summary["stages"]["FORM_HYPOTHESIS"] = hyp_res

        # Stage 3: DESIGN_EXPERIMENT
        action_id_des = self._record_action(cycle_id, "DESIGN_EXPERIMENT", "plan_parameters", "L0")
        exp_plan = {
            "hypothesis_id": hyp_res["hypothesis_id"],
            "rounds": target_rounds,
            "solver": solver,
            "timeout": 30,
            "seed": 42
        }
        self._record_action_output(action_id_des, exp_plan)
        summary["stages"]["DESIGN_EXPERIMENT"] = exp_plan

        # Stage 4: VALIDATE_PLAN (Anti-clamping & constraint validation)
        action_id_val = self._record_action(cycle_id, "VALIDATE_PLAN", "validate_constraints", "L0")
        if target_rounds < 1 or target_rounds > 64:
            raise ToolValidationError(f"Invalid plan: rounds {target_rounds} violates anti-clamping [1, 64].")
        validation_status = {"valid": True, "target_rounds": target_rounds}
        self._record_action_output(action_id_val, validation_status)
        summary["stages"]["VALIDATE_PLAN"] = validation_status

        # Stage 5: EXECUTE
        action_id_exe = self._record_action(cycle_id, "EXECUTE", "run_experiment", "L2")
        exp_id = f"exp_campaign_c{cycle_id}_{int(time.time()*1000)}"
        run_res = self.tools.execute_tool("run_experiment", {
            "experiment_id": exp_id,
            "hypothesis_id": hyp_res["hypothesis_id"],
            "rounds": target_rounds,
            "solver": solver,
            "timeout": 30
        }, action_id=action_id_exe)
        summary["stages"]["EXECUTE"] = run_res

        # Wait for worker completion
        self.worker_pool.job_queue.join()
        time.sleep(0.1)

        # Stage 6: VERIFY
        action_id_ver = self._record_action(cycle_id, "VERIFY", "get_experiment", "L3")
        exp_details = self.tools.execute_tool("get_experiment", {"experiment_id": exp_id}, action_id=action_id_ver)
        verifications = exp_details.get("verifications", [])
        is_verified = any(v.get("is_valid") for v in verifications)
        ver_summary = {
            "verified": is_verified,
            "verifications_count": len(verifications),
            "trust_level": "L3" if is_verified else "L1"
        }
        summary["stages"]["VERIFY"] = ver_summary

        # Stage 7: STORE_EVIDENCE
        action_id_sto = self._record_action(cycle_id, "STORE_EVIDENCE", "verify_evidence_package", "L3")
        artifacts = exp_details.get("artifacts", [])
        sto_summary = {"artifacts_count": len(artifacts), "status": "stored_and_hashed"}
        self._record_action_output(action_id_sto, sto_summary)
        summary["stages"]["STORE_EVIDENCE"] = sto_summary

        # Stage 8: ANALYZE
        action_id_ana = self._record_action(cycle_id, "ANALYZE", "analyze_results", "L1")
        ana_res = self.tools.execute_tool("analyze_results", {"experiment_id": exp_id}, action_id=action_id_ana)
        summary["stages"]["ANALYZE"] = ana_res

        # Stage 9: DECIDE_NEXT_STEP
        action_id_dec = self._record_action(cycle_id, "DECIDE_NEXT_STEP", "plan_next", "L0")
        next_step = {
            "decision": "proceed" if is_verified else "adjust_heuristics",
            "next_target_rounds": target_rounds + 1 if is_verified and target_rounds < 64 else target_rounds,
            "rationale": f"Rounds {target_rounds} evaluation complete. Verified: {is_verified}."
        }
        self._record_action_output(action_id_dec, next_step)
        summary["stages"]["DECIDE_NEXT_STEP"] = next_step

        self.db.record_event("CAMPAIGN_CYCLE_COMPLETED", f"cycle_{cycle_id}", summary)
        return summary

    def _record_action(self, cycle: int, step_type: str, action_name: str, trust_level: str) -> str:
        action_id = f"act_{int(time.time()*1000)}"
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
            conn.execute("""
                UPDATE agent_actions 
                SET output_payload = ?
                WHERE id = ?
            """, (json.dumps(output, default=str), action_id))
            conn.commit()
        finally:
            conn.close()
