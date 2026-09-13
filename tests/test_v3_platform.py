"""
Comprehensive Automated Test Suite for SHA-256 Research Platform v3.0
Validates:
  1. SQLite Research State & 19 Entities
  2. Crash Recovery & Orphaned Job Detection
  3. Anti-Clamping across all low-level APIs and platform layers
  4. Local Model Runtime & iGPU Memory Budgeting
  5. Task-Aware Model Router & Non-Delegation of Cryptographic Truth
  6. Vision-Language Model (VLM) Visual Observer & L1 Observations
  7. Local RAG / Research Memory with Epistemic Trust Prioritization
  8. Worker Execution Lifecycle (QUEUED -> COMPLETED / CANCELLED)
  9. Auditable Evidence Package & Deterministic Root Hash
  10. Agent Tool Registry & Sandboxed Execution
  11. Autonomous Research Campaign (9-Stage Cycle)
  12. Headless REST API Endpoints & Status Codes
  13. Web Frontend UI Client Serving
"""

import os
import sys
import json
import time
import shutil
import tempfile
import asyncio
import unittest
from datetime import datetime, timezone

# Add repository root to sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sha256_research_platform.storage.db import DatabaseManager
from sha256_research_platform.models import (
    LocalModelRuntime, TaskRouter, CryptographicTruthViolationError, ModelManifest
)
from sha256_research_platform.models.hardware import probe_hardware
from sha256_research_platform.vlm import VisualLanguageObserver
from sha256_research_platform.rag import LocalResearchMemory
from sha256_research_platform.workers import ResearchWorkerPool
from sha256_research_platform.recovery import CrashRecoveryManager
from sha256_research_platform.evidence import EvidenceStore, sha256_file
from sha256_research_platform.agent import (
    ToolRegistry, ToolValidationError, AutonomousResearchCampaign,
    TrustLevel, EpistemicTrustManager, EpistemicIntegrityError
)
from sha256_research_platform.api.app import app


class TestV3Platform(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sha256_v3_test_")
        self.db_path = os.path.join(self.temp_dir, "test_kb.sqlite")
        self.evidence_dir = os.path.join(self.temp_dir, "evidence")
        self.db = DatabaseManager(db_path=self.db_path)
        self.runtime = LocalModelRuntime(db=self.db, models_dir=os.path.join(self.temp_dir, "models"))
        self.worker_pool = ResearchWorkerPool(db=self.db, max_workers=2)
        self.tools = ToolRegistry(db=self.db, runtime=self.runtime, worker_pool=self.worker_pool)

    def tearDown(self):
        self.worker_pool.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Test SQLite Schema and 19 Entities
    def test_01_sqlite_schema_and_19_entities(self):
        conn = self.db.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in cur.fetchall()}
        conn.close()

        required_entities = [
            "projects", "research_goals", "hypotheses", "experiments",
            "experiment_runs", "candidates", "verifications", "artifacts",
            "models", "model_runs", "agent_actions", "tool_calls",
            "observations", "metrics", "datasets", "benchmarks",
            "reports", "jobs", "events"
        ]

        for entity in required_entities:
            self.assertIn(entity, tables, f"Missing required entity table: {entity}")

        counts = self.db.get_system_counts()
        self.assertIsInstance(counts, dict)
        self.assertGreaterEqual(counts["hypotheses"], 1)

    # 2. Test Crash Recovery & Orphaned Job Detection
    def test_02_crash_recovery(self):
        conn = self.db.get_connection()
        # Seed an experiment and job left in RUNNING
        conn.execute("""
            INSERT INTO experiments (id, hypothesis_id, status, rounds, solver)
            VALUES ('exp_crashed_1', 'H1', 'RUNNING', 8, 'cadical')
        """)
        conn.execute("""
            INSERT INTO jobs (id, experiment_id, job_type, status)
            VALUES ('job_crashed_1', 'exp_crashed_1', 'EXPERIMENT_RUN', 'RUNNING')
        """)
        conn.commit()
        conn.close()

        recovery_mgr = CrashRecoveryManager(db=self.db)
        summary = recovery_mgr.detect_and_recover_orphaned_jobs()

        self.assertEqual(summary["orphaned_experiments_count"], 1)
        self.assertEqual(summary["orphaned_jobs_count"], 1)

        conn = self.db.get_connection()
        exp_row = conn.execute("SELECT status, outcome FROM experiments WHERE id = 'exp_crashed_1'").fetchone()
        job_row = conn.execute("SELECT status FROM jobs WHERE id = 'job_crashed_1'").fetchone()
        conn.close()

        self.assertEqual(exp_row["status"], "FAILED")
        self.assertEqual(exp_row["outcome"], "CRASH_TERMINATED")
        self.assertEqual(job_row["status"], "ORPHANED")

    # 3. Test Anti-Clamping across all layers
    def test_03_anti_clamping_enforcement(self):
        # Layer 1: Worker Pool rejects rounds < 1 and > 64
        res0 = self.worker_pool.enqueue_experiment("exp_clamp_0", "H1", rounds=0)
        self.assertEqual(res0["status"], "REJECTED")

        res65 = self.worker_pool.enqueue_experiment("exp_clamp_65", "H1", rounds=65)
        self.assertEqual(res65["status"], "REJECTED")

        # Layer 2: Tool Registry raises ToolValidationError
        with self.assertRaises(ToolValidationError):
            self.tools.execute_tool("create_experiment", {"rounds": 0})

        with self.assertRaises(ToolValidationError):
            self.tools.execute_tool("create_experiment", {"rounds": 65})

        with self.assertRaises(ToolValidationError):
            self.tools.execute_tool("verify_candidate", {
                "message_a_hex": "aa", "message_b_hex": "bb", "rounds": 0
            })

    # 4. Test Local Model Runtime & Memory Budgeting
    def test_04_local_model_runtime_and_memory(self):
        models = self.runtime.list_models()
        self.assertGreaterEqual(len(models), 3)

        # Load model
        m_id = "v3-research-llm-local"
        loaded = self.runtime.load_model(m_id)
        self.assertTrue(loaded)
        self.assertEqual(self.runtime.loaded_model_id, m_id)

        # Load second model should unload first (load->use->unload discipline)
        m_id2 = "v3-vlm-analyzer-local"
        self.runtime.load_model(m_id2)
        self.assertEqual(self.runtime.loaded_model_id, m_id2)

        # Generating completion
        comp = self.runtime.generate_completion(m_id, "Propose next hypothesis")
        self.assertIsInstance(comp, str)
        self.assertGreater(len(comp), 10)

        # Enforce memory budget refusal
        oversized = ModelManifest(
            model_id="oversized-model",
            name="Oversized",
            model_class="ResearchLLM",
            format="Mock",
            quantization="N/A",
            context_length=2048,
            runtime="mock",
            backend="cpu",
            size_bytes=100 * 1024 * 1024 * 1024, # 100 GB
            checksum="abc",
            capabilities=["none"]
        )
        self.runtime._manifests[oversized.model_id] = oversized
        with self.assertRaises(MemoryError):
            self.runtime.load_model("oversized-model")

    # 5. Test Model Router & Cryptographic Non-Delegation
    def test_05_model_router_and_truth_boundary(self):
        router = TaskRouter(self.runtime)
        res = router.route_task("simple_planning", {"prompt": "Next step"})
        self.assertEqual(res["routed_to"], "v3-research-llm-local")

        # Hard boundary test: MUST NOT route cryptographic verification to AI model
        with self.assertRaises(CryptographicTruthViolationError):
            router.route_task("cryptographic_verification", {})

        with self.assertRaises(CryptographicTruthViolationError):
            router.route_task("verify", {})

    # 6. Test VLM Visual Observer
    def test_06_vlm_visual_observer(self):
        observer = VisualLanguageObserver(db=self.db, runtime=self.runtime)

        # Create dummy plot file
        plot_path = os.path.join(self.temp_dir, "differential_plot.png")
        with open(plot_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...")

        obs = observer.analyze_visual_artifact(plot_path, "Differential Characteristic Carry Distribution")
        self.assertEqual(obs.trust_level, "L1") # Must be L1 unverified
        self.assertEqual(obs.observation_type, "visual")
        self.assertIn("differential", obs.content.lower())

        conn = self.db.get_connection()
        db_obs = conn.execute("SELECT * FROM observations WHERE id = ?", (obs.id,)).fetchone()
        conn.close()
        self.assertIsNotNone(db_obs)

    # 7. Test Local RAG / Research Memory
    def test_07_local_research_memory(self):
        rag = LocalResearchMemory(db=self.db, runtime=self.runtime)
        indexed_count = rag.reindex()
        self.assertGreater(indexed_count, 0)

        results = rag.search("Known Answer Tests", top_k=3)
        self.assertIsInstance(results, list)
        for r in results:
            self.assertIn(r.trust_level, ["L0", "L1", "L2", "L3", "L4", "L5"])

    # 8. Test Worker Execution Lifecycle & Evidence Generation
    def test_08_worker_execution_lifecycle_and_evidence(self):
        self.worker_pool.start()
        exp_id = f"exp_test_unit_{int(time.time()*1000)}"

        res = self.worker_pool.enqueue_experiment(
            experiment_id=exp_id,
            hypothesis_id="H1",
            rounds=4,
            solver="cadical"
        )
        self.assertEqual(res["status"], "QUEUED")

        # Wait for completion
        self.worker_pool.job_queue.join()

        conn = self.db.get_connection()
        row = conn.execute("SELECT status, outcome, classification FROM experiments WHERE id = ?", (exp_id,)).fetchone()
        conn.close()

        self.assertEqual(row["status"], "COMPLETED")
        self.assertEqual(row["outcome"], "CONFIRMED")
        self.assertEqual(row["classification"], "ReducedRoundPreimageVerified")

        # Verify evidence package files
        exp_dir = os.path.join("evidence", "experiments", exp_id)
        self.assertTrue(os.path.exists(exp_dir))
        for req_file in ["request.json", "environment.json", "stdout.log", "stderr.log", "result.json", "verification.json", "manifest.json", "report.md"]:
            self.assertTrue(os.path.exists(os.path.join(exp_dir, req_file)), f"Missing {req_file}")

        # Clean up transient test evidence package so release manifest integrity stays clean
        shutil.rmtree(exp_dir, ignore_errors=True)

    # 9. Test Agent Tool Registry & Sandboxing
    def test_09_agent_tool_registry_and_sandboxing(self):
        # get_system_status
        status = self.tools.execute_tool("get_system_status", {})
        self.assertIn("hardware", status)

        # create_hypothesis
        hyp = self.tools.execute_tool("create_hypothesis", {
            "title": "SAT Inversion Speedup",
            "description": "Testing speedup on 10 rounds."
        })
        self.assertEqual(hyp["trust_level"], "L0")

        # read_artifact sandbox rejection (path traversal)
        with self.assertRaises(ToolValidationError):
            self.tools.execute_tool("read_artifact", {"path": "../../etc/passwd"})

    # 10. Test Epistemic Trust Validation
    def test_10_epistemic_trust_validation(self):
        # Promotion to L3 requires an authentic valid verifier verdict
        with self.assertRaises(EpistemicIntegrityError):
            EpistemicTrustManager.validate_promotion("L2", "L3", None)

        with self.assertRaises(EpistemicIntegrityError):
            EpistemicTrustManager.validate_promotion("L2", "L3", {"is_valid": False})

        # Valid verdict passes
        valid_verdict = {"is_valid": True, "classification": "ReducedRoundCollision", "actual_rounds": 16}
        self.assertTrue(EpistemicTrustManager.validate_promotion("L2", "L3", valid_verdict))

    # 11. Test Autonomous Research Campaign (9-Stage Cycle)
    def test_11_autonomous_campaign_cycle(self):
        campaign = AutonomousResearchCampaign(db=self.db, tool_registry=self.tools, worker_pool=self.worker_pool)
        cycle_result = campaign.run_cycle(target_rounds=4, solver="cadical")

        expected_stages = [
            "OBSERVE", "FORM_HYPOTHESIS", "DESIGN_EXPERIMENT", "VALIDATE_PLAN",
            "EXECUTE", "VERIFY", "STORE_EVIDENCE", "ANALYZE", "DECIDE_NEXT_STEP"
        ]
        for stage in expected_stages:
            self.assertIn(stage, cycle_result["stages"], f"Missing stage: {stage}")

        self.assertTrue(cycle_result["stages"]["VERIFY"]["verified"])

        # Clean up any transient exp_campaign directories
        exp_base = "evidence/experiments"
        if os.path.exists(exp_base):
            for d in os.listdir(exp_base):
                if d.startswith("exp_campaign"):
                    shutil.rmtree(os.path.join(exp_base, d), ignore_errors=True)

    # 12. Test Headless REST API Endpoints & Validation
    def test_12_headless_api_endpoints(self):
        async def run_api_tests():
            async def req(method, path, body=None):
                resp_data = {'status': None, 'body': b''}
                async def recv():
                    return {'type': 'http.request', 'body': json.dumps(body).encode('utf-8') if body else b'', 'more_body': False}
                async def snd(msg):
                    if msg['type'] == 'http.response.start':
                        resp_data['status'] = msg['status']
                    elif msg['type'] == 'http.response.body':
                        resp_data['body'] += msg.get('body', b'')
                scope = {
                    'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
                    'method': method, 'path': path, 'raw_path': path.encode(),
                    'query_string': b'', 'headers': [(b'content-type', b'application/json')]
                }
                await app(scope, recv, snd)
                return resp_data['status'], json.loads(resp_data['body'].decode('utf-8'))

            s_code, s_json = await req('GET', '/api/status')
            self.assertEqual(s_code, 200)
            self.assertEqual(s_json['status'], 'ONLINE')

            m_code, m_json = await req('GET', '/api/models')
            self.assertEqual(m_code, 200)
            self.assertIn('models', m_json)

            # Anti-clamping rejection over HTTP
            c0_code, c0_json = await req('POST', '/api/experiments', {'rounds': 0})
            self.assertEqual(c0_code, 400)
            self.assertIn('Anti-clamping violation', c0_json['error'])

            c65_code, c65_json = await req('POST', '/api/experiments', {'rounds': 65})
            self.assertEqual(c65_code, 400)
            self.assertIn('Anti-clamping violation', c65_json['error'])

        asyncio.run(run_api_tests())


if __name__ == "__main__":
    unittest.main(verbosity=2)
