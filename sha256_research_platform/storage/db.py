"""
SQLite Research State Repository for SHA-256 Research Framework v3.0
Supports entities:
projects, research_goals, hypotheses, experiments, experiment_runs,
candidates, verifications, artifacts, models, model_runs, agent_actions,
tool_calls, observations, metrics, datasets, benchmarks, reports, jobs, events.
"""

import sqlite3
import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

SCHEMA_SQL = """
-- 1. Projects
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'ACTIVE'
);

-- 2. Research Goals
CREATE TABLE IF NOT EXISTS research_goals (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    title TEXT NOT NULL,
    target_rounds INTEGER,
    success_criteria TEXT,
    status TEXT DEFAULT 'OPEN',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);

-- 3. Hypotheses
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    goal_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    title TEXT NOT NULL,
    description TEXT,
    falsification_criteria TEXT,
    status TEXT DEFAULT 'ACTIVE',
    trust_level TEXT DEFAULT 'L0',
    FOREIGN KEY(project_id) REFERENCES projects(id),
    FOREIGN KEY(goal_id) REFERENCES research_goals(id)
);

-- 4. Experiments
CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'QUEUED',
    rounds INTEGER NOT NULL,
    solver TEXT NOT NULL,
    backend TEXT DEFAULT 'cpu',
    seed INTEGER DEFAULT 0,
    timeout INTEGER DEFAULT 60,
    parameters TEXT,
    source_commit TEXT,
    environment TEXT,
    target_digest TEXT,
    outcome TEXT,
    classification TEXT,
    FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id)
);

-- 5. Experiment Runs
CREATE TABLE IF NOT EXISTS experiment_runs (
    id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL,
    run_number INTEGER DEFAULT 1,
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    exit_code INTEGER,
    status TEXT DEFAULT 'PENDING',
    stdout_path TEXT,
    stderr_path TEXT,
    raw_output TEXT,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

-- 6. Candidates
CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,
    experiment_id TEXT,
    message_hex TEXT,
    message_b_hex TEXT,
    rounds INTEGER NOT NULL,
    iv_hex TEXT,
    is_custom_iv BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

-- 7. Verifications
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    candidate_id TEXT,
    experiment_id TEXT,
    is_valid BOOLEAN NOT NULL,
    classification TEXT NOT NULL,
    failure_reason TEXT,
    digest_a TEXT,
    digest_b TEXT,
    hamming_distance INTEGER,
    verified_rounds INTEGER,
    verifier_version TEXT DEFAULT 'v3.0.0-independent',
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(candidate_id) REFERENCES candidates(id),
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

-- 8. Artifacts
CREATE TABLE IF NOT EXISTS artifacts (
    sha256_hash TEXT PRIMARY KEY,
    experiment_id TEXT,
    relative_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    description TEXT,
    artifact_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

-- 9. Models
CREATE TABLE IF NOT EXISTS models (
    model_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    model_class TEXT NOT NULL, -- ResearchLLM, VisionLanguageModel, EmbeddingModel
    format TEXT NOT NULL,      -- GGUF, ONNX, Mock
    quantization TEXT,
    context_length INTEGER,
    runtime TEXT NOT NULL,     -- llama.cpp, directml, mock
    backend TEXT NOT NULL,     -- vulkan, cpu
    size_bytes INTEGER,
    checksum TEXT,
    capabilities TEXT,
    is_loaded BOOLEAN DEFAULT 0,
    loaded_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 10. Model Runs
CREATE TABLE IF NOT EXISTS model_runs (
    id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    latency_ms REAL DEFAULT 0.0,
    parameters TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(model_id) REFERENCES models(model_id)
);

-- 11. Agent Actions
CREATE TABLE IF NOT EXISTS agent_actions (
    id TEXT PRIMARY KEY,
    cycle_number INTEGER DEFAULT 1,
    step_type TEXT NOT NULL, -- OBSERVE, FORM_HYPOTHESIS, DESIGN_EXPERIMENT, VALIDATE_PLAN, EXECUTE, VERIFY, STORE_EVIDENCE, ANALYZE, DECIDE_NEXT_STEP
    action_name TEXT NOT NULL,
    input_payload TEXT,
    output_payload TEXT,
    trust_level TEXT DEFAULT 'L0',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 12. Tool Calls
CREATE TABLE IF NOT EXISTS tool_calls (
    id TEXT PRIMARY KEY,
    action_id TEXT,
    tool_name TEXT NOT NULL,
    arguments TEXT,
    result TEXT,
    is_error BOOLEAN DEFAULT 0,
    execution_time_ms REAL DEFAULT 0.0,
    called_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(action_id) REFERENCES agent_actions(id)
);

-- 13. Observations
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    observation_type TEXT NOT NULL, -- textual, visual, solver_metric, differential
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    confidence REAL DEFAULT 1.0,
    source_artifact TEXT,
    model_id TEXT,
    trust_level TEXT DEFAULT 'L1', -- L1 unverified observation
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(model_id) REFERENCES models(model_id)
);

-- 14. Metrics
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id TEXT,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    unit TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

-- 15. Datasets
CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    format TEXT NOT NULL,
    num_records INTEGER,
    sha256_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 16. Benchmarks
CREATE TABLE IF NOT EXISTS benchmarks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    backend TEXT NOT NULL,
    device_name TEXT,
    rounds INTEGER NOT NULL,
    batch_size INTEGER NOT NULL,
    throughput_mhashes_sec REAL NOT NULL,
    latency_ms REAL,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 17. Reports
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    report_type TEXT NOT NULL,
    markdown_content TEXT NOT NULL,
    generated_by TEXT DEFAULT 'autonomous_research_agent',
    file_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 18. Jobs
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    experiment_id TEXT,
    job_type TEXT NOT NULL,
    status TEXT DEFAULT 'QUEUED', -- QUEUED, PREPARING, RUNNING, VERIFYING, COMPLETED, FAILED, TIMEOUT, CANCELLED, ORPHANED
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

-- 19. Events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    aggregate_id TEXT,
    payload TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Backward compatibility with v2 tables
CREATE TABLE IF NOT EXISTS machine_profiles (
    id TEXT PRIMARY KEY,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    os_info TEXT,
    cpu_info TEXT,
    gpu_info TEXT,
    toolchain_info TEXT
);

CREATE TABLE IF NOT EXISTS solver_runs (
    id TEXT PRIMARY KEY,
    experiment_id TEXT,
    solver_name TEXT,
    status TEXT,
    wall_time_seconds REAL,
    conflicts INTEGER,
    decisions INTEGER,
    raw_output TEXT,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

CREATE TABLE IF NOT EXISTS claims (
    id TEXT PRIMARY KEY,
    claim_type TEXT,
    rounds INTEGER,
    verified_by_verifier BOOLEAN,
    evidence_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_experiments_status ON experiments(status);
CREATE INDEX IF NOT EXISTS idx_experiments_hypothesis ON experiments(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_verifications_experiment ON verifications(experiment_id);
CREATE INDEX IF NOT EXISTS idx_metrics_experiment ON metrics(experiment_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
"""


class DatabaseManager:
    """Manages SQLite database initialization, migrations, and operations."""

    def __init__(self, db_path: str = "evidence/knowledge_base.sqlite"):
        self.db_path = db_path
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.executescript(SCHEMA_SQL)
            self._migrate_existing_tables(cur)
            cur.executescript(INDEXES_SQL)
            self._insert_default_data(cur)
            conn.commit()
        finally:
            conn.close()

    def _migrate_existing_tables(self, cur: sqlite3.Cursor) -> None:
        """Add any missing columns to existing tables for backward compatibility."""
        migrations = {
            "experiments": {
                "status": "TEXT DEFAULT 'QUEUED'",
                "backend": "TEXT DEFAULT 'cpu'",
                "seed": "INTEGER DEFAULT 0",
                "timeout": "INTEGER DEFAULT 60",
                "parameters": "TEXT",
                "source_commit": "TEXT",
                "environment": "TEXT",
                "updated_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            },
            "verifications": {
                "experiment_id": "TEXT",
                "digest_a": "TEXT",
                "digest_b": "TEXT",
                "hamming_distance": "INTEGER",
                "verified_rounds": "INTEGER",
                "verifier_version": "TEXT DEFAULT 'v3.0.0-independent'"
            },
            "artifacts": {
                "experiment_id": "TEXT",
                "artifact_type": "TEXT"
            },
            "hypotheses": {
                "project_id": "TEXT",
                "goal_id": "TEXT",
                "trust_level": "TEXT DEFAULT 'L0'"
            },
            "candidates": {
                "message_b_hex": "TEXT",
                "is_custom_iv": "BOOLEAN DEFAULT 0"
            }
        }

        for tbl, cols in migrations.items():
            try:
                cur.execute(f"PRAGMA table_info({tbl})")
                existing_cols = {row["name"] for row in cur.fetchall()}
                for col, col_def in cols.items():
                    if col not in existing_cols:
                        try:
                            cur.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {col_def}")
                        except sqlite3.OperationalError:
                            pass
            except sqlite3.OperationalError:
                pass

    def _insert_default_data(self, cur: sqlite3.Cursor) -> None:
        """Seed default project, research goals, and foundational hypotheses."""
        cur.execute(
            "INSERT OR IGNORE INTO projects (id, name, description) VALUES (?, ?, ?)",
            ("proj_sha256_v3", "Autonomous SHA-256 Cryptanalysis", "Autonomous research platform for reduced-round SHA-256 analysis.")
        )
        cur.execute(
            "INSERT OR IGNORE INTO research_goals (id, project_id, title, target_rounds, success_criteria) VALUES (?, ?, ?, ?, ?)",
            ("goal_inversion_bounds", "proj_sha256_v3", "Determine SAT/SMT Inversion Bounds for Reduced SHA-256", 16, "Empirical inversion runtime < 60s independently verified")
        )

        default_hypotheses = [
            ("H1", "proj_sha256_v3", "goal_inversion_bounds",
             "SAT-based reduced-round inversion",
             "Modern CDCL solvers (CaDiCaL/Kissat) can invert SHA-256 up to 16 rounds within 5 seconds.",
             "Timeout or UNSAT on <= 16 rounds under standard IV", "L0"),
            ("H2", "proj_sha256_v3", "goal_inversion_bounds",
             "Linear differential characteristic propagation",
             "Single-bit difference on W[1] bit 31 propagates through round 2 without collision cancellation.",
             "Non-matching output difference delta-A at round 2", "L0"),
            ("H3", "proj_sha256_v3", "goal_inversion_bounds",
             "Vulkan GPU batch throughput scaling",
             "Vulkan compute pipeline achieves higher throughput than single-core CPU for batch sizes >= 512.",
             "Vulkan throughput <= CPU baseline throughput", "L0")
        ]

        for h in default_hypotheses:
            cur.execute(
                """INSERT OR IGNORE INTO hypotheses 
                   (id, project_id, goal_id, title, description, falsification_criteria, trust_level)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                h
            )

    # Core Query Methods
    def record_event(self, event_type: str, aggregate_id: str, payload: Dict[str, Any]) -> None:
        conn = self.get_connection()
        try:
            conn.execute(
                "INSERT INTO events (event_type, aggregate_id, payload) VALUES (?, ?, ?)",
                (event_type, aggregate_id, json.dumps(payload, sort_keys=True))
            )
            conn.commit()
        finally:
            conn.close()

    def get_system_counts(self) -> Dict[str, int]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            counts = {}
            for tbl in ["hypotheses", "experiments", "experiment_runs", "candidates", "verifications", "artifacts", "models", "jobs", "reports"]:
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                counts[tbl] = cur.fetchone()[0]
            return counts
        finally:
            conn.close()
