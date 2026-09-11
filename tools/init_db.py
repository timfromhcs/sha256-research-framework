#!/usr/bin/env python3
"""
SQLite Knowledge Base Initializer
Establishes the research knowledge repository for hypotheses, runs, claims, and metrics.
"""

import sqlite3
import os
import json
import glob

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS machine_profiles (
    id TEXT PRIMARY KEY,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    os_info TEXT,
    cpu_info TEXT,
    gpu_info TEXT,
    toolchain_info TEXT
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    title TEXT,
    description TEXT,
    falsification_criteria TEXT,
    status TEXT DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rounds INTEGER,
    solver TEXT,
    target_digest TEXT,
    outcome TEXT,
    classification TEXT,
    FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id)
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

CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,
    experiment_id TEXT,
    message_hex TEXT,
    rounds INTEGER,
    iv_hex TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id)
);

CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    candidate_id TEXT,
    is_valid BOOLEAN,
    classification TEXT,
    failure_reason TEXT,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(candidate_id) REFERENCES candidates(id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    sha256_hash TEXT PRIMARY KEY,
    relative_path TEXT,
    size_bytes INTEGER,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS claims (
    id TEXT PRIMARY KEY,
    claim_type TEXT,
    rounds INTEGER,
    verified_by_verifier BOOLEAN,
    evidence_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id TEXT,
    metric_name TEXT,
    metric_value REAL,
    unit TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

def init_db(db_path="evidence/knowledge_base.sqlite"):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA_SQL)

    # Insert default hypotheses
    default_hypotheses = [
        ("H1", "SAT-based reduced-round inversion", "SAT solvers can invert SHA-256 for <= 16 rounds in under 5 seconds.", "Timeout or UNSAT on 16 rounds"),
        ("H2", "Linear differential characteristic propagation", "MSB difference on W[1] propagates through round 2 without collision cancellation.", "Non-matching output difference ΔA"),
        ("H3", "Vulkan GPU batch speedup", "GPU compute pipeline achieves throughput scaling proportional to workgroup batch size.", "Vulkan throughput does not exceed CPU baseline")
    ]

    for h in default_hypotheses:
        cur.execute("INSERT OR IGNORE INTO hypotheses (id, title, description, falsification_criteria) VALUES (?, ?, ?, ?)", h)

    # Populate experiments from manifests (sorted for deterministic insertion order)
    manifests = sorted(glob.glob("evidence/experiments/**/manifest.json", recursive=True))
    for m in manifests:
        try:
            with open(m, "r", encoding="utf-8") as f:
                d = json.load(f)
            exp_id = d.get("experiment_id")
            ver = d.get("verification", {})
            rounds = ver.get("actual_rounds", 0)
            cls_name = d.get("classification", "Unknown")
            outcome = "CONFIRMED" if d.get("outcome_success") else "FAILED"

            cur.execute("""
                INSERT OR IGNORE INTO experiments (id, hypothesis_id, rounds, solver, target_digest, outcome, classification)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (exp_id, "H1", rounds, "CaDiCaL/Kissat", ver.get("digest_b", ""), outcome, cls_name))
        except Exception:
            pass

    conn.commit()
    conn.close()
    print(f"Knowledge base SQLite initialized successfully at {db_path}")

if __name__ == "__main__":
    init_db()
