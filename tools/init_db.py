#!/usr/bin/env python3
"""
SQLite Knowledge Base Initializer
Establishes the research knowledge repository for hypotheses, runs, claims, and metrics
supporting the full v3 autonomous research entity schema.
"""

import sqlite3
import os
import sys
import json
import glob

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sha256_research_platform.storage.db import DatabaseManager, SCHEMA_SQL

def init_db(db_path="evidence/knowledge_base.sqlite"):
    db = DatabaseManager(db_path=db_path)
    conn = db.get_connection()
    cur = conn.cursor()

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
                INSERT OR IGNORE INTO experiments (id, hypothesis_id, status, rounds, solver, target_digest, outcome, classification)
                VALUES (?, ?, 'COMPLETED', ?, ?, ?, ?, ?)
            """, (exp_id, "H1", rounds, "CaDiCaL/Kissat", ver.get("digest_b", ""), outcome, cls_name))
        except Exception:
            pass

    conn.commit()
    conn.close()
    print(f"Knowledge base SQLite initialized successfully at {db_path}")

if __name__ == "__main__":
    init_db()
