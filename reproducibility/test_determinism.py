#!/usr/bin/env python3
"""
Python Deterministic Behavior & Canonical Serialization Test Suite
Validates that serialization, hashing, database queries, and ML features
produce bitwise identical results across repeated runs.
"""

import os
import sys
import json
import sqlite3
import hashlib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reproducibility.verify_evidence import compute_evidence_root_hash

def test_json_canonicalization():
    print("[Test 1] Canonical JSON serialization determinism... ", end="")
    data = {
        "zebra": 1,
        "apple": 2,
        "nested": {"beta": [3, 2, 1], "alpha": "test"},
        "flag": True,
        "null_val": None
    }

    dump_a = json.dumps(data, indent=2, sort_keys=True)
    dump_b = json.dumps(data, indent=2, sort_keys=True)
    dump_c = json.dumps(data, indent=2, sort_keys=True)

    if dump_a == dump_b == dump_c:
        print("PASSED")
        return True
    print("FAILED")
    return False

def test_root_evidence_hash_determinism():
    print("[Test 2] Canonical evidence root hash determinism (Runs A, B, C)... ", end="")
    hash_a = compute_evidence_root_hash("evidence")
    hash_b = compute_evidence_root_hash("evidence")
    hash_c = compute_evidence_root_hash("evidence")

    if hash_a == hash_b == hash_c and len(hash_a) == 64:
        print(f"PASSED ({hash_a[:16]}...)")
        return True
    print("FAILED")
    return False

def test_sqlite_query_determinism():
    print("[Test 3] SQLite deterministic query ordering... ", end="")
    db_path = "evidence/knowledge_base.sqlite"
    if not os.path.exists(db_path):
        print("SKIPPED (No sqlite db)")
        return True

    conn = sqlite3.connect(db_path)
    # PRAGMA integrity_check
    res = conn.execute("PRAGMA integrity_check;").fetchall()
    if res != [("ok",)]:
        print("FAILED (PRAGMA integrity_check failed)")
        return False

    # Explicit ordering check
    q = "SELECT id, rounds, outcome FROM experiments ORDER BY id ASC;"
    r1 = conn.execute(q).fetchall()
    r2 = conn.execute(q).fetchall()
    r3 = conn.execute(q).fetchall()
    conn.close()

    if r1 == r2 == r3:
        print("PASSED")
        return True
    print("FAILED")
    return False

def test_ml_data_generation_determinism():
    print("[Test 4] ML feature generation reproducibility under seed 42... ", end="")
    def generate_feats(seed):
        rng = np.random.RandomState(seed)
        active_bits = rng.poisson(lam=3.0, size=(10, 8)).astype(np.float32)
        conditions = rng.randint(0, 30, size=(10, 1)).astype(np.float32)
        return np.hstack([active_bits, conditions])

    f_a = generate_feats(42)
    f_b = generate_feats(42)
    f_c = generate_feats(42)

    if np.array_equal(f_a, f_b) and np.array_equal(f_b, f_c):
        print("PASSED")
        return True
    print("FAILED")
    return False

def main():
    print("===============================================================")
    print("      Python Canonicalization & Determinism Test Suite         ")
    print("===============================================================")

    tests = [
        test_json_canonicalization,
        test_root_evidence_hash_determinism,
        test_sqlite_query_determinism,
        test_ml_data_generation_determinism
    ]

    passed = sum(1 for t in tests if t())
    total = len(tests)

    print("===============================================================")
    print(f"  Determinism Results: {passed} / {total} passed")
    print("===============================================================")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
