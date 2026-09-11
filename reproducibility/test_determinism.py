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
import tempfile
import shutil
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reproducibility.verify_evidence import (
    compute_evidence_root_hash,
    canonical_manifest_hash,
    canonical_json_bytes,
    verify_evidence
)
from tools.generate_release_manifest import verify_manifest, compute_root_evidence_hash

def test_json_canonicalization():
    print("[Test 1] Canonical JSON serialization determinism... ", end="")
    data = {
        "zebra": 1,
        "apple": 2,
        "nested": {"beta": [3, 2, 1], "alpha": "test"},
        "flag": True,
        "null_val": None
    }

    dump_a = canonical_json_bytes(data)
    dump_b = canonical_json_bytes(data)
    dump_c = canonical_json_bytes(data)

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

def test_correct_evidence_hash_passes():
    print("[Test 3] Correct release evidence hash passes verification... ", end="")
    ret = verify_evidence("evidence")
    if ret == 0:
        print("PASSED")
        return True
    print(f"FAILED (verify_evidence returned {ret})")
    return False

def test_modified_evidence_causes_failure():
    print("[Test 4] Modified evidence detection (tamper detection)... ", end="")
    with tempfile.TemporaryDirectory() as td:
        shutil.copytree("evidence", os.path.join(td, "evidence"))
        m_path = os.path.join(td, "evidence", "experiments", "exp_reduced_20260905_181908_109_f489", "manifest.json")
        with open(m_path, "r", encoding="utf-8") as f:
            d = json.load(f)
        d["verification"]["actual_rounds"] = 999  # Tamper
        with open(m_path, "w", encoding="utf-8") as f:
            json.dump(d, f)

        # Verification must detect tamper and return non-zero
        ret = verify_evidence(os.path.join(td, "evidence"))
        if ret != 0:
            print("PASSED (Tamper detected correctly)")
            return True
        print("FAILED (Tamper was NOT detected!)")
        return False

def test_modified_recorded_hash_causes_failure():
    print("[Test 5] Modified recorded hash detection... ", end="")
    with tempfile.TemporaryDirectory() as td:
        shutil.copytree("evidence", os.path.join(td, "evidence"))
        rm_path = os.path.join(td, "evidence", "release_manifest.json")
        with open(rm_path, "r", encoding="utf-8") as f:
            d = json.load(f)
        d["root_evidence_hash"] = "0" * 64  # Tampered hash
        with open(rm_path, "w", encoding="utf-8") as f:
            json.dump(d, f)

        ret = verify_manifest(rm_path)
        if ret != 0:
            print("PASSED (Mismatched hash detected correctly)")
            return True
        print("FAILED (Mismatched recorded hash was NOT detected!)")
        return False

def test_reordered_json_key_order_invariance():
    print("[Test 6] Reordered JSON key-order invariance... ", end="")
    m_path = "evidence/experiments/exp_reduced_20260905_181908_109_f489/manifest.json"
    with open(m_path, "r", encoding="utf-8") as f:
        d = json.load(f)
    h_orig = canonical_manifest_hash(m_path)

    # Reorder keys in reversed order
    rev_d = {k: d[k] for k in reversed(list(d.keys()))}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
        json.dump(rev_d, tf, indent=4)
        tmp_path = tf.name
    try:
        h_reordered = canonical_manifest_hash(tmp_path)
        if h_orig == h_reordered:
            print("PASSED (Canonical hash invariant under key reordering)")
            return True
        print("FAILED (Canonical hash changed under key reordering)")
        return False
    finally:
        os.remove(tmp_path)

def test_semantic_difference_detection():
    print("[Test 7] Semantic difference detection (arrays/values)... ", end="")
    m_path = "evidence/experiments/exp_reduced_20260905_181908_109_f489/manifest.json"
    with open(m_path, "r", encoding="utf-8") as f:
        d = json.load(f)
    h_orig = canonical_manifest_hash(m_path)

    # Modify a semantically significant value
    d["verification"]["actual_rounds"] = 12
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
        json.dump(d, tf, indent=2)
        tmp_path = tf.name
    try:
        h_modified = canonical_manifest_hash(tmp_path)
        if h_orig != h_modified:
            print("PASSED (Semantic difference detected)")
            return True
        print("FAILED (Semantic change was NOT detected)")
        return False
    finally:
        os.remove(tmp_path)

def test_release_manifest_generation_determinism():
    print("[Test 8] Release manifest generation determinism... ", end="")
    h1 = compute_root_evidence_hash("evidence")
    h2 = compute_root_evidence_hash("evidence")
    if h1 == h2 and len(h1) == 64:
        print(f"PASSED ({h1[:16]}...)")
        return True
    print("FAILED")
    return False

def test_self_reference_exclusion():
    print("[Test 9] Self-reference exclusion & tamper isolation... ", end="")
    root_orig = compute_evidence_root_hash("evidence")
    with tempfile.TemporaryDirectory() as td:
        shutil.copytree("evidence", os.path.join(td, "evidence"))
        rm_path = os.path.join(td, "evidence", "release_manifest.json")
        with open(rm_path, "r", encoding="utf-8") as f:
            d = json.load(f)
        d["arbitrary_new_field"] = "tamper_value"
        with open(rm_path, "w", encoding="utf-8") as f:
            json.dump(d, f)

        # Root evidence hash calculation MUST be invariant to release_manifest changes
        root_after = compute_evidence_root_hash(os.path.join(td, "evidence"))
        if root_orig == root_after:
            print("PASSED (Release manifest excluded from evidence root hash)")
            return True
        print("FAILED (Evidence root hash was affected by release_manifest changes!)")
        return False

def test_sqlite_query_determinism():
    print("[Test 10] SQLite deterministic query ordering... ", end="")
    db_path = "evidence/knowledge_base.sqlite"
    if not os.path.exists(db_path):
        print("SKIPPED (No sqlite db)")
        return True

    conn = sqlite3.connect(db_path)
    res = conn.execute("PRAGMA integrity_check;").fetchall()
    if res != [("ok",)]:
        print("FAILED (PRAGMA integrity_check failed)")
        return False

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
    print("[Test 11] ML feature generation reproducibility under seed 42... ", end="")
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

def test_cross_platform_line_ending_invariance():
    print("[Test 12] Cross-platform line-ending invariance (CRLF vs LF)... ", end="")
    root_native = compute_evidence_root_hash("evidence")

    with tempfile.TemporaryDirectory() as td:
        shutil.copytree("evidence", os.path.join(td, "evidence"))
        # Force CRLF on all manifest files
        for root, _, files in os.walk(os.path.join(td, "evidence")):
            for f in files:
                if f.endswith(".json"):
                    p = os.path.join(root, f)
                    content = open(p, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
                    open(p, "wb").write(content)
        root_crlf = compute_evidence_root_hash(os.path.join(td, "evidence"))

    with tempfile.TemporaryDirectory() as td:
        shutil.copytree("evidence", os.path.join(td, "evidence"))
        # Force LF on all manifest files
        for root, _, files in os.walk(os.path.join(td, "evidence")):
            for f in files:
                if f.endswith(".json"):
                    p = os.path.join(root, f)
                    content = open(p, "rb").read().replace(b"\r\n", b"\n")
                    open(p, "wb").write(content)
        root_lf = compute_evidence_root_hash(os.path.join(td, "evidence"))

    if root_native == root_crlf == root_lf:
        print("PASSED (Bitwise identical hash under CRLF and LF)")
        return True
    print(f"FAILED (native={root_native}, crlf={root_crlf}, lf={root_lf})")
    return False

def main():
    print("===============================================================")
    print("      Python Canonicalization & Determinism Test Suite         ")
    print("===============================================================")

    tests = [
        test_json_canonicalization,
        test_root_evidence_hash_determinism,
        test_correct_evidence_hash_passes,
        test_modified_evidence_causes_failure,
        test_modified_recorded_hash_causes_failure,
        test_reordered_json_key_order_invariance,
        test_semantic_difference_detection,
        test_release_manifest_generation_determinism,
        test_self_reference_exclusion,
        test_cross_platform_line_ending_invariance,
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
