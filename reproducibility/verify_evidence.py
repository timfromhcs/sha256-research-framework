#!/usr/bin/env python3
"""
Evidence Integrity & Hash Verification Script
Validates all SHA-256 artifact hashes, manifests, and candidate digests.
"""

import os
import sys
import glob
import json
import hashlib

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def verify_evidence(evidence_dir="evidence"):
    print("===============================================================")
    print("        SHA-256 Evidence Integrity & Anti-Tamper Check        ")
    print("===============================================================")

    manifests = glob.glob(f"{evidence_dir}/experiments/**/manifest.json", recursive=True)
    if not manifests:
        print(f"Warning: No manifests found in {evidence_dir}/experiments.")
        return 0

    total_artifacts = 0
    tamper_detected = False

    for m_path in manifests:
        exp_dir = os.path.dirname(m_path)
        print(f"\nVerifying manifest: {m_path}")
        with open(m_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        exp_id = data.get("experiment_id")
        artifacts = data.get("artifacts", [])

        for a in artifacts:
            rel_path = a.get("path")
            expected_hash = a.get("sha256")
            full_path = os.path.join(exp_dir, rel_path)

            if not os.path.exists(full_path):
                print(f"  [ERROR] Artifact missing: {full_path}")
                tamper_detected = True
                continue

            actual_hash = sha256_file(full_path)
            if actual_hash.lower() != expected_hash.lower():
                print(f"  [TAMPER DETECTED] Hash mismatch for {rel_path}:")
                print(f"    Expected: {expected_hash}")
                print(f"    Actual:   {actual_hash}")
                tamper_detected = True
            else:
                print(f"  [OK] {rel_path} ({actual_hash[:16]}...)")
            total_artifacts += 1

        # Check verifier section
        ver = data.get("verification", {})
        if ver.get("is_valid", False):
            # Verify candidate digests
            da = ver.get("digest_a")
            db = ver.get("digest_b")
            if da != db:
                print(f"  [TAMPER DETECTED] Claimed valid but digest A != digest B!")
                tamper_detected = True

    if tamper_detected:
        print("\nFATAL: Evidence tampering or missing artifacts detected!")
        return 1

    print(f"\nAll {len(manifests)} manifests and {total_artifacts} artifacts verified untampered.")
    return 0

if __name__ == "__main__":
    sys.exit(verify_evidence())
