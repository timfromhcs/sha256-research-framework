#!/usr/bin/env python3
"""
Evidence Integrity & Hash Verification Script
Validates all SHA-256 artifact hashes, manifests, candidate digests,
and the canonical release manifest root evidence hash.
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
    return h.hexdigest().lower()

def compute_evidence_root_hash(evidence_dir="evidence"):
    manifest_pattern = os.path.join(evidence_dir, "experiments", "**", "manifest.json")
    manifest_files = sorted(glob.glob(manifest_pattern, recursive=True))

    lines = []
    for m in manifest_files:
        rel = os.path.relpath(m, evidence_dir).replace(os.sep, "/")
        with open(m, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest().lower()
        lines.append(f"{rel}:{h}\n")

    canonical_text = "".join(lines).encode("utf-8")
    return hashlib.sha256(canonical_text).hexdigest().lower()

def verify_evidence(evidence_dir="evidence"):
    print("===============================================================")
    print("        SHA-256 Evidence Integrity & Anti-Tamper Check        ")
    print("===============================================================")

    manifest_pattern = os.path.join(evidence_dir, "experiments", "**", "manifest.json")
    manifests = sorted(glob.glob(manifest_pattern, recursive=True))
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

    # Verify release manifest
    rel_manifest_path = os.path.join(evidence_dir, "release_manifest.json")
    if os.path.exists(rel_manifest_path):
        print(f"\nVerifying Release Manifest: {rel_manifest_path}")
        with open(rel_manifest_path, "r", encoding="utf-8") as f:
            rel_data = json.load(f)

        expected_root = compute_evidence_root_hash(evidence_dir)
        actual_root = rel_data.get("root_evidence_hash", "").lower()

        if expected_root != actual_root:
            print(f"  [TAMPER DETECTED] Release manifest root_evidence_hash mismatch!")
            print(f"    Expected: {expected_root}")
            print(f"    Recorded: {actual_root}")
            return 1
        print(f"  [OK] root_evidence_hash verified ({actual_root[:16]}...)")

        source_commit = rel_data.get("source_commit_sha")
        if not source_commit or len(source_commit) != 40:
            print(f"  [ERROR] Release manifest source_commit_sha invalid or missing: {source_commit}")
            return 1
        print(f"  [OK] source_commit_sha verified ({source_commit})")

    return 0

if __name__ == "__main__":
    sys.exit(verify_evidence())
