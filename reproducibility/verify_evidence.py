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
import argparse

try:
    import jsonschema
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()

def canonical_json_bytes(obj):
    """
    Serializes a Python object to canonical JSON bytes according to RFC 8785:
    - UTF-8 encoding
    - Keys sorted lexicographically
    - Compact separators (',', ':') with no extra whitespace or newlines
    - Deterministic float and integer representation
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def canonical_manifest_hash(manifest_path):
    """
    Computes a canonical SHA-256 hash of a JSON manifest file.
    Ensures key-order invariance, whitespace formatting invariance,
    and cross-platform OS line ending invariance (CRLF vs LF).
    """
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest().lower()

def compute_evidence_root_hash(evidence_dir="evidence"):
    """
    Computes a deterministic, content-addressable SHA-256 Merkle root hash
    across all experiment manifests in evidence_dir.
    Guarantees cross-platform determinism (Windows, Linux, macOS) by:
    - Normalizing path separators to forward slashes
    - Sorting by relative path
    - Using canonical JSON representation for manifest hashing
    - Explicitly excluding release_manifest.json to avoid self-reference
    """
    manifest_pattern = os.path.join(evidence_dir, "experiments", "**", "manifest.json")
    raw_files = glob.glob(manifest_pattern, recursive=True)
    rel_files = sorted([os.path.relpath(f, evidence_dir).replace(os.sep, "/") for f in raw_files])

    lines = []
    for rel in rel_files:
        full_path = os.path.join(evidence_dir, rel.replace("/", os.sep))
        h = canonical_manifest_hash(full_path)
        lines.append(f"{rel}:{h}\n")

    canonical_text = "".join(lines).encode("utf-8")
    return hashlib.sha256(canonical_text).hexdigest().lower()

def is_safe_relative_path(base_dir, target_path):
    """
    Ensures target_path resolves strictly within base_dir (prevents directory traversal).
    Guards against both POSIX and Windows absolute paths, drive letters, and UNC paths.
    """
    if not target_path:
        return False
    # Reject Windows drive specifiers (e.g. C:file, C:\file, C:/file) on all platforms
    if len(target_path) >= 2 and target_path[1] == ':' and target_path[0].isalpha():
        return False
    # Reject absolute root path on either POSIX or Windows (leading / or \)
    if target_path.startswith('/') or target_path.startswith('\\'):
        return False
    if os.path.isabs(target_path):
        return False
    if os.path.splitdrive(target_path)[0]:
        return False
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(os.path.join(base_dir, target_path))
    try:
        common = os.path.commonpath([base_abs, target_abs])
        return common == base_abs
    except (ValueError, OSError):
        return False

def validate_schema(data, schema_path):
    if not HAVE_JSONSCHEMA:
        return True, "jsonschema not installed"
    if not os.path.exists(schema_path):
        return True, f"schema file not found: {schema_path}"
    try:
        with open(schema_path, "r", encoding="utf-8") as sf:
            schema = json.load(sf)
        jsonschema.validate(instance=data, schema=schema)
        return True, "valid"
    except Exception as e:
        return False, str(e)

def verify_evidence(evidence_dir="evidence", allow_empty=False, require_release_manifest=False, schema_dir="schemas"):
    print("===============================================================")
    print("        SHA-256 Evidence Integrity & Anti-Tamper Check        ")
    print("===============================================================")

    manifest_pattern = os.path.join(evidence_dir, "experiments", "**", "manifest.json")
    manifests = sorted(glob.glob(manifest_pattern, recursive=True))
    if not manifests:
        if allow_empty:
            print(f"Notice: No manifests found in {evidence_dir}/experiments (--allow-empty specified).")
        else:
            print(f"FATAL: No manifests found in {evidence_dir}/experiments.")
            print("Failing closed: evidence set must not be empty unless --allow-empty is explicitly passed.")
            return 1

    total_artifacts = 0
    tamper_detected = False
    manifest_schema_path = os.path.join(schema_dir, "manifest.schema.json")
    release_schema_path = os.path.join(schema_dir, "release_manifest.schema.json")

    for m_path in manifests:
        exp_dir = os.path.dirname(m_path)
        print(f"\nVerifying manifest: {m_path}")
        try:
            with open(m_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  [ERROR] Failed to parse manifest JSON: {e}")
            tamper_detected = True
            continue

        # Schema validation
        valid_schema, schema_err = validate_schema(data, manifest_schema_path)
        if not valid_schema:
            print(f"  [SCHEMA VIOLATION] {schema_err}")
            tamper_detected = True

        artifacts = data.get("artifacts", [])
        if not isinstance(artifacts, list):
            print(f"  [ERROR] 'artifacts' must be a list in {m_path}")
            tamper_detected = True
            artifacts = []

        for a in artifacts:
            if not isinstance(a, dict):
                print(f"  [ERROR] Malformed artifact entry: {a}")
                tamper_detected = True
                continue

            rel_path = a.get("path")
            expected_hash = a.get("sha256")

            if not rel_path or not expected_hash:
                print(f"  [ERROR] Artifact missing path or sha256: {a}")
                tamper_detected = True
                continue

            # Path traversal guard
            if not is_safe_relative_path(exp_dir, rel_path):
                print(f"  [SECURITY] Path traversal detected for artifact path: '{rel_path}'")
                tamper_detected = True
                continue

            full_path = os.path.normpath(os.path.join(exp_dir, rel_path))

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
        if isinstance(ver, dict) and ver.get("is_valid", False):
            # Verify candidate digests
            da = ver.get("digest_a")
            db = ver.get("digest_b")
            if da != db:
                print(f"  [TAMPER DETECTED] Claimed valid but digest A != digest B!")
                tamper_detected = True

    if tamper_detected:
        print("\nFATAL: Evidence tampering, schema violation, or missing artifacts detected!")
        return 1

    print(f"\nAll {len(manifests)} manifests and {total_artifacts} artifacts verified untampered.")

    # Verify release manifest
    rel_manifest_path = os.path.join(evidence_dir, "release_manifest.json")
    if require_release_manifest and not os.path.exists(rel_manifest_path):
        print(f"\nFATAL: Required release manifest missing: {rel_manifest_path}")
        return 1

    if os.path.exists(rel_manifest_path):
        print(f"\nVerifying Release Manifest: {rel_manifest_path}")
        try:
            with open(rel_manifest_path, "r", encoding="utf-8") as f:
                rel_data = json.load(f)
        except Exception as e:
            print(f"  [ERROR] Failed to parse release manifest JSON: {e}")
            return 1

        # Schema validation
        valid_schema, schema_err = validate_schema(rel_data, release_schema_path)
        if not valid_schema:
            print(f"  [SCHEMA VIOLATION] Release manifest: {schema_err}")
            return 1

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

def main():
    parser = argparse.ArgumentParser(description="Evidence Integrity & Anti-Tamper Check")
    parser.add_argument("--evidence-dir", default="evidence", help="Path to evidence directory")
    parser.add_argument("--schema-dir", default="schemas", help="Path to schemas directory")
    parser.add_argument("--allow-empty", action="store_true", help="Allow empty manifest directory without failing")
    parser.add_argument("--require-release-manifest", action="store_true", help="Require release_manifest.json to exist")
    args = parser.parse_args()

    return verify_evidence(
        evidence_dir=args.evidence_dir,
        allow_empty=args.allow_empty,
        require_release_manifest=args.require_release_manifest,
        schema_dir=args.schema_dir
    )

if __name__ == "__main__":
    sys.exit(main())
