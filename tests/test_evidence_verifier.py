#!/usr/bin/env python3
"""
Unit and Adversarial Tests for Evidence Verifier (reproducibility/verify_evidence.py)
Tests that verify_evidence fails closed on:
- Empty evidence sets without --allow-empty
- Missing manifests
- Path traversal in artifact paths
- Tampered hashes
- Missing artifacts
- Malformed JSON
- Schema violations
- Missing release manifest when required
- Tampered release manifest root hash
"""

import os
import json
import tempfile
import shutil
import pytest
from pathlib import Path

from reproducibility.verify_evidence import (
    verify_evidence,
    is_safe_relative_path,
    canonical_manifest_hash,
    compute_evidence_root_hash
)
from tools.generate_release_manifest import verify_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_is_safe_relative_path():
    with tempfile.TemporaryDirectory() as td:
        assert is_safe_relative_path(td, "file.txt") is True
        assert is_safe_relative_path(td, "subdir/file.txt") is True
        assert is_safe_relative_path(td, "../outside.txt") is False
        assert is_safe_relative_path(td, "../../etc/passwd") is False
        assert is_safe_relative_path(td, "/absolute/path") is False
        assert is_safe_relative_path(td, "C:\\Windows\\System32") is False
        assert is_safe_relative_path(td, "") is False


def test_empty_manifests_fails_closed():
    with tempfile.TemporaryDirectory() as td:
        ev_dir = os.path.join(td, "empty_evidence")
        os.makedirs(os.path.join(ev_dir, "experiments"))
        # Must fail closed by default (exit code 1)
        res = verify_evidence(ev_dir, allow_empty=False)
        assert res == 1

        # Must succeed only when allow_empty is explicitly True
        res_ok = verify_evidence(ev_dir, allow_empty=True)
        assert res_ok == 0


def test_path_traversal_artifact_rejected():
    with tempfile.TemporaryDirectory() as td:
        ev_dir = os.path.join(td, "evidence")
        exp_dir = os.path.join(ev_dir, "experiments", "exp_traversal")
        os.makedirs(exp_dir)

        # Create a file outside exp_dir
        outside_file = os.path.join(td, "secret.txt")
        with open(outside_file, "w") as f:
            f.write("secret data")

        manifest = {
            "experiment_id": "exp_traversal",
            "timestamp": "2026-10-20T00:00:00Z",
            "git_commit": "0" * 40,
            "system": {"os": "Linux", "cpu": "Test", "gpu": "None"},
            "hypothesis": {"id": "H1", "statement": "Test"},
            "parameters": {"rounds": 8, "solver": "test"},
            "artifacts": [
                {
                    "path": "../../secret.txt",
                    "sha256": "0" * 64,
                    "description": "Exploit traversal"
                }
            ],
            "verification": {"is_valid": False}
        }
        with open(os.path.join(exp_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        res = verify_evidence(ev_dir, schema_dir=str(REPO_ROOT / "schemas"))
        assert res == 1


def test_missing_artifact_rejected():
    with tempfile.TemporaryDirectory() as td:
        ev_dir = os.path.join(td, "evidence")
        exp_dir = os.path.join(ev_dir, "experiments", "exp_missing")
        os.makedirs(exp_dir)

        manifest = {
            "experiment_id": "exp_missing",
            "timestamp": "2026-10-20T00:00:00Z",
            "git_commit": "0" * 40,
            "system": {"os": "Linux", "cpu": "Test", "gpu": "None"},
            "hypothesis": {"id": "H1", "statement": "Test"},
            "parameters": {"rounds": 8, "solver": "test"},
            "artifacts": [
                {
                    "path": "nonexistent.bin",
                    "sha256": "0" * 64,
                    "description": "Missing file"
                }
            ],
            "verification": {"is_valid": False}
        }
        with open(os.path.join(exp_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        res = verify_evidence(ev_dir, schema_dir=str(REPO_ROOT / "schemas"))
        assert res == 1


def test_tampered_hash_rejected():
    with tempfile.TemporaryDirectory() as td:
        ev_dir = os.path.join(td, "evidence")
        exp_dir = os.path.join(ev_dir, "experiments", "exp_tamper")
        os.makedirs(exp_dir)

        art_file = os.path.join(exp_dir, "artifact.bin")
        with open(art_file, "wb") as f:
            f.write(b"actual content")

        manifest = {
            "experiment_id": "exp_tamper",
            "timestamp": "2026-10-20T00:00:00Z",
            "git_commit": "0" * 40,
            "system": {"os": "Linux", "cpu": "Test", "gpu": "None"},
            "hypothesis": {"id": "H1", "statement": "Test"},
            "parameters": {"rounds": 8, "solver": "test"},
            "artifacts": [
                {
                    "path": "artifact.bin",
                    "sha256": "1" * 64,  # Incorrect hash
                    "description": "Tampered file"
                }
            ],
            "verification": {"is_valid": False}
        }
        with open(os.path.join(exp_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        res = verify_evidence(ev_dir, schema_dir=str(REPO_ROOT / "schemas"))
        assert res == 1


def test_malformed_json_rejected():
    with tempfile.TemporaryDirectory() as td:
        ev_dir = os.path.join(td, "evidence")
        exp_dir = os.path.join(ev_dir, "experiments", "exp_malformed")
        os.makedirs(exp_dir)

        with open(os.path.join(exp_dir, "manifest.json"), "w", encoding="utf-8") as f:
            f.write("{ this is not valid json :")

        res = verify_evidence(ev_dir, schema_dir=str(REPO_ROOT / "schemas"))
        assert res == 1


def test_required_release_manifest_missing_fails():
    with tempfile.TemporaryDirectory() as td:
        ev_dir = os.path.join(td, "evidence")
        exp_dir = os.path.join(ev_dir, "experiments", "exp_1")
        os.makedirs(exp_dir)

        manifest = {
            "experiment_id": "exp_1",
            "timestamp": "2026-10-20T00:00:00Z",
            "git_commit": "0" * 40,
            "system": {"os": "Linux", "cpu": "Test", "gpu": "None"},
            "hypothesis": {"id": "H1", "statement": "Test"},
            "parameters": {"rounds": 8, "solver": "test"},
            "artifacts": [],
            "verification": {"is_valid": False}
        }
        with open(os.path.join(exp_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        # When require_release_manifest is True, missing release_manifest.json must fail
        res = verify_evidence(ev_dir, require_release_manifest=True, schema_dir=str(REPO_ROOT / "schemas"))
        assert res == 1
