"""
Auditable Evidence Package Storage for SHA-256 Research Platform v3.0
Every experiment run produces:
  request.json, environment.json, stdout.log, stderr.log,
  result.json, verification.json, manifest.json, report.md
Enforces deterministic root evidence hashing and prevents silent overwriting.
"""

import os
import json
import hashlib
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

from ..storage.db import DatabaseManager
from ..models.hardware import probe_hardware


def sha256_file(filepath: str) -> str:
    """Computes standard hexadecimal SHA-256 of file contents."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_current_git_commit() -> str:
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return "UNKNOWN_COMMIT"


class EvidenceStore:
    """Manages creation, hashing, and verification of auditable experiment evidence packages."""

    def __init__(self, base_dir: str = "evidence", db: Optional[DatabaseManager] = None):
        self.base_dir = base_dir
        self.experiments_dir = os.path.join(self.base_dir, "experiments")
        self.db = db or DatabaseManager()
        os.makedirs(self.experiments_dir, exist_ok=True)

    def create_evidence_package(
        self,
        experiment_id: str,
        request_data: Dict[str, Any],
        stdout_text: str,
        stderr_text: str,
        result_data: Dict[str, Any],
        verification_data: Dict[str, Any],
        artifacts: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Assembles and writes complete evidence package for an experiment.
        
        Refuses to silently overwrite existing packages.
        """
        exp_dir = os.path.join(self.experiments_dir, experiment_id)
        if os.path.exists(exp_dir):
            # Never silently overwrite: generate a timestamped sub-run or error
            run_suffix = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            exp_dir = os.path.join(self.experiments_dir, f"{experiment_id}_{run_suffix}")

        artifacts_dir = os.path.join(exp_dir, "artifacts")
        os.makedirs(artifacts_dir, exist_ok=True)

        source_commit = get_current_git_commit()
        hw = probe_hardware()
        created_at = datetime.now(timezone.utc).isoformat()

        # 1. environment.json
        environment_data = {
            "source_commit": source_commit,
            "os": os.name,
            "cpu_model": hw.cpu_model,
            "cpu_cores": hw.cpu_cores,
            "vulkan_available": hw.vulkan_available,
            "vulkan_device": hw.vulkan_device_name,
            "vulkan_driver": hw.vulkan_driver_version,
            "vulkan_api": hw.vulkan_api_version,
            "total_ram_bytes": hw.total_ram_bytes,
            "created_at": created_at
        }
        env_path = os.path.join(exp_dir, "environment.json")
        with open(env_path, "w", encoding="utf-8") as f:
            json.dump(environment_data, f, indent=2, sort_keys=True)

        # 2. request.json
        req_path = os.path.join(exp_dir, "request.json")
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(request_data, f, indent=2, sort_keys=True)

        # 3. stdout.log & stderr.log
        stdout_path = os.path.join(exp_dir, "stdout.log")
        with open(stdout_path, "w", encoding="utf-8") as f:
            f.write(stdout_text)

        stderr_path = os.path.join(exp_dir, "stderr.log")
        with open(stderr_path, "w", encoding="utf-8") as f:
            f.write(stderr_text)

        # 4. result.json
        res_path = os.path.join(exp_dir, "result.json")
        with open(res_path, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2, sort_keys=True)

        # 5. verification.json
        ver_path = os.path.join(exp_dir, "verification.json")
        with open(ver_path, "w", encoding="utf-8") as f:
            json.dump(verification_data, f, indent=2, sort_keys=True)

        # 6. report.md
        rounds = request_data.get("rounds", "N/A")
        solver = request_data.get("solver", "N/A")
        is_valid = verification_data.get("is_valid", False)
        cls_name = verification_data.get("classification", "Unknown")

        report_md = f"""# Experiment Report: {experiment_id}

## Execution Summary
- **Target Rounds**: {rounds}
- **Solver**: {solver}
- **Status**: {result_data.get("status", "COMPLETED")}
- **Verification Verdict**: {"VERIFIED VALID" if is_valid else "REFUTED / INVALID"}
- **Classification**: {cls_name}
- **Timestamp**: {created_at}
- **Source Commit**: `{source_commit}`

## Cryptographic Classification Integrity
> [!NOTE]
> Reduced-round solutions are strictly classified as `{cls_name}`.
> Full 64-round SHA-256 remains unbroken.

## Environment
- CPU: {hw.cpu_model} ({hw.cpu_cores} cores)
- Vulkan Device: {hw.vulkan_device_name or "N/A"}
"""
        report_path = os.path.join(exp_dir, "report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        # 7. Collect and hash all package files for manifest.json
        pkg_files = [
            ("request.json", req_path),
            ("environment.json", env_path),
            ("stdout.log", stdout_path),
            ("stderr.log", stderr_path),
            ("result.json", res_path),
            ("verification.json", ver_path),
            ("report.md", report_path)
        ]

        if artifacts:
            for art in artifacts:
                art_rel = art.get("relative_path")
                art_full = os.path.join(exp_dir, art_rel) if not os.path.isabs(art_rel) else art_rel
                if os.path.exists(art_full):
                    pkg_files.append((art_rel, art_full))

        manifest_artifacts = []
        conn = self.db.get_connection()
        try:
            for rel_name, full_path in pkg_files:
                fhash = sha256_file(full_path)
                fsize = os.path.getsize(full_path)
                manifest_artifacts.append({
                    "path": rel_name,
                    "relative_path": rel_name,
                    "sha256": fhash,
                    "sha256_hash": fhash,
                    "size_bytes": fsize,
                    "description": f"Evidence file: {rel_name}"
                })
                # Persist in SQLite artifacts
                conn.execute("""
                    INSERT OR REPLACE INTO artifacts (sha256_hash, experiment_id, relative_path, size_bytes, description, artifact_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (fhash, experiment_id, rel_name, fsize, f"Evidence file for {experiment_id}", "evidence_package"))
            conn.commit()
        finally:
            conn.close()

        # Deterministic evidence package root hash:
        # Hash of sorted (path + sha256)
        manifest_artifacts.sort(key=lambda x: x["path"])
        root_hasher = hashlib.sha256()
        for item in manifest_artifacts:
            root_hasher.update(f"{item['path']}:{item['sha256']}\n".encode("utf-8"))
        root_evidence_hash = root_hasher.hexdigest()

        # 8. manifest.json
        manifest_data = {
            "experiment_id": experiment_id,
            "source_commit": source_commit,
            "created_at": created_at,
            "root_evidence_hash": root_evidence_hash,
            "verification": verification_data,
            "outcome_success": is_valid,
            "classification": cls_name,
            "artifacts": manifest_artifacts
        }
        manifest_path = os.path.join(exp_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, sort_keys=True)

        return manifest_data
