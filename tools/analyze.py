#!/usr/bin/env python3
"""
Research Analysis & Telemetry Engine
Analyzes experiment manifests, solver statistics, and differential characteristics.
"""

import os
import json
import glob
from pathlib import Path

def analyze_experiments(evidence_dir="evidence/experiments"):
    print("===============================================================")
    print("           SHA-256 Research Telemetry & Analysis               ")
    print("===============================================================")

    manifests = glob.glob(f"{evidence_dir}/**/manifest.json", recursive=True)
    print(f"Found {len(manifests)} experiment runs in {evidence_dir}.")

    stats = {
        "total_experiments": len(manifests),
        "successful_verifications": 0,
        "failed_verifications": 0,
        "classifications": {},
        "by_rounds": {}
    }

    for m_path in manifests:
        try:
            with open(m_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            exp_id = data.get("experiment_id", "unknown")
            cls_name = data.get("classification", "Unknown")
            stats["classifications"][cls_name] = stats["classifications"].get(cls_name, 0) + 1

            ver = data.get("verification", {})
            if ver.get("is_valid", False):
                stats["successful_verifications"] += 1
            else:
                stats["failed_verifications"] += 1

            r = ver.get("actual_rounds", 0)
            if r > 0:
                stats["by_rounds"][r] = stats["by_rounds"].get(r, 0) + 1

        except Exception as e:
            print(f"Error parsing manifest {m_path}: {e}")

    print("\nExperiment Summary:")
    print(f" - Total Experiments: {stats['total_experiments']}")
    print(f" - Valid Results Verified: {stats['successful_verifications']}")
    print(f" - Rejected / Inconclusive: {stats['failed_verifications']}")
    print("\nClassifications Breakdown:")
    for k, v in stats["classifications"].items():
        print(f"   * {k}: {v}")

    os.makedirs("reports", exist_ok=True)
    with open("reports/research_analysis.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    print("\nSaved analysis to reports/research_analysis.json")
    return stats

if __name__ == "__main__":
    analyze_experiments()
