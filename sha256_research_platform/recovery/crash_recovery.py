"""
Crash Recovery and Orphaned Job Management for SHA-256 Research Platform v3.0
Detects experiments and jobs left in non-terminal states (PREPARING, RUNNING, VERIFYING)
due to unexpected system crashes or power termination, and transitions them reliably.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from ..storage.db import DatabaseManager


class CrashRecoveryManager:
    """Detects and resolves orphaned jobs and experiments following process crashes."""

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or DatabaseManager()

    def detect_and_recover_orphaned_jobs(self, auto_retry: bool = False) -> Dict[str, Any]:
        """Scans SQLite database for jobs/experiments left in unfinished states and marks them ORPHANED/FAILED.
        
        Never silently marks a crashed job as completed.
        """
        conn = self.db.get_connection()
        orphaned_experiments = []
        orphaned_jobs = []

        try:
            cur = conn.cursor()

            # 1. Inspect experiments in non-terminal states
            cur.execute("""
                SELECT id, hypothesis_id, status, rounds, solver 
                FROM experiments 
                WHERE status IN ('PREPARING', 'RUNNING', 'VERIFYING', 'QUEUED')
            """)
            exp_rows = cur.fetchall()

            now_str = datetime.now(timezone.utc).isoformat()

            for row in exp_rows:
                exp_id = row["id"]
                prev_status = row["status"]

                if prev_status == "QUEUED" and not auto_retry:
                    # Keep queued or mark pending
                    continue

                new_status = "FAILED"
                cur.execute("""
                    UPDATE experiments 
                    SET status = ?, outcome = 'CRASH_TERMINATED', 
                        classification = 'ProcessInterruptedBeforeCompletion',
                        updated_at = ?
                    WHERE id = ?
                """, (new_status, now_str, exp_id))

                orphaned_experiments.append({
                    "experiment_id": exp_id,
                    "previous_status": prev_status,
                    "new_status": new_status,
                    "reason": "Process terminated unexpectedly while job was active"
                })

            # 2. Inspect jobs table
            cur.execute("""
                SELECT id, experiment_id, status, job_type 
                FROM jobs 
                WHERE status IN ('PREPARING', 'RUNNING', 'VERIFYING')
            """)
            job_rows = cur.fetchall()

            for row in job_rows:
                job_id = row["id"]
                prev_status = row["status"]
                new_status = "ORPHANED"

                cur.execute("""
                    UPDATE jobs 
                    SET status = ?, error_message = 'Process terminated abruptly; marked ORPHANED on restart',
                        completed_at = ?
                    WHERE id = ?
                """, (new_status, now_str, job_id))

                orphaned_jobs.append({
                    "job_id": job_id,
                    "experiment_id": row["experiment_id"],
                    "previous_status": prev_status,
                    "new_status": new_status
                })

            conn.commit()

        finally:
            conn.close()

        recovery_summary = {
            "recovered_at": datetime.now(timezone.utc).isoformat(),
            "orphaned_experiments_count": len(orphaned_experiments),
            "orphaned_jobs_count": len(orphaned_jobs),
            "orphaned_experiments": orphaned_experiments,
            "orphaned_jobs": orphaned_jobs
        }

        if orphaned_experiments or orphaned_jobs:
            self.db.record_event("CRASH_RECOVERY_EXECUTED", "system", recovery_summary)

        return recovery_summary
