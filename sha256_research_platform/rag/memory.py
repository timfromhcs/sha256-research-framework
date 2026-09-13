"""
Local Research Memory and RAG Retrieval System for SHA-256 Research Platform v3.0
Indexes documentation, reports, hypotheses, and evidence packages.
Prioritizes independently verified evidence (L3+) over unverified observations or model suggestions.
"""

import os
import re
import json
import glob
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

from ..storage.db import DatabaseManager
from ..models.runtime import LocalModelRuntime


@dataclass
class SearchResult:
    doc_id: str
    title: str
    source_type: str  # "evidence", "report", "documentation", "hypothesis", "observation"
    snippet: str
    trust_level: str  # L0, L1, L2, L3, L4, L5
    score: float
    file_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LocalResearchMemory:
    """Provides local lexical and semantic retrieval across research corpus with epistemic awareness."""

    def __init__(self, db: Optional[DatabaseManager] = None, runtime: Optional[LocalModelRuntime] = None):
        self.db = db or DatabaseManager()
        self.runtime = runtime or LocalModelRuntime(self.db)
        self._index: List[Dict[str, Any]] = []
        self.reindex()

    def reindex(self) -> int:
        """Re-scans documents, reports, and evidence packages into memory index."""
        self._index.clear()

        # 1. Index documentation
        docs_dir = "docs"
        if os.path.isdir(docs_dir):
            for root, _, files in os.walk(docs_dir):
                for f in files:
                    if f.endswith(".md"):
                        p = os.path.join(root, f)
                        try:
                            with open(p, "r", encoding="utf-8") as fp:
                                content = fp.read()
                            title = f.replace(".md", "").replace("-", " ").capitalize()
                            self._index.append({
                                "doc_id": f"doc:{p}",
                                "title": title,
                                "source_type": "documentation",
                                "content": content,
                                "trust_level": "L2",
                                "file_path": p
                            })
                        except Exception:
                            pass

        # 2. Index reports
        reports_dir = "reports"
        if os.path.isdir(reports_dir):
            for f in os.listdir(reports_dir):
                if f.endswith(".md"):
                    p = os.path.join(reports_dir, f)
                    try:
                        with open(p, "r", encoding="utf-8") as fp:
                            content = fp.read()
                        self._index.append({
                            "doc_id": f"report:{f}",
                            "title": f.replace(".md", "").replace("_", " ").capitalize(),
                            "source_type": "report",
                            "content": content,
                            "trust_level": "L2",
                            "file_path": p
                        })
                    except Exception:
                        pass

        # 3. Index evidence manifests (Verified evidence = L3)
        manifests = sorted(glob.glob("evidence/experiments/**/manifest.json", recursive=True))
        for m in manifests:
            try:
                with open(m, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                exp_id = data.get("experiment_id", os.path.basename(os.path.dirname(m)))
                verdict = data.get("verification", {})
                is_valid = verdict.get("is_valid", False)
                content = json.dumps(data, indent=2)
                trust = "L3" if is_valid else "L2"
                self._index.append({
                    "doc_id": f"evidence:{exp_id}",
                    "title": f"Evidence Manifest: {exp_id}",
                    "source_type": "evidence",
                    "content": content,
                    "trust_level": trust,
                    "file_path": m
                })
            except Exception:
                pass

        # 4. Index hypotheses from DB
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, title, description, falsification_criteria, trust_level FROM hypotheses")
            for row in cur.fetchall():
                content = f"{row['title']}\n{row['description']}\nFalsification: {row['falsification_criteria']}"
                self._index.append({
                    "doc_id": f"hyp:{row['id']}",
                    "title": f"Hypothesis {row['id']}: {row['title']}",
                    "source_type": "hypothesis",
                    "content": content,
                    "trust_level": row["trust_level"] or "L0",
                    "file_path": None
                })
        finally:
            conn.close()

        return len(self._index)

    def search(
        self,
        query: str,
        top_k: int = 5,
        prefer_verified: bool = True
    ) -> List[SearchResult]:
        """Searches index. If prefer_verified is True, boosts verified evidence (L3+)."""
        tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 2]
        if not tokens:
            return []

        results = []
        for item in self._index:
            content_lower = item["content"].lower()
            title_lower = item["title"].lower()

            matches = sum(1 for t in tokens if t in content_lower)
            title_matches = sum(2 for t in tokens if t in title_lower)
            base_score = matches + title_matches

            if base_score > 0:
                # Epistemic trust boost: L3 verified evidence gets priority
                trust_boost = 1.0
                if prefer_verified and item["trust_level"] in {"L3", "L4", "L5"}:
                    trust_boost = 2.0

                final_score = float(base_score) * trust_boost

                # Generate snippet
                idx = -1
                for t in tokens:
                    idx = content_lower.find(t)
                    if idx != -1:
                        break
                start = max(0, idx - 40) if idx != -1 else 0
                snippet = item["content"][start : start + 200].replace("\n", " ").strip() + "..."

                results.append(SearchResult(
                    doc_id=item["doc_id"],
                    title=item["title"],
                    source_type=item["source_type"],
                    snippet=snippet,
                    trust_level=item["trust_level"],
                    score=final_score,
                    file_path=item["file_path"]
                ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_k]
