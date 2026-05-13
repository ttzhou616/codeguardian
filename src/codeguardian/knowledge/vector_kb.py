"""Vector-backed knowledge base using ChromaDB for semantic search and persistence."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional

from codeguardian.models.findings import Finding


class VectorKnowledgeBase:
    """Persistent knowledge base with semantic similarity search via ChromaDB.

    Replaces the in-memory KnowledgeBase with:
    - Persistent storage across sessions
    - Semantic search: find similar past findings even when code moves
    - False positive learning: auto-suppress findings similar to known FPs
    """

    def __init__(self, storage_path: str | Path | None = None):
        self._storage_path = Path(storage_path or ".codeguardian_vectordb")
        self._client = None
        self._collection = None
        self._initialized = False

    @property
    def initialized(self) -> bool:
        return self._initialized

    def _ensure_init(self) -> None:
        if self._initialized:
            return
        try:
            import chromadb
            self._client = chromadb.PersistentClient(
                path=str(self._storage_path),
            )
            self._collection = self._client.get_or_create_collection(
                name="codeguardian_findings",
                metadata={"description": "CodeGuardian review findings with FP labels"},
            )
            self._initialized = True
        except ImportError:
            pass  # ChromaDB not installed; fall back gracefully
        except Exception:
            self._initialized = True  # Don't retry on error

    def add_false_positive(self, finding: Finding) -> None:
        """Record a finding as false positive for future suppression."""
        self._ensure_init()
        if not self._collection:
            return

        doc_id = f"fp-{finding.rule_id}-{uuid.uuid4().hex[:8]}"
        text = self._finding_to_text(finding)
        metadata = {
            "rule_id": finding.rule_id,
            "file_path": finding.file_path,
            "title": finding.title,
            "category": finding.category.value,
            "is_false_positive": True,
            "timestamp": str(self._now()),
        }
        try:
            self._collection.add(
                ids=[doc_id],
                documents=[text],
                metadatas=[metadata],
            )
        except Exception:
            pass

    def is_false_positive(self, finding: Finding, threshold: float = 0.85) -> bool:
        """Check if a finding is semantically similar to a known FP."""
        self._ensure_init()
        if not self._collection:
            return False

        try:
            text = self._finding_to_text(finding)
            results = self._collection.query(
                query_texts=[text],
                n_results=3,
                where={"is_false_positive": True},
                include=["distances"],
            )
            if results and results["ids"] and results["ids"][0]:
                distances = results.get("distances", [[1.0]])[0]
                # ChromaDB uses cosine distance; convert to similarity (0-1)
                similarities = [1.0 - d for d in distances]
                return any(s >= threshold for s in similarities)
        except Exception:
            pass

        return False

    def filter_false_positives(
        self, findings: list[Finding], threshold: float = 0.85,
    ) -> list[Finding]:
        """Return findings with semantically-matched false positives removed."""
        return [f for f in findings if not self.is_false_positive(f, threshold)]

    def remove_false_positive(self, finding: Finding) -> None:
        """Remove a false positive entry (undo)."""
        self._ensure_init()
        if not self._collection:
            return

        try:
            text = self._finding_to_text(finding)
            results = self._collection.query(
                query_texts=[text],
                n_results=1,
                where={"is_false_positive": True, "rule_id": finding.rule_id},
            )
            if results and results["ids"] and results["ids"][0]:
                self._collection.delete(ids=results["ids"][0])
        except Exception:
            pass

    def get_stats(self) -> dict:
        """Return knowledge base statistics."""
        self._ensure_init()
        if not self._collection:
            return {"initialized": False}

        try:
            count = self._collection.count()
            fp_results = self._collection.get(
                where={"is_false_positive": True},
                include=[],
            )
            return {
                "initialized": True,
                "total_entries": count,
                "false_positives": len(fp_results.get("ids", [])),
                "storage_path": str(self._storage_path),
            }
        except Exception:
            return {"initialized": True, "error": "Failed to get stats"}

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _finding_to_text(finding: Finding) -> str:
        """Convert a finding to searchable text."""
        parts = [
            f"Rule: {finding.rule_id}",
            f"Title: {finding.title}",
            f"Category: {finding.category.value}",
            f"File: {finding.file_path}",
            f"Lines: {finding.line_start}-{finding.line_end}",
            f"Description: {finding.description}",
        ]
        if finding.suggestion:
            parts.append(f"Suggestion: {finding.suggestion}")
        return "\n".join(parts)

    @staticmethod
    def _now() -> float:
        import time
        return time.time()
