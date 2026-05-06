"""
memory.py — CAI-style episodic + semantic RAG memory for NEXUS.

Architecture (mirrors CAI memory.py):

  Episodic Memory (per-target collection in Qdrant):
    Each confirmed finding → LLM summary → vector → Qdrant "nexus_<host>" collection
    Retrieval: "show me past SQLi findings on Node.js targets"

  Semantic Memory (global cross-target collection):
    All confirmed findings → vectors → Qdrant "nexus_global" collection
    Retrieval: "what payloads worked against Express + SQLite before?"

  Online mode:  store confirmed findings in real-time during scan
  Offline mode: batch-ingest from scan JSON results after scan

Environment variables:
  NEXUS_MEMORY=episodic|semantic|all   (default: all)
  NEXUS_MEMORY_ONLINE=1                (store during scan, default: on)
  NEXUS_QDRANT_URL=http://localhost:6333  (Qdrant server, default: in-memory)
  NEXUS_MEMORY_TOP_K=5                 (results to retrieve, default: 5)
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ensure venv packages are importable regardless of which python3 is used.
# Only inject venv site-packages if the packages aren't already importable
# (avoids loading wrong-python-version .so files from a different venv).
# ---------------------------------------------------------------------------
try:
    import qdrant_client as _qc_test  # noqa: F401
    del _qc_test
except ImportError:
    _VENV_SITE = Path(__file__).parent.parent.parent.parent / ".venv" / "lib"
    if _VENV_SITE.exists():
        for _p in _VENV_SITE.iterdir():
            _sp = _p / "site-packages"
            if _sp.exists() and str(_sp) not in sys.path:
                sys.path.append(str(_sp))  # append, not insert — avoid shadowing

_QDRANT_URL  = os.getenv("NEXUS_QDRANT_URL", ":memory:")
_MEMORY_MODE = os.getenv("NEXUS_MEMORY", "all")          # episodic | semantic | all
_ONLINE      = os.getenv("NEXUS_MEMORY_ONLINE", "1") == "1"
_TOP_K       = int(os.getenv("NEXUS_MEMORY_TOP_K", "5"))

_GLOBAL_COLLECTION  = "nexus_global"
_EMBED_MODEL        = "all-MiniLM-L6-v2"   # 384-dim, runs locally, no API key needed
_EMBED_DIM          = 384

# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

_qdrant_client = None
_embedder      = None


def _get_client():
    global _qdrant_client
    if _qdrant_client is None:
        try:
            from qdrant_client import QdrantClient
            if _QDRANT_URL == ":memory:":
                _qdrant_client = QdrantClient(":memory:")
            else:
                _qdrant_client = QdrantClient(url=_QDRANT_URL)
            logger.info("[memory] Qdrant client: %s", _QDRANT_URL)
        except ImportError:
            logger.warning("[memory] qdrant-client not installed — memory disabled")
            _qdrant_client = None
    return _qdrant_client


def _get_embedder():
    global _embedder
    if _embedder is None:
        try:
            from sentence_transformers import SentenceTransformer
            _embedder = SentenceTransformer(_EMBED_MODEL)
            logger.info("[memory] Embedder loaded: %s", _EMBED_MODEL)
        except ImportError:
            logger.warning("[memory] sentence-transformers not installed — memory disabled")
            _embedder = None
    return _embedder


def _embed(text: str) -> Optional[List[float]]:
    emb = _get_embedder()
    if emb is None:
        return None
    return emb.encode(text, normalize_embeddings=True).tolist()


def _ensure_collection(name: str):
    client = _get_client()
    if client is None:
        return
    try:
        from qdrant_client.models import VectorParams, Distance
        existing = [c.name for c in client.get_collections().collections]
        if name not in existing:
            client.create_collection(
                collection_name=name,
                vectors_config=VectorParams(size=_EMBED_DIM, distance=Distance.COSINE),
            )
            logger.info("[memory] Created collection: %s", name)
    except Exception as exc:
        logger.debug("[memory] _ensure_collection error: %s", exc)


# ---------------------------------------------------------------------------
# Memory record
# ---------------------------------------------------------------------------

@dataclass
class MemoryRecord:
    """One confirmed finding stored in memory."""
    finding_id:   str
    check_id:     str
    tech_stack:   str        # "node-sqlite", "php-mysql", …
    target_host:  str        # hostname only (anonymised)
    severity:     str
    payload:      str
    param_name:   str
    description:  str
    evidence_note:str = ""
    timestamp:    float = field(default_factory=time.time)

    def to_text(self) -> str:
        """Natural-language representation for embedding."""
        return (
            f"{self.check_id} vulnerability on {self.tech_stack} target. "
            f"Parameter: {self.param_name}. "
            f"Payload: {self.payload[:120]}. "
            f"Severity: {self.severity}. "
            f"Notes: {self.description[:200]}"
        )

    def to_payload(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# ScanMemory — the main interface
# ---------------------------------------------------------------------------

class ScanMemory:
    """
    CAI-style episodic + semantic memory for NEXUS scanner.

    Usage::

        mem = ScanMemory()
        mem.store(record, target_host="juice.local")
        results = mem.query("SQLi payloads that worked on Express.js", top_k=5)
    """

    _instance: Optional["ScanMemory"] = None

    @classmethod
    def get(cls) -> "ScanMemory":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._mode   = _MEMORY_MODE
        self._online = _ONLINE
        self._enabled = _get_client() is not None and _get_embedder() is not None

    def is_enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def store(self, record: MemoryRecord, target_host: str = "") -> bool:
        """
        Store a confirmed finding in memory.
        Episodic: in per-target collection.
        Semantic:  in global collection.
        """
        if not self._enabled:
            return False

        text   = record.to_text()
        vector = _embed(text)
        if vector is None:
            return False

        payload = record.to_payload()
        point_id = str(uuid.uuid4())

        client = _get_client()
        if client is None:
            return False

        from qdrant_client.models import PointStruct

        try:
            # Episodic: per-target collection
            if self._mode in ("episodic", "all") and target_host:
                col = _collection_name(target_host)
                _ensure_collection(col)
                client.upsert(
                    collection_name=col,
                    points=[PointStruct(id=point_id, vector=vector, payload=payload)],
                )

            # Semantic: global cross-target collection
            if self._mode in ("semantic", "all"):
                _ensure_collection(_GLOBAL_COLLECTION)
                client.upsert(
                    collection_name=_GLOBAL_COLLECTION,
                    points=[PointStruct(id=point_id, vector=vector, payload=payload)],
                )

            logger.debug("[memory] stored %s (check=%s)", point_id, record.check_id)
            return True

        except Exception as exc:
            logger.debug("[memory] store error: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(
        self,
        query_text: str,
        top_k: int = _TOP_K,
        target_host: str = "",
        filter_check_id: Optional[str] = None,
    ) -> List[MemoryRecord]:
        """
        Retrieve top-k most similar past findings.

        If target_host given and mode includes episodic → search per-target collection.
        Always also searches global collection (semantic).
        """
        if not self._enabled:
            return []

        vector = _embed(query_text)
        if vector is None:
            return []

        client = _get_client()
        if client is None:
            return []

        from qdrant_client.models import Filter, FieldCondition, MatchValue, Query

        qdrant_filter = None
        if filter_check_id:
            qdrant_filter = Filter(
                must=[FieldCondition(key="check_id", match=MatchValue(value=filter_check_id))]
            )

        results: List[MemoryRecord] = []
        seen_ids: set = set()

        collections_to_search: List[str] = []
        if self._mode in ("episodic", "all") and target_host:
            col = _collection_name(target_host)
            try:
                existing = [c.name for c in client.get_collections().collections]
                if col in existing:
                    collections_to_search.append(col)
            except Exception:
                pass
        if self._mode in ("semantic", "all"):
            try:
                existing = [c.name for c in client.get_collections().collections]
                if _GLOBAL_COLLECTION in existing:
                    collections_to_search.append(_GLOBAL_COLLECTION)
            except Exception:
                pass

        for col in collections_to_search:
            try:
                # qdrant-client >= 1.7 uses query_points()
                resp = client.query_points(
                    collection_name=col,
                    query=vector,
                    limit=top_k,
                    query_filter=qdrant_filter,
                    with_payload=True,
                )
                hits = resp.points
                for hit in hits:
                    pid = str(hit.id)
                    if pid in seen_ids:
                        continue
                    seen_ids.add(pid)
                    p = hit.payload or {}
                    results.append(MemoryRecord(
                        finding_id   = p.get("finding_id", pid),
                        check_id     = p.get("check_id", ""),
                        tech_stack   = p.get("tech_stack", ""),
                        target_host  = p.get("target_host", ""),
                        severity     = p.get("severity", ""),
                        payload      = p.get("payload", ""),
                        param_name   = p.get("param_name", ""),
                        description  = p.get("description", ""),
                        evidence_note= p.get("evidence_note", ""),
                        timestamp    = p.get("timestamp", 0.0),
                    ))
            except Exception as exc:
                logger.debug("[memory] query error on %s: %s", col, exc)

        # Sort by timestamp (most recent first)
        results.sort(key=lambda r: r.timestamp, reverse=True)
        return results[:top_k]

    # ------------------------------------------------------------------
    # Convenience: build a MemoryRecord from a NEXUS Finding
    # ------------------------------------------------------------------

    @staticmethod
    def record_from_finding(finding, tech_stack: str = "", evidence_note: str = "") -> MemoryRecord:
        from urllib.parse import urlparse
        ip = getattr(finding, "insertion_point", None)
        ev = getattr(finding, "evidence", None)
        url = ip.url if ip else ""
        host = urlparse(url).netloc if url else "unknown"
        return MemoryRecord(
            finding_id   = str(getattr(finding, "id", uuid.uuid4())),
            check_id     = finding.check_id,
            tech_stack   = tech_stack,
            target_host  = host,
            severity     = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            payload      = (ev.payload if ev else "")[:300],
            param_name   = ip.name if ip else "",
            description  = finding.description[:400],
            evidence_note= evidence_note[:300],
        )

    def stats(self) -> dict:
        client = _get_client()
        if client is None or not self._enabled:
            return {"enabled": False}
        try:
            cols = client.get_collections().collections
            total = sum(
                (client.get_collection(c.name).points_count or 0)
                for c in cols
                if c.name.startswith("nexus_")
            )
            return {
                "enabled": True,
                "collections": len(cols),
                "total_points": total,
                "mode": self._mode,
            }
        except Exception:
            return {"enabled": True, "error": "stats unavailable"}


def _collection_name(host: str) -> str:
    """Safe Qdrant collection name from a hostname."""
    safe = re.sub(r"[^a-z0-9_]", "_", host.lower())[:40]
    return f"nexus_{safe}"
