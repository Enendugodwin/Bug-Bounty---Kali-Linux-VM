"""Lightweight RAG memory for past scan results (TF-IDF based)."""

from __future__ import annotations

import os
import pickle
import threading
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

MAX_DOCS = int(os.getenv("KPM_MEMORY_MAX_DOCS", "2000"))


class SecurityMemory:
    """A small, thread-safe, file-backed vector store of scan results.

    Documents are stored verbatim; the TF-IDF model is (re)fit on demand at
    query time, which keeps writes cheap and avoids re-fitting the whole
    corpus on every ``add_document``.
    """

    def __init__(self, storage_path: str = "memory.pkl"):
        self.storage_path = Path(__file__).resolve().parent.parent / storage_path
        self.documents: list[dict] = []
        self.vectorizer = TfidfVectorizer()
        self._lock = threading.Lock()
        self.load_memory()

    # ------------------------------------------------------------------
    def load_memory(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            with open(self.storage_path, "rb") as fh:
                data = pickle.load(fh)
            self.documents = data.get("documents", []) or []
            self.vectorizer = data.get("vectorizer", self.vectorizer)
        except Exception:  # noqa: BLE001 - never crash on a corrupt store
            self.documents = []

    def save_memory(self) -> None:
        tmp = self.storage_path.with_suffix(".pkl.tmp")
        with open(tmp, "wb") as fh:
            pickle.dump(
                {"documents": self.documents, "vectorizer": self.vectorizer},
                fh,
            )
        os.replace(tmp, self.storage_path)  # atomic on POSIX/Windows

    # ------------------------------------------------------------------
    def add_document(self, text: str, metadata: dict) -> None:
        if not text:
            return
        with self._lock:
            self.documents.append({"text": text, "metadata": metadata})
            if len(self.documents) > MAX_DOCS:
                self.documents = self.documents[-MAX_DOCS:]
            self.save_memory()

    def query(self, query_text: str, top_k: int = 3) -> list[dict]:
        with self._lock:
            docs = list(self.documents)
        if not docs:
            return []

        texts = [d.get("text", "") for d in docs]
        vectorizer = TfidfVectorizer()
        matrix = vectorizer.fit_transform(texts)
        query_vec = vectorizer.transform([query_text])

        similarities = cosine_similarity(query_vec, matrix).flatten()
        order = similarities.argsort()[-top_k:][::-1]

        results = []
        for idx in order:
            if similarities[idx] > 0:
                results.append({
                    "score": float(similarities[idx]),
                    "document": docs[idx],
                })
        return results


# Global instance
memory = SecurityMemory()
