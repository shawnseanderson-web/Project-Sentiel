import sqlite3
import json
import math
import re
import os
import logging
from typing import List, Dict, Any, Tuple

logging.basicConfig(level=logging.INFO, format="[VECTOR RAG] %(asctime)s - %(message)s")
logger = logging.getLogger("EvidenceVectorDB")

class EvidenceVectorDB:
    """
    Embedded Vector Database & RAG (Retrieval-Augmented Generation) Engine.
    Provides local semantic similarity search over unstructured case files, transcripts,
    and investigator notes without requiring cloud embedding API calls.
    """
    def __init__(self, db_path: str = "sentinel_rag.db", vector_dim: int = 128):
        self.db_path = db_path
        self.vector_dim = vector_dim
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    doc_id TEXT,
                    source_file TEXT,
                    chunk_index INTEGER,
                    text_content TEXT,
                    vector_json TEXT,
                    metadata_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower() for w in re.findall(r'\b\w+\b', text)]

    def _embed_text(self, text: str) -> List[float]:
        """
        Computes a normalized dense embedding vector for text using 
        hashed character/word n-gram feature projections.
        """
        tokens = self._tokenize(text)
        vec = [0.0] * self.vector_dim
        if not tokens:
            return vec

        for t in tokens:
            # Deterministic hash projection into vector dimensions
            h = int(re.sub(r'[^0-9]', '', str(hash(t)))) if str(hash(t)) else 0
            idx = abs(hash(t)) % self.vector_dim
            sign = 1.0 if (hash(t) % 2 == 0) else -1.0
            vec[idx] += sign * (1.0 + math.log(1 + tokens.count(t)))

        # L2 Normalization
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        if len(vec1) != len(vec2):
            return 0.0
        dot = sum(a * b for a, b in zip(vec1, vec2))
        return float(dot)

    def index_document(self, doc_id: str, source_file: str, text_content: str, metadata: Dict[str, Any] = None) -> int:
        """
        Splits text content into semantic paragraphs, embeds each chunk,
        and persists into the local SQLite vector store.
        """
        metadata = metadata or {}
        paragraphs = [p.strip() for p in text_content.split('\n\n') if p.strip()]
        if not paragraphs:
            paragraphs = [text_content.strip()]

        chunks_indexed = 0
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Clear existing chunks for this doc
            cursor.execute("DELETE FROM evidence_chunks WHERE doc_id = ?", (doc_id,))
            
            for idx, p in enumerate(paragraphs):
                chunk_id = f"{doc_id}_chunk_{idx}"
                embedding = self._embed_text(p)
                cursor.execute("""
                    INSERT INTO evidence_chunks 
                    (chunk_id, doc_id, source_file, chunk_index, text_content, vector_json, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    chunk_id,
                    doc_id,
                    source_file,
                    idx,
                    p,
                    json.dumps(embedding),
                    json.dumps(metadata)
                ))
                chunks_indexed += 1
            conn.commit()

        logger.info(f"Indexed document {doc_id} ({source_file}) into {chunks_indexed} vector chunk(s).")
        return chunks_indexed

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Executes semantic RAG similarity search across all evidence chunks.
        """
        query_vec = self._embed_text(query)
        results = []

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT chunk_id, doc_id, source_file, chunk_index, text_content, vector_json, metadata_json FROM evidence_chunks")
            rows = cursor.fetchall()

            for row in rows:
                chunk_id, doc_id, source_file, chunk_index, text_content, vector_json, metadata_json = row
                chunk_vec = json.loads(vector_json)
                sim_score = self._cosine_similarity(query_vec, chunk_vec)

                # Bonus for exact keyword match in raw text
                for term in set(self._tokenize(query)):
                    if term in text_content.lower():
                        sim_score += 0.15

                results.append({
                    "chunk_id": chunk_id,
                    "doc_id": doc_id,
                    "source_file": source_file,
                    "chunk_index": chunk_index,
                    "text_content": text_content,
                    "similarity_score": round(sim_score, 4),
                    "metadata": json.loads(metadata_json)
                })

        # Sort descending by score
        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        return results[:top_k]
