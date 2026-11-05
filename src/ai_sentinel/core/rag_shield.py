import re
from typing import List, Dict, Any

class RagShield:
    """
    RAG-specific security guardrail to scan retrieved context chunks 
    for indirect prompt injection, malicious delimiters, and payload hijacking.
    """
    def __init__(self):
        # Suspicious markers often used to break out of context blocks in RAG
        self.injection_markers = [
            "ignore previous instructions",
            "system:",
            "assistant:",
            "new instructions:",
            "disregard context",
            "you must now act as"
        ]

    def scan_chunks(self, chunks: List[str]) -> Dict[str, Any]:
        """
        Scans a list of retrieved RAG document chunks for embedded prompt injection attacks.
        """
        flagged_chunks = []
        risk_score = 0.0

        for idx, chunk in enumerate(chunks):
            normalized = chunk.lower()
            detected_threats = []

            for marker in self.injection_markers:
                if marker in normalized:
                    detected_threats.append(marker)
                    risk_score = max(risk_score, 0.9)

            if detected_threats:
                flagged_chunks.append({
                    "chunk_index": idx,
                    "content_snippet": chunk[:100] + "..." if len(chunk) > 100 else chunk,
                    "detected_markers": detected_threats
                })

        return {
            "is_safe": len(flagged_chunks) == 0,
            "risk_score": risk_score,
            "flagged_chunks": flagged_chunks
        }