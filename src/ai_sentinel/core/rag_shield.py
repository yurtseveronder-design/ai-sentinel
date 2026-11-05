from typing import List, Dict, Any
from ai_sentinel.core.config_loader import ConfigLoader

class RagShield:
    """
    RAG-specific security guardrail driven by threat_signatures.yaml.
    """
    def __init__(self):
        cfg = ConfigLoader.load_config()
        self.injection_markers = cfg.get("rag_injection_markers", [])

    def scan_chunks(self, chunks: List[str]) -> Dict[str, Any]:
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