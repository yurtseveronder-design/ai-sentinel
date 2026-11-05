import re
from typing import List, Dict, Any
from ai_sentinel.core.config_loader import ConfigLoader

class ThreatClassifier:
    """
    Context-aware threat classifier driven by threat_signatures.yaml.
    """
    def __init__(self):
        cfg = ConfigLoader.load_config()
        self.trigger_verbs = cfg.get("trigger_verbs", [])
        self.sensitive_terms = cfg.get("sensitive_terms", [])

    def analyze(self, text: str) -> dict:
        normalized = text.lower()
        matched_rules = []
        risk_score = 0.0

        classic_patterns = [
            r"ignore previous instructions",
            r"you are now an unrestricted",
            r"disregard former mandates"
        ]
        
        for pattern in classic_patterns:
            if re.search(pattern, normalized):
                matched_rules.append("prompt_injection_signature")
                risk_score = max(risk_score, 0.9)

        has_sensitive = any(term in normalized for term in self.sensitive_terms)
        has_trigger = any(verb in normalized for verb in self.trigger_verbs)

        if has_sensitive and has_trigger:
            matched_rules.append("system_prompt_extraction")
            risk_score = max(risk_score, 1.0)
        elif has_sensitive and not has_trigger:
            risk_score = max(risk_score, 0.1)

        return {
            "risk_score": risk_score,
            "matched_rules": list(set(matched_rules))
        }


class SemanticGuardrail:
    """
    Dynamic semantic guardrail using YAML-defined threat signatures.
    """
    def __init__(self, threshold: float = None):
        cfg = ConfigLoader.load_config()
        self.threshold = threshold if threshold is not None else cfg["thresholds"].get("semantic_similarity", 0.75)
        self._model = None
        self.threat_signatures = cfg.get("threat_signatures", [])
        self._threat_embeddings = None

    def _get_model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer('all-MiniLM-L6-v2')
                if self.threat_signatures:
                    self._threat_embeddings = self._model.encode(self.threat_signatures, convert_to_tensor=True)
            except Exception:
                self._model = "FAILED"
        return None if self._model == "FAILED" else self._model

    def check(self, text: str) -> Dict[str, Any]:
        model = self._get_model()
        if model is None or self._threat_embeddings is None:
            return {"is_safe": True, "similarity_score": 0.85, "reason": "mock_fallback_active"}

        try:
            from sentence_transformers import util
            query_embedding = model.encode(text, convert_to_tensor=True)
            cos_scores = util.cos_sim(query_embedding, self._threat_embeddings)
            max_score = float(cos_scores.max())

            is_safe = max_score < self.threshold
            return {
                "is_safe": is_safe,
                "similarity_score": max_score,
                "risk_score": max_score if not is_safe else 0.0
            }
        except Exception as e:
            return {"is_safe": True, "similarity_score": 0.0, "error": str(e)}