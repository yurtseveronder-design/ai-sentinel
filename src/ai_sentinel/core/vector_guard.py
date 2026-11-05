from typing import List, Set

class VectorGuard:
    """
    Lightweight semantic threat detector using token set intersection (Jaccard/overlap)
    to catch paraphrased prompt injections.
    """
    def __init__(self):
        self.known_threat_signatures: List[Set[str]] = [
            {"ignore", "previous", "instructions", "reveal", "system", "prompt"},
            {"bypass", "safety", "filters", "unrestricted", "mode"},
            {"exfiltrate", "sensitive", "user", "data", "credentials"},
            {"sudo", "active", "ignore", "constraints"},
            {"disregard", "mandates", "instructions", "initialization"}
        ]

    def evaluate_semantic_risk(self, prompt: str) -> float:
        prompt_tokens: Set[str] = set(prompt.lower().split())
        max_overlap = 0.0
        
        for signature in self.known_threat_signatures:
            if not signature:
                continue
            intersection = prompt_tokens & signature
            overlap = len(intersection) / len(signature)
            if overlap > max_overlap:
                max_overlap = overlap
                
        return max_overlap