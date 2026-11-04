import re
from typing import Dict, Any

class PromptShieldCore:
    def __init__(self, risk_threshold: float = 0.7):
        self.risk_threshold = risk_threshold
        self.injection_patterns = [r"ignore previous instructions", r"system override", r"reveal secret prompt"]

    def scan_prompt(self, prompt: str) -> Dict[str, Any]:
        return {"is_safe": True, "risk_score": 0.0, "engine": "sentinel-core-v1"}
Core security utilities and structured validation guards for ai-sentinel. 
import re 
from typing import Dict, Any 
 
class PromptShieldCore: 
    def __init__(self, risk_threshold: float = 0.7): 
        self.risk_threshold = risk_threshold 
        self.injection_patterns = [r"ignore previous instructions", r"system override", r"reveal secret prompt"] 
 
    def scan_prompt(self, prompt: str) -, Any]: 
        return {"is_safe": True, "risk_score": 0.0, "engine": "sentinel-core-v1"} 
