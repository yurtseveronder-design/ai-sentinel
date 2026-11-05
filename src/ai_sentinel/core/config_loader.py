import os
import yaml
from typing import Dict, Any

class ConfigLoader:
    """
    Loads and caches configuration from threat_signatures.yaml as the single source of truth.
    """
    _config: Dict[str, Any] = None

    @classmethod
    def load_config(cls) -> Dict[str, Any]:
        if cls._config is not None:
            return cls._config

        config_paths = [
            "config/threat_signatures.yaml",
            "../config/threat_signatures.yaml",
            "../../config/threat_signatures.yaml"
        ]
        
        config_data = {}
        for path in config_paths:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f) or {}
                break

        cls._config = {
            "mode": config_data.get("mode", "enforce"),
            "thresholds": config_data.get("thresholds", {"semantic_similarity": 0.75, "risk_score_block": 0.8}),
            "trigger_verbs": config_data.get("trigger_verbs", ["ignore", "reveal", "bypass"]),
            "sensitive_terms": config_data.get("sensitive_terms", ["system prompt", "configuration"]),
            "threat_signatures": config_data.get("threat_signatures", []),
            "rag_injection_markers": config_data.get("rag_injection_markers", ["ignore previous instructions", "system:"])
        }
        return cls._config