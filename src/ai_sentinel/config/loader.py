import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ConfigLoader:
    @staticmethod
    def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
        if not config_path or not os.path.exists(config_path):
            return {
                "thresholds": {"block_threshold": 0.8},
                "threat_signatures": []
            }
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("Failed to load configuration from %s: %s", config_path, e, exc_info=True)
            return {
                "thresholds": {"block_threshold": 0.8},
                "threat_signatures": []
            }