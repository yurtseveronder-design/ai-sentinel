import yaml
from pathlib import Path

def load_config(config_path: str | Path = None) -> dict:
    if config_path is None:
        raise FileNotFoundError("Config path is required.")
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        raise FileNotFoundError(f"Could not read config file: {e}")
    if not content.strip():
        raise ValueError("Configuration file is empty.")
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML syntax: {e}")
    if data is None:
        raise ValueError("Configuration file yielded empty content.")
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a dictionary.")
    return data
