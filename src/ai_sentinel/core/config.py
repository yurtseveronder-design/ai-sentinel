import os, yaml

def load_config(path: str = None) -> dict:
    if not path:
        raise FileNotFoundError("Config path not provided")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    if os.path.getsize(path) == 0:
        raise ValueError("Config file is empty")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data is None:
                raise ValueError("Config file is empty or invalid")
            if not isinstance(data, dict):
                raise ValueError("Invalid YAML structure")
            return data
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")
