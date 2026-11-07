import os
import pytest
import importlib

def test_gateway_fails_without_api_key(monkeypatch):
    # Ensure the environment variable is completely removed
    monkeypatch.delenv("AI_SENTINEL_API_KEY", raising=False)
    
    # Importing the module should trigger a hard crash (ValueError)
    with pytest.raises(ValueError, match="Critical startup failure: AI_SENTINEL_API_KEY"):
        import ai_sentinel.api.gateway
        # Reload ensures it runs the module-level code again if it was already cached
        importlib.reload(ai_sentinel.api.gateway)