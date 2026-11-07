import os
import importlib
import pytest

def test_gateway_fails_without_api_key(monkeypatch):
    monkeypatch.delenv("AI_SENTINEL_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        import ai_sentinel.api.gateway
        importlib.reload(ai_sentinel.api.gateway)