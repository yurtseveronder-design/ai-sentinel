import importlib

import pytest


def test_gateway_fails_without_api_key(monkeypatch):
    monkeypatch.delenv("AI_SENTINEL_API_KEY", raising=False)
    import ai_sentinel.api.gateway as gateway

    try:
        with pytest.raises(SystemExit):
            importlib.reload(gateway)
    finally:
        # The failed reload leaves module state without a key; restore it for later tests.
        monkeypatch.setenv("AI_SENTINEL_API_KEY", "test-api-key")
        importlib.reload(gateway)
