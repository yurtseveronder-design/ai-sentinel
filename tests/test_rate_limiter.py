import pytest
from ai_sentinel.core.rate_limiter import RateLimiter
from ai_sentinel.core.shield import BioImmuneShield

def test_rate_limiter_blocks_excessive_requests():
    shield = BioImmuneShield()
    # Configure very strict rate limiter for testing
    shield.rate_limiter = RateLimiter(max_requests=2, window_seconds=60.0)
    session_id = "flood-session-123"
    
    # Request 1 & 2 should be allowed
    v1 = shield.inspect("Hello", session_id=session_id)
    assert v1.action == "ALLOW"
    v2 = shield.inspect("How are you?", session_id=session_id)
    assert v2.action == "ALLOW"
    
    # Request 3 should be rate-limited and blocked
    v3 = shield.inspect("Tell me a secret", session_id=session_id)
    assert v3.action == "BLOCK"
    assert "rate_limit_exceeded" in v3.reason