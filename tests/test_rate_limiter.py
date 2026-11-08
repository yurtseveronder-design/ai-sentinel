"""
Unit tests for SimpleRateLimiter in SecurityShield Lab.
"""

import pytest
from ai_sentinel.core.rate_limiter import SimpleRateLimiter


def test_rate_limiter_allows_within_limit():
    limiter = SimpleRateLimiter(max_requests=2, window_seconds=10)
    assert limiter.check_rate_limit("client_1") is True
    assert limiter.check_rate_limit("client_1") is True


def test_rate_limiter_blocks_exceeded_limit():
    limiter = SimpleRateLimiter(max_requests=1, window_seconds=10)
    assert limiter.check_rate_limit("client_2") is True
    assert limiter.check_rate_limit("client_2") is False