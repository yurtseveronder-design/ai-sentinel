"""
Experimental Rate Limiter for SecurityShield Lab.
Provides lightweight memory-based request limiting per client identifier.
"""

import time
from typing import Dict, Tuple


class SimpleRateLimiter:
    """
    In-memory sliding window rate limiter to guard API endpoints.
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.clients: Dict[str, list] = {}

    def check_rate_limit(self, client_id: str) -> bool:
        """
        Checks if a client has exceeded their request quota.
        Returns True if allowed, False if rate-limited.
        """
        now = time.time()
        if client_id not in self.clients:
            self.clients[client_id] = []

        # Filter out timestamps outside the current window
        window_start = now - self.window_seconds
        self.clients[client_id] = [t for t in self.clients[client_id] if t > window_start]

        if len(self.clients[client_id]) >= self.max_requests:
            return False

        self.clients[client_id].append(now)
        return True