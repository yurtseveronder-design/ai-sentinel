import time
import threading
from typing import Dict, List

class RateLimiter:
    """
    Lightweight in-memory sliding-window rate limiter per session ID.
    """
    def __init__(self, max_requests: int = 15, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.client_timestamps: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, session_id: str) -> bool:
        if not session_id:
            return True  # Unidentified sessions bypass strict rate limiting or use global fallbacks

        now = time.time()
        with self._lock:
            if session_id not in self.client_timestamps:
                self.client_timestamps[session_id] = []

            # Filter out timestamps outside the current time window
            window_start = now - self.window_seconds
            self.client_timestamps[session_id] = [
                t for t in self.client_timestamps[session_id] if t > window_start
            ]

            if len(self.client_timestamps[session_id]) >= self.max_requests:
                return False

            self.client_timestamps[session_id].append(now)
            return True