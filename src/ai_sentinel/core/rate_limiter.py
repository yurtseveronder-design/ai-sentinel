import time
import threading
from typing import Dict, List

class RateLimiter:
    """
    Bounded, memory-safe sliding-window rate limiter with TTL cleanup and size capping.
    """
    def __init__(self, max_requests: int = 20, window_seconds: float = 60.0, max_tracked_sessions: int = 10000):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tracked_sessions = max_tracked_sessions
        self.client_timestamps: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, session_id: str) -> bool:
        if not session_id:
            return True

        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            # Prevent unbounded growth by clearing oldest sessions if limit reached
            if len(self.client_timestamps) >= self.max_tracked_sessions and session_id not in self.client_timestamps:
                oldest_session = next(iter(self.client_timestamps))
                del self.client_timestamps[oldest_session]

            if session_id not in self.client_timestamps:
                self.client_timestamps[session_id] = []

            # Filter out timestamps outside the sliding window
            self.client_timestamps[session_id] = [
                t for t in self.client_timestamps[session_id] if t > window_start
            ]

            if len(self.client_timestamps[session_id]) >= self.max_requests:
                return False

            self.client_timestamps[session_id].append(now)
            return True