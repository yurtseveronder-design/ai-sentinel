import time

class PerformanceTracker:
    @staticmethod
    def measure_latency(func, *args, **kwargs):
        """
        Measures the execution time (latency) of a target function.
        Returns a tuple of (result, elapsed_time_in_seconds).
        """
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()

        elapsed = end_time - start_time
        return result, elapsed

    @staticmethod
    def calculate_throughput(token_count: int, elapsed_seconds: float) -> float:
        """
        Calculates token generation throughput (tokens/second).
        """
        if elapsed_seconds <= 0:
            return 0.0
        return token_count / elapsed_seconds