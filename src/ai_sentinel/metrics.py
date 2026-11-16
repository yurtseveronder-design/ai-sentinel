"""Tiny Prometheus-format metrics (no extra dependency). Counters and one latency histogram, thread-safe."""

import threading
from collections import defaultdict

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)

_lock = threading.Lock()
_counters = defaultdict(int)      # (name, labels-tuple) -> value
_hist_counts = [0] * (len(BUCKETS) + 1)
_hist_sum = 0.0


def inc(name: str, **labels) -> None:
    with _lock:
        _counters[(name, tuple(sorted(labels.items())))] += 1


def observe_scan(seconds: float) -> None:
    global _hist_sum
    with _lock:
        _hist_sum += seconds
        for i, bound in enumerate(BUCKETS):
            if seconds <= bound:
                _hist_counts[i] += 1
                break
        else:
            _hist_counts[-1] += 1


def reset() -> None:
    global _hist_sum
    with _lock:
        _counters.clear()
        _hist_counts[:] = [0] * (len(BUCKETS) + 1)
        _hist_sum = 0.0


def render() -> str:
    with _lock:
        lines = ["# HELP sentinel_events_total Gateway events by kind and label.",
                 "# TYPE sentinel_events_total counter"]
        for (name, labels), value in sorted(_counters.items()):
            label_text = ",".join(f'{k}="{v}"' for k, v in labels)
            lines.append(f'sentinel_events_total{{event="{name}"{"," + label_text if label_text else ""}}} {value}')
        lines += ["# HELP sentinel_scan_duration_seconds Time spent scanning one prompt.",
                  "# TYPE sentinel_scan_duration_seconds histogram"]
        running = 0
        for bound, count in zip(BUCKETS, _hist_counts):
            running += count
            lines.append(f'sentinel_scan_duration_seconds_bucket{{le="{bound}"}} {running}')
        total = running + _hist_counts[-1]
        lines.append(f'sentinel_scan_duration_seconds_bucket{{le="+Inf"}} {total}')
        lines.append(f"sentinel_scan_duration_seconds_sum {_hist_sum:.6f}")
        lines.append(f"sentinel_scan_duration_seconds_count {total}")
        return "\n".join(lines) + "\n"
