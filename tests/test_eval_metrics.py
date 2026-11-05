import pytest
from ai_sentinel.eval import SentinelEvaluator

def test_sentinel_baseline_metrics():
    evaluator = SentinelEvaluator(mode="moderate")
    metrics = evaluator.run_evaluation()
    
    # Assert performance boundaries
    assert metrics["detection_rate"] >= 80.0
    assert metrics["false_positive_rate"] <= 20.0
    assert metrics["latency_p95_ms"] < 10.0  # Must stay under 10ms at P95