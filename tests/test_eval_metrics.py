import pytest
from ai_sentinel.eval.evaluator import SentinelEvaluator

def test_sentinel_baseline_metrics():
    evaluator = SentinelEvaluator(mode="moderate")
    metrics = evaluator.run_evaluation()
    
    # Assert performance boundaries aligned with current detection suite
    assert metrics["detection_rate"] >= 60.0