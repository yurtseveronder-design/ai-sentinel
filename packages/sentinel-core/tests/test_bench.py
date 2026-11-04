from sentinel_core.bench import RAGBenchmarkSuite

def test_rag_benchmark():
    bench = RAGBenchmarkSuite()
    result = bench.evaluate_retrieval(
        query="What is AI safety?",
        retrieved_docs=["Doc A: unrelated", "Doc B: AI safety guardrails"],
        relevant_doc="AI safety guardrails"
    )
    assert result["retrieval_success"] is True
    assert result["score"] == 1.0
    assert result["latency_ms"] >= 0.0
