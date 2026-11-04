import time

class RAGBenchmarkSuite:
    def __init__(self):
        self.metrics = {}

    def evaluate_retrieval(self, query: str, retrieved_docs: list, relevant_doc: str) -> dict:
        start_time = time.perf_counter()
        
        # Hit-rate / Precision at K
        hit = any(relevant_doc in doc for doc in retrieved_docs)
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        score = 1.0 if hit else 0.0
        
        return {
            "query": query,
            "retrieval_success": hit,
            "latency_ms": latency_ms,
            "score": score
        }
