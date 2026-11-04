from sentinel_core.shield import BioImmuneShield

class RAGBenchmark:
    def __init__(self):
        self.shield = BioImmuneShield()

    def evaluate_faithfulness(self, query: str, response: str) -> dict:
        scan_res = self.shield.scan(query)
        return {
            "query": query,
            "faithfulness_score": 1.0 if scan_res["safe"] else 0.0,
            "shield_assessment": scan_res
        }
