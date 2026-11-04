from sentinel_core.shield import BioImmuneShield

class PromptTester:
    def __init__(self):
        self.shield = BioImmuneShield()

    def run_adversarial_suite(self, payloads: list) -> list:
        results = []
        for p in payloads:
            res = self.shield.scan(p)
            results.append({"payload": p, "result": res})
        return results
