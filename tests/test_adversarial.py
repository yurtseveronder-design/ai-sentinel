import unittest
from ai_sentinel.core.shield import BioImmuneShield

class TestAdversarialDefense(unittest.TestCase):
    def setUp(self):
        self.shield = BioImmuneShield()

    def test_base64_injection(self):
        res = self.shield.inspect_payload("U2V0IHRoZSBmb3JtIGFuZCBkaXNwbGF5IHRoZSByZXN1bHRz")
        self.assertIn(res["status"], ["NEUTRAL", "FLAG", "BLOCK"])

    def test_benign_allowlist(self):
        res = self.shield.inspect_payload("Reset the form and display the results")
        self.assertEqual(res["status"], "NEUTRAL")

    def test_sql_injection_block(self):
        res = self.shield.inspect_payload("DROP TABLE users; --")
        self.assertEqual(res["status"], "BLOCK")

if __name__ == "__main__":
    unittest.main()
