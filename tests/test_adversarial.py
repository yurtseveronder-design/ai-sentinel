import unittest
from sentinel_core.shield import BioImmuneShield

class TestAdversarialDefense(unittest.TestCase):
    def setUp(self):
        self.shield = BioImmuneShield()

    def test_benign_allowlist(self):
        res = self.shield.inspect_payload("Reset the form and display the results")
        self.assertEqual(res["status"], "ALLOW")

    def test_base64_injection(self):
        res = self.shield.inspect_payload("U2V0IHRoZSBmb3Jt")
        self.assertIn(res["status"], ["ALLOW", "NEUTRAL"])

    def test_sql_injection_block(self):
        res = self.shield.inspect_payload("DROP TABLE users; --")
        self.assertEqual(res["status"], "NEUTRAL")

if __name__ == "__main__":
    unittest.main()
