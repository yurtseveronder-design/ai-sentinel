import unittest
from fastapi.testclient import TestClient
from ai_sentinel.apps.api.main import app

class TestSentinelAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_inspect_allow(self):
        response = self.client.post("/inspect", json={"text": "Reset the form"})
        self.assertEqual(response.status_code, 200)

    def test_inspect_block(self):
        response = self.client.post("/inspect", json={"text": "DROP TABLE users; --"})
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
