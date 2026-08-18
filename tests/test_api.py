import sys
import unittest
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from fastapi.testclient import TestClient
    from app import app
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False


@unittest.skipUnless(FASTAPI_AVAILABLE, "FastAPI / TestClient is not available.")
class URLAPITests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_analyze_valid_https_url_success(self):
        response = self.client.post("/api/analyze-url", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["url"], "https://example.com")
        self.assertIn("prediction", data)
        self.assertIn("security_status", data)
        self.assertEqual(data["security_status"], "SAFE")
        self.assertIn("probabilities", data)
        self.assertIn("risk_score", data)
        self.assertIn("indicators", data)
        self.assertTrue(data["model_used"])

    def test_analyze_valid_http_url_success(self):
        response = self.client.post("/api/analyze-url", json={"url": "http://example.org/news/article"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["url"], "http://example.org/news/article")
        self.assertIn("security_status", data)

    def test_analyze_url_with_ip_address(self):
        response = self.client.post("/api/analyze-url", json={"url": "http://192.168.1.1/login/verify-bank-account"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn(data["security_status"], {"SUSPICIOUS", "MALICIOUS"})
        self.assertGreater(data["risk_score"], 30)

    def test_analyze_url_validation_rejections(self):
        invalid_urls = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://example.com",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "",
            "   ",
            "not-a-valid-url",
            "https://example.com:" + "9999999",  # Invalid port
            "https://example.com/" + "a" * 2050,  # Exceeds max length
        ]
        for bad_url in invalid_urls:
            response = self.client.post("/api/analyze-url", json={"url": bad_url})
            self.assertEqual(response.status_code, 422, f"Failed to reject invalid URL: {bad_url}")

    def test_get_model_info_endpoint(self):
        response = self.client.get("/api/model-info")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("model_name", data)
        self.assertIn("classes", data)
        self.assertIn("test_evaluation", data)
        self.assertEqual(set(data["classes"]), {"benign", "defacement", "malware", "phishing"})


if __name__ == "__main__":
    unittest.main()
