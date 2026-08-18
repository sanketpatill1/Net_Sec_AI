import sys
import unittest
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from networksecurity.url_analysis.classifier import predict_with_model
from networksecurity.url_analysis.features import FEATURE_NAMES, extract_url_features, feature_row
from networksecurity.url_analysis.risk_engine import assess_risk
from networksecurity.url_analysis.validator import URLValidationError, normalize_dataset_url, normalize_url


class URLAnalysisTests(unittest.TestCase):
    def test_valid_https_url(self):
        self.assertEqual(normalize_url("https://Example.com/path"), "https://example.com/path")

    def test_valid_http_url(self):
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")

    def test_dataset_url_normalization(self):
        self.assertEqual(normalize_dataset_url("example.com/login"), "http://example.com/login")
        self.assertEqual(normalize_dataset_url("https://example.com"), "https://example.com")

    def test_rejects_unsafe_or_empty_urls(self):
        invalid_cases = [
            "",
            "   ",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://example.com",
            "data:text/html,test",
            "http://",
            "https://",
            "http://user:pass@example.com",  # Credential rejection
        ]
        for value in invalid_cases:
            with self.assertRaises(URLValidationError, msg=f"Should reject: {value}"):
                normalize_url(value)

    def test_rejects_extremely_long_url(self):
        with self.assertRaises(URLValidationError):
            normalize_url("https://example.com/" + "a" * 2050)

    def test_ip_at_subdomains_and_encoding_features(self):
        features = extract_url_features("http://192.0.2.1/a%20b?x=1#section")
        self.assertEqual(features["has_ip_address"], 1)
        self.assertGreater(features["encoded_character_count"], 0)
        self.assertEqual(features["has_fragment"], 1)
        self.assertEqual(set(features), set(FEATURE_NAMES))
        self.assertEqual(len(feature_row("http://192.0.2.1/a%20b?x=1#section")), len(FEATURE_NAMES))
        self.assertEqual(extract_url_features("https://a.b.c.d.example.com")["excessive_subdomains"], 1)

    def test_at_symbol_detection_and_rejection(self):
        # In authority: rejected as credentials
        with self.assertRaises(URLValidationError):
            normalize_url("http://legit.com@phishing.com/login")

        # In path/query: permitted and detected in features
        features = extract_url_features("http://example.com/user/@handle?tag=@security")
        self.assertEqual(features["has_at_symbol"], 1)

    def test_suspicious_url_scores_higher_than_normal_url(self):
        safe = assess_risk("https://example.com")
        suspicious = assess_risk("http://192.0.2.1/login/verify-account?x=1&y=2&z=3&a=4&b=5&c=6")
        self.assertEqual(safe["prediction"], "SAFE")
        self.assertGreater(suspicious["risk_score"], safe["risk_score"])
        self.assertIn(suspicious["prediction"], {"SUSPICIOUS", "MALICIOUS"})

    def test_model_prediction_output_structure(self):
        result = predict_with_model("https://google.com")
        self.assertIsNotNone(result)
        self.assertIn("prediction", result)
        self.assertIn("security_status", result)
        self.assertIn("confidence", result)
        self.assertIn("probabilities", result)
        self.assertIn("malicious_probability", result)
        self.assertTrue(result["model_used"])
        self.assertIn(result["prediction"], {"benign", "defacement", "malware", "phishing"})
        self.assertIn(result["security_status"], {"SAFE", "SUSPICIOUS", "MALICIOUS"})

    def test_defacement_url_prediction(self):
        # Known defacement pattern from dataset
        url = "http://www.garage-pirenne.be/index.php?option=com_content&view=article&id=1"
        result = predict_with_model(url)
        self.assertIsNotNone(result)
        self.assertEqual(result["prediction"], "defacement")
        self.assertEqual(result["security_status"], "MALICIOUS")


if __name__ == "__main__":
    unittest.main()
