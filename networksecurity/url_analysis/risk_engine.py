"""Explainable, string-only URL risk assessment.

Risk is a transparent heuristic and is deliberately separate from ML confidence.
"""

from .features import extract_url_features


def assess_risk(url: str) -> dict:
    features = extract_url_features(url)
    score = 0
    indicators: list[str] = []

    def add(condition: bool, points: int, message: str) -> None:
        nonlocal score
        if condition:
            score += points
            indicators.append(message)

    add(features["uses_https"] == 1, -5, "HTTPS is enabled")
    add(features["has_ip_address"] == 1, 30, "IP address used instead of a domain name")
    add(features["has_at_symbol"] == 1, 25, "URL contains an @ symbol")
    add(features["is_shortener"] == 1, 18, "URL shortening service detected")
    add(features["suspicious_keyword_count"] > 0, min(25, features["suspicious_keyword_count"] * 7), "Suspicious login or account-related keyword detected")
    add(features["excessive_subdomains"] == 1, 15, "Excessive number of subdomains")
    add(features["url_length"] > 120, 12, "Unusually long URL")
    add(features["encoded_character_count"] > 0, 8, "Encoded characters detected")
    add(features["query_parameter_count"] > 5, 8, "Many query parameters detected")
    add(features["suspicious_tld"] == 1, 8, "TLD is frequently abused in phishing campaigns")
    add(features["unusual_hostname_pattern"] == 1, 8, "Unusual hostname pattern detected")
    add(features["uses_http"] == 1, 6, "URL does not use HTTPS")
    score = max(0, min(100, score))
    if not indicators:
        indicators.append("Normal URL structure; no high-risk URL patterns detected")
    if score <= 30:
        prediction, risk_level = "SAFE", "LOW"
    elif score <= 60:
        prediction, risk_level = "SUSPICIOUS", "MEDIUM"
    else:
        prediction, risk_level = "MALICIOUS", "HIGH"
    return {"prediction": prediction, "risk_score": score, "risk_level": risk_level, "indicators": indicators, "features": features}
