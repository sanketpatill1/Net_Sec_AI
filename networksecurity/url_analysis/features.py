"""Shared deterministic URL feature extraction for training and prediction."""

import math
import re
from collections import Counter
from ipaddress import ip_address
from urllib.parse import parse_qsl, urlsplit

from .validator import normalize_url

FEATURE_NAMES = (
    "url_length", "hostname_length", "path_length", "dot_count", "subdomain_count",
    "slash_count", "hyphen_count", "underscore_count", "digit_count", "special_char_count",
    "has_at_symbol", "has_ip_address", "uses_https", "uses_http", "suspicious_keyword_count",
    "is_shortener", "excessive_subdomains", "encoded_character_count", "query_parameter_count",
    "has_fragment", "suspicious_tld", "unusual_hostname_pattern", "url_entropy", "hostname_digit_count",
)
SUSPICIOUS_KEYWORDS = ("login", "verify", "secure", "account", "update", "wallet", "bonus", "free", "bank", "signin")
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "work", "country", "stream"}


def _is_ip(hostname: str) -> bool:
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_url_features(value: str) -> dict[str, int]:
    """Return a feature dictionary in the stable FEATURE_NAMES order."""
    url = normalize_url(value)
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    labels = hostname.split(".")
    subdomain_count = max(0, len(labels) - 2) if not _is_ip(hostname) else 0
    raw_without_scheme = url.split("://", 1)[1] if "://" in url else url
    keyword_count = sum(keyword in raw_without_scheme.lower() for keyword in SUSPICIOUS_KEYWORDS)
    entropy_target = raw_without_scheme if raw_without_scheme else url
    entropy = -sum((count / len(entropy_target)) * math.log2(count / len(entropy_target)) for count in Counter(entropy_target).values()) if entropy_target else 0.0

    return {
        "url_length": len(raw_without_scheme),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "dot_count": raw_without_scheme.count("."),
        "subdomain_count": subdomain_count,
        "slash_count": raw_without_scheme.count("/"),
        "hyphen_count": raw_without_scheme.count("-"),
        "underscore_count": raw_without_scheme.count("_"),
        "digit_count": sum(char.isdigit() for char in raw_without_scheme),
        "special_char_count": len(re.findall(r"[^A-Za-z0-9./:_?&=#+%-]", raw_without_scheme)),
        "has_at_symbol": int("@" in raw_without_scheme),
        "has_ip_address": int(_is_ip(hostname)),
        "uses_https": int(parsed.scheme == "https"),
        "uses_http": int(parsed.scheme == "http"),
        "suspicious_keyword_count": keyword_count,
        "is_shortener": int(hostname in SHORTENER_DOMAINS),
        "excessive_subdomains": int(subdomain_count >= 3),
        "encoded_character_count": raw_without_scheme.count("%"),
        "query_parameter_count": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "has_fragment": int(bool(parsed.fragment)),
        "suspicious_tld": int(labels[-1] in SUSPICIOUS_TLDS if labels else False),
        "unusual_hostname_pattern": int("--" in hostname or hostname.count("-") >= 3),
        "url_entropy": round(entropy, 6),
        "hostname_digit_count": sum(char.isdigit() for char in hostname),
    }


def feature_row(value: str) -> list[int]:
    features = extract_url_features(value)
    return [features[name] for name in FEATURE_NAMES]
