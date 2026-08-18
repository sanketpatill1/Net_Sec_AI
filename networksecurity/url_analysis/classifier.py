"""URL Machine Learning classifier loader and inference engine."""

import json
from pathlib import Path
import joblib
import numpy as np

from .features import FEATURE_NAMES, extract_url_features, feature_row

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PRIMARY_MODEL_PATH = PROJECT_ROOT / "models" / "url_classifier.joblib"
PRIMARY_METADATA_PATH = PROJECT_ROOT / "models" / "model_metadata.json"
LEGACY_MODEL_PATH = PROJECT_ROOT / "url_model" / "url_classifier.joblib"
LEGACY_METADATA_PATH = PROJECT_ROOT / "url_model" / "metrics.json"

_CACHED_MODEL = None
_CACHED_METADATA = None


def get_model_and_metadata():
    global _CACHED_MODEL, _CACHED_METADATA
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL, _CACHED_METADATA

    model_path = PRIMARY_MODEL_PATH if PRIMARY_MODEL_PATH.exists() else LEGACY_MODEL_PATH
    metadata_path = PRIMARY_METADATA_PATH if PRIMARY_METADATA_PATH.exists() else LEGACY_METADATA_PATH

    if not model_path.exists():
        return None, None

    try:
        _CACHED_MODEL = joblib.load(model_path)
    except Exception:
        _CACHED_MODEL = None

    if metadata_path.exists():
        try:
            _CACHED_METADATA = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            _CACHED_METADATA = None

    return _CACHED_MODEL, _CACHED_METADATA


def predict_with_model(url: str) -> dict | None:
    model, metadata = get_model_and_metadata()
    if model is None:
        return None

    features_dict = extract_url_features(url)
    features_arr = np.asarray([[features_dict[name] for name in FEATURE_NAMES]], dtype=np.float32)

    raw_prediction = model.predict(features_arr)[0]
    predicted_class = str(raw_prediction).lower()

    classes = [str(c).lower() for c in getattr(model, "classes_", ["benign", "defacement", "malware", "phishing"])]

    probabilities_dict = {}
    malicious_prob = 0.0

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(features_arr)[0]
        probabilities_dict = {
            cls: round(float(probs[i]), 4)
            for i, cls in enumerate(classes)
        }
        malicious_prob = sum(prob for cls, prob in probabilities_dict.items() if cls != "benign")

    # Domain sampling calibration:
    # In URL datasets where benign samples are exclusively deep paths and root domains were only sampled in phishing,
    # clean root domains with zero risk indicators should not be falsely marked as phishing.
    is_clean_root_domain = (
        features_dict["path_length"] == 0
        and features_dict["has_ip_address"] == 0
        and features_dict["has_at_symbol"] == 0
        and features_dict["suspicious_keyword_count"] == 0
        and features_dict["is_shortener"] == 0
        and features_dict["suspicious_tld"] == 0
        and features_dict["unusual_hostname_pattern"] == 0
        and features_dict["hostname_digit_count"] == 0
        and features_dict["hyphen_count"] == 0
        and features_dict["subdomain_count"] <= 1
    )

    if is_clean_root_domain and predicted_class != "benign":
        predicted_class = "benign"
        probabilities_dict = {"benign": 0.95, "defacement": 0.02, "malware": 0.01, "phishing": 0.02}
        malicious_prob = 0.05

    # Map to security status: SAFE, SUSPICIOUS, MALICIOUS
    if predicted_class == "benign":
        if malicious_prob > 0.35:
            security_status = "SUSPICIOUS"
        else:
            security_status = "SAFE"
    else:
        # Threat class (phishing, malware, defacement)
        if malicious_prob >= 0.45 or probabilities_dict.get(predicted_class, 0.0) >= 0.40:
            security_status = "MALICIOUS"
        else:
            security_status = "SUSPICIOUS"

    confidence = probabilities_dict.get(predicted_class, 1.0) if probabilities_dict else 1.0

    return {
        "prediction": predicted_class,
        "security_status": security_status,
        "threat_type": predicted_class.capitalize(),
        "confidence": round(float(confidence), 4),
        "probabilities": probabilities_dict,
        "malicious_probability": round(float(malicious_prob), 4),
        "model_used": True,
        "model_name": metadata.get("model_name", type(model).__name__) if metadata else type(model).__name__,
    }
