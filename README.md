# NetSecAI: URL-Based Website Security Analyzer

An intelligent, production-ready cybersecurity system designed to analyze website URLs and detect malicious cyber threats—including **Phishing**, **Malware**, and **Web Defacement**—using deterministic lexical URL feature extraction, trained machine learning models, and explainable heuristic risk engines.

---

## 1. Project Overview

Modern cyberattacks frequently leverage deceptive, obfuscated, or malicious URLs to conduct credential harvesting, malware delivery, and domain hijacking. 

**NetSecAI** provides a real-time URL security analysis engine that:
1. Validates and normalizes user-submitted URLs without performing dangerous external network fetches.
2. Extracts **24 deterministic structural and lexical features** (e.g., Shannon entropy, token lengths, subdomain depth, keyword triggers, TLD risk).
3. Evaluates the feature vector with a trained **Random Forest multi-class classifier** (300 estimators, balanced sub-sampling).
4. Generates a multi-class probability distribution (`benign`, `defacement`, `phishing`, `malware`) and mapped security tier (`SAFE`, `SUSPICIOUS`, `MALICIOUS`).
5. Augments predictions with an explainable **0–100 heuristic risk score** and human-readable risk indicators.

> **Important Usage Note**: The dataset/CSV is used purely for offline internal model training. End users interact with the system strictly by entering a target website URL (e.g., `https://example.com`). CSV file uploads are **not** required for standard website analysis.

---

## 2. Architecture & Workflow

```
                          ┌──────────────────────────┐
                          │   User Enters Web URL    │
                          │   (e.g., https://... )   │
                          └─────────────┬────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │    Strict Validation     │
                          │ & Scheme Normalization   │
                          └─────────────┬────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │  Deterministic 24-Feature│
                          │   Lexical Extraction     │
                          └───────┬──────────┬───────┘
                                  │          │
                 ┌────────────────┘          └────────────────┐
                 ▼                                            ▼
   ┌──────────────────────────┐                 ┌──────────────────────────┐
   │  Trained ML Classifier   │                 │ Heuristic Risk Engine    │
   │  (Random Forest Multi)   │                 │ (Structural Indicators)  │
   └─────────────┬────────────┘                 └─────────────┬────────────┘
                 │                                            │
                 │   P(Benign), P(Phishing),                  │   0-100 Risk Score,
                 │   P(Defacement), P(Malware)                │   Security Indicators
                 │                                            │
                 └────────────────┬──────────┬────────────────┘
                                  │          │
                                  ▼          ▼
                          ┌──────────────────────────┐
                          │ Calibrated Risk Response │
                          │  (SAFE / SUSP / MAL)     │
                          └─────────────┬────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │  React Dark-Mode UI      │
                          │  & Real-Time Dashboard   │
                          └──────────────────────────┘
```

---

## 3. Technology Stack

- **Backend**: Python 3.13 / FastAPI, Uvicorn, Pydantic, scikit-learn, joblib, Pandas, NumPy.
- **Frontend**: React 19, Vite, Lucide Icons, Custom Vanilla CSS Glassmorphism Design System.
- **Machine Learning**: Random Forest Classifier, HistGradientBoosting, Logistic Regression, StandardScaler.
- **Testing**: Python `unittest`, `FastAPI TestClient`, Vite build audits.

---

## 4. Dataset Source & Preprocessing

The primary training dataset is **`Malicious URL v3.csv`** (sourced from real-world malicious and benign URL repositories):

### Data Statistics & Cleaning Audit:
- **Raw Input Rows**: 49,750
- **Missing Values**: 0
- **Malformed / Invalid URLs Removed**: 1 (Invalid IDNA hostname)
- **Duplicate URLs Removed**: 9,311
- **Conflicting Labels on Identical URLs**: 0
- **Final Clean Rows**: **40,438**
- **Clean Label Distribution**:
  - `benign`: 29,854 (73.83%) $\rightarrow$ `SAFE`
  - `defacement`: 7,455 (18.44%) $\rightarrow$ `MALICIOUS`
  - `phishing`: 2,459 (6.08%) $\rightarrow$ `MALICIOUS`
  - `malware`: 670 (1.66%) $\rightarrow$ `MALICIOUS`

### Stratified Data Split (Leakage-Free):
- **Training Set (70%)**: 28,306 samples
- **Validation Set (15%)**: 6,066 samples
- **Held-Out Test Set (15%)**: 6,066 samples

---

## 5. URL Feature Engineering

All **24 features** are computed in-memory directly from the URL string without external network queries:

| Feature Name | Description & Security Relevance |
| :--- | :--- |
| `url_length` | Total character count of domain, path, and query. |
| `hostname_length` | Hostname character count; long hosts often indicate DGA or spoofing. |
| `path_length` | Path character length. |
| `dot_count` | Number of `.` characters across the URL. |
| `subdomain_count` | Number of subdomains (excluding TLD & apex domain). |
| `slash_count` | Number of `/` path and query delimiters. |
| `hyphen_count` | Hyphen count; commonly abused in brand spoofing (`paypal-security-update`). |
| `underscore_count` | Underscore count in path or domain. |
| `digit_count` | Total numerical digits in URL string. |
| `special_char_count` | Count of non-alphanumeric characters excluding standard delimiters. |
| `has_at_symbol` | Binary flag for `@` in path/query (used to obscure destination authority). |
| `has_ip_address` | Binary flag for IPv4/IPv6 host instead of a registered domain. |
| `uses_https` | Binary flag for secure HTTPS protocol. |
| `uses_http` | Binary flag for plain HTTP protocol. |
| `suspicious_keyword_count` | Matches for sensitive triggers (`login`, `verify`, `account`, `bank`, `wallet`, `signin`, `update`). |
| `is_shortener` | Binary flag detecting known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.). |
| `excessive_subdomains` | Binary flag for $\ge 3$ subdomains. |
| `encoded_character_count` | Count of `%` hex-encoded sequences. |
| `query_parameter_count` | Number of parsed URL query arguments. |
| `has_fragment` | Binary flag for `#` anchor fragment. |
| `suspicious_tld` | Binary flag for high-abuse TLDs (`.zip`, `.xyz`, `.top`, `.tk`, `.click`, `.work`). |
| `unusual_hostname_pattern` | Binary flag for multi-hyphens or double hyphens (`--`). |
| `url_entropy` | Shannon entropy measuring character randomness. |
| `hostname_digit_count` | Total numerical digits in the hostname. |

---

## 6. Model Training & Evaluation

Three candidate models were evaluated on the stratified validation split:

| Candidate Model | Validation Accuracy | Validation Macro F1 | Weighted F1 | Multi-Class ROC-AUC (OvR) |
| :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression (Balanced)** | 72.72% | 54.81% | 75.90% | 86.90% |
| **HistGradientBoosting** | 89.60% | 79.14% | 90.02% | 97.44% |
| **Random Forest (Selected)** | **93.27%** | **85.77%** | **93.08%** | **97.49%** |

### Final Evaluation on Held-Out Test Set (6,066 samples):
- **Overall Accuracy**: **92.88%**
- **Macro F1 Score**: **85.41%**
- **Weighted F1 Score**: **92.71%**
- **Multi-Class ROC-AUC (Macro OvR)**: **97.49%**

#### Per-Class Performance Breakdown:
| Class | Precision | Recall | F1-Score | Test Support |
| :--- | :---: | :---: | :---: | :---: |
| **Benign** | 93.91% | 97.50% | 95.67% | 4,478 |
| **Defacement** | 87.43% | 80.86% | 84.01% | 1,118 |
| **Phishing** | 96.17% | 81.57% | 88.27% | 369 |
| **Malware** | 90.00% | 62.38% | 73.68% | 101 |

---

## 7. API Reference

### 1. Analyze URL
- **Endpoint**: `POST /api/analyze-url`
- **Request Body**:
  ```json
  {
    "url": "https://example.com/login"
  }
  ```
- **Response**:
  ```json
  {
    "url": "https://example.com/login",
    "prediction": "benign",
    "security_status": "SAFE",
    "threat_type": "Benign",
    "confidence": 0.95,
    "probabilities": {
      "benign": 0.95,
      "defacement": 0.02,
      "malware": 0.01,
      "phishing": 0.02
    },
    "malicious_probability": 0.05,
    "risk_score": 2,
    "risk_level": "LOW",
    "indicators": [
      "HTTPS is enabled",
      "Suspicious login or account-related keyword detected"
    ],
    "features": {
      "url_length": 17,
      "hostname_length": 11,
      "path_length": 6,
      "dot_count": 1,
      "subdomain_count": 0,
      "slash_count": 1,
      "hyphen_count": 0,
      "underscore_count": 0,
      "digit_count": 0,
      "special_char_count": 0,
      "has_at_symbol": 0,
      "has_ip_address": 0,
      "uses_https": 1,
      "uses_http": 0,
      "suspicious_keyword_count": 1,
      "is_shortener": 0,
      "excessive_subdomains": 0,
      "encoded_character_count": 0,
      "query_parameter_count": 0,
      "has_fragment": 0,
      "suspicious_tld": 0,
      "unusual_hostname_pattern": 0,
      "url_entropy": 3.42,
      "hostname_digit_count": 0
    },
    "analysis_type": "Trained ML classifier + URL-structure risk indicators",
    "model_used": true,
    "model_name": "random_forest",
    "notice": "Risk score and prediction are derived purely from URL structure and machine learning; they are not an absolute guarantee of website safety."
  }
  ```

### 2. Model Metadata & Evaluation Info
- **Endpoint**: `GET /api/model-info`
- **Response**: Returns full model metadata, candidate benchmark tables, and confusion matrix.

---

## 8. Installation & Local Setup

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Clone & Install Backend Dependencies
```powershell
cd C:\Network_Security
pip install -r requirements.txt
```

### 2. Prepare Dataset & Train Model
```powershell
# Step 1: Clean raw dataset
python training/prepare_url_dataset.py

# Step 2: Train and save Random Forest classifier
python training/train_url_classifier.py
```

### 3. Start FastAPI Backend Server
```powershell
python app.py
```
*Backend runs at: `http://127.0.0.1:8000` (API documentation at `/docs`)*

### 4. Start React Frontend
In a new terminal:
```powershell
cd C:\Network_Security\frontend
npm install
npm run dev
```
*Frontend runs at: `http://localhost:5173`*

---

## 9. Security Audit & Considerations

1. **SSRF Safe**: The backend performs zero remote HTTP/TCP connections for submitted URLs. It treats all user input as untrusted text.
2. **Strict Protocol Whitelisting**: Only `http://` and `https://` are permitted. Dangerous schemes like `javascript:`, `data:`, `file:`, and `ftp:` are rejected immediately with HTTP 422.
3. **Input Sanitization**: Control characters, invalid ports, and excessively long URLs ($> 2,048$ characters) are blocked.
4. **CORS Hardened**: Restricted to trusted local development origins (`http://localhost:5173`, `http://127.0.0.1:5173`).

---

## 10. Limitations & Disclaimer

- **Lexical Nature**: The model classifies URLs based on text structure and lexical characteristics. A legitimate compromised website hosting fresh zero-day phishing on an otherwise normal domain may receive a low structural risk score.
- **Safety Disclaimer**: The risk score and machine learning prediction represent probabilistic threat assessments based on known patterns; they do not guarantee that any website is safe or malicious. Always exercise caution when browsing unfamiliar links.
