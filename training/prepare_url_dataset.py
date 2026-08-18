"""Clean the raw URL dataset and write a reproducible audit report.

Usage: python training/prepare_url_dataset.py
"""

import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from networksecurity.url_analysis.validator import URLValidationError, normalize_dataset_url

RAW_PATH = Path("data/raw/Malicious URL v3.csv")
OUTPUT_PATH = Path("data/processed/url_dataset_clean.csv")
REPORT_PATH = Path("data/processed/cleaning_report.json")
LABELS = {"benign", "defacement", "phishing", "malware"}


def main() -> None:
    df = pd.read_csv(RAW_PATH)
    report = {"input_rows": len(df), "removed": {}}
    df = df[["url", "type"]].rename(columns={"type": "label"}).copy()
    df["url"] = df["url"].astype("string").str.strip()
    df["label"] = df["label"].astype("string").str.strip().str.lower()
    missing = df["url"].isna() | df["url"].eq("") | df["label"].isna() | df["label"].eq("")
    report["removed"]["missing_url_or_label"] = int(missing.sum())
    df = df.loc[~missing].copy()
    invalid_label = ~df["label"].isin(LABELS)
    report["removed"]["invalid_label"] = int(invalid_label.sum())
    df = df.loc[~invalid_label].copy()
    normalized, invalid_urls = [], []
    for value in df["url"]:
        try:
            normalized.append(normalize_dataset_url(value))
            invalid_urls.append(False)
        except URLValidationError:
            normalized.append(None)
            invalid_urls.append(True)
    df["url"] = normalized
    invalid = pd.Series(invalid_urls, index=df.index)
    report["removed"]["malformed_url"] = int(invalid.sum())
    df = df.loc[~invalid].copy()
    before_dedup = len(df)
    df = df.drop_duplicates(subset=["url"], keep="first")
    report["removed"]["duplicate_url"] = before_dedup - len(df)
    df = df.sort_values("url").reset_index(drop=True)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)
    report.update({"output_rows": len(df), "label_distribution": df["label"].value_counts().to_dict(), "output_file": str(OUTPUT_PATH)})
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
