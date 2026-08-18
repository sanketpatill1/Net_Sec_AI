"""Train and evaluate multiclass URL classifiers with data leakage prevention and robust evaluation.

Usage: python training/train_url_classifier.py [path/to/clean_dataset.csv]
"""

import datetime
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from networksecurity.url_analysis.features import FEATURE_NAMES, feature_row

DEFAULT_DATASET = PROJECT_ROOT / "data" / "processed" / "url_dataset_clean.csv"
MODELS_DIR = PROJECT_ROOT / "models"
LEGACY_MODELS_DIR = PROJECT_ROOT / "url_model"


def train_and_evaluate(dataset_path: Path) -> dict:
    print(f"Loading cleaned dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(str).str.strip().str.lower()

    # Extract 24 features
    print(f"Extracting {len(FEATURE_NAMES)} features for {len(df)} URLs...")
    x = np.asarray([feature_row(url) for url in df["url"]], dtype=np.float32)
    y = df["label"].to_numpy()
    classes = sorted(np.unique(y).tolist())
    print(f"Unique classes ({len(classes)}): {classes}")

    # Stratified Train (70%) / Validation (15%) / Test (15%) split
    x_train_val, x_test, y_train_val, y_test = train_test_split(
        x, y, test_size=0.15, random_state=42, stratify=y
    )
    x_train, x_val, y_train, y_val = train_test_split(
        x_train_val, y_train_val, test_size=0.17647, random_state=42, stratify=y_train_val  # 0.17647 * 0.85 approx 0.15
    )

    split_stats = {
        "train": {
            "total": len(y_train),
            "distribution": pd.Series(y_train).value_counts().to_dict(),
        },
        "validation": {
            "total": len(y_val),
            "distribution": pd.Series(y_val).value_counts().to_dict(),
        },
        "test": {
            "total": len(y_test),
            "distribution": pd.Series(y_test).value_counts().to_dict(),
        },
    }

    print("\nDataset Split Summary:")
    print(f"  Training:   {split_stats['train']['total']} samples -> {split_stats['train']['distribution']}")
    print(f"  Validation: {split_stats['validation']['total']} samples -> {split_stats['validation']['distribution']}")
    print(f"  Testing:    {split_stats['test']['total']} samples -> {split_stats['test']['distribution']}\n")

    # Define candidate model pipelines
    candidate_pipelines = {
        "logistic_regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=25,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=200,
            random_state=42,
            class_weight="balanced",
        ),
    }

    validation_results = {}
    fitted_models = {}

    for name, model in candidate_pipelines.items():
        print(f"Training {name}...")
        model.fit(x_train, y_train)
        fitted_models[name] = model

        # Validation evaluation
        val_pred = model.predict(x_val)
        val_acc = accuracy_score(y_val, val_pred)
        val_macro_f1 = f1_score(y_val, val_pred, average="macro", zero_division=0)
        val_weighted_f1 = f1_score(y_val, val_pred, average="weighted", zero_division=0)

        prec, rec, f1, supp = precision_recall_fscore_support(y_val, val_pred, labels=classes, zero_division=0)
        per_class_metrics = {
            cls: {
                "precision": round(float(prec[i]), 4),
                "recall": round(float(rec[i]), 4),
                "f1_score": round(float(f1[i]), 4),
                "support": int(supp[i]),
            }
            for i, cls in enumerate(classes)
        }

        # Multiclass ROC-AUC (OvR)
        val_roc_auc = None
        if hasattr(model, "predict_proba"):
            try:
                val_proba = model.predict_proba(x_val)
                val_roc_auc = float(roc_auc_score(y_val, val_proba, multi_class="ovr", average="macro"))
            except Exception as e:
                print(f"  Note: ROC-AUC calculation skipped for {name}: {e}")

        validation_results[name] = {
            "accuracy": round(float(val_acc), 4),
            "macro_f1": round(float(val_macro_f1), 4),
            "weighted_f1": round(float(val_weighted_f1), 4),
            "roc_auc_macro_ovr": round(val_roc_auc, 4) if val_roc_auc is not None else None,
            "per_class": per_class_metrics,
        }
        print(f"  -> {name} | Val Accuracy: {val_acc:.4f} | Val Macro F1: {val_macro_f1:.4f} | Val Weighted F1: {val_weighted_f1:.4f}")

    # Model Selection: Prioritize Macro F1 on validation set
    best_name = max(validation_results.keys(), key=lambda k: validation_results[k]["macro_f1"])
    best_model = fitted_models[best_name]
    print(f"\nSelected Best Model: {best_name} (Validation Macro F1: {validation_results[best_name]['macro_f1']})")

    # Final Evaluation on Held-Out Test Set
    print("\nEvaluating best model on held-out test set...")
    test_pred = best_model.predict(x_test)
    test_acc = accuracy_score(y_test, test_pred)
    test_macro_f1 = f1_score(y_test, test_pred, average="macro", zero_division=0)
    test_weighted_f1 = f1_score(y_test, test_pred, average="weighted", zero_division=0)

    test_prec, test_rec, test_f1, test_supp = precision_recall_fscore_support(
        y_test, test_pred, labels=classes, zero_division=0
    )
    test_per_class = {
        cls: {
            "precision": round(float(test_prec[i]), 4),
            "recall": round(float(test_rec[i]), 4),
            "f1_score": round(float(test_f1[i]), 4),
            "support": int(test_supp[i]),
        }
        for i, cls in enumerate(classes)
    }

    test_roc_auc = None
    if hasattr(best_model, "predict_proba"):
        try:
            test_proba = best_model.predict_proba(x_test)
            test_roc_auc = float(roc_auc_score(y_test, test_proba, multi_class="ovr", average="macro"))
        except Exception:
            pass

    test_cm = confusion_matrix(y_test, test_pred, labels=classes).tolist()
    test_report_dict = classification_report(y_test, test_pred, labels=classes, output_dict=True, zero_division=0)

    # Compile comprehensive metadata
    model_metadata = {
        "model_name": best_name,
        "model_type": type(best_model).__name__,
        "dataset_name": dataset_path.name,
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_samples": len(df),
        "split_samples": split_stats,
        "feature_count": len(FEATURE_NAMES),
        "features": list(FEATURE_NAMES),
        "classes": classes,
        "label_mapping": {
            "benign": "SAFE",
            "defacement": "MALICIOUS",
            "phishing": "MALICIOUS",
            "malware": "MALICIOUS",
        },
        "candidate_validation_comparison": validation_results,
        "test_evaluation": {
            "accuracy": round(float(test_acc), 4),
            "macro_f1": round(float(test_macro_f1), 4),
            "weighted_f1": round(float(test_weighted_f1), 4),
            "roc_auc_macro_ovr": round(test_roc_auc, 4) if test_roc_auc is not None else None,
            "per_class": test_per_class,
            "confusion_matrix": test_cm,
            "classification_report": test_report_dict,
        },
    }

    # Save to models/ directory
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, MODELS_DIR / "url_classifier.joblib")
    (MODELS_DIR / "model_metadata.json").write_text(json.dumps(model_metadata, indent=2), encoding="utf-8")
    (MODELS_DIR / "feature_names.json").write_text(json.dumps(list(FEATURE_NAMES), indent=2), encoding="utf-8")

    # Also save to url_model/ for backwards compatibility
    LEGACY_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, LEGACY_MODELS_DIR / "url_classifier.joblib")
    (LEGACY_MODELS_DIR / "metrics.json").write_text(json.dumps(model_metadata, indent=2), encoding="utf-8")
    (LEGACY_MODELS_DIR / "feature_names.json").write_text(json.dumps(list(FEATURE_NAMES), indent=2), encoding="utf-8")

    print("\n=======================================================")
    print(f"Model saved successfully to {MODELS_DIR / 'url_classifier.joblib'}")
    print(f"Test Accuracy: {test_acc:.4f} | Test Macro F1: {test_macro_f1:.4f} | Test Weighted F1: {test_weighted_f1:.4f}")
    if test_roc_auc is not None:
        print(f"Test ROC-AUC (Macro OvR): {test_roc_auc:.4f}")
    print("=======================================================\n")
    print(json.dumps(test_per_class, indent=2))
    return model_metadata


def main():
    dataset_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DATASET
    if not dataset_path.exists():
        raise FileNotFoundError(f"Cleaned dataset not found at {dataset_path}. Run training/prepare_url_dataset.py first.")
    train_and_evaluate(dataset_path)


if __name__ == "__main__":
    main()
