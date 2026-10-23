"""Filesystem locations for datasets, trained models and evaluation reports.

Kept free of Django imports so the training pipeline can run standalone.
"""
from __future__ import annotations

from pathlib import Path

# .../FraudShieldAI/detection/ml/artifacts.py -> parents[2] == project root
BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "data"
ARTIFACT_DIR = BASE_DIR / "mlartifacts"

# Default dataset + model locations. Overridable by the training command.
DEFAULT_DATASET = DATA_DIR / "fraud_text_dataset.csv"
MODEL_PATH = ARTIFACT_DIR / "text_classifier.joblib"
METRICS_PATH = ARTIFACT_DIR / "evaluation_report.json"

MODEL_VERSION = "tfidf-logreg-baseline-1"


def ensure_artifact_dir() -> Path:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_DIR
