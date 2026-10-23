"""Reproducible text-classification model (TF-IDF + Logistic Regression).

Training/evaluation and inference live here, entirely separate from Django
views. The web layer only calls :func:`predict_text` and
:func:`url_analyzer.analyze_url` through the service layer.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_fscore_support,
    accuracy_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .artifacts import MODEL_PATH, MODEL_VERSION, ensure_artifact_dir
from .dataset import LabeledCorpus, load_corpus
from .result import FRAUD, LEGITIMATE, AnalysisResult

RANDOM_STATE = 42  # fixed for reproducibility
TEST_SIZE = 0.25


class ModelUnavailableError(Exception):
    """Raised when the trained model artifact is missing or unreadable."""


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=1,
                    max_df=0.9,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    solver="liblinear",
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )


def train_and_evaluate(
    corpus: LabeledCorpus | None = None,
    dataset_path: Path | str | None = None,
) -> Tuple[Pipeline, Dict[str, Any]]:
    """Fit the model, evaluate on a held-out test split and return metrics.

    Metrics are computed only from real predictions on the test set - nothing is
    fabricated or estimated.
    """
    corpus = corpus or load_corpus(dataset_path or "data/fraud_text_dataset.csv")

    X_train, X_test, y_train, y_test = train_test_split(
        corpus.texts,
        corpus.labels,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=corpus.labels,
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    metrics: Dict[str, Any] = {
        "model_version": MODEL_VERSION,
        "dataset": str(dataset_path or "data/fraud_text_dataset.csv"),
        "total_samples": len(corpus),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision_fraud": round(float(precision), 4),
        "recall_fraud": round(float(recall), 4),
        "f1_fraud": round(float(f1), 4),
        # Confusion matrix rows = actual [ham, fraud], cols = predicted [ham, fraud].
        "confusion_matrix": {
            "labels": ["legitimate", "fraud"],
            "true_negative_false_positive": [int(cm[0][0]), int(cm[0][1])],
            "false_negative_true_positive": [int(cm[1][0]), int(cm[1][1])],
        },
        "note": (
            "Metrics are measured on a held-out split of the small project "
            "baseline corpus and do NOT represent real-world accuracy."
        ),
    }
    return pipeline, metrics


def save_model(pipeline: Pipeline, metrics: Dict[str, Any]) -> Path:
    ensure_artifact_dir()
    joblib.dump({"pipeline": pipeline, "model_version": MODEL_VERSION}, MODEL_PATH)
    Path(metrics["report_path"] if "report_path" in metrics else _metrics_path()).write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    return MODEL_PATH


def _metrics_path() -> Path:
    from .artifacts import METRICS_PATH

    return METRICS_PATH


# Lazy loader so importing this module never requires the artifact to exist.
_CACHE: Dict[str, Any] = {"pipeline": None}


def _load_pipeline() -> Pipeline:
    if _CACHE["pipeline"] is not None:
        return _CACHE["pipeline"]
    if not Path(MODEL_PATH).exists():
        raise ModelUnavailableError(
            "The text-classification model has not been trained yet. "
            "Run 'python manage.py train_model' to create it."
        )
    try:
        payload = joblib.load(MODEL_PATH)
    except Exception as exc:  # corrupt artifact -> honest failure, no fake result
        raise ModelUnavailableError(f"Model artifact is unreadable: {exc}") from exc
    _CACHE["pipeline"] = payload["pipeline"]
    return _CACHE["pipeline"]


def model_available() -> bool:
    """True only when a real, loadable trained model exists."""
    try:
        _load_pipeline()
        return True
    except ModelUnavailableError:
        return False


def _top_signal_terms(pipeline: Pipeline, text: str, top_n: int = 5) -> List[str]:
    """Return input tokens whose learned weights most support the fraud class."""
    tfidf = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["clf"]
    vec = tfidf.transform([text])
    feature_names = tfidf.get_feature_names_out()
    # LogisticRegression.coef_[0] is weights for the positive (fraud) class.
    weights = clf.coef_[0]
    idx = vec.nonzero()[1]
    if len(idx) == 0:
        return []
    scored = sorted(idx, key=lambda i: weights[i], reverse=True)[:top_n]
    return [feature_names[i] for i in scored if weights[i] > 0]


def predict_text(text: str, channel: str = "sms") -> AnalysisResult:
    """Classify SMS/email text using the trained model.

    Raises :class:`ModelUnavailableError` when no trained model is present, so
    callers can show an honest message rather than inventing a prediction.
    """
    if not text or not text.strip():
        raise ValueError("Analysis text must not be empty.")

    pipeline = _load_pipeline()
    proba = pipeline.predict_proba([text])[0]
    label = int(pipeline.predict([text])[0])
    fraud_prob = float(proba[1]) if len(proba) == 2 else float(label)

    signals = _top_signal_terms(pipeline, text)
    recommendations = _recommendations_for_text(label, signals)

    return AnalysisResult(
        channel=channel,
        classification=FRAUD if label == 1 else LEGITIMATE,
        risk_score=round(fraud_prob, 4),
        score_kind="probability",
        signals=signals,
        recommendations=recommendations,
        source="text_model",
        model_version=MODEL_VERSION,
        detail={"fraud_probability": round(fraud_prob, 4)},
    )


def _recommendations_for_text(label: int, signals: List[str]) -> List[str]:
    recs: List[str] = []
    lowered = " ".join(signals).lower()
    if label == 1:
        recs.append("Treat this message as suspicious; do not click links or reply.")
        if "http" in lowered or any(s.startswith("http") for s in signals):
            recs.append("Verify any link by navigating to the official site directly.")
        recs.append("Report the sender and delete the message if unverified.")
    else:
        recs.append("No strong fraud indicators found; still exercise normal caution.")
    return recs
