"""Dataset loading for the text classifier.

Uses the standard-library csv module (no pandas) to keep the training pipeline
lightweight and reproducible.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .artifacts import DEFAULT_DATASET


class DatasetError(Exception):
    """Raised when the labelled dataset is missing or malformed."""


@dataclass
class LabeledCorpus:
    texts: List[str]
    labels: List[int]

    def __len__(self) -> int:
        return len(self.texts)


def load_corpus(path: Path | str = DEFAULT_DATASET) -> LabeledCorpus:
    """Read the labelled CSV into parallel ``texts`` and ``labels`` lists.

    Raises :class:`DatasetError` if the file is absent or has no usable rows so
    callers can show an honest "dataset unavailable" message instead of a fake
    prediction.
    """
    path = Path(path)
    if not path.exists():
        raise DatasetError(f"Dataset not found at {path}.")

    texts: List[str] = []
    labels: List[int] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or not {"text", "label"}.issubset(reader.fieldnames):
            raise DatasetError(
                "Dataset must contain at least 'text' and 'label' columns."
            )
        for row in reader:
            text = (row.get("text") or "").strip()
            raw_label = (row.get("label") or "").strip()
            if not text or raw_label not in {"0", "1"}:
                continue
            texts.append(text)
            labels.append(int(raw_label))

    if len(texts) < 2 or len(set(labels)) < 2:
        raise DatasetError(
            "Dataset needs examples of both classes to train a model."
        )
    return LabeledCorpus(texts=texts, labels=labels)
