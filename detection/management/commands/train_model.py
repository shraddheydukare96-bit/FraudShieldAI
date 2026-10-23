"""Management command: train and evaluate the text classifier.

Reproducible (fixed random state, stratified train/test split). Prints metrics
and a confusion matrix computed from real predictions, then saves the model
artifact and a JSON evaluation report to ``mlartifacts/``.
"""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from detection.ml import classifier
from detection.ml.artifacts import METRICS_PATH, MODEL_PATH, ensure_artifact_dir
from detection.ml.dataset import DatasetError, load_corpus


class Command(BaseCommand):
    help = "Train the SMS/email fraud classifier and report evaluation metrics."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dataset",
            default="data/fraud_text_dataset.csv",
            help="Path to the labelled CSV dataset.",
        )

    def handle(self, *args, **options):
        dataset_path = options["dataset"]
        try:
            corpus = load_corpus(dataset_path)
        except DatasetError as exc:
            raise CommandError(str(exc))

        self.stdout.write(f"Loaded {len(corpus)} labelled examples from {dataset_path}")

        pipeline, metrics = classifier.train_and_evaluate(
            corpus=corpus, dataset_path=dataset_path
        )

        ensure_artifact_dir()
        metrics["report_path"] = str(METRICS_PATH)
        classifier.save_model(pipeline, metrics)

        # Print an honest summary.
        self.stdout.write(self.style.HTTP_INFO("\n=== Evaluation (held-out test split) ==="))
        cm = metrics["confusion_matrix"]
        self.stdout.write(f"Model version      : {metrics['model_version']}")
        self.stdout.write(f"Train / test       : {metrics['train_samples']} / {metrics['test_samples']}")
        self.stdout.write(f"Accuracy           : {metrics['accuracy']}")
        self.stdout.write(f"Precision (fraud)  : {metrics['precision_fraud']}")
        self.stdout.write(f"Recall    (fraud)  : {metrics['recall_fraud']}")
        self.stdout.write(f"F1        (fraud)  : {metrics['f1_fraud']}")
        self.stdout.write(
            "Confusion matrix   : TN={} FP={} | FN={} TP={}".format(
                cm["true_negative_false_positive"][0],
                cm["true_negative_false_positive"][1],
                cm["false_negative_true_positive"][0],
                cm["false_negative_true_positive"][1],
            )
        )
        self.stdout.write(self.style.WARNING(f"\nNote: {metrics['note']}"))

        self.stdout.write(self.style.SUCCESS(f"\nSaved model   -> {MODEL_PATH}"))
        self.stdout.write(self.style.SUCCESS(f"Saved report  -> {METRICS_PATH}"))
        # Machine-readable echo for pipelines/CI.
        self.stdout.write(json.dumps(metrics))
