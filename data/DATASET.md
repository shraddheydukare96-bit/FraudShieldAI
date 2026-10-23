# Baseline Fraud Text Dataset

File: `data/fraud_text_dataset.csv`
Columns: `channel` (`sms` | `email`), `text`, `label` (`1` = fraud/phishing/spam, `0` = legitimate/ham).

## Source and provenance

This corpus is **authored specifically for the FraudShield AI project**. The
example messages were written by this project to cover common fraud patterns
(urgency, prize/lottery lures, credential-harvesting links, payment pressure,
delivery scams, get-rich-quick schemes) alongside ordinary legitimate traffic.

It is **not** the UCI "SMS Spam Collection", not Enron-Spam, and not copied from
any third-party dataset. No external dataset is downloaded or bundled. This keeps
provenance and licensing unambiguous.

## License

Released under the same permissive license as the FraudShield AI source,
**CC0 1.0 Universal (public domain dedication)** for the data. You may use,
modify and redistribute it freely. This is stated here so there is no ambiguity
about the data's rights.

## Honest limitations

- It is a **small baseline corpus (~100 examples)** intended only to demonstrate a
  reproducible end-to-end training/eval pipeline.
- Reported metrics (precision/recall/F1/confusion matrix) are computed on a
  held-out split of **this dataset only**. They do **not** represent real-world
  detection accuracy on production traffic.
- Real deployment requires a much larger, independently collected, and properly
  licensed dataset and recalibration.

## How to retrain

```powershell
python manage.py train_model
```

This writes the trained pipeline and an evaluation report to `mlartifacts/`.
