"""Framework-free machine-learning package for FraudShield AI.

Modules:
  * ``dataset``     - load the labelled CSV corpus.
  * ``classifier``  - TF-IDF + LogisticRegression train/eval/predict.
  * ``url_analyzer``- transparent rule-based URL risk scoring.
  * ``url_reputation`` - optional external reputation lookup (off by default).
  * ``engine``      - channel dispatch returning a unified ``AnalysisResult``.
  * ``result``      - the unified result dataclass.
"""
