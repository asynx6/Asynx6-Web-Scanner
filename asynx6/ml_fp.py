"""Optional ML-based false-positive filter. V3.

Uses TF-IDF + LogisticRegression to re-score findings based on patterns from
labeled training data. Falls back gracefully if scikit-learn is not installed.
"""

from __future__ import annotations

import logging
from typing import Any

from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_sklearn_available: bool | None = None


def _check_sklearn() -> bool:
    global _sklearn_available
    if _sklearn_available is None:
        try:
            import sklearn  # noqa: F401
            _sklearn_available = True
        except ImportError:
            _sklearn_available = False
            log.warning(
                "scikit-learn not installed; ml_fp filter is a passthrough"
            )
    return _sklearn_available


def _features(finding: Finding) -> str:
    """Stringify a finding into a token bag for TF-IDF."""
    return " ".join([
        finding.type,
        finding.severity.value,
        finding.location,
        finding.description,
        finding.payload or "",
    ])


# A tiny built-in seed training set. Real deployments should train on a
# much larger labeled corpus, but this gives a non-zero baseline.
_SEED_DATA: list[tuple[str, int]] = [
    # (text, label) where label: 1 = real, 0 = false-positive
    ("SQL Injection confirmed root user admin CRITICAL", 1),
    ("SQL Injection test parameter payload", 0),
    ("Reflected XSS script alert confirmed HIGH", 1),
    ("Reflected XSS encoded output encoded low risk", 0),
    ("Local File Inclusion root:x:0:0: confirmed CRITICAL", 1),
    ("Local File Inclusion 404 not found", 0),
    ("Missing Content-Security-Policy LOW", 1),
    ("Missing Content-Security-Policy header default", 0),
    ("Open Redirect evil.example.com CRITICAL MEDIUM", 1),
    ("Open Redirect same origin relative url", 0),
    ("JWT alg=none token CRITICAL", 1),
    ("JWT normal valid token", 0),
    ("SSRF AWS IMDS reachable", 1),
    ("SSRF URL parameter 200 response", 0),
]


class FalsePositiveFilter:
    """TF-IDF + LogReg filter for finding re-scoring.

    Usage:
        flt = FalsePositiveFilter()
        flt.fit_seed()
        for finding in ctx.findings:
            score = flt.score(finding)
            if score < 0.5:
                finding.confidence = max(0, finding.confidence - 30)
    """

    def __init__(self) -> None:
        self._vectorizer = None
        self._classifier = None
        self._fitted = False

    def fit_seed(self) -> bool:
        """Fit on the built-in seed corpus. Returns True on success."""
        if not _check_sklearn():
            return False
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        texts = [t for t, _ in _SEED_DATA]
        labels = [l for _, l in _SEED_DATA]
        self._vectorizer = TfidfVectorizer(
            lowercase=True, max_features=500, ngram_range=(1, 2)
        )
        X = self._vectorizer.fit_transform(texts)
        self._classifier = LogisticRegression(max_iter=200)
        self._classifier.fit(X, labels)
        self._fitted = True
        return True

    def fit(self, findings: list[Finding], labels: list[int]) -> bool:
        """Fit on a custom (text, label) dataset."""
        if not _check_sklearn():
            return False
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        texts = [_features(f) for f in findings]
        self._vectorizer = TfidfVectorizer(
            lowercase=True, max_features=1000, ngram_range=(1, 2)
        )
        X = self._vectorizer.fit_transform(texts)
        self._classifier = LogisticRegression(max_iter=500)
        self._classifier.fit(X, labels)
        self._fitted = True
        return True

    def score(self, finding: Finding) -> float:
        """Return probability (0.0 - 1.0) that the finding is real.

        If sklearn is missing or the model is not fitted, returns 0.5
        (neutral — caller should keep the original confidence).
        """
        if not self._fitted or not _check_sklearn():
            return 0.5
        X = self._vectorizer.transform([_features(finding)])
        proba = self._classifier.predict_proba(X)[0]
        # index 1 = "real" class
        return float(proba[1])

    def adjust(self, finding: Finding) -> Finding:
        """Re-score a finding based on ML heuristic. Mutates confidence.

        If ML says probably-real (>0.7), boost confidence.
        If ML says probably-FP (<0.3), reduce confidence by 30.
        Otherwise leave unchanged.
        """
        prob = self.score(finding)
        if prob > 0.7:
            finding.confidence = min(100, finding.confidence + 10)
        elif prob < 0.3:
            finding.confidence = max(0, finding.confidence - 30)
        return finding