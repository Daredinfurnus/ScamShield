"""Baseline text analysis using TF-IDF + Logistic Regression.

This module provides deterministic, locally-run text classification. It does not
depend on any external API and works offline once the vectorizer/model are fitted
(implemented in Phase 4). Until then it returns a neutral baseline so the rest of
the pipeline can be built and tested.
"""
from typing import Dict, Any


class TextAnalyzer:
    def analyze(self, text: str) -> Dict[str, Any]:
        """Run baseline scam classification on raw message text.

        Returns a dict with score (0-1), label, evidence snippet, and source.
        """
        return {
            "score": 0.0,
            "label": "unknown",
            "evidence": text[:200],
            "source": "message_body",
            "note": "TF-IDF + LogisticRegression model not yet trained (Phase 4); returning neutral baseline.",
        }