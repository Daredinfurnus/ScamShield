"""Deterministic backend risk scoring engine.

Risk scores are calculated here, never by the LLM. The engine aggregates
individual risk signals (text, URL, OCR, entity) into a 0-100 score and a risk
band (low / medium / high / critical).
"""
from typing import List, Dict, Any


class RiskScorer:
    # Thresholds for risk bands
    CRITICAL = 75
    HIGH = 50
    MEDIUM = 25

    def score(self, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate signals into a 0-100 risk score and band.

        Each signal dict may contain a 'score' (0-100 contribution) and optional
        'weight' multiplier. Missing scores default to 0.
        """
        total = 0.0
        for signal in signals:
            weight = signal.get("weight", 1.0)
            total += signal.get("score", 0.0) * weight

        score = min(100.0, max(0.0, round(total, 2)))

        if score >= self.CRITICAL:
            band = "critical"
        elif score >= self.HIGH:
            band = "high"
        elif score >= self.MEDIUM:
            band = "medium"
        else:
            band = "low"

        return {"risk_score": score, "risk_band": band}