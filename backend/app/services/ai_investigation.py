"""OpenAI-powered evidence-based investigation explanations and reports.

The LLM is used only to generate explanations that reference actual evidence and
to draft structured investigation report text. It never calculates or overrides
the risk score (that is the job of risk_scoring.py).

If the OpenAI API key is missing or the request fails, a clearly labelled
fallback message is returned. Fallback output is never presented as real AI
analysis.
"""
from typing import Optional, List, Dict, Any


class AIInvestigator:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def explain(self, findings: List[Dict[str, Any]], risk_score: float) -> str:
        """Produce an evidence-based explanation of the investigation result."""
        if not self.api_key:
            return (
                "[AI explanation unavailable] OpenAI API key not configured. "
                f"Risk score ({risk_score}) was calculated by the deterministic "
                "backend scoring engine, not by an LLM."
            )

        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            # TODO Phase 7: build evidence-grounded prompt and call chat.completions
            return (
                "[AI explanation pending] OpenAI client initialized but "
                "evidence-based explanation generation not yet implemented (Phase 7)."
            )
        except Exception as exc:  # noqa: BLE001 - surface API failures as labelled fallback
            return (
                f"[AI explanation unavailable] {type(exc).__name__}: {exc}. "
                "Risk score was calculated by the backend scoring engine."
            )

    def draft_report(self, investigation: Dict[str, Any]) -> str:
        """Draft a structured investigation report (JSON/text) referencing evidence."""
        if not self.api_key:
            return (
                "[AI report unavailable] OpenAI API key not configured. "
                "Report content below was assembled by the backend report engine."
            )
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            # TODO Phase 7/9: generate report text
            return "[AI report pending] OpenAI report generation not yet implemented (Phase 7/9)."
        except Exception as exc:  # noqa: BLE001
            return f"[AI report unavailable] {type(exc).__name__}: {exc}."