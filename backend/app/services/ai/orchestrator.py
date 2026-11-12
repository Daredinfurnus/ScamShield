"""AI orchestrator for ScamShield AI Investigation Assistant."""

from __future__ import annotations

from typing import Any, Dict, Optional


class AIOrchestrator:
    """Orchestrates AI investigation operations with OpenAI and deterministic fallback."""

    def __init__(
        self,
        openai_provider: Optional[OpenAIProvider] = None,
        deterministic_fallback: Optional[DeterministicFallback] = None,
    ):
        """Initialize the AI orchestrator."""
        self._openai_provider = openai_provider or OpenAIProvider()
        self._deterministic_fallback = deterministic_fallback or DeterministicFallback()

    def explain_investigation(
        self,
        investigation_id: int,
        findings: list[dict[str, Any]],
        risk_score: float,
        risk_band: str,
    ) -> dict[str, Any]:
        """Produce an evidence-based explanation of the investigation result."""
        # Try OpenAI provider first
        try:
            openai_result = self._openai_provider.explain(
                investigation_id=investigation_id,
                findings=findings,
                risk_score=risk_score,
            )

            if not openai_result.get("success"):
                raise ValueError(openai_result.get("error", "OpenAI request failed"))

            data = openai_result.get("data", {})

            return {
                "success": True,
                "provider": "openai",
                "fallback_used": False,
                "data": {
                    "explanation": data.get("summary", ""),
                    "supporting_evidence": data.get("observations", []),
                    "uncertainties": data.get("limitations", []),
                    "recommended_actions": data.get("recommendations", []),
                    "limitations": data.get("limitations", []),
                    "risk_score": risk_score,
                    "risk_band": risk_band,
                },
                "error": None,
            }

        except Exception:
            # OpenAI failed - fall back to deterministic
            fallback_result = self._deterministic_fallback.explain(
                findings=findings,
                risk_score=risk_score,
                risk_band=risk_band,
            )

            return {
                "success": True,
                "provider": "deterministic",
                "fallback_used": True,
                "data": {
                    "summary": fallback_result.get("summary", ""),
                    "observations": fallback_result.get("observations", []),
                    "recommendations": fallback_result.get("recommendations", []),
                    "limitations": fallback_result.get("limitations", []),
                    "risk_score": risk_score,
                    "risk_band": risk_band,
                },
                "error": None,
            }

    def generate_report(
        self,
        investigation_id: int,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Draft a structured investigation report."""
        # Try OpenAI provider first
        try:
            openai_result = self._openai_provider.draft_report(
                investigation_id=investigation_id,
                investigation_data=investigation_data,
            )

            # Validate OpenAI response succeeded
            if not openai_result.get("success"):
                raise ValueError(openai_result.get("error", "OpenAI request failed"))

            return {
                "success": True,
                "provider": "openai",
                "fallback_used": False,
                "data": {
                    "title": openai_result.get("title", ""),
                    "executive_summary": openai_result.get("executive_summary", ""),
                    "detailed_findings": openai_result.get("detailed_findings", ""),
                    "supporting_evidence": openai_result.get("supporting_evidence", []),
                    "uncertainties": openai_result.get("uncertainties", []),
                    "recommended_actions": openai_result.get("recommended_actions", []),
                    "limitations": openai_result.get("limitations", []),
                    "risk_score_from_scorer": investigation_data.get("risk_score"),
                    "risk_band_from_scorer": investigation_data.get("risk_band"),
                },
                "error": None,
            }

        except Exception:
            # OpenAI failed - fall back to deterministic
            fallback_result = self._deterministic_fallback.draft_report(
                investigation_data=investigation_data
            )

            return {
                "success": True,
                "provider": "deterministic",
                "fallback_used": True,
                "data": {
                    "investigation_id": fallback_result.get("investigation_id"),
                    "risk_score": fallback_result.get("risk_score"),
                    "risk_band": fallback_result.get("risk_band"),
                    "findings": fallback_result.get("findings", []),
                    "summary": fallback_result.get("summary", ""),
                    "recommendations": fallback_result.get("recommendations", []),
                    "limitations": fallback_result.get("limitations", []),
                },
                "error": None,
            }