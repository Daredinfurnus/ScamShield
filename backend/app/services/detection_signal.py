"""Standardized detection signal contract.

A detection signal represents a single risk indicator produced by an analysis
service. Signals are aggregated by RiskScorer to produce the authoritative
risk score. The LLM never calculates or overrides risk scores.
"""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class DetectionSignal(BaseModel):
    """A structured risk signal from an analysis service.

    Attributes:
        signal_type: Category of signal (e.g. text, url, ocr).
        name: Human-readable signal name.
        description: Detailed signal description.
        score: Risk contribution 0-100.
        weight: Multiplier for the signal score (default 1.0).
        confidence: Confidence in the signal 0-1 (default 1.0).
        evidence_snippet: Actual observed evidence from input.
        evidence_source: Source of the evidence (e.g. message_body, url_input).
        metadata: Non-secret additional data.
    """

    signal_type: str = Field(..., description="Category of signal")
    name: str = Field(..., description="Human-readable signal name")
    description: Optional[str] = Field(
        None, description="Detailed signal description"
    )
    score: float = Field(
        0.0, ge=0.0, le=100.0, description="Risk contribution 0-100"
    )
    weight: float = Field(1.0, ge=0.0, description="Multiplier for signal score")
    confidence: float = Field(
        1.0, ge=0.0, le=1.0, description="Confidence in signal 0-1"
    )
    evidence_snippet: Optional[str] = Field(
        None, description="Actual observed evidence"
    )
    evidence_source: Optional[str] = Field(
        None, description="Source of the evidence"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None, description="Non-secret additional data"
    )

    @field_validator("metadata")
    @classmethod
    def _no_secrets(
        cls, v: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Ensure metadata does not contain API keys or secrets."""
        if v is None:
            return v
        forbidden = {
            "api_key",
            "apikey",
            "secret",
            "password",
            "token",
            "private_key",
        }
        for key in v:
            if key.lower() in forbidden:
                raise ValueError(
                    f"Metadata key '{key}' may contain secrets"
                )
        return v

    def to_api_signal(self) -> Dict[str, Any]:
        """Convert to the API-facing Signal dict format."""
        return {
            "name": self.name,
            "score": self.score,
            "evidence": self.evidence_snippet or "",
            "source": self.evidence_source or "",
            "signal_type": self.signal_type,
            "description": self.description,
            "weight": self.weight,
            "confidence": self.confidence,
            "evidence_snippet": self.evidence_snippet,
            "evidence_source": self.evidence_source,
            "metadata": self.metadata,
        }