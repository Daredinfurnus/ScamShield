"""Evidence normalization service.

Validates, normalizes, and structures evidence so that every finding
references actual, traceable input data. Never fabricates evidence.
"""
from typing import Any, Dict, Optional
import hashlib


class EvidenceService:
    """Handles evidence validation and normalization."""

    MAX_INPUT_SIZE = 10000  # characters

    def __init__(self, max_input_size: Optional[int] = None):
        self.max_input_size = max_input_size or self.MAX_INPUT_SIZE

    def validate_input(self, value: str, field_name: str = "input") -> str:
        """Validate that input is present, non-whitespace, and within size limits.

        Returns the stripped input value. Raises ValueError on invalid input.
        """
        if value is None:
            raise ValueError(f"{field_name} is required")
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")
        stripped = value.strip()
        if not stripped:
            raise ValueError(f"{field_name} cannot be empty or whitespace-only")
        if len(value) > self.max_input_size:
            raise ValueError(
                f"{field_name} exceeds maximum size of "
                f"{self.max_input_size} characters"
            )
        return stripped

    def normalize_text(self, text: str) -> str:
        """Normalize text for analysis while preserving semantic content."""
        return " ".join(text.split())

    def make_evidence_reference(
        self,
        snippet: str,
        source: str,
        original: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a structured evidence reference pointing to actual input.

        The snippet is capped at 500 characters. A short hash of the original
        input provides traceability without storing the full input in every
        finding.
        """
        return {
            "evidence_snippet": snippet[:500],
            "evidence_source": source,
            "evidence_hash": hashlib.sha256(
                (original or snippet).encode()
            ).hexdigest()[:16],
            "original_length": len(original or snippet),
        }

    def extract_snippet(self, text: str, max_length: int = 500) -> str:
        """Extract a safe evidence snippet from text."""
        if not text:
            return ""
        return text[:max_length]