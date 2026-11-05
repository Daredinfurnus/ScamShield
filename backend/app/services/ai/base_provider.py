
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AIProviderABC(ABC):
    """Abstract base class for ScamShield AI providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider name."""
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the provider is available."""
        pass

    @abstractmethod
    def explain(
        self,
        investigation_id: int,
        findings: list[dict[str, Any]],
        risk_score: float,
    ) -> dict[str, Any]:
        """Explain an investigation using supplied evidence."""
        pass

    @abstractmethod
    def draft_report(
        self,
        investigation_id: int,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate an evidence-based investigation report."""
        pass

    @abstractmethod
    def chat(
        self,
        investigation_id: int,
        question: str,
    ) -> dict[str, Any]:
        """Answer investigation-specific questions."""
        pass

    @abstractmethod
    def get_status(self) -> dict[str, Any]:
        """Return provider status."""
        pass
