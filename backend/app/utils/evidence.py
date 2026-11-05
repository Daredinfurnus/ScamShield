"""Evidence reference helpers.

Every AI-generated finding must reference actual evidence. This module helps
build evidence-backed finding records so explanations stay grounded in data.
"""
from typing import Any, Dict


def make_evidence(snippet: str, source: str) -> Dict[str, Any]:
    """Return an evidence dict pairing an observed snippet with its source."""
    return {"evidence_snippet": snippet, "evidence_source": source}