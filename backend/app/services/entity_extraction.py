"""Entity extraction: regex-based pull of phones, URLs, emails, addresses.

Deterministic local extraction (Phase 8). Sentence Transformers semantic
similarity and optional NER are layered on top later. Returns a list of entity
dicts with type, value, and normalized value.
"""
from typing import List, Dict, Any


class EntityExtractor:
    def extract(self, text: str) -> List[Dict[str, Any]]:
        """Extract candidate entities from investigation text."""
        return [
            {
                "entity_type": "unknown",
                "value": "",
                "normalized_value": "",
                "note": "Entity extraction not yet implemented (Phase 8); returning empty fallback.",
            }
        ]