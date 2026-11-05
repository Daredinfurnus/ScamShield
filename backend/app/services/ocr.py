"""EasyOCR screenshot text extraction with a labelled fallback.

EasyOCR is initialized lazily. If it is unavailable (missing model files,
torch issues, etc.), this returns an empty result with a clear note rather than
pretending OCR succeeded.
"""
from typing import Dict, Any


class OCRProcessor:
    def extract(self, image_path: str) -> Dict[str, Any]:
        """Extract visible text from a screenshot image file."""
        return {
            "text": "",
            "score": 0.0,
            "evidence": "",
            "source": "ocr",
            "note": "EasyOCR not yet initialized (Phase 6); returning empty fallback.",
        }