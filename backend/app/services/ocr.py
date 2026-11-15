"""EasyOCR screenshot text extraction with lazy initialization and graceful fallback.

Extracts visible text from screenshot images (via file path, bytes, or PIL Image)
using EasyOCR. Returns extracted text, average confidence score, and evidence
attribution details for downstream scam detection analysis.
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
from typing import Any, Dict, Optional, Union

logger = logging.getLogger(__name__)


def _patch_pillow_antialias() -> None:
    """Restore the removed `PIL.Image.ANTIALIAS` constant.

    EasyOCR 1.7.0 references `Image.ANTIALIAS`, which was removed in Pillow 10+.
    Pointing it at `Image.LANCZOS` keeps the legacy interpolation constant alive
    without changing the actual resize behaviour.
    """
    try:
        import PIL.Image as _Image

        if not hasattr(_Image, "ANTIALIAS"):
            _Image.ANTIALIAS = _Image.LANCZOS  # type: ignore[attr-defined]
    except Exception:
        pass


def _ensure_utf8_stdout() -> None:
    """Force stdout/stderr to UTF-8 encoding.

    EasyOCR's download progress bar emits Unicode block characters (e.g.
    \\u2588) that raise UnicodeEncodeError under non-UTF-8 console codepages
    (e.g. Windows cp437/cp1252). Reconfiguring the streams before importing
    EasyOCR prevents the reader initialization from failing on such systems.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            encoding = getattr(stream, "encoding", None) or ""
            if encoding.lower() in ("utf-8", "utf8"):
                continue
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            try:
                import io

                wrapper = io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace", line_buffering=True)
                setattr(sys, stream_name, wrapper)
            except Exception:
                pass


class OCRProcessor:
    """Lazy-loading EasyOCR engine for screenshot text extraction."""

    def __init__(self, languages: Optional[list[str]] = None, gpu: bool = False):
        self.languages = languages or ["en"]
        self.gpu = gpu
        self._reader: Any = None
        self._initialized: bool = False
        self._init_failed: bool = False
        self._init_error: Optional[str] = None

    def _get_reader(self) -> Any:
        """Lazily initialize the EasyOCR reader instance."""
        if self._initialized:
            return self._reader
        if self._init_failed:
            return None

        try:
            _ensure_utf8_stdout()
            _patch_pillow_antialias()
            import easyocr

            logger.info("Initializing EasyOCR reader (languages=%s, gpu=%s)...", self.languages, self.gpu)
            self._reader = easyocr.Reader(self.languages, gpu=self.gpu)
            self._initialized = True
            return self._reader
        except Exception as e:
            self._init_failed = True
            self._init_error = f"{type(e).__name__}: {str(e)}"
            logger.warning("Failed to initialize EasyOCR reader: %s", self._init_error)
            return None

    def extract(self, image_input: Union[str, bytes]) -> Dict[str, Any]:
        """Extract visible text from a screenshot image file or raw bytes.

        Returns a dictionary with:
          - text: Combined extracted text (space-separated)
          - confidence: Average confidence score (0.0 to 1.0)
          - lines: Detailed list of extracted lines with individual confidence scores
          - source: "ocr_screenshot"
          - status: "success" | "partial" | "fallback" | "failed"
          - note: Optional explanation
        """
        if not image_input:
            return {
                "text": "",
                "confidence": 0.0,
                "lines": [],
                "source": "ocr_screenshot",
                "status": "failed",
                "note": "No image input provided",
            }

        temp_path: Optional[str] = None
        image_path: str

        try:
            if isinstance(image_input, bytes):
                # Write bytes to a temporary file for EasyOCR processing
                with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
                    tmp.write(image_input)
                    temp_path = tmp.name
                image_path = temp_path
            else:
                image_path = image_input

            if not os.path.exists(image_path):
                return {
                    "text": "",
                    "confidence": 0.0,
                    "lines": [],
                    "source": "ocr_screenshot",
                    "status": "failed",
                    "note": f"Image file not found: {image_path}",
                }

            reader = self._get_reader()
            if reader is None:
                return {
                    "text": "",
                    "confidence": 0.0,
                    "lines": [],
                    "source": "ocr_screenshot",
                    "status": "fallback",
                    "note": f"EasyOCR reader unavailable ({self._init_error or 'initialization failed'})",
                }

            # Run OCR extraction
            # readtext returns [(bbox, text, prob), ...]
            results = reader.readtext(image_path)

            if not results:
                return {
                    "text": "",
                    "confidence": 1.0,  # Successfully processed, but no text detected
                    "lines": [],
                    "source": "ocr_screenshot",
                    "status": "success",
                    "note": "Image processed successfully; no text detected.",
                }

            lines = []
            total_prob = 0.0
            extracted_words = []

            for _bbox, text_str, prob in results:
                clean_text = text_str.strip()
                if clean_text:
                    lines.append({"text": clean_text, "confidence": float(prob)})
                    extracted_words.append(clean_text)
                    total_prob += float(prob)

            full_text = " ".join(extracted_words)
            avg_confidence = total_prob / len(lines) if lines else 0.0

            return {
                "text": full_text,
                "confidence": round(avg_confidence, 4),
                "lines": lines,
                "source": "ocr_screenshot",
                "status": "success",
                "note": f"Successfully extracted {len(lines)} line(s) of text from screenshot.",
            }

        except Exception as e:
            logger.error("OCR text extraction error: %s", e, exc_info=True)
            return {
                "text": "",
                "confidence": 0.0,
                "lines": [],
                "source": "ocr_screenshot",
                "status": "failed",
                "note": f"OCR extraction error: {type(e).__name__}: {str(e)}",
            }
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
