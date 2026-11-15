"""Evidence normalization service.

Validates, normalizes, and structures evidence so that every finding
references actual, traceable input data. Never fabricates evidence.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Optional


class EvidenceService:
    """Handles evidence validation and normalization."""

    MAX_INPUT_SIZE = 10000  # characters

    # Patterns for OCR text normalization
    _CAMEL_SPLIT = re.compile(r"([a-z])([A-Z])")  # lowercase + UPPERCASE boundary
    _DIGIT_LETTER = re.compile(r"([0-9])([A-Za-z])")  # digit + letter
    _LETTER_DIGIT = re.compile(r"([A-Za-z])([0-9])")  # letter + digit
    _REPEATED_PUNCT = re.compile(r"([.!?,;:])\1+")  # collapse repeated punctuation

    # Common scam keywords that OCR often merges into adjacent words
    _SCAM_KEYWORDS = [
        "account", "verify", "password", "unlock", "upi", "upiid", "vpa",
        "your", "send", "click", "urgent", "suspended", "bank", "verify",
        "here", "now", "confirm", "payment", "transfer", "otp", "pin",
        "blocked", "frozen", "login", "credential", "kyc", "incomplete",
        "fraud", "scam", "phishing", "malware", "virus", "security",
        "click", "link", "url", "website", "portal", "login", "signin",
        "password", "username", "email", "phone", "mobile", "number",
        "credit", "card", "debit", "bank", "atm", "cvv", "expiry",
        "wallet", "paytm", "phonepe", "gpay", "googlepay", "bhim",
        "investment", "guaranteed", "return", "profit", "earning",
        "lottery", "prize", "winner", "congratulations", "claim",
        "delivery", "parcel", "package", "customs", "duty", "fee",
        "redelivery", "reschedule", "release", "held", "detained",
        "arrest", "warrant", "legal", "police", "court", "notice",
        "government", "official", "representative", "department",
        "income", "tax", "refund", "rebate", "bonus", "reward",
        "bitcoin", "crypto", "ethereum", "token", "ico", "wallet",
        "free", "gift", "voucher", "coupon", "discount", "offer",
        "limited", "time", "act", "now", "immediate", "urgent",
    ]

    # Build a single regex to find these keywords without word boundaries
    _KEYWORD_PATTERN = re.compile(
        r"(?i)(" + "|".join(re.escape(kw) for kw in _SCAM_KEYWORDS) + r")"
    )

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

    def normalize_ocr_text(self, text: str) -> str:
        """Normalize OCR output by inserting word boundaries where they are likely missing.

        OCR often merges adjacent words (e.g., 'Youraccounthas' -> 'Your account has').
        This heuristic inserts spaces:
          - between lowercase and UPPERCASE transitions (camelCase boundaries)
          - between digits and letters
          - before/after common scam keywords that appear without boundaries
        It also collapses repeated punctuation and normalizes whitespace.
        """
        if not text:
            return ""

        # 1. Insert space at camelCase / PascalCase boundaries: aB -> a B
        text = self._CAMEL_SPLIT.sub(r"\1 \2", text)
        # 2. Digit-letter and letter-digit boundaries
        text = self._DIGIT_LETTER.sub(r"\1 \2", text)
        text = self._LETTER_DIGIT.sub(r"\1 \2", text)
        # 3. Insert spaces around scam keywords that are merged into text
        #    We match the keyword and ensure it has boundaries on both sides
        def _kw_replacer(m: re.Match) -> str:
            kw = m.group(1)
            # Look at surrounding characters to decide if boundaries needed
            start, end = m.span()
            left = text[start - 1] if start > 0 else " "
            right = text[end] if end < len(text) else " "
            # If no word boundary on left and left is alnum, add space
            prefix = " " if left.isalnum() else ""
            # If no word boundary on right and right is alnum, add space
            suffix = " " if right.isalnum() else ""
            return f"{prefix}{kw}{suffix}"

        text = self._KEYWORD_PATTERN.sub(_kw_replacer, text)
        # 4. Collapse repeated punctuation
        text = self._REPEATED_PUNCT.sub(r"\1", text)
        # 5. Normalize whitespace
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