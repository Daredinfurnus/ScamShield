"""Central investigation engine.

Orchestrates the full investigation pipeline:

1. Receive and validate input
2. Normalize and preserve evidence
3. Call the appropriate analysis service
4. Collect structured detection signals
5. Pass signals to RiskScorer (single source of truth for risk)
6. Generate structured findings
7. Persist investigation and findings
8. Return structured analysis response

The engine never calculates risk independently; it always delegates to
RiskScorer. The LLM never overrides calculated scores.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session

from app.services.risk_scoring import RiskScorer
from app.services.text_analysis import TextAnalyzer
from app.services.url_analysis import URLAnalyzer
from app.services.ocr import OCRProcessor
from app.services.scam_detector import ScamDetector
from app.services.detection_signal import DetectionSignal
from app.services.evidence_service import EvidenceService
from app.models.investigation import Investigation
from app.models.finding import Finding
from app.database import SessionLocal

logger = logging.getLogger(__name__)


# Maximum number of URLs extracted from OCR text to analyze (DoS bound)
_MAX_URLS_FROM_OCR = 10

# Maximum image payload size in bytes (10 MB)
_MAX_IMAGE_BYTES = 10 * 1024 * 1024

# Regex used to locate URLs inside extracted OCR text
_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


class InvestigationEngine:
    """Coordinates the investigation pipeline end to end."""

    def __init__(
        self,
        risk_scorer: Optional[RiskScorer] = None,
        text_analyzer: Optional[TextAnalyzer] = None,
        url_analyzer: Optional[URLAnalyzer] = None,
        ocr_processor: Optional[OCRProcessor] = None,
        scam_detector: Optional[ScamDetector] = None,
        evidence_service: Optional[EvidenceService] = None,
        db_session: Optional[Session] = None,
    ):
        self.risk_scorer = risk_scorer or RiskScorer()
        self.text_analyzer = text_analyzer or TextAnalyzer()
        self.url_analyzer = url_analyzer or URLAnalyzer()
        self.ocr_processor = ocr_processor or OCRProcessor()
        self.scam_detector = scam_detector or ScamDetector()
        self.evidence_service = evidence_service or EvidenceService()
        self._db_session = db_session

    def _get_db(self) -> Session:
        if self._db_session is not None:
            return self._db_session
        return SessionLocal()

    def _build_findings(
        self, investigation_id: int, signals: List[DetectionSignal]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for signal in signals:
            findings.append(
                {
                    "investigation_id": investigation_id,
                    "finding_type": signal.signal_type,
                    "title": f"{signal.signal_type} analysis",
                    "description": signal.description or "",
                    "evidence_snippet": signal.evidence_snippet or "",
                    "evidence_source": signal.evidence_source or "",
                    "score": signal.score,
                }
            )
        return findings

    def _persist(
        self,
        session: Session,
        input_type: str,
        title: str,
        input_content: str,
        risk_score: float,
        risk_band: str,
        status: str,
        signals: List[DetectionSignal],
        tenant_id: Optional[int] = None,
        created_by_user_id: Optional[int] = None,
        is_anonymous: bool = False,
        access_token_hash: Optional[str] = None,
        access_token_expires_at: Optional[Any] = None,
    ) -> Investigation:
        investigation = Investigation(
            tenant_id=tenant_id,
            created_by_user_id=created_by_user_id,
            title=title,
            input_type=input_type,
            input_content=input_content,
            risk_score=risk_score,
            risk_band=risk_band,
            status=status,
            is_anonymous=is_anonymous,
            access_token_hash=access_token_hash,
            access_token_expires_at=access_token_expires_at,
        )
        session.add(investigation)
        session.flush()
        findings = self._build_findings(investigation.id, signals)
        for finding_data in findings:
            session.add(Finding(**finding_data))
        session.commit()
        session.refresh(investigation)
        return investigation

    def _response(
        self,
        investigation_id: Optional[int],
        status: str,
        risk_score: float,
        risk_band: str,
        signals: List[DetectionSignal],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        analysis_summary: str,
        created_at: Optional[str],
        access_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "investigation_id": investigation_id,
            "status": status,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "signals": [s.to_api_signal() for s in signals],
            "entities": [],
            "findings": findings,
            "evidence": evidence,
            "analysis_summary": analysis_summary,
            "created_at": created_at,
            "access_token": access_token,
        }

    def analyze_text(
        self,
        text: str,
        title: str = "Text Investigation",
        db: Optional[Session] = None,
        tenant_id: Optional[int] = None,
        created_by_user_id: Optional[int] = None,
        is_anonymous: bool = False,
        access_token_hash: Optional[str] = None,
        access_token_expires_at: Optional[Any] = None,
        raw_access_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run the full text investigation pipeline."""
        session = db or self._get_db()
        owns_session = db is None
        try:
            cleaned = self.evidence_service.validate_input(text, "text")
            normalized = self.evidence_service.normalize_text(cleaned)

            evidence_ref = self.evidence_service.make_evidence_reference(
                snippet=self.evidence_service.extract_snippet(normalized),
                source="message_body",
                original=cleaned,
            )

            analysis_result = self.scam_detector.detect(normalized)

            signals: List[DetectionSignal] = list(analysis_result)

            # --- URL extraction and analysis ---
            # Extract URLs from the message text and analyze them separately.
            # Bounded to a maximum of 10 extracted URLs per message to prevent DoS.
            import re as _re
            url_pattern = _re.compile(
                r"https?://[^\s<>\"]+|www\.[^\s<>\"]+",
                _re.IGNORECASE,
            )
            for i, um in enumerate(url_pattern.finditer(normalized)):
                if i >= 10:
                    break
                extracted_url = um.group(0)
                # Normalize: ensure scheme for URLs like www.example.com
                if not extracted_url.startswith(("http://", "https://")):
                    extracted_url = "http://" + extracted_url
                url_analysis = self.url_analyzer.analyze(extracted_url)
                url_signals = url_analysis.get("signals", [])
                if url_signals:
                    for us in url_signals:
                        # Override evidence source to reflect URL-in-text context
                        us.evidence_source = "url_in_message"
                        us.evidence_snippet = extracted_url
                    signals.extend(url_signals)

            scoring_result = self.risk_scorer.score(
                [{"score": s.score, "weight": s.weight} for s in signals]
            )
            risk_score = scoring_result["risk_score"]
            risk_band = scoring_result["risk_band"]

            findings = self._build_findings(0, signals)

            investigation = self._persist(
                session,
                input_type="text",
                title=title,
                input_content=cleaned,
                risk_score=risk_score,
                risk_band=risk_band,
                status="completed" if signals else "completed",
                signals=signals,
                tenant_id=tenant_id,
                created_by_user_id=created_by_user_id,
                is_anonymous=is_anonymous,
                access_token_hash=access_token_hash,
                access_token_expires_at=access_token_expires_at,
            )

            persisted_findings = [
                {
                    "id": f.id,
                    "investigation_id": f.investigation_id,
                    "finding_type": f.finding_type,
                    "title": f.title,
                    "description": f.description,
                    "evidence_snippet": f.evidence_snippet,
                    "evidence_source": f.evidence_source,
                    "score": f.score,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in investigation.findings
            ]

            if signals:
                categories = sorted({s.metadata.get("category", "unknown") for s in signals if s.metadata})
                summary = (
                    f"Text analysis completed. Risk score: {risk_score}/100 ({risk_band}). "
                    f"Detected {len(signals)} signal(s) across categories: {', '.join(categories)}. "
                    "Every signal references actual evidence from the submitted message."
                )
            else:
                summary = (
                    f"Text analysis completed. Risk score: {risk_score}/100 ({risk_band}). "
                    "No scam indicators detected. This does not guarantee the message is safe."
                )

            return self._response(
                investigation_id=investigation.id,
                status=investigation.status,
                risk_score=investigation.risk_score,
                risk_band=investigation.risk_band,
                signals=signals,
                findings=persisted_findings,
                evidence=[evidence_ref],
                analysis_summary=summary,
                created_at=investigation.created_at.isoformat() if investigation.created_at else None,
                access_token=raw_access_token,
            )
        except ValueError as e:
            if owns_session:
                session.rollback()
            raise e

    def analyze_url(
        self,
        url: str,
        title: str = "URL Investigation",
        db: Optional[Session] = None,
        tenant_id: Optional[int] = None,
        created_by_user_id: Optional[int] = None,
        is_anonymous: bool = False,
        access_token_hash: Optional[str] = None,
        access_token_expires_at: Optional[Any] = None,
        raw_access_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run the URL investigation pipeline."""
        session = db or self._get_db()
        owns_session = db is None
        try:
            cleaned = self.evidence_service.validate_input(url, "url")

            evidence_ref = self.evidence_service.make_evidence_reference(
                snippet=self.evidence_service.extract_snippet(cleaned),
                source="url_input",
                original=cleaned,
            )

            analysis_result = self.url_analyzer.analyze(cleaned)

            raw_score = float(analysis_result.get("score", 0.0))
            signal = DetectionSignal(
                signal_type="url",
                name="url_heuristic",
                description=analysis_result.get("note", "URL analysis signal"),
                score=raw_score * 100.0,
                weight=1.0,
                confidence=0.5,
                evidence_snippet=evidence_ref["evidence_snippet"],
                evidence_source=evidence_ref["evidence_source"],
                metadata={"label": analysis_result.get("label", "unknown")},
            )
            signals = [signal]

            scoring_result = self.risk_scorer.score(
                [{"score": s.score, "weight": s.weight} for s in signals]
            )
            risk_score = scoring_result["risk_score"]
            risk_band = scoring_result["risk_band"]

            findings = self._build_findings(0, signals)

            investigation = self._persist(
                session,
                input_type="url",
                title=title,
                input_content=cleaned,
                risk_score=risk_score,
                risk_band=risk_band,
                status="completed",
                signals=signals,
                tenant_id=tenant_id,
                created_by_user_id=created_by_user_id,
                is_anonymous=is_anonymous,
                access_token_hash=access_token_hash,
                access_token_expires_at=access_token_expires_at,
            )

            persisted_findings = [
                {
                    "id": f.id,
                    "investigation_id": f.investigation_id,
                    "finding_type": f.finding_type,
                    "title": f.title,
                    "description": f.description,
                    "evidence_snippet": f.evidence_snippet,
                    "evidence_source": f.evidence_source,
                    "score": f.score,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in investigation.findings
            ]

            return self._response(
                investigation_id=investigation.id,
                status=investigation.status,
                risk_score=investigation.risk_score,
                risk_band=investigation.risk_band,
                signals=signals,
                findings=persisted_findings,
                evidence=[evidence_ref],
                analysis_summary=(
                    f"URL analysis completed. Risk score: {risk_score}/100 "
                    f"({risk_band}). Note: heuristic placeholder; "
                    "detection is limited."
                ),
                created_at=investigation.created_at.isoformat() if investigation.created_at else None,
                access_token=raw_access_token,
            )
        except ValueError as e:
            if owns_session:
                session.rollback()
            raise e
        except Exception as e:
            if owns_session:
                session.rollback()
            return self._response(
                investigation_id=None,
                status="failed",
                risk_score=0.0,
                risk_band="low",
                signals=[],
                findings=[],
                evidence=[],
                analysis_summary=(
                    f"URL analysis failed: {type(e).__name__}. "
                    "This is not a verified safe result."
                ),
                created_at=None,
            )
        finally:
            if owns_session:
                session.close()

    def analyze_image(
        self,
        image_input: Optional[Union[str, bytes]] = None,
        filename: Optional[str] = None,
        title: str = "Screenshot Investigation",
        db: Optional[Session] = None,
        tenant_id: Optional[int] = None,
        created_by_user_id: Optional[int] = None,
        is_anonymous: bool = False,
        access_token_hash: Optional[str] = None,
        access_token_expires_at: Optional[Any] = None,
        raw_access_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run the screenshot / image investigation pipeline (Phase 6).

        1. Receives an image payload (file path, raw bytes, or base64-encoded string).
        2. Extracts visible text via `OCRProcessor`.
        3. If text is extracted, passes it to `ScamDetector` and `URLAnalyzer`.
        4. Calculates an evidence-grounded risk score via `RiskScorer`.
        5. Persists the investigation record, OCR evidence, and structured findings.
        6. Returns an authoritative analysis response.
        """
        session = db or self._get_db()
        owns_session = db is None

        # Resolve image bytes from string/bytes/base64
        raw_bytes: Optional[bytes] = None
        image_source_label = filename or "uploaded_screenshot.png"

        if image_input:
            if isinstance(image_input, bytes):
                raw_bytes = image_input
            elif isinstance(image_input, str):
                if image_input.startswith("data:image/"):
                    # Data URL format
                    try:
                        _, b64_str = image_input.split(",", 1)
                        raw_bytes = base64.b64decode(b64_str)
                    except Exception as e:
                        raise ValueError(f"Invalid base64 data URL: {e}")
                elif os.path.exists(image_input):
                    try:
                        with open(image_input, "rb") as f:
                            raw_bytes = f.read()
                    except Exception as e:
                        raise ValueError(f"Failed to read image file '{image_input}': {e}")
                else:
                    # Raw base64 string
                    try:
                        raw_bytes = base64.b64decode(image_input)
                    except Exception:
                        raw_bytes = image_input.encode("utf-8")

        if raw_bytes and len(raw_bytes) > _MAX_IMAGE_BYTES:
            raise ValueError(f"Image payload size exceeds maximum limit of {_MAX_IMAGE_BYTES // (1024 * 1024)} MB")

        try:
            # 1. OCR Extraction
            ocr_result = self.ocr_processor.extract(raw_bytes if raw_bytes else "")

            extracted_text = (ocr_result.get("text") or "").strip()
            ocr_status = ocr_result.get("status", "failed")
            ocr_note = ocr_result.get("note", "")

            signals: List[DetectionSignal] = []
            evidence_refs: List[Dict[str, Any]] = []

            if extracted_text:
                # OCR text often merges adjacent words (e.g. 'Youraccounthas').
                # normalize_ocr_text inserts word boundaries so the ScamDetector
                # regex patterns can match reliably.
                normalized_text = self.evidence_service.normalize_ocr_text(extracted_text)
                evidence_ref = self.evidence_service.make_evidence_reference(
                    snippet=self.evidence_service.extract_snippet(normalized_text),
                    source="ocr_screenshot",
                    original=extracted_text,
                )
                evidence_refs.append(evidence_ref)

                # Add OCR Signal
                ocr_signal = DetectionSignal(
                    signal_type="ocr",
                    name="ocr_text_extraction",
                    description=f"Extracted visible text via EasyOCR ({ocr_result.get('confidence', 0.0) * 100:.1f}% confidence)",
                    score=0.0,  # Base OCR extraction contributes 0 score on its own
                    weight=1.0,
                    confidence=float(ocr_result.get("confidence", 1.0)),
                    evidence_snippet=self.evidence_service.extract_snippet(normalized_text, 300),
                    evidence_source="ocr_screenshot",
                    metadata={"source": "ocr", "lines_count": len(ocr_result.get("lines", []))},
                )
                signals.append(ocr_signal)

                # 2. Text Detection on OCR output
                text_signals = self.scam_detector.detect(normalized_text)
                for ts in text_signals:
                    ts.evidence_source = "ocr_screenshot"
                signals.extend(text_signals)

                # 3. URL Extraction and analysis on OCR output
                for i, um in enumerate(_URL_PATTERN.finditer(normalized_text)):
                    if i >= _MAX_URLS_FROM_OCR:
                        break
                    extracted_url = um.group(0)
                    if not extracted_url.startswith(("http://", "https://")):
                        extracted_url = "http://" + extracted_url
                    url_analysis = self.url_analyzer.analyze(extracted_url)
                    url_signals = url_analysis.get("signals", [])
                    if url_signals:
                        for us in url_signals:
                            us.evidence_source = "url_in_ocr_screenshot"
                            us.evidence_snippet = extracted_url
                        signals.extend(url_signals)

            else:
                # No text extracted or OCR uninitialized
                evidence_refs.append(
                    {
                        "evidence_snippet": f"Filename: {image_source_label}",
                        "evidence_source": "image_upload",
                        "evidence_hash": "0000000000000000",
                        "original_length": len(raw_bytes) if raw_bytes else 0,
                    }
                )

            # 4. Risk Scoring
            raw_signal_scores = [{"score": s.score, "weight": s.weight} for s in signals]
            scoring_result = self.risk_scorer.score(raw_signal_scores)
            risk_score = scoring_result["risk_score"]
            risk_band = scoring_result["risk_band"]

            inv_status = "completed" if (extracted_text or ocr_status == "success") else "incomplete"

            # 5. Persistence
            investigation = self._persist(
                session,
                input_type="image",
                title=title or f"Screenshot Investigation: {image_source_label}",
                input_content=extracted_text if extracted_text else f"[Image file: {image_source_label}]",
                risk_score=risk_score,
                risk_band=risk_band,
                status=inv_status,
                signals=signals,
                tenant_id=tenant_id,
                created_by_user_id=created_by_user_id,
                is_anonymous=is_anonymous,
                access_token_hash=access_token_hash,
                access_token_expires_at=access_token_expires_at,
            )

            persisted_findings = [
                {
                    "id": f.id,
                    "investigation_id": f.investigation_id,
                    "finding_type": f.finding_type,
                    "title": f.title,
                    "description": f.description,
                    "evidence_snippet": f.evidence_snippet,
                    "evidence_source": f.evidence_source,
                    "score": f.score,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in investigation.findings
            ]

            if extracted_text:
                summary = (
                    f"Screenshot analysis completed via OCR. Risk score: {risk_score}/100 ({risk_band}). "
                    f"Extracted {len(ocr_result.get('lines', []))} lines of text. "
                    f"Detected {len(signals)} risk signal(s). {ocr_note}"
                )
            else:
                summary = (
                    f"Screenshot analysis finished with status '{inv_status}'. "
                    f"No text detected in image or OCR reader was unavailable. {ocr_note}"
                )

            return self._response(
                investigation_id=investigation.id,
                status=investigation.status,
                risk_score=investigation.risk_score,
                risk_band=investigation.risk_band,
                signals=signals,
                findings=persisted_findings,
                evidence=evidence_refs,
                analysis_summary=summary,
                created_at=investigation.created_at.isoformat() if investigation.created_at else None,
                access_token=raw_access_token,
            )

        except ValueError as e:
            if owns_session:
                session.rollback()
            raise e
        except Exception as e:
            logger.error("analyze_image error: %s", e, exc_info=True)
            if owns_session:
                session.rollback()
            return self._response(
                investigation_id=None,
                status="failed",
                risk_score=0.0,
                risk_band="low",
                signals=[],
                findings=[],
                evidence=[],
                analysis_summary=f"Image analysis failed: {type(e).__name__}: {str(e)}",
                created_at=None,
            )
        finally:
            if owns_session:
                session.close()