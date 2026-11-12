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
from typing import Any, Dict, List, Optional
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
    ) -> Investigation:
        investigation = Investigation(
            title=title,
            input_type=input_type,
            input_content=input_content,
            risk_score=risk_score,
            risk_band=risk_band,
            status=status,
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
        }

    def analyze_text(
        self,
        text: str,
        title: str = "Text Investigation",
        db: Optional[Session] = None,
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
            # A URL alone is not proof of fraud; URLAnalyzer applies heuristics
            # (suspicious TLD, IP address, shortener, etc.) and RiskScorer
            # aggregates the result.
            import re as _re
            url_pattern = _re.compile(
                r"https?://[^\s<>\"]+|www\.[^\s<>\"]+",
                _re.IGNORECASE,
            )
            for um in url_pattern.finditer(normalized):
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
        title: str = "Image Investigation",
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """Image/OCR analysis is not yet implemented.

        Returns an explicit not-implemented response. Does NOT return a
        successful low-risk verdict for unanalyzed evidence.
        """
        session = db or self._get_db()
        owns_session = db is None
        try:
            investigation = Investigation(
                title=title,
                input_type="image",
                input_content="",
                risk_score=0.0,
                risk_band="low",
                status="incomplete",
            )
            session.add(investigation)
            session.commit()
            session.refresh(investigation)

            return self._response(
                investigation_id=investigation.id,
                status=investigation.status,
                risk_score=0.0,
                risk_band="low",
                signals=[],
                findings=[],
                evidence=[],
                analysis_summary=(
                    "Image/OCR analysis is not yet implemented (Phase 6). "
                    "No image was analyzed. Do not interpret this as a safe "
                    "result."
                ),
                created_at=investigation.created_at.isoformat() if investigation.created_at else None,
            )
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
                    f"Image analysis setup failed: {type(e).__name__}"
                ),
                created_at=None,
            )
        finally:
            if owns_session:
                session.close()