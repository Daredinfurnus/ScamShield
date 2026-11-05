from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.analysis import (
    AnalyzeTextRequest,
    AnalyzeURLRequest,
    AnalyzeImageRequest,
    AnalysisResponse,
    Signal,
)
from app.services.investigation_engine import InvestigationEngine

router = APIRouter()


def _get_engine(db: Session) -> InvestigationEngine:
    """Create an InvestigationEngine scoped to the current DB session."""
    return InvestigationEngine(db_session=db)


def _handle_engine_result(result: Dict[str, Any]) -> AnalysisResponse:
    """Convert engine result to AnalysisResponse, handling failed status."""
    if result.get("status") == "failed" and result.get("investigation_id") is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("analysis_summary", "Analysis failed"),
        )
    return AnalysisResponse(**result)


@router.post("/text", response_model=AnalysisResponse)
def analyze_text(
    payload: AnalyzeTextRequest,
    db: Session = Depends(get_db),
):
    """Analyze raw message text for scam indicators.

    Uses the InvestigationEngine to validate input, run text analysis,
    collect signals, score via RiskScorer, and persist results.
    """
    engine = _get_engine(db)
    try:
        result = engine.analyze_text(
            text=payload.text,
            title=f"Text Investigation: {payload.text[:60]}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return _handle_engine_result(result)


@router.post("/url", response_model=AnalysisResponse)
def analyze_url(
    payload: AnalyzeURLRequest,
    db: Session = Depends(get_db),
):
    """Analyze a URL for scam indicators.

    Uses the InvestigationEngine to validate input, run URL analysis,
    collect signals, score via RiskScorer, and persist results.
    """
    engine = _get_engine(db)
    try:
        result = engine.analyze_url(
            url=payload.url,
            title=f"URL Investigation: {payload.url[:60]}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return _handle_engine_result(result)


@router.post("/image", response_model=AnalysisResponse)
def analyze_image(
    payload: AnalyzeImageRequest,
    db: Session = Depends(get_db),
):
    """Analyze an uploaded screenshot via OCR.

    Image/OCR analysis is not yet implemented (Phase 6). Returns an
    explicit not-implemented response with status 'incomplete'. Does
    NOT return a successful low-risk verdict for unanalyzed evidence.
    """
    engine = _get_engine(db)
    result = engine.analyze_image(
        title=f"Image Investigation: {payload.investigation_id or 'new'}",
    )
    return _handle_engine_result(result)