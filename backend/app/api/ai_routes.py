"""AI investigation API routes for ScamShield."""

from fastapi import APIRouter, Depends, Path, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.investigation import Investigation
from app.services.ai.orchestrator import AIOrchestrator
from app.services.ai.deterministic_fallback import DeterministicFallback
from app.api.deps import get_investigation_with_access

router = APIRouter(prefix="/ai", tags=["ai"])


def get_orchestrator(db: Session = Depends(get_db)) -> AIOrchestrator:
    from app.services.ai.openai_provider import OpenAIProvider
    openai_provider = OpenAIProvider()
    deterministic_fallback = DeterministicFallback()
    return AIOrchestrator(
        openai_provider=openai_provider,
        deterministic_fallback=deterministic_fallback,
    )


@router.get("/investigations/{investigation_id}/explain", response_model=dict)
def explain_investigation(
    investigation_id: int,
    investigation: Investigation = Depends(get_investigation_with_access),
    orchestrator: AIOrchestrator = Depends(get_orchestrator),
):
    """Get AI-generated explanation of an investigation.

    Uses tenant isolation and capability-token access control.
    Returns 404 for unauthorized access to prevent enumeration.
    """

    findings = [
        {
            "id": f.id,
            "finding_type": f.finding_type,
            "title": f.title,
            "description": f.description,
            "evidence_snippet": f.evidence_snippet,
            "evidence_source": f.evidence_source,
            "score": f.score,
        }
        for f in investigation.findings
    ]

    risk_score = investigation.risk_score
    risk_band = investigation.risk_band

    result = orchestrator.explain_investigation(
        investigation_id=investigation_id,
        findings=findings,
        risk_score=risk_score,
        risk_band=risk_band,
    )

    return {
        "investigation_id": investigation_id,
        "risk_score": risk_score,
        "risk_band": risk_band,
        "provider": result["provider"],
        "fallback_used": result["fallback_used"],
        "data": result["data"],
        "error": result["error"],
    }


@router.get("/investigations/{investigation_id}/report", response_model=dict)
def generate_report(
    investigation_id: int,
    investigation: Investigation = Depends(get_investigation_with_access),
    orchestrator: AIOrchestrator = Depends(get_orchestrator),
):
    """Get AI-generated investigation report.

    Uses tenant isolation and capability-token access control.
    Returns 404 for unauthorized access to prevent enumeration.
    """

    investigation_data = {
        "id": investigation.id,
        "title": investigation.title or "Investigation Report",
        "input_type": investigation.input_type or "",
        "input_content": investigation.input_content or "",
        "risk_score": investigation.risk_score,
        "risk_band": investigation.risk_band,
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "title": f.title,
                "description": f.description,
                "evidence_snippet": f.evidence_snippet,
                "evidence_source": f.evidence_source,
                "score": f.score,
            }
            for f in investigation.findings
        ],
        "status": investigation.status or "unknown",
        "created_at": investigation.created_at.isoformat() if investigation.created_at else "",
    }

    result = orchestrator.generate_report(
        investigation_id=investigation_id,
        investigation_data=investigation_data,
    )

    return {
        "investigation_id": investigation_id,
        "provider": result["provider"],
        "fallback_used": result["fallback_used"],
        "data": result["data"],
        "error": result["error"],
    }


@router.get("/status", response_model=dict)
def ai_status(
    orchestrator: AIOrchestrator = Depends(get_orchestrator),
):
    """Get AI provider status.

    OpenAI is optional. When it is not configured, the deterministic fallback
    provider is always available for explanations and reports.
    """
    openai_status = orchestrator._openai_provider.get_status()
    return {
        "provider": openai_status["provider"],
        "available": openai_status["available"],
        "model": openai_status["model"],
        "fallback_available": True,
        "fallback_provider": "deterministic",
    }