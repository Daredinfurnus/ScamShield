from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class AnalyzeTextRequest(BaseModel):
    text: str
    investigation_id: Optional[int] = None


class AnalyzeURLRequest(BaseModel):
    url: str
    investigation_id: Optional[int] = None


class AnalyzeImageRequest(BaseModel):
    investigation_id: Optional[int] = None


class Signal(BaseModel):
    """A single risk signal with its evidence and source.

    Extended for Phase 2 with standardized detection signal fields.
    """

    name: str
    score: float
    evidence: str
    source: str
    signal_type: Optional[str] = None
    description: Optional[str] = None
    weight: Optional[float] = None
    confidence: Optional[float] = None
    evidence_snippet: Optional[str] = None
    evidence_source: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AnalysisResponse(BaseModel):
    risk_score: float
    risk_band: str
    signals: List[Signal]
    entities: List[Dict[str, Any]]
    explanation: Optional[str] = None
    investigation_id: Optional[int] = None
    status: Optional[str] = None
    findings: Optional[List[Dict[str, Any]]] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    analysis_summary: Optional[str] = None
    created_at: Optional[str] = None