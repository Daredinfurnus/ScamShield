from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, List


class InvestigationBase(BaseModel):
    title: str
    input_type: str
    input_content: str


class InvestigationCreate(InvestigationBase):
    pass


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    finding_type: str
    title: str
    description: Optional[str] = None
    evidence_snippet: Optional[str] = None
    evidence_source: Optional[str] = None
    score: float
    created_at: datetime


class InvestigationRead(InvestigationBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    risk_score: float
    risk_band: str
    status: str
    created_at: datetime
    findings: List[FindingRead] = []