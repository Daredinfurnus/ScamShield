from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional


class FindingBase(BaseModel):
    finding_type: str
    title: str
    description: Optional[str] = None
    evidence_snippet: Optional[str] = None
    evidence_source: Optional[str] = None
    score: float = 0.0


class FindingCreate(FindingBase):
    investigation_id: int


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    created_at: datetime