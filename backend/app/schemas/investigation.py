from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class InvestigationBase(BaseModel):
    title: str
    input_type: str
    input_content: str


class InvestigationCreate(InvestigationBase):
    pass


class InvestigationRead(InvestigationBase):
    id: int
    risk_score: float
    risk_band: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True