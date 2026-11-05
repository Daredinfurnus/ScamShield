from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class ReportRead(BaseModel):
    id: int
    investigation_id: int
    generated_at: datetime
    format: str  # json | pdf

    class Config:
        from_attributes = True