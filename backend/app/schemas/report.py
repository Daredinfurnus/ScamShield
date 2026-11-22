from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    generated_at: datetime
    format: str  # json | pdf