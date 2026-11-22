from typing import Optional
from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_investigation_with_access
from app.models.entity import Entity
from app.models.investigation import Investigation

router = APIRouter()


@router.get("/")
def list_entities(
    investigation_id: int = Path(..., description="Investigation ID"),
    investigation: Investigation = Depends(get_investigation_with_access),
    db: Session = Depends(get_db)
):
    """List entities for an investigation.

    Uses tenant isolation and capability-token access control.
    Returns 404 for unauthorized access to prevent enumeration.
    """
    return db.query(Entity).filter(Entity.investigation_id == investigation.id).all()