from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
from app.api.deps import get_db
from app.models.investigation import Investigation
from app.schemas.investigation import InvestigationRead, FindingRead

router = APIRouter()

@router.get("/", response_model=list[InvestigationRead])
def list_investigations(db: Session = Depends(get_db)):
    """List investigations with associated findings, ordered by creation date descending."""
    return (
        db.query(Investigation)
        .options(joinedload(Investigation.findings))
        .order_by(Investigation.created_at.desc())
        .all()
    )

@router.get("/{investigation_id}", response_model=InvestigationRead)
def get_investigation(investigation_id: int, db: Session = Depends(get_db)):
    """Retrieve one investigation by ID with eager-loaded findings.

    Returns HTTP 404 if the investigation does not exist.
    All persisted Finding fields are serialized correctly via InvestigationRead.
    """
    obj = (
        db.query(Investigation)
        .options(joinedload(Investigation.findings))
        .filter(Investigation.id == investigation_id)
        .first()
    )
    if not obj:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return obj
    