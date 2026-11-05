from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.models.investigation import Investigation
from app.schemas.investigation import InvestigationCreate, InvestigationRead

router = APIRouter()


@router.post("/", response_model=InvestigationRead, status_code=201)
def create_investigation(payload: InvestigationCreate, db: Session = Depends(get_db)):
    obj = Investigation(**payload.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.get("/", response_model=list[InvestigationRead])
def list_investigations(db: Session = Depends(get_db)):
    return db.query(Investigation).order_by(Investigation.created_at.desc()).all()


@router.get("/{investigation_id}", response_model=InvestigationRead)
def get_investigation(investigation_id: int, db: Session = Depends(get_db)):
    obj = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return obj