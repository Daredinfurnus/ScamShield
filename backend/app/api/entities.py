from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.models.entity import Entity

router = APIRouter()


@router.get("/")
def list_entities(investigation_id: int, db: Session = Depends(get_db)):
    return db.query(Entity).filter(Entity.investigation_id == investigation_id).all()