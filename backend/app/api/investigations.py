from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import (
    get_db,
    get_current_user,
    get_investigation_with_access,
)
from app.models.investigation import Investigation
from app.models.user import User
from app.schemas.investigation import InvestigationRead
from app.schemas.auth import ClaimInvestigationRequest
from app.services.security.token_service import hash_token

router = APIRouter()


@router.get("/", response_model=List[InvestigationRead])
def list_investigations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List investigations belonging strictly to the caller's tenant.

    Anonymous users are barred from listing investigations.
    """
    return (
        db.query(Investigation)
        .options(joinedload(Investigation.findings))
        .filter(Investigation.tenant_id == current_user.tenant_id)
        .order_by(Investigation.created_at.desc())
        .all()
    )


@router.get("/{investigation_id}", response_model=InvestigationRead)
def get_investigation(
    investigation: Investigation = Depends(get_investigation_with_access),
):
    """Retrieve one investigation by ID.

    Access is strictly mediated:
    - Authenticated users can access their own tenant's investigations.
    - Anonymous users require the matching cryptographic capability token.
    - Unauthorized or missing records uniformly return HTTP 404.
    """
    return investigation


@router.post("/{investigation_id}/claim", response_model=InvestigationRead)
def claim_investigation(
    investigation_id: int,
    payload: ClaimInvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Claim an anonymous investigation into the authenticated user's tenant account."""
    investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    if not investigation.is_anonymous or not investigation.access_token_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Investigation is not an unclaimed anonymous record",
        )

    # Validate capability token
    token_h = hash_token(payload.access_token)
    if token_h != investigation.access_token_hash:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    # Check expiration
    if investigation.access_token_expires_at:
        now = datetime.now(timezone.utc)
        expires_at = investigation.access_token_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Capability token has expired")

    # Claim: transfer ownership to user and tenant, revoke anonymous token
    investigation.tenant_id = current_user.tenant_id
    investigation.created_by_user_id = current_user.id
    investigation.is_anonymous = False
    investigation.access_token_hash = None
    investigation.access_token_expires_at = None

    db.commit()
    db.refresh(investigation)
    return investigation
