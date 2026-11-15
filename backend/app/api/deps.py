"""API dependency injection: database, authentication, tenant isolation, and capability verification."""

from __future__ import annotations

from typing import Generator, Optional
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, Header, Query, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.user import User, ApiKey
from app.models.investigation import Investigation
from app.services.security.token_service import decode_access_token, hash_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_db() -> Generator:
    """Provide a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Optional[User]:
    """Extract authenticated User from Bearer JWT, X-API-Key, or HttpOnly cookie."""
    # 1. Check API Key first if supplied
    if x_api_key:
        key_h = hash_token(x_api_key)
        api_key_record = (
            db.query(ApiKey)
            .filter(ApiKey.key_hash == key_h, ApiKey.is_revoked == False)  # noqa: E712
            .first()
        )
        if api_key_record:
            if api_key_record.expires_at and api_key_record.expires_at < datetime.now(timezone.utc):
                return None
            user = db.query(User).filter(User.id == api_key_record.user_id, User.is_active == True).first()  # noqa: E712
            if user:
                return user

    # 2. Check Bearer token or cookie
    token: Optional[str] = None
    if bearer:
        token = bearer.credentials
    elif "access_token" in request.cookies:
        token = request.cookies.get("access_token")

    if not token:
        return None

    payload = decode_access_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    try:
        uid_int = int(user_id)
    except ValueError:
        return None

    user = db.query(User).filter(User.id == uid_int, User.is_active == True).first()  # noqa: E712
    return user


def get_current_user(
    current_user: Optional[User] = Depends(get_current_user_optional),
) -> User:
    """Enforce that request must be authenticated."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


def require_role(required_role: str):
    """Enforce role-based access control (admin > investigator > viewer)."""
    hierarchy = {"admin": 3, "investigator": 2, "viewer": 1}

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_level = hierarchy.get(current_user.role, 0)
        req_level = hierarchy.get(required_role, 0)
        if user_level < req_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: requires {required_role} role",
            )
        return current_user

    return role_checker


def get_investigation_with_access(
    investigation_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    x_investigation_token: Optional[str] = Header(None, alias="X-Investigation-Token"),
    token_query: Optional[str] = Query(None, alias="token"),
) -> Investigation:
    """Verify resource-level access to an investigation.

    Rules:
    - Authenticated users can access investigations belonging to their tenant.
    - Anonymous users CANNOT access other tenants' investigations.
    - Anonymous investigations require matching the cryptographic capability token.
    - If unauthorized or not found, always return 404 (prevent IDOR & enumeration).
    """
    investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    # If caller is an authenticated user
    if current_user:
        # Check tenant isolation
        if investigation.tenant_id and investigation.tenant_id != current_user.tenant_id:
            # Cross-tenant access denied
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
        return investigation

    # Caller is anonymous
    capability_token = x_investigation_token or token_query
    if not capability_token or not investigation.access_token_hash:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    provided_hash = hash_token(capability_token)
    if provided_hash != investigation.access_token_hash:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    # Check token expiration
    if investigation.access_token_expires_at:
        now = datetime.now(timezone.utc)
        expires_at = investigation.access_token_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access capability has expired")

    return investigation
