"""Authentication and user management API endpoints."""

import secrets
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.config import settings
from app.models.tenant import Tenant
from app.models.user import User, RefreshToken, ApiKey
from app.schemas.auth import (
    UserCreate,
    UserLogin,
    TokenResponse,
    RefreshTokenRequest,
    UserResponse,
    ApiKeyCreate,
    ApiKeyResponse,
)
from app.services.security.password import hash_password, verify_password
from app.services.security.token_service import (
    create_access_token,
    generate_refresh_token,
    generate_api_key,
    hash_token,
)

# Ensure types are available in global namespace for pydantic/FastAPI
UserCreateType = UserCreate
UserLoginType = UserLogin
TokenResponseType = TokenResponse
RefreshTokenRequestType = RefreshTokenRequest

router = APIRouter(prefix="/auth", tags=["auth"])

# Rate limiter for auth endpoints
limiter = Limiter(key_func=get_remote_address)


def _is_secure_cookie() -> bool:
    """Return True when the HttpOnly access token cookie should be marked secure.

    Cookies are only marked secure outside of development environments, where
    HTTPS termination is assumed. Local dev servers (HTTP) cannot set secure
    cookies, so they remain False to keep the login flow working.
    """
    return settings.APP_ENV.lower() not in ("development", "dev", "local")


@router.post("/register", response_model=TokenResponse)
@limiter.limit("10/minute")
def register(payload: UserCreate, request: Request, response: Response, db: Session = Depends(get_db)):
    """Register a new user and organization tenant."""
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists",
        )

    # Resolve or create tenant
    tenant_name = payload.tenant_name or f"{payload.email.split('@')[0]}'s Organization"
    tenant_slug = f"{tenant_name.lower().replace(' ', '-')}-{secrets.token_hex(4)}"

    tenant = Tenant(name=tenant_name, slug=tenant_slug, status="active")
    db.add(tenant)
    db.flush()

    user = User(
        tenant_id=tenant.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role or "investigator",
        is_active=True,
    )
    db.add(user)
    db.flush()

    # Generate tokens
    access_token = create_access_token(user_id=user.id, tenant_id=tenant.id, role=user.role)
    raw_rt, rt_hash, rt_expires = generate_refresh_token()
    family_id = secrets.token_hex(16)

    rt_record = RefreshToken(
        user_id=user.id,
        token_hash=rt_hash,
        family_id=family_id,
        expires_at=rt_expires,
        is_revoked=False,
    )
    db.add(rt_record)
    db.commit()

    # Set secure HttpOnly cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=_is_secure_cookie(),  # Set to True when HTTPS is terminated
        max_age=900,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_rt,
        expires_in=900,
    )


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(payload: UserLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    """Authenticate with email and password via Argon2id."""
    user = db.query(User).filter(User.email == payload.email, User.is_active == True).first()  # noqa: E712
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user_id=user.id, tenant_id=user.tenant_id, role=user.role)
    raw_rt, rt_hash, rt_expires = generate_refresh_token()
    family_id = secrets.token_hex(16)

    rt_record = RefreshToken(
        user_id=user.id,
        token_hash=rt_hash,
        family_id=family_id,
        expires_at=rt_expires,
        is_revoked=False,
    )
    db.add(rt_record)
    db.commit()

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=_is_secure_cookie(),
        max_age=900,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_rt,
        expires_in=900,
    )


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("10/minute")
def refresh_token(payload: RefreshTokenRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Rotate and refresh an access token. Detects replay attacks to revoke token families."""
    token_h = hash_token(payload.refresh_token)
    rt = db.query(RefreshToken).filter(RefreshToken.token_hash == token_h).first()

    if not rt:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Replay attack detection: if token is already revoked, invalidate its entire family
    if rt.is_revoked:
        db.query(RefreshToken).filter(RefreshToken.family_id == rt.family_id).update({"is_revoked": True})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token replay detected. Session terminated.",
        )

    now = datetime.now(timezone.utc)
    expires_at = rt.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        rt.is_revoked = True
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # Invalidate current refresh token
    rt.is_revoked = True

    # Generate new token pair in the same family
    user = db.query(User).filter(User.id == rt.user_id, User.is_active == True).first()  # noqa: E712
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account disabled")

    new_access_token = create_access_token(user_id=user.id, tenant_id=user.tenant_id, role=user.role)
    new_raw_rt, new_rt_hash, new_rt_expires = generate_refresh_token()

    new_rt = RefreshToken(
        user_id=user.id,
        token_hash=new_rt_hash,
        family_id=rt.family_id,
        expires_at=new_rt_expires,
        is_revoked=False,
    )
    db.add(new_rt)
    db.commit()

    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        samesite="lax",
        secure=_is_secure_cookie(),
        max_age=900,
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_raw_rt,
        expires_in=900,
    )


@router.post("/logout")
@limiter.limit("10/minute")
def logout(request: Request, response: Response):
    """Clear session cookie."""
    response.delete_cookie(key="access_token", secure=_is_secure_cookie(), samesite="lax")
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Retrieve current authenticated user profile."""
    return current_user


@router.post("/api-keys", response_model=ApiKeyResponse)
def create_key(
    payload: ApiKeyCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a new scoped API key for programmatic integrations.

    Only administrators can create API keys.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create API keys",
        )
    raw_key, key_prefix, key_h = generate_api_key(payload.name)
    api_key = ApiKey(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        name=payload.name,
        key_prefix=key_prefix,
        key_hash=key_h,
        scopes=payload.scopes or "investigations:read,investigations:write,analysis:run",
        is_revoked=False,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return ApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        raw_key=raw_key,
        scopes=api_key.scopes,
        created_at=api_key.created_at,
    )


@router.get("/api-keys", response_model=List[ApiKeyResponse])
def list_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all API keys belonging to the current user's tenant.

    Only administrators can list API keys.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can list API keys",
        )
    return (
        db.query(ApiKey)
        .filter(ApiKey.tenant_id == current_user.tenant_id, ApiKey.is_revoked == False)  # noqa: E712
        .all()
    )


@router.delete("/api-keys/{key_id}")
def revoke_key(
    key_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke an API key.

    Only administrators can revoke API keys.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can revoke API keys",
        )
    key = (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.tenant_id == current_user.tenant_id)
        .first()
    )
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    key.is_revoked = True
    db.commit()
    return {"message": "API key revoked successfully"}