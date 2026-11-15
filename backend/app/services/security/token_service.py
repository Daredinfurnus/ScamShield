"""Token and capability management service."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from jose import JWTError, jwt

from app.config import settings

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
CAPABILITY_TOKEN_EXPIRE_DAYS = 30


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token string."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(
    user_id: int,
    tenant_id: int,
    role: str = "investigator",
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate a short-lived signed JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "tid": tenant_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token. Returns payload or None if invalid/expired."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_refresh_token() -> Tuple[str, str, datetime]:
    """Generate a raw refresh token, its SHA-256 hash, and expiration timestamp."""
    raw_token = f"scam_rt_{secrets.token_urlsafe(48)}"
    token_h = hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return raw_token, token_h, expires_at


def generate_api_key(name: str) -> Tuple[str, str, str]:
    """Generate a raw API key, its display prefix, and its SHA-256 hash.

    Format: scam_live_<prefix>_<secret>
    """
    prefix = secrets.token_hex(6)  # 12 chars
    secret = secrets.token_urlsafe(32)
    raw_key = f"scam_live_{prefix}_{secret}"
    key_h = hash_token(raw_key)
    return raw_key, f"scam_live_{prefix}", key_h


def generate_investigation_capability() -> Tuple[str, str, datetime]:
    """Generate an anonymous investigation access capability token and its SHA-256 hash.

    Format: scam_cap_<secret>
    """
    raw_cap = f"scam_cap_{secrets.token_urlsafe(32)}"
    cap_h = hash_token(raw_cap)
    expires_at = datetime.now(timezone.utc) + timedelta(days=CAPABILITY_TOKEN_EXPIRE_DAYS)
    return raw_cap, cap_h, expires_at
