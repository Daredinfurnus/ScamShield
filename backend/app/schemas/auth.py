"""Authentication and authorization schemas."""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    tenant_name: Optional[str] = Field(None, max_length=100)
    role: Optional[str] = "investigator"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes in seconds


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scopes: Optional[str] = "investigations:read,investigations:write,analysis:run"


class ApiKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    raw_key: Optional[str] = None  # Only returned upon initial generation
    scopes: str
    created_at: Optional[datetime] = None


class UserResponse(BaseModel):
    id: int
    email: str
    tenant_id: int
    role: str
    is_active: bool
    created_at: Optional[datetime] = None


class ClaimInvestigationRequest(BaseModel):
    access_token: str = Field(..., description="The capability token returned when the investigation was submitted anonymously")
