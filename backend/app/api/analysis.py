from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user_optional
from app.models.user import User
from app.schemas.analysis import (
    AnalyzeTextRequest,
    AnalyzeURLRequest,
    AnalyzeImageRequest,
    AnalysisResponse,
)
from app.services.investigation_engine import InvestigationEngine
from app.services.security.token_service import generate_investigation_capability

router = APIRouter()


def _get_engine(db: Session) -> InvestigationEngine:
    """Create an InvestigationEngine scoped to the current DB session."""
    return InvestigationEngine(db_session=db)


def _handle_engine_result(result: Dict[str, Any]) -> AnalysisResponse:
    """Convert engine result to AnalysisResponse, handling failed status."""
    if result.get("status") == "failed" and result.get("investigation_id") is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("analysis_summary", "Analysis failed"),
        )
    return AnalysisResponse(**result)


@router.post("/text", response_model=AnalysisResponse)
def analyze_text(
    payload: AnalyzeTextRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Analyze raw message text for scam indicators.

    Supports both authenticated multi-tenant investigations and anonymous public intake.
    Anonymous submissions receive an independent, high-entropy capability token.
    """
    engine = _get_engine(db)

    # Resolve tenant and capability tokens
    if current_user:
        tenant_id = current_user.tenant_id
        user_id = current_user.id
        is_anonymous = False
        cap_h = None
        cap_expires = None
        raw_cap = None
    else:
        raw_cap, cap_h, cap_expires = generate_investigation_capability()
        tenant_id = None
        user_id = None
        is_anonymous = True

    try:
        result = engine.analyze_text(
            text=payload.text,
            title=f"Text Investigation: {payload.text[:60]}",
            tenant_id=tenant_id,
            created_by_user_id=user_id,
            is_anonymous=is_anonymous,
            access_token_hash=cap_h,
            access_token_expires_at=cap_expires,
            raw_access_token=raw_cap,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return _handle_engine_result(result)


@router.post("/url", response_model=AnalysisResponse)
def analyze_url(
    payload: AnalyzeURLRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Analyze a URL for scam indicators."""
    engine = _get_engine(db)

    if current_user:
        tenant_id = current_user.tenant_id
        user_id = current_user.id
        is_anonymous = False
        cap_h = None
        cap_expires = None
        raw_cap = None
    else:
        raw_cap, cap_h, cap_expires = generate_investigation_capability()
        tenant_id = None
        user_id = None
        is_anonymous = True

    try:
        result = engine.analyze_url(
            url=payload.url,
            title=f"URL Investigation: {payload.url[:60]}",
            tenant_id=tenant_id,
            created_by_user_id=user_id,
            is_anonymous=is_anonymous,
            access_token_hash=cap_h,
            access_token_expires_at=cap_expires,
            raw_access_token=raw_cap,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return _handle_engine_result(result)


@router.post("/image", response_model=AnalysisResponse)
async def analyze_image(
    file: Optional[UploadFile] = File(None),
    image_data_base64: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Analyze an uploaded screenshot via OCR.

    Accepts either a multipart/form-data file upload (`file`) or a base64-encoded
    string (`image_data_base64`). Both authenticated and anonymous submissions
    are supported. Anonymous submissions receive a capability token for later
    claim/access.
    """
    engine = _get_engine(db)

    if current_user:
        tenant_id = current_user.tenant_id
        user_id = current_user.id
        is_anonymous = False
        cap_h = None
        cap_expires = None
        raw_cap = None
    else:
        raw_cap, cap_h, cap_expires = generate_investigation_capability()
        tenant_id = None
        user_id = None
        is_anonymous = True

    # Resolve image bytes from file upload or base64 string
    image_bytes: Optional[bytes] = None
    resolved_filename = filename or (file.filename if file else "uploaded_screenshot.png")

    if file is not None:
        content = await file.read()
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )
        image_bytes = content
    elif image_data_base64:
        # Allow data URL prefix or raw base64
        import base64

        try:
            if image_data_base64.startswith("data:image/"):
                _, b64_str = image_data_base64.split(",", 1)
                image_bytes = base64.b64decode(b64_str)
            else:
                image_bytes = base64.b64decode(image_data_base64)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 image data: {e}",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Image file (multipart) or base64 image_data_base64 is required",
        )

    try:
        result = engine.analyze_image(
            image_input=image_bytes,
            filename=resolved_filename,
            title=f"Screenshot Investigation: {resolved_filename}",
            tenant_id=tenant_id,
            created_by_user_id=user_id,
            is_anonymous=is_anonymous,
            access_token_hash=cap_h,
            access_token_expires_at=cap_expires,
            raw_access_token=raw_cap,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    return _handle_engine_result(result)
