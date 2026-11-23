from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse
from ipaddress import ip_address

from app.services.detection_signal import DetectionSignal
from app.services.ssrf_protection import is_ip_allowed, normalize_ip

# Maximum image size in bytes (10 MiB)
MAX_IMAGE_BYTES: int = 10 * 1024 * 1024
# Maximum base64 input size (approximately 10 MiB decoded)
MAX_BASE64_INPUT_BYTES: int = int(10 * 1024 * 1024 * 4 / 3)

from fastapi import HTTPException, APIRouter

router = APIRouter()


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate a URL string syntactically and check hostname validity."""
    if not url:
        return False, "URL is required"
    if len(url) > 2000:
        return False, "URL exceeds maximum length of 2000 characters"
    try:
        parsed = urlparse(url)
    except ValueError as e:
        return False, f"Malformed URL structure: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only http and https are allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must include a hostname"
    if "_" in hostname:
        return False, f"Hostname contains underscores which are not valid: {hostname}"
    try:
        ip = normalize_ip(hostname)
        allowed, reason = is_ip_allowed(ip)
        if not allowed:
            return False, f"Restricted destination IP: {reason}"
    except ValueError:
        if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
            return False, f"Hostname contains invalid characters: {hostname}"
        parts = hostname.split(".")
        if len(parts) < 2:
            return False, f"Hostname must contain at least one dot: {hostname}"
        for part in parts:
            if not part:
                return False, f"Hostname contains empty label: {hostname}"
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", part):
                return False, f"Hostname label invalid: {part} in {hostname}"

    return True, None


def normalize_url(url: str) -> Dict[str, Any]:
    """Normalize a URL into its canonical components."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    path = parsed.path
    if not path or path == "":
        path = "/"
    elif path != "/" and path.endswith("/") and len(path) > 1:
        path = path.rstrip("/")

    query_items = parse_qs(parsed.query, keep_blank_values=True)
    query_items_sorted: List[Tuple[str, str]] = []
    seen_keys: set = set()
    for k, v_list in sorted(query_items.items(), key=lambda x: x[0].lower()):
        kk = k.lower()
        if kk not in seen_keys:
            seen_keys.add(kk)
            vv = v_list[0].lower() if v_list else ""
            query_items_sorted.append((kk, vv))
    query_str = "&".join(k + "=" + v for k, v in query_items_sorted)
    fragment = parsed.fragment.lower() if parsed.fragment else None

    return {
        "original": url,
        "scheme": scheme,
        "host": hostname,
        "port": port,
        "path": path,
        "query": query_str,
        "fragment": fragment,
    }


def _signal(
    signal_type: str,
    name: str,
    description: str,
    score: float,
    evidence_snippet: str,
    evidence_source: str = "url_input",
    metadata: Optional[Dict[str, Any]] = None,
    weight: float = 1.0,
    confidence: float = 1.0,
) -> DetectionSignal:
    return DetectionSignal(
        signal_type=signal_type,
        name=name,
        description=description,
        score=score,
        weight=weight,
        confidence=confidence,
        evidence_snippet=evidence_snippet,
        evidence_source=evidence_source,
        metadata=metadata,
    )


def _ip_version(hostname: str) -> str:
    try:
        ip = ip_address(hostname)
        return "IPv4" if ip.version == 4 else "IPv6"
    except ValueError:
        return "unknown"


def build_signals(url: str, normalized: Dict[str, Any]) -> List[DetectionSignal]:
    """Generate risk signals from normalized URL components."""
    hostname: str = normalized.get("host", "")
    hostname_lower = hostname.lower()
    signals: List[DetectionSignal] = []

    # 1. IP address used instead of a domain
    try:
        ip_address(hostname)
        signals.append(
            _signal(
                "url",
                "ip_in_url",
                "URL uses an IP address rather than a domain name, unusual for legitimate websites.",
                30.0,
                hostname,
                "url_input",
                {"is_ip": True, "ip_version": _ip_version(hostname)},
                1.0,
                0.70,
            )
        )
    except ValueError:
        pass

    # 2. Punycode or internationalised hostname
    if hostname.startswith("xn--"):
        signals.append(
            _signal(
                "url",
                "punycode_hostname",
                "Hostname contains punycode encoding (xn--), often used for IDN homograph attacks.",
                25.0,
                hostname,
                "url_input",
                {"is_punycode": True},
                1.0,
                0.65,
            )
        )

    # 3. Suspicious or high-risk TLD
    parts = hostname.split(".")
    tld = parts[-1].lower() if len(parts) >= 2 else ""
    if tld and tld in {"top", "xyz", "cc", "gq", "ml", "tk", "cf"}:
        signals.append(
            _signal(
                "url",
                "suspicious_tld",
                f"Hostname uses a high-risk TLD (.{tld}), frequently associated with malicious infrastructure.",
                20.0,
                f".{tld}",
                "url_input",
                {"tld": tld},
                1.0,
                0.60,
            )
        )

    # 4. Known URL shortener
    if hostname_lower in {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "bit.do"}:
        signals.append(
            _signal(
                "url",
                "url_shortener",
                "Hostname is a known URL shortener service, often used by scammers to hide the final destination.",
                25.0,
                hostname,
                "url_input",
                {"shortener": hostname_lower},
                1.0,
                0.70,
            )
        )

    # 5. Suspicious path segments and query params
    path = normalized.get("path", "").lower()
    query = normalized.get("query", "").lower()
    full_path_context = path + query

    suspicious_path_terms = ["login", "verify", "secure", "banking", "account", "update", "signin"]
    for term in suspicious_path_terms:
        if term in full_path_context:
            signals.append(
                _signal(
                    "url",
                    f"suspicious_path_{term}",
                    f"URL contains suspicious path/query term: {term}.",
                    10.0,
                    term,
                    "url_input",
                    {"term": term},
                    1.0,
                    0.50,
                )
            )

    # 6. Simple typosquatting check (e.g., paypa1)
    if "paypa1" in hostname_lower:
        signals.append(
            _signal(
                "url",
                "typosquatting_attempt",
                "Hostname contains suspicious typosquatting pattern.",
                25.0,
                hostname_lower,
                "url_input",
                {"pattern": "paypa1"},
                1.0,
                0.70,
            )
        )

    return signals


class URLAnalyzer:
    """Analyzes URLs for risk signals using deterministic heuristics.

    Every signal references actual evidence from the submitted URL.
    RiskScorer aggregates signal scores into a 0-100 risk score and band.
    """

    def analyze(self, url: str) -> Dict[str, Any]:
        valid, reason = validate_url(url)
        if not valid:
            return {
                "score": 0.0,
                "label": "low",
                "evidence": url,
                "source": "url_heuristic",
                "signals": [],
                "note": f"URL validation feedback: {reason}. This is not a verified safe result.",
            }

        normalized = normalize_url(url)
        signals = build_signals(url, normalized)

        from app.services.risk_scoring import RiskScorer

        raw_scores = [{"score": s.score, "weight": s.weight} for s in signals]
        if raw_scores:
            scorer = RiskScorer()
            scoring_result = scorer.score(raw_scores)
        else:
            scoring_result = {"risk_score": 0.0, "risk_band": "low"}

        return {
            "score": scoring_result["risk_score"],
            "label": scoring_result["risk_band"],
            "evidence": url,
            "source": "url_heuristic",
            "signals": signals,
            "note": None,
        }


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
        # Enforce size limit at API ingestion - read in bounded chunks
        if len(content) > MAX_IMAGE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_PAYLOAD_TOO_LARGE,
                detail=f"Image exceeds maximum size limit of 10 MiB",
            )
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )
        image_bytes = content
    elif image_data_base64:
        # Allow data URL prefix or raw base64
        import base64

        # Validate and check base64 size before decoding
        if len(image_data_base64) > MAX_BASE64_INPUT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_PAYLOAD_TOO_LARGE,
                detail=f"Base64 input exceeds maximum decoded size of 10 MiB",
            )
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