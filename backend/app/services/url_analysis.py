"""Deterministic URL analysis engine.

Applies syntactic validation, component extraction, and rule-based heuristics
to identify risk indicators in suspicious URLs (IP usage, Punycode/IDN attacks,
high-risk TLDs, and URL shorteners).

Separates passive syntactic analysis from active network fetching.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse
from ipaddress import ip_address

from app.services.detection_signal import DetectionSignal
from app.services.ssrf_protection import is_ip_allowed, normalize_ip


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
    query_parts: List[str] = []
    seen_keys: set = set()
    for k, v_list in sorted(query_items.items()):
        kk = k.lower()
        if kk not in seen_keys:
            seen_keys.add(kk)
            vv = v_list[0].lower() if v_list else ""
            query_parts.append(f"{kk}={vv}")
    query_str = "&".join(query_parts) if query_parts else ""
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