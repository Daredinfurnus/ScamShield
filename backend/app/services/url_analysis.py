from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Any, Dict, List, Optional, Tuple

from app.services.detection_signal import DetectionSignal


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate a URL string."""
    if not url:
        return False, "URL is required"
    if len(url) > 2000:
        return False, "URL exceeds maximum length of 2000 characters"
    try:
        parsed = urlparse(url)
    except ValueError as e:
        return False, f"Malformed URL structure: {e}"
    scheme = parsed.scheme.lower() if parsed.scheme else ""
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only http and https are allowed."
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must include a hostname"
    if "_" in hostname:
        return False, f"Hostname contains underscores which are not valid: {hostname}"
    try:
        ip_address(hostname)
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


def normalize_url(url: str) -> Dict[str, str]:
    """Normalize a URL into its canonical components."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()
    port = parsed.port
    if scheme == "https" and hostname_lower.endswith(":443"):
        host_for_ssrf = hostname_lower[:-4]
    elif scheme == "http" and hostname_lower.endswith(":80"):
        host_for_ssrf = hostname_lower[:-3]
    else:
        host_for_ssrf = hostname_lower
    path = parsed.path
    if not path or path == "":
        path = "/"
    elif path != "/" and path.endswith("/") and len(path) > 1:
        path = path.rstrip("/")
    query_items = parse_qs(parsed.query, keep_blank_values=True)
    query_parts: List[str] = []
    seen_keys: set = set()
    for k, v_list in query_items.items():
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
        "host": hostname_lower,
        "port": port,
        "path": path,
        "query": query_str,
        "fragment": fragment,
        "host_for_ssrf": host_for_ssrf,
    }


class URLAnalyzer:
    """Analyzes URLs for risk signals using deterministic heuristics."""

    def analyze(self, url: str) -> Dict[str, Any]:
        """Analyze a URL and return risk signals with evidence."""
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
        from urllib.parse import urlparse as _parse
        normalized = {
            "original": url,
            "scheme": parsed.scheme.lower() if (parsed := _parse(url)).scheme else "http",
            "host": (parsed.hostname or "").lower(),
            "port": parsed.port,
            "path": parsed.path or "/" if (parsed := _parse(url)).path else "/",
            "query": "",
            "fragment": parsed.fragment.lower() if parsed.fragment else None,
            "host_for_ssrf": (_parse(url).hostname or "").lower(),
        }
        # Simple signal: check if IP address
        signals = []
        try:
            ip_address(normalized["host"])
            signals.append(
                type('Signal', (), {
                    'signal_type': 'url',
                    'name': 'ip_in_url',
                    'description': 'URL uses an IP address rather than a domain name',
                    'score': 30.0,
                    'weight': 1.0,
                    'confidence': 0.70,
                    'evidence_snippet': normalized["host"],
                    'evidence_source': 'url_input',
                    'metadata': {'is_ip': True, 'ip_version': 'IPv4' if '.' in normalized["host"] else 'IPv6'}
                })()
            )
        except ValueError:
            pass
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
def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    if not url:
        return False, "URL is required"
    if len(url) > 2000:
        return False, "URL exceeds maximum length of 2000 characters"
    try:
        parsed = urlparse(url)
    except ValueError as e:
        return False, f"Malformed URL structure: {e}"
    scheme = parsed.scheme.lower() if parsed.scheme else ""
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only http and https are allowed."
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must include a hostname"
    if "_" in hostname:
        return False, f"Hostname contains underscores which are not valid: {hostname}"
    try:
        ip_address(hostname)
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


def normalize_url(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()
    port = parsed.port
    if scheme == "https" and hostname_lower.endswith(":443"):
        host_for_ssrf = hostname_lower[:-4]
    elif scheme == "http" and hostname_lower.endswith(":80"):
        host_for_ssrf = hostname_lower[:-3]
    else:
        host_for_ssrf = hostname_lower
    path = parsed.path
    if not path or path == "":
        path = "/"
    elif path != "/" and path.endswith("/") and len(path) > 1:
        path = path.rstrip("/")
    query_items = parse_qs(parsed.query, keep_blank_values=True)
    query_parts: List[str] = []
    seen_keys: set = set()
    for k, v_list in query_items.items():
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
        "host": hostname_lower,
        "port": port,
        "path": path,
        "query": query_str,
        "fragment": fragment,
        "host_for_ssrf": host_for_ssrf,
    }
def _signal(signal_type: str, name: str, description: str, score: float, evidence_snippet: str, evidence_source: str = "url_input", metadata: Optional[Dict[str, Any]] = None, weight: float = 1.0, confidence: float = 1.0) -> DetectionSignal:
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


def _count_subdomain_labels(hostname: str) -> int:
    if not hostname:
        return 0
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def _ip_version(hostname: str) -> str:
    try:
        ip_address(hostname)
        return "IPv4" if "." in hostname else "IPv6"
    except ValueError:
        return "unknown"


def build_signals(url: str, normalized: Dict[str, str]) -> List[DetectionSignal]:
    hostname: str = normalized.get("host", "")
    path: str = normalized.get("path", "/")
    query: str = normalized.get("query", "")
    scheme: str = normalized.get("scheme", "http")
    original: str = normalized.get("original", url)
    signals: List[DetectionSignal] = []

    # 1. IP address used instead of a domain
    try:
        ip_address(hostname)
        signals.append(
            _signal("url", "ip_in_url", "URL uses an IP address rather than a domain name, unusual for legitimate websites.", 30.0, hostname, "url_input", {"is_ip": True, "ip_version": _ip_version(hostname)}, 1.0, 0.70)
        )
    except ValueError:
        pass

    # 2. Punycode or internationalised hostname
    if hostname.startswith("xn--"):
        signals.append(
            _signal("url", "punycode_hostname", "Hostname contains punycode encoding (xn--), often used for IDN homograph attacks.", 25.0, hostname, "url_input", {"is_punycode": True}, 1.0, 0.65)
        )

    # 3. Suspicious or high-risk TLD
    parts = hostname.split(".")
    tld = parts[-1].lower() if len(parts) >= 2 else ""
    if tld and tld in {"top", "xyz", "cc", "gq", "ml", "tk", "cf"}:
        signals.append(
            _signal("url", "suspicious_tld", f"Hostname uses a high-risk TLD (.{tld}), frequently associated with malicious infrastructure.", 20.0, f".{tld}", "url_input", {"tld": tld}, 1.0, 0.60)
        )

    # 4. Known URL shortener
    hostname_lower = hostname.lower()
    if hostname_lower in {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "bit.do"}:
        signals.append(
            _signal("url", "url_shortener", "Hostname is a known URL shortener service, often used by scammers to hide the final destination.", 25.0, hostname, "url_input", {"shortener": hostname_lower}, 1.0, 0.70)
        )

    return signals


class URLAnalyzer:
    """Analyzes URLs for risk signals using deterministic heuristics.

    Every signal references actual evidence from the submitted URL.
    The LLM never calculates or overrides the risk score — RiskScorer is the sole authoritative source.

    The analysis pipeline:
    1. validate_url() — syntactic validation
    2. normalize_url() — component extraction
    3. build_signals() — heuristic signal generation
    4. RiskScorer aggregates signal scores into a 0–100 risk score and band
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
