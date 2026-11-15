"""Comprehensive Server-Side Request Forgery (SSRF) protection and safe HTTP client.

Implements strict validation of target URLs, DNS resolution checks, private/reserved
IP blacklisting, connection IP pinning, redirect hop revalidation, and size limits.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import httpx

# Blocked IP networks covering RFC 1918, RFC 3927 (link-local), loopback, carrier-grade NAT,
# multicast, reserved, and cloud provider instance metadata services.
BLOCKED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback IPv4
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / Cloud metadata (AWS/GCP/Azure)
    ipaddress.ip_network("172.16.0.0/12"),    # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),     # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.88.99.0/24"),   # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),   # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),    # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),   # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked ranges
    ipaddress.ip_network("::/128"),           # Unspecified
    ipaddress.ip_network("::1/128"),          # Loopback
    ipaddress.ip_network("fc00::/7"),         # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),        # Link-local
    ipaddress.ip_network("ff00::/8"),         # Multicast
    ipaddress.ip_network("2001:db8::/32"),    # Documentation
]

# Explicit metadata hostnames
BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
    "100.100.100.200",  # Alibaba Cloud metadata
}

ALLOWED_SCHEMES: Set[str] = {"http", "https"}
ALLOWED_PORTS: Set[int] = {80, 443}
MAX_REDIRECTS: int = 5
MAX_RESPONSE_BYTES: int = 1_048_576  # 1 MB
CONNECT_TIMEOUT: float = 3.0
READ_TIMEOUT: float = 5.0


class SSRFValidationError(ValueError):
    """Raised when a URL violates SSRF safety boundaries."""
    pass


def normalize_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an IP string, normalizing IPv4-mapped IPv6 addresses."""
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def is_ip_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, Optional[str]]:
    """Verify if an IP address is safe for outbound connections."""
    if ip.is_loopback:
        return False, f"Loopback address disallowed: {ip}"
    if ip.is_private:
        return False, f"Private network address disallowed: {ip}"
    if ip.is_link_local:
        return False, f"Link-local address disallowed: {ip}"
    if ip.is_multicast:
        return False, f"Multicast address disallowed: {ip}"
    if ip.is_reserved:
        return False, f"Reserved address disallowed: {ip}"
    if ip.is_unspecified:
        return False, f"Unspecified address disallowed: {ip}"

    for blocked_net in BLOCKED_NETWORKS:
        if ip in blocked_net:
            return False, f"Destination belongs to restricted range: {blocked_net}"

    return True, None


def resolve_and_validate_host(hostname: str, port: int) -> List[str]:
    """Resolve DNS A and AAAA records, validating that EVERY resolved IP is permitted."""
    hostname_clean = hostname.strip().lower().rstrip(".")
    if hostname_clean in BLOCKED_HOSTNAMES:
        raise SSRFValidationError(f"Target host is explicitly blacklisted: {hostname}")

    # Check if hostname is a direct IP
    try:
        direct_ip = normalize_ip(hostname_clean)
        allowed, reason = is_ip_allowed(direct_ip)
        if not allowed:
            raise SSRFValidationError(reason)
        return [str(direct_ip)]
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(
            hostname_clean,
            port,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as e:
        raise SSRFValidationError(f"DNS resolution failed for {hostname}: {e}")

    if not addr_info:
        raise SSRFValidationError(f"No IP addresses resolved for {hostname}")

    validated_ips: List[str] = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        ip = normalize_ip(ip_str)
        allowed, reason = is_ip_allowed(ip)
        if not allowed:
            raise SSRFValidationError(f"Resolved IP {ip} for {hostname} is forbidden: {reason}")
        if str(ip) not in validated_ips:
            validated_ips.append(str(ip))

    return validated_ips


def validate_target_url(url: str) -> Dict[str, Any]:
    """Perform comprehensive pre-connection SSRF validation of a URL."""
    if not url or len(url) > 2000:
        raise SSRFValidationError("URL missing or exceeds 2000 character limit")

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFValidationError(f"Scheme '{scheme}' not permitted; only http and https are allowed")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("URL has no hostname")

    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFValidationError(f"Port {port} not permitted; only ports 80 and 443 are allowed")

    validated_ips = resolve_and_validate_host(hostname, port)

    return {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "validated_ips": validated_ips,
    }


def safe_fetch_url(
    url: str,
    max_redirects: int = MAX_REDIRECTS,
    timeout: float = CONNECT_TIMEOUT,
) -> Dict[str, Any]:
    """Safely fetch a URL with DNS rebinding protection and redirect revalidation.

    Connects strictly to pre-validated IPs, intercepts redirects, limits response size,
    and strips credentials across origin changes.
    """
    current_url = url
    redirect_chain: List[str] = []

    for hop in range(max_redirects + 1):
        redirect_chain.append(current_url)
        info = validate_target_url(current_url)
        target_ip = info["validated_ips"][0]
        scheme = info["scheme"]
        hostname = info["hostname"]
        port = info["port"]

        # To prevent DNS rebinding, we connect directly to the validated IP
        # while passing the original Host header and TLS SNI
        headers = {
            "User-Agent": "ScamShield-ThreatIntel/1.0",
            "Host": hostname,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

        # Build direct IP URL with port
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            ip_url = f"{scheme}://{target_ip}{info['path']}"
        else:
            ip_url = f"{scheme}://{target_ip}:{port}{info['path']}"

        if info["query"]:
            ip_url += f"?{info['query']}"

        try:
            # Note: For HTTPS with IP connection, we verify the hostname certificate
            with httpx.Client(
                verify=True,
                follow_redirects=False,
                timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT, read=READ_TIMEOUT),
            ) as client:
                # If target is an IP, we request with host header and extensions
                # To guarantee SNI matches hostname, httpx supports extensions={"sni_hostname": hostname}
                req = client.build_request("GET", ip_url, headers=headers, extensions={"sni_hostname": hostname})
                response = client.send(req, stream=True)

                if response.is_redirect:
                    location = response.headers.get("Location")
                    if not location:
                        break
                    # Resolve relative redirect against current URL
                    next_url = urljoin(current_url, location)
                    if hop >= max_redirects:
                        raise SSRFValidationError("Exceeded maximum redirect limit (5 hops)")
                    current_url = next_url
                    continue

                # Read body with maximum size guard
                body_chunks = []
                bytes_read = 0
                for chunk in response.iter_bytes():
                    bytes_read += len(chunk)
                    if bytes_read > MAX_RESPONSE_BYTES:
                        raise SSRFValidationError(f"Response size exceeds limit ({MAX_RESPONSE_BYTES} bytes)")
                    body_chunks.append(chunk)

                content = b"".join(body_chunks)
                content_type = response.headers.get("content-type", "")

                return {
                    "success": True,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "content_length": len(content),
                    "text_preview": content[:2000].decode("utf-8", errors="replace"),
                }

        except (httpx.RequestError, ssl_error) if 'ssl_error' in locals() else (httpx.RequestError, ssl.SSLError) if 'ssl' in locals() else httpx.RequestError as e:
            return {
                "success": False,
                "error": str(e),
                "final_url": current_url,
                "redirect_chain": redirect_chain,
            }

    return {
        "success": False,
        "error": "Redirect limit exceeded",
        "final_url": current_url,
        "redirect_chain": redirect_chain,
    }
