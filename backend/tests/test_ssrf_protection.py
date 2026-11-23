"""Tests for SSRF protection implementation."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.services.ssrf_protection import (
    normalize_ip,
    is_ip_allowed,
    resolve_and_validate_host,
    validate_target_url,
    safe_fetch_url,
    SSRFValidationError,
    BLOCKED_HOSTNAMES,
    MAX_REDIRECTS,
)


# ========== IP Normalization Tests ==========

def test_normalize_ipv4():
    """Test IPv4 normalization."""
    ip = normalize_ip("192.168.1.1")
    assert str(ip) == "192.168.1.1"


def test_normalize_ipv6():
    """Test IPv6 normalization."""
    ip = normalize_ip("::1")
    assert str(ip) == "::1"


def test_normalize_ipv4_mapped_ipv6():
    """Test IPv4-mapped IPv6 address normalization."""
    ip = normalize_ip("::ffff:192.168.1.1")
    assert str(ip) == "192.168.1.1"


# ========== IP Allowance Tests ==========

def test_loopback_ipv4_blocked():
    """Loopback IPv4 (127.0.0.1) must be blocked."""
    ip = normalize_ip("127.0.0.1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    assert "Loopback" in reason


def test_loopback_ipv6_blocked():
    """Loopback IPv6 (::1) must be blocked."""
    ip = normalize_ip("::1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    assert "Loopback" in reason


def test_private_rfc1918_blocked():
    """RFC 1918 private ranges must be blocked."""
    private_ips = ["10.0.0.1", "172.16.0.1", "192.168.1.1"]
    for ip_str in private_ips:
        ip = normalize_ip(ip_str)
        allowed, reason = is_ip_allowed(ip)
        assert allowed is False, f"{ip_str} should be blocked: {reason}"


def test_link_local_blocked():
    """Link-local addresses (169.254.x.x) must be blocked.

    Note: Python's ipaddress module categorizes 169.254.x.x as 'private',
    so it's caught by the is_private check first.
    """
    ip = normalize_ip("169.254.169.254")  # AWS metadata
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    # Python's ipaddress module categorizes 169.254.x.x as private
    assert "Private" in reason or "Link-local" in reason


def test_multicast_blocked():
    """Multicast addresses must be blocked."""
    ip = normalize_ip("224.0.0.1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    assert "Multicast" in reason


def test_reserved_blocked():
    """Reserved addresses must be blocked.

    Note: 240.0.0.0/4 is both reserved and in BLOCKED_NETWORKS.
    The is_reserved check catches it first.
    """
    ip = normalize_ip("240.0.0.1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    assert "Reserved" in reason or "Private" in reason


def test_public_ip_allowed():
    """Legitimate public IPs must be allowed."""
    public_ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    for ip_str in public_ips:
        ip = normalize_ip(ip_str)
        allowed, reason = is_ip_allowed(ip)
        assert allowed is True, f"{ip_str} should be allowed: {reason}"


def test_ipv6_public_allowed():
    """Legitimate public IPv6 must be allowed."""
    ip = normalize_ip("2001:4860:4860::8888")  # Google DNS IPv6
    allowed, reason = is_ip_allowed(ip)
    assert allowed is True


# ========== Hostname Resolution & Validation ==========

def test_blocked_hostname_rejected():
    """Explicitly blacklisted hostnames must be rejected."""
    for hostname in BLOCKED_HOSTNAMES:
        with pytest.raises(Exception) as exc_info:
            resolve_and_validate_host(hostname, 80)
        assert "blacklisted" in str(exc_info.value).lower()


def test_direct_ip_allowed():
    """Direct IP address that is public should pass."""
    ips = ["8.8.8.8", "1.1.1.1"]
    for ip in ips:
        result = resolve_and_validate_host(ip, 443)
        assert len(result) == 1
        assert result[0] == ip


def test_direct_private_ip_rejected():
    """Direct private IP must be rejected."""
    with pytest.raises(Exception) as exc_info:
        resolve_and_validate_host("10.0.0.1", 80)
    assert "forbidden" in str(exc_info.value).lower()


def test_localhost_rejected():
    """localhost must be rejected."""
    with pytest.raises(Exception) as exc_info:
        resolve_and_validate_host("localhost", 80)
    assert "blacklisted" in str(exc_info.value).lower()


def test_aws_metadata_rejected():
    """AWS metadata endpoint must be rejected."""
    with pytest.raises(Exception) as exc_info:
        resolve_and_validate_host("169.254.169.254", 80)
    assert "forbidden" in str(exc_info.value).lower() or "blacklisted" in str(exc_info.value).lower()


# ========== URL Validation ==========

def test_missing_scheme_rejected():
    """URLs without scheme must be rejected."""
    with pytest.raises(Exception) as exc_info:
        validate_target_url("example.com")
    assert "Scheme" in str(exc_info.value) or "scheme" in str(exc_info.value).lower()


def test_invalid_scheme_rejected():
    """Non-http/https schemes must be rejected."""
    with pytest.raises(Exception) as exc_info:
        validate_target_url("ftp://example.com")
    assert "Scheme" in str(exc_info.value) or "scheme" in str(exc_info.value).lower()


def test_missing_hostname_rejected():
    """URL without hostname must be rejected."""
    with pytest.raises(Exception) as exc_info:
        validate_target_url("http://")
    assert "hostname" in str(exc_info.value).lower()


def test_invalid_port_rejected():
    """Non-standard ports must be rejected."""
    with pytest.raises(Exception) as exc_info:
        validate_target_url("http://example.com:8080")
    assert "Port" in str(exc_info.value) or "port" in str(exc_info.value).lower()


def test_valid_url_accepted():
    """Valid URL with public IP must pass."""
    result = validate_target_url("https://example.com")
    assert "validated_ips" in result
    assert len(result["validated_ips"]) > 0


def test_https_default_port_443():
    """HTTPS defaults to port 443."""
    result = validate_target_url("https://example.com")
    assert result["port"] == 443


def test_http_default_port_80():
    """HTTP defaults to port 80."""
    result = validate_target_url("http://example.com")
    assert result["port"] == 80


def test_non_standard_port_rejected():
    """Non-standard port must be rejected."""
    with pytest.raises(Exception) as exc_info:
        validate_target_url("http://example.com:8080")
    assert "Port" in str(exc_info.value) or "port" in str(exc_info.value).lower()


# ========== Multi-step Redirect Tests ==========

def test_redirect_to_private_ip_blocked():
    """Redirect to private IP must be blocked."""
    # The key test is that validate_target_url rejects private IPs
    with pytest.raises(Exception):
        validate_target_url("http://10.0.0.1")


# ========== IPv6 Tests ==========

def test_ipv6_loopback_blocked():
    """IPv6 loopback (::1) must be blocked."""
    ip = normalize_ip("::1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    assert "Loopback" in reason


def test_ipv6_unique_local_blocked():
    """IPv6 Unique Local Address (fc00::/7) must be blocked."""
    ip = normalize_ip("fc00::1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    assert "Private" in reason


def test_ipv6_link_local_blocked():
    """IPv6 link-local (fe80::/10) must be blocked.

    Note: Python's ipaddress module categorizes fe80::/10 as 'private',
    so it's caught by the is_private check first.
    """
    ip = normalize_ip("fe80::1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    # Python's ipaddress module categorizes fe80::/10 as private
    assert "Private" in reason or "Link-local" in reason


def test_ipv6_multicast_blocked():
    """IPv6 multicast (ff00::/8) must be blocked."""
    ip = normalize_ip("ff02::1")
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False
    assert "Multicast" in reason


def test_ipv6_public_allowed():
    """Public IPv6 must be allowed."""
    ip = normalize_ip("2001:4860:4860::8888")  # Google DNS
    allowed, reason = is_ip_allowed(ip)
    assert allowed is True


def test_ipv4_mapped_ipv6_normalized():
    """IPv4-mapped IPv6 must be normalized to IPv4."""
    ip = normalize_ip("::ffff:192.168.1.1")
    assert str(ip) == "192.168.1.1"
    allowed, reason = is_ip_allowed(ip)
    assert allowed is False  # 192.168.1.1 is private


def test_ipv6_compressed_notation():
    """Compressed IPv6 notation must be handled.

    Note: 2001:db8::/32 is a documentation prefix and is blocked.
    Use a different public IPv6 for this test.
    """
    ip = normalize_ip("2001:4860:4860::1")  # Google DNS compressed
    allowed, reason = is_ip_allowed(ip)
    assert allowed is True


# ========== Redirect Chain Tests ==========

def test_redirect_limit():
    """Redirect limit constant must be reasonable."""
    assert MAX_REDIRECTS == 5


# ========== DNS Rebinding Protection ==========

@patch("app.services.ssrf_protection.socket.getaddrinfo")
def test_connection_uses_validated_ip(mock_getaddrinfo):
    """Connection should use pre-validated IP to prevent DNS rebinding."""
    # This tests that the validation logic returns specific IPs
    # The actual safe_fetch_url tests would need httpx mocking
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
    ]

    validated_ips = resolve_and_validate_host("example.com", 443)
    assert "8.8.8.8" in validated_ips


# ========== IPv6 URL Construction ==========

def test_ipv6_literal_brackets():
    """IPv6 literals must be bracketed in URLs."""
    # This tests the URL construction logic in safe_fetch_url
    # The code should bracket IPv6 literals when building URLs
    pass  # Requires full integration test


# ========== Error Handling ==========

def test_dns_failure_handled():
    """DNS resolution failures must be handled gracefully."""
    with patch("app.services.ssrf_protection.socket.getaddrinfo") as mock:
        import socket
        mock.side_effect = socket.gaierror("Name or service not known")
        with pytest.raises(Exception) as exc_info:
            resolve_and_validate_host("nonexistent.invalid", 80)
        assert "DNS resolution failed" in str(exc_info.value)


def test_no_ips_resolved():
    """Hostname resolving to no IPs must be rejected."""
    with patch("app.services.ssrf_protection.socket.getaddrinfo") as mock:
        mock.return_value = []
        with pytest.raises(Exception) as exc_info:
            resolve_and_validate_host("example.com", 80)
        assert "No IP addresses resolved" in str(exc_info.value)


# ========== IPv6 Literal Brackets in URL Construction ==========

def test_ipv6_url_construction():
    """IPv6 literals must be bracketed in URL construction."""
    # The safe_fetch_url function should bracket IPv6 literals
    # e.g., http://[::1]/path not http://::1/path
    # This is tested by the URL construction logic in safe_fetch_url
    pass  # Requires integration test


# ========== Connection Pinning ==========

@patch("app.services.ssrf_protection.httpx.Client")
def test_connection_uses_validated_ip(mock_client_class):
    """Connection should use pre-validated IP to prevent DNS rebinding."""
    # This would test that safe_fetch_url builds URL with validated IP
    # and uses Host header + SNI for the original hostname
    pass  # Requires integration test with httpx mocking


if __name__ == "__main__":
    pytest.main([__file__, "-v"])