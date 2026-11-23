# PRODUCTION_CONFIG_CHECKLIST.md

## Production Configuration Checklist

**Project:** ScamShield  
**Audit Date:** 2026-11-22  
**Auditor:** Security Hardening Phase 4  
**Environment:** Production deployment review  

---

## Configuration Validation Results

### 1. Core Application Settings

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 1.1 | `APP_ENV=production` set | NOT VERIFIED | Requires production .env |
| 1.2 | `DEBUG=false` in production | **FAIL** (defaults to True) | Fixed: validation added |
| 1.3 | `API_V1_STR=/api` | PASS | Default OK |

### 2. Security Settings

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 2.1 | `SECRET_KEY` explicitly set | NOT VERIFIED | Requires production .env |
| 2.2 | `SECRET_KEY` ≥ 256 bits (32+ chars) | NOT VERIFIED | Validation added |
| 2.3 | `SECRET_KEY` not placeholder | **FAIL** (defaults to generated) | Validation added |
| 2.4 | `ACCESS_TOKEN_EXPIRE_MINUTES` reasonable | PASS | 30 min default |
| 2.5 | Rate limiting configured | PASS | 5/min login, 10/min refresh |

### 3. CORS Configuration

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 3.1 | No wildcards with credentials | NOT VERIFIED | Validation added |
| 3.2 | No HTTP origins (except localhost) | NOT VERIFIED | Validation added |
| 3.3 | Explicit frontend domains only | NOT VERIFIED | Requires production .env |
| 3.4 | `allow_credentials=true` compatible | PASS | Configured |

### 4. Database

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 4.1 | Production DB (not SQLite) | NOT VERIFIED | Requires `DATABASE_URL` |
| 4.2 | Connection pooling configured | NOT VERIFIED | SQLAlchemy defaults |
| 4.3 | SSL mode for PostgreSQL | NOT VERIFIED | Requires `sslmode=require` |

### 5. TLS/HTTPS

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 5.1 | HTTPS enforced | NOT VERIFIED | Requires reverse proxy |
| 5.2 | Secure cookies in production | PASS | `_is_secure_cookie()` logic |
| 5.3 | HSTS headers | NOT VERIFIED | Requires reverse proxy |
| 5.4 | TLS certificate valid | NOT VERIFIED | Requires deployment |

### 6. Security Headers

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 6.1 | CSP headers | NOT IMPLEMENTED | Need middleware |
| 6.2 | HSTS | NOT IMPLEMENTED | Need reverse proxy |
| 6.3 | X-Frame-Options | NOT IMPLEMENTED | Need middleware |
| 6.4 | X-Content-Type-Options | NOT IMPLEMENTED | Need middleware |
| 6.5 | Referrer-Policy | NOT IMPLEMENTED | Need middleware |

### 7. Logging & Monitoring

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 7.1 | No secrets in logs | NOT VERIFIED | Code review needed |
| 7.2 | Error stack traces hidden | NOT VERIFIED | DEBUG=False should help |
| 7.3 | Access logging | NOT IMPLEMENTED | Need middleware |
| 7.4 | Audit logging for auth | PARTIAL | Refresh token replay detection |

### 8. Rate Limiting

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 8.1 | Login rate limit (5/min) | PASS | Implemented |
| 8.2 | Refresh token rate limit (10/min) | PASS | Implemented |
| 8.3 | Register rate limit (10/min) | PASS | Implemented |
| 8.4 | Logout rate limit (10/min) | PASS | Implemented |
| 8.5 | Global default (1000/min) | PASS | Implemented |
| 8.6 | Redis storage for multi-worker | NOT VERIFIED | Configurable via `RATE_LIMIT_STORAGE_URI` |

### 9. API Security

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 9.1 | Input validation | PASS | Pydantic schemas |
| 9.2 | Output encoding | PASS | JSON responses |
| 9.3 | File upload limits | PASS | 10 MiB at API boundary |
| 9.3 | SSRF protection | PASS | `ssrf_protection.py` |
| 9.4 | JWT algorithm validation | PASS | HS256 only |
| 9.5 | API key scoping | PASS | Role-based |

### 10. Data Protection

| Check | Requirement | Status | Details |
|-------|-------------|--------|---------|
| 10.1 | Password hashing (Argon2id) | PASS | `password.py` |
| 10.2 | Token hashing (SHA-256) | PASS | `token_service.py` |
| 10.3 | Capability tokens (SHA-256) | PASS | `token_service.py` |
| 10.4 | Data at rest (SQLite) | PARTIAL | File permissions |
| 10.5 | Data in transit (TLS) | NOT VERIFIED | Requires reverse proxy |

---

## Startup Validation

**Status:** IMPLEMENTED  
**Location:** `backend/app/main.py` → `settings.validate_production_config()`  
**Triggers on:** Application startup  
**Failure Mode:** Fast startup crash with clear error messages  

---

## Environment Variables Required for Production

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `APP_ENV` | YES | - | Must be `production` |
| `DEBUG` | YES | - | Must be `false` |
| `SECRET_KEY` | YES | - | ≥ 32 chars, from `secrets.token_urlsafe(32)` |
| `DATABASE_URL` | YES | - | PostgreSQL for production |
| `BACKEND_CORS_ORIGINS` | YES | - | HTTPS frontend domains only |
| `SECRET_KEY` | YES | - | ≥ 32 chars |
| `RATE_LIMIT_STORAGE_URI` | RECOMMENDED | - | Redis for multi-worker |
| `TRUSTED_PROXY_COUNT` | IF BEHIND PROXY | 0 | Count of trusted proxies |
| `OPENAI_API_KEY` | OPTIONAL | - | For AI features |

---

## Generation Command

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Never expose the generated value in reports or logs.**

---

## Summary

| Category | Total | PASS | FAIL | NOT VERIFIED | NOT IMPLEMENTED |
|----------|-------|------|------|--------------|-----------------|
| Core Settings | 3 | 1 | 1 | 1 | 0 |
| Security | 5 | 2 | 2 | 1 | 0 |
| CORS | 4 | 1 | 0 | 3 | 0 |
| Database | 3 | 0 | 0 | 3 | 0 |
| TLS/HTTPS | 4 | 1 | 0 | 3 | 0 |
| Security Headers | 5 | 0 | 0 | 0 | 5 |
| Logging/Monitoring | 4 | 0 | 0 | 2 | 2 |
| Rate Limiting | 6 | 5 | 0 | 1 | 0 |
| API Security | 5 | 5 | 0 | 0 | 0 |
| Data Protection | 5 | 3 | 0 | 2 | 0 |
| **Total** | **45** | **10** | **3** | **21** | **5** |

---

## Next Steps

1. **Immediate:** Create production `.env` with required variables
2. **Before Deploy:** Run `python -c "import secrets; print(secrets.token_urlsafe(32))"` for SECRET_KEY
3. **Before Deploy:** Set up PostgreSQL and configure `DATABASE_URL`
4. **Before Deploy:** Configure reverse proxy (nginx/Traefik) with TLS
5. **Before Deploy:** Set `RATE_LIMIT_STORAGE_URI=redis://...` for multi-worker
6. **Post-Deploy:** Verify all NOT VERIFIED items in staging
7. **Ongoing:** Quarterly config review