# DEPENDENCY_AUDIT.md

## Dependency Audit Report

**Audit Date:** 2026-11-22  
**Python Version:** 3.12.10  
**pip Version:** 25.0.1  
**pip-audit Version:** 2.10.1  
**Scan Date:** 2026-11-22  
**Audit Tool:** pip-audit 2.10.1  
**Dependencies Scanned:** 85 packages  
**Environment:** Windows 11, Python 3.12.10  

---

## Findings Summary

**Total Vulnerabilities Found:** 50  
**Affected Packages:** 8  
**Fixable Vulnerabilities:** Most (fix versions available)  
**Unfixable Vulnerabilities:** ecdsa, transformers (partial), sentence-transformers (partial)

---

## Vulnerability Findings

### 1. python-dotenv (1.0.1)
- **Vulnerabilities:** 2 (PYSEC-2026-2270 - duplicate)
- **Fixed in:** 1.2.2
- **Severity:** Not specified
- **Action:** Upgrade to 1.2.2+

### 2. python-multipart (0.0.9)
- **Vulnerabilities:** 12 (PYSEC-2026-1851, PYSEC-2026-1852, PYSEC-2026-3036-3040)
- **Fixed in:** 0.0.31+
- **Severity:** Multiple - DoS and ReDoS vulnerabilities
- **Action:** Upgrade to 0.0.31+ (CRITICAL - affects file upload)

### 3. sentence-transformers (2.7.0)
- **Vulnerabilities:** 1 (PYSEC-2026-4164)
- **Fixed in:** 5.6.0
- **Severity:** Not specified
- **Action:** Upgrade to 5.6.0+ (MAJOR VERSION - breaking changes likely)

### 4. pytest (8.2.0)
- **Vulnerabilities:** 2 (PYSEC-2026-1845 - duplicate)
- **Fixed in:** 9.0.3
- **Severity:** Not specified
- **Action:** Upgrade to 9.0.3+ (MAJOR VERSION - breaking changes)

### 5. python-jose (3.3.0)
- **Vulnerabilities:** 6 (PYSEC-2024-232, PYSEC-2024-233, PYSEC-2025-185, PYSEC-2026-4298)
- **Fixed in:** 3.4.0+
- **Severity:** JWT algorithm confusion vulnerabilities
- **Action:** Upgrade to 3.4.0+ (CRITICAL - affects JWT auth)

### 6. starlette (0.38.6)
- **Vulnerabilities:** 10 (PYSEC-2026-161, PYSEC-2026-1941, PYSEC-2026-1943, PYSEC-2026-2280, PYSEC-2026-2281, PYSEC-2026-2281, PYSEC-2026-248, PYSEC-2026-249, PYSEC-2026-248, PYSEC-2026-249)
- **Fixed in:** 0.40.0+ (0.47.2, 1.0.1, 1.1.0, 1.3.1)
- **Severity:** Multiple - DoS, header injection, etc.
- **Action:** Upgrade to latest 0.47.x or 1.x (part of FastAPI)

### 7. transformers (4.57.6)
- **Vulnerabilities:** 7 (PYSEC-2025-217, PYSEC-2026-2288-2290, PYSEC-2026-3929, PYSEC-2026-4174)
- **Fixed in:** 5.0.0+ (partial)
- **Severity:** Model loading/arbitrary code execution
- **Action:** Upgrade if possible (MAJOR VERSION - breaking changes)

### 8. ecdsa (0.19.2)
- **Vulnerabilities:** 2 (PYSEC-2026-1325 - duplicate)
- **Fixed in:** None available
- **Severity:** Timing attacks on ECDSA
- **Action:** No fix available. Consider monitoring.

---

## Remediation Plan

### Immediate (Critical - Security Patches)

| Package | Current | Target | Risk | Action |
|---------|---------|--------|------|--------|
| python-multipart | 0.0.9 | 0.0.31+ | HIGH - DoS in file upload | Upgrade |
| python-jose | 3.3.0 | 3.4.0+ | HIGH - JWT vulnerabilities | Upgrade |
| starlette | 0.38.6 | 0.47.2+ | HIGH - DoS, header injection | Upgrade (via FastAPI) |
| python-dotenv | 1.0.1 | 1.2.2+ | MEDIUM | Upgrade |

### Major Version Upgrades (Breaking - Require Testing)

| Package | Current | Target | Risk | Action |
|---------|---------|--------|------|--------|
| pytest | 8.2.0 | 9.0.3+ | MEDIUM - test suite | Upgrade & test |
| sentence-transformers | 2.7.0 | 5.6.0+ | HIGH - ML models | Evaluate compatibility |
| transformers | 4.57.6 | 5.x | HIGH - ML models | Evaluate compatibility |

### Unfixable / Monitoring

| Package | Current | Status | Action |
|---------|---------|--------|--------|
| ecdsa | 0.19.2 | No fix | Monitor, consider alternative |
| transformers | 4.57.6 | Partial fix | Upgrade when compatible |
| sentence-transformers | 2.7.0 | Partial fix | Upgrade when compatible |

---

## Affected Dependency Paths

```
python-multipart -> fastapi -> uvicorn[standard]
python-jose -> python-jose[cryptography] -> auth
starlette -> fastapi -> uvicorn[standard]
sentence-transformers -> torch -> easyocr -> investigation_engine
transformers -> sentence-transformers
ecdsa -> python-jose[cryptography]
pytest -> test suite
python-dotenv -> pydantic-settings -> config
```

---

## Post-Upgrade Testing Required

After upgrading critical packages:

1. [ ] Run all 125 backend tests
2. [ ] Run detection benchmark (50/50 target)
3. [ ] Test file upload (multipart)
3. [ ] Test JWT authentication flow
3. [ ] Test CORS and rate limiting
3. [ ] Run frontend build and Playwright tests
4. [ ] Run detection benchmark (target 100% accuracy)

---

## Remaining Vulnerabilities (After Critical Upgrades)

| Package | Remaining Vulns | Severity | Status |
|---------|----------------|----------|--------|
| ecdsa | 2 | MEDIUM | NO FIX |
| transformers | Partial | HIGH | MONITOR |
| sentence-transformers | Partial | MEDIUM | DEFERRED |
| transformers (additional) | Multiple | HIGH | DEFERRED |

---

## Audit Limitations

- **Database Access:** pip-audit may not have accessed all vulnerability databases
- **Transitive Dependencies:** Some findings may be in transitive deps
- **False Positives:** Some vulnerabilities may not be exploitable in our context
- **ML Dependencies:** transformers/sentence-transformers have architecture-specific concerns

---

## Recommendations

1. **Immediate:** Upgrade python-multipart, python-jose, starlette, python-dotenv
2. **Deferred:** Evaluate ML dependency upgrades in separate branch
3. **Monitor:** ecdsa - check for updates monthly
4. **Document:** Add to security review process for quarterly audits

---

## Final Audit Status (After Upgrades)

| Package | Original Version | Target Version | Status |
|---------|------------------|----------------|--------|
| python-multipart | 0.0.9 | 0.0.31+ | PENDING UPGRADE |
| python-jose | 3.3.0 | 3.4.0+ | PENDING UPGRADE |
| starlette | 0.38.6 | 0.47.2+ | PENDING UPGRADE |
| python-dotenv | 1.0.1 | 1.2.2+ | PENDING UPGRADE |
| pytest | 8.2.0 | 9.0.3+ | DEFERRED |
| sentence-transformers | 2.7.0 | 5.6.0+ | DEFERRED |
| transformers | 4.57.6 | 5.x | DEFERRED |
| ecdsa | 0.19.2 | N/A | NO FIX AVAILABLE |

**Summary:** 4 critical packages need immediate upgrade. 3 packages have major version upgrades requiring testing. 1 package has no available fix.