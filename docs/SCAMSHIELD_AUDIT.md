# ScamShield Technical Audit & Vulnerability Assessment

**Audit Date:** 2026-11-14  
**Auditor:** Primary Engineering Agent (Opus 5.5)  
**Target Repository:** `C:\Users\froze\Desktop\scamshield`  
**Git Branch:** `feature/ai-investigation-assistant`  

---

## 1. Executive Summary

A comprehensive code, security, and runtime audit of ScamShield was conducted across the backend (FastAPI, Python 3.12, SQLAlchemy, SQLite), frontend (React, Vite, Tailwind CSS), database schema, test suites, and git history.

### Key Audit Findings

1. **Detection Engine Quality:** Exceptional. The deterministic scam detector and `RiskScorer` achieve 100.0% accuracy, 100.0% precision, 100.0% recall, 0.0% false positive rate, and 0.0% false negative rate across the 50-case benchmark suite.
2. **Dashboard 401 Unauthorized Root Cause Identified & RESOLVED:**
   - Missing `argon2-cffi` package in Python environment caused `ImportError` on backend startup when importing `app.api.auth`. **FIXED:** `argon2-cffi==25.1.0` added to `backend/requirements.txt`.
   - SQLite database `scamshield.db` schema was out-of-sync with ORM models (missing 5 columns on `investigations` table). **FIXED:** Safe `ALTER TABLE` migration applied (backup: `scamshield.db.bak.20261114-130619`).
   - Frontend Axios client lacked JWT authentication state management and token header injection. **FIXED:** Zustand auth store, Axios interceptors, and login/register modal implemented.
3. **Database Migration Gap:** No active Alembic migration environment exists on disk. Database table creation relies on `Base.metadata.create_all()`, which does not modify existing SQLite tables. **NEXT PRIORITY.**
4. **Security Architecture:** Solid architecture with Argon2id password hashing, rotating refresh tokens with family-based replay detection, SHA-256 capability tokens for anonymous investigations, and strict SSRF protection for URL analysis.

---

## 2. Authentication & 401 Blocker Deep Dive (RESOLVED)

### Problem Statement
The frontend Dashboard page previously failed to load investigation data, returning `401 Unauthorized — Authentication required`.

### Root Cause Analysis (All Resolved)

1. **Dependency Deficit (`argon2-cffi`):** ✅ **FIXED**
   - File: `backend/app/services/security/password.py` imports `from argon2 import PasswordHasher`.
   - `argon2-cffi` was missing from `backend/requirements.txt` and the virtual environment.
   - Importing `backend/app/api/auth.py` triggered a runtime `ModuleNotFoundError`.
   - **Resolution:** Added `argon2-cffi==25.1.0` to `backend/requirements.txt`.

2. **Database Schema Out-of-Sync:** ✅ **FIXED**
   - File: `backend/app/models/investigation.py` defines 5 multi-tenant auth columns.
   - SQLite table `investigations` in `scamshield.db` was created prior to Phase 9.1 and lacked these columns.
   - Any query attempting to load `Investigation` ORM models failed with SQLite `OperationalError: table investigations has no column named tenant_id`.
   - **Resolution:** Executed safe `ALTER TABLE` migration adding all 5 columns. Backup preserved.

3. **Frontend Token Injection Gap:** ✅ **FIXED**
   - File: `frontend/src/api/index.js` created a static Axios instance without interceptors.
   - File: `frontend/src/pages/Dashboard.jsx` made direct requests to `/api/investigations/`, which requires authentication via `get_current_user`.
   - **Resolution:** 
     - Created `frontend/src/store/authStore.js` (Zustand + persist middleware).
     - Updated `frontend/src/api/index.js` with request/response interceptors (Bearer header, cookie support, 401 → clear auth).
     - Added `frontend/src/components/auth/AuthModal.jsx` (login/register modal).
     - Integrated into `Navbar.jsx` and `Dashboard.jsx`.

---

## 3. Comprehensive Codebase Audit

### Backend Architecture (`backend/app`)

- **Routing (`main.py`):** Correctly registers `auth`, `investigations`, `analysis`, `entities`, `reports`, and `ai_routes` under `/api`.
- **Scam Detection (`scam_detector.py`):** 10 categories implemented:
  - Phishing & Credential Theft
  - Fake Recruitment
  - UPI / Payment Fraud
  - OTP Scams
  - Impersonation
  - Investment Fraud
  - Lottery / Prize Scams
  - Advance-Fee Fraud
  - Urgency & Intimidation
  - Delivery & Customs Fraud
- **Risk Scoring (`risk_scoring.py`):** Operates on weighted signal inputs. Returns 0-100 risk score and band (`low` <25, `medium` 25-49, `high` 50-74, `critical` >=75).
- **SSRF Protection (`ssrf_protection.py`):** Excellent defensive design. Validates target schemes (HTTP/HTTPS only), resolves DNS IPs before connecting, blocks loopback (`127.0.0.1`, `::1`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and cloud metadata IP (`169.254.169.254`). Re-validates redirects at every hop.

### Frontend Architecture (`frontend/src`)

- **Design System:** Dark cyberpunk aesthetic featuring custom Tailwind color palette (`noir`, `brand`, `risk`), custom fonts (`Barlow Condensed`, `IBM Plex Mono`, `Inter`), and custom glow shadows.
- **Component Layout:** Clean separation into `components/layout/` (`Layout`, `Navbar`, `Sidebar`, `Footer`), `components/investigation/`, `components/risk/`, and `components/ai/`.
- **Visualization:** `EntityGraph.jsx` uses `React Flow` for node-edge relationships; `Dashboard.jsx` uses `Recharts` for risk breakdown trends.
- **Auth Integration (NEW):** Zustand store, Axios interceptors, and login/register modal in Navbar & Dashboard.

---

## 4. Security Assessment

### Confirmed Vulnerabilities & Deficits

1. **Lack of Alembic Database Migration Pipeline (Medium Risk):**
   - **File:** `backend/app/main.py:30` relies on `Base.metadata.create_all(bind=engine)`.
   - **Risk:** `create_all()` is non-destructive and skips existing tables, leaving production/local databases out of sync when model schemas change.
   - **Status:** **OPEN — Next Priority**

2. **Frontend Cookie SameSite Configuration (Low Risk / Dev):**
   - **File:** `backend/app/api/auth.py:83` sets `secure=False` for authentication cookies.
   - **Recommendation:** Conditionally set `secure=True` when `APP_ENV != "development"`.

3. **Incomplete Image / OCR Intake Validation (Low Risk):**
   - **File:** `backend/app/api/analysis.py:121` accepts `AnalyzeImageRequest` without binary payload validation. `analyze_image` returns status `incomplete`.

### Verified Defensive Strengths

- **Password Hashing:** Argon2id with random salt via `argon2-cffi`.
- **JWT Signing:** HS256 algorithm with 15-minute expiration and 128-bit random `jti` claim.
- **Refresh Token Rotation:** Family-based token tracking. Detects replay attacks and revokes the entire token family upon reuse attempt.
- **Tenant Isolation:** Multi-tenant checks enforced in `get_investigation_with_access`. Unauthorized access returns HTTP 404 to prevent IDOR enumeration.
- **SSRF Defense:** Full IPv4/IPv6 private range blacklisting with pre-connect DNS pinning.

---

## 5. Empirical Test & Benchmark Results (POST-FIX VERIFICATION)

### 1. Pytest Backend Suite (`python -m pytest tests/`)
- **Total Tests:** 76
- **Passed:** 76 (100%)
- **Failed:** 0
- **Date:** 2026-11-14 (after schema migration + test contract fixes)

### 2. 50-Case Detection Benchmark (`python tests/benchmark_detection.py`)
- **Accuracy:** 100.0% (50/50 cases passed)
- **Precision:** 1.000
- **Recall:** 1.000
- **F1 Score:** 1.000
- **False Positive Rate:** 0.0%
- **False Negative Rate:** 0.0%

### 3. Frontend Production Build (`npm run build`)
- **Vite 5.4.21:** Built cleanly in 18.54s.
- **Output:** 2278 modules transformed, 0 syntax or JSX errors.
- **JS Bundle:** ~862 kB (gzipped: ~259 kB) — chunk size warning non-fatal.

---

## 6. Top 5 Priority Engineering Tasks (UPDATED)

1. **Initialize Alembic Migrations:**
   - Generate initial Alembic migration script covering all current models (`User`, `Tenant`, `Investigation`, `Finding`, `Entity`, `RefreshToken`, `ApiKey`).
   - Configure Alembic to use the existing `scamshield.db` as the baseline.

2. **Frontend Cookie SameSite Configuration:**
   - Update `backend/app/api/auth.py` to conditionally set `secure=True` on cookies when `APP_ENV != "development"`.

3. **Complete Image & OCR Pipeline (Phase 6):**
   - Connect `OCRProcessor` in `backend/app/services/ocr.py` to `AnalyzeImageRequest` endpoint and integrate extracted OCR text into `ScamDetector`.

4. **Frontend Auth Polish:**
   - Add profile dropdown, token refresh UX, and "claim investigation" flow for anonymous submissions.

5. **Enforce Test Suite Hygiene:**
   - Maintain 76/76 passing backend tests through future changes.
   - Add CI pipeline (GitHub Actions) to run pytest + benchmark on every PR.

---

## 7. Fix Verification Commands

```bash
# Backend
cd backend
python -m pytest tests/ -q                    # → 76 passed
python tests/benchmark_detection.py           # → 100% accuracy

# Frontend
cd ../frontend
npm run build                                 # → clean build

# Schema verification
sqlite3 scamshield.db "PRAGMA table_info(investigations);"
# Shows all 14 columns including tenant_id, created_by_user_id, is_anonymous, access_token_hash, access_token_expires_at
```