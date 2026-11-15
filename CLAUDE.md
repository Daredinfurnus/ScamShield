# ScamShield — Project Reference & Guidelines

ScamShield is an AI-powered Digital Fraud Investigation and Intelligence Platform that investigates suspicious messages, URLs, and screenshots using machine learning, NLP, computer vision, generative AI, and multi-agent workflows.

---

## Architecture Overview

- **Backend Framework:** FastAPI (Python 3.12)
- **Database:** SQLite (`scamshield.db`) via SQLAlchemy 2.0 (PostgreSQL-compatible)
- **Authentication:** JWT (HS256) + Cookie + Scoped API Keys (`scam_live_...`) + Anonymous Capabilities (`scam_cap_...`) + Argon2id password hashing
- **Frontend Framework:** React 18 + Vite 5 + Tailwind CSS + React Router v6 + Zustand + React Flow + Recharts
- **Detection Architecture:** Single source of truth scoring engine (`RiskScorer`), category-specific regex/NLP detectors (`ScamDetector`), SSRF-protected URL inspection (`URLAnalyzer`), evidence extraction (`EvidenceService`), and optional OpenAI explanation orchestrator with deterministic fallback (`AIOrchestrator`).

---

## Repository Structure

```
scamshield/
├── backend/
│   ├── app/
│   │   ├── api/                  # FastAPI routers (auth, analysis, investigations, entities, reports, ai_routes, deps)
│   │   ├── models/               # SQLAlchemy ORM models (tenant, user, investigation, finding, entity)
│   │   ├── schemas/              # Pydantic request/response contracts (auth, analysis, investigation, finding, report)
│   │   ├── services/             # Core investigation pipeline & detectors
│   │   │   ├── ai/               # AI orchestrator, OpenAI provider, deterministic fallback
│   │   │   ├── security/         # Password (argon2id) and Token service (JWT/SHA-256)
│   │   │   ├── scam_detector.py  # Central 10-category deterministic scam detector
│   │   │   ├── risk_scoring.py   # Authoritative risk scorer (0-100 scale & band mapping)
│   │   │   ├── investigation_engine.py  # Central pipeline orchestrator
│   │   │   └── ssrf_protection.py       # Comprehensive SSRF URL protection
│   │   ├── config.py             # App configuration via pydantic-settings
│   │   ├── database.py           # SQLAlchemy engine & session factory
│   │   └── main.py               # FastAPI entrypoint & router registration
│   ├── reports/                  # Benchmark execution output & phase reports
│   └── tests/                    # Pytest suite & 50-case detection benchmark
├── docs/                         # Project documentation, state, and audit logs
│   ├── AGENT_HANDOFF.md
│   ├── PROJECT_STATE.md
│   └── SCAMSHIELD_AUDIT.md
└── frontend/
    ├── src/
    │   ├── api/                  # Axios HTTP client configuration
    │   ├── components/           # UI components (common, layout, risk, investigation, graph, ai)
    │   ├── hooks/                # React custom hooks
    │   ├── pages/                # Page components (Landing, Dashboard, NewInvestigation, etc.)
    │   ├── store/                # Zustand state management
    │   ├── App.jsx               # Root router provider
    │   ├── index.css             # Tailwind & Cyberpunk design system styles
    │   └── routes.jsx            # React Router table
    ├── package.json
    ├── tailwind.config.js
    └── vite.config.js
```

---

## Core Invariants & Engineering Rules

1. **Scoring Invariant:** Risk scores (0.0 to 100.0) are calculated strictly by `RiskScorer` in `backend/app/services/risk_scoring.py`. The LLM never invents or overrides risk scores.
2. **Evidence-Grounded Findings:** Every detection signal and finding must reference an actual evidence snippet extracted from the submitted input.
3. **Graceful Fallback:** If OpenAI API keys are missing or external APIs fail, `AIOrchestrator` must fall back cleanly to `DeterministicFallback` without crashing or returning fake AI output.
4. **Tenant & IDOR Security:** Cross-tenant access is strictly forbidden. Mismatched tenant access or missing capability tokens MUST return HTTP 404 (not 403 or 401) to prevent resource enumeration.
5. **Non-Destructive DB Safety:** Do not drop databases or lose existing tables. Schema updates must be migrated safely.

---

## Development & Test Commands

### Backend Commands

```bash
cd backend

# Install dependencies (requires argon2-cffi)
pip install -r requirements.txt
pip install argon2-cffi

# Run FastAPI development server
uvicorn app.main:app --reload --port 8000

# Run full backend pytest suite
python -m pytest tests/ -v

# Run 50-case detection benchmark
python tests/benchmark_detection.py
```

### Frontend Commands

```bash
cd frontend

# Install dependencies
npm install

# Run Vite dev server (proxies /api to localhost:8000)
npm run dev

# Production build check
npm run build
```

---

## Detection Benchmark Targets

The project maintains a 50-case synthetic benchmark suite (`backend/tests/fixtures/detection_benchmark.json`).
Current Verified Baseline (Phase 8D):
- **Accuracy:** 100.0% (50/50 cases)
- **Precision:** 100.0%
- **Recall:** 100.0%
- **False Positive Rate:** 0.0% (0 false alarms)
- **False Negative Rate:** 0.0% (0 missed scams)

---

## Key Model Relationships & Roles

- `Tenant`: Organizational boundary (`id`, `name`, `slug`, `status`).
- `User`: Member of a tenant (`id`, `tenant_id`, `email`, `hashed_password`, `role`). Roles: `admin` (3), `investigator` (2), `viewer` (1).
- `Investigation`: Primary case record (`id`, `tenant_id`, `created_by_user_id`, `title`, `input_type`, `input_content`, `risk_score`, `risk_band`, `status`, `is_anonymous`, `access_token_hash`, `access_token_expires_at`).
- `Finding`: Risk signal associated with an investigation (`id`, `investigation_id`, `finding_type`, `score`, `evidence_snippet`, `evidence_source`).
- `Entity`: Extracted IOC / indicator (`id`, `investigation_id`, `entity_type`, `value`, `normalized_value`).
