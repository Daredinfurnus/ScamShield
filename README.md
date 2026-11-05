# ScamShield

"Don't Just Detect Scams. Investigate Them."

An AI-powered Digital Fraud Investigation and Intelligence Platform that investigates suspicious messages, URLs, and screenshots using machine learning, NLP, computer vision, generative AI, and AI agent workflows.

## Stack

- **Backend:** FastAPI, Python 3.12, SQLAlchemy, SQLite (Postgres-migratable via Alembic), scikit-learn, Sentence Transformers, EasyOCR, NetworkX, OpenAI
- **Frontend:** React, Vite, Tailwind CSS, React Router, Axios, Recharts, React Flow

## Folder Structure

```
scamshield/
├── backend/                 # FastAPI application
└── frontend/                # React + Vite application
```

## Getting Started

### Backend

```bash
cd backend
cp .env.example .env
# edit .env with your API keys (OpenAI, Safe Browsing, etc.)
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API docs are available at `http://localhost:8000/docs`.

### Frontend

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

The app runs at `http://localhost:5173` and proxies `/api` to the backend.

## Development Phases

1. Repository setup & architecture (current)
2. Backend foundation & database
3. Frontend foundation & design system
4. Text analysis & risk scoring
5. URL intelligence
6. Screenshot & OCR analysis
7. AI investigation workflow
8. Entity relationship graph
9. Dashboard, reports & history
10. Integration, testing & deployment

## Core Principles

- Risk scores are calculated by the backend scoring engine — never invented by the LLM.
- Every AI finding references actual evidence.
- No hardcoded API keys; all configuration via environment variables.
- Unavailable external services return clearly labelled fallbacks — never fake AI.