from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
from app.api import investigations, analysis, entities, reports

# Import all model modules so SQLAlchemy can resolve inter-model
# string relationships (e.g. Investigation.findings -> Finding) before
# Base.metadata.create_all() configures the mappers.
from app.models import investigation, finding, entity  # noqa: F401

# Create all tables defined by SQLAlchemy models.
# In production this is managed by Alembic migrations; create_all is convenient
# for local SQLite development during the hackathon.
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(investigations.router, prefix="/api/investigations")
app.include_router(analysis.router, prefix="/api/analysis")
app.include_router(entities.router, prefix="/api/investigations/{investigation_id}/entities")
app.include_router(reports.router, prefix="/api/investigations/{investigation_id}/report")


@app.get("/health")
def health():
    """Health check endpoint for uptime monitoring and load balancers."""
    return {"status": "ok", "app": settings.APP_NAME, "env": settings.APP_ENV}


@app.get("/")
def root():
    return {"message": "ScamShield API", "docs": "/docs"}