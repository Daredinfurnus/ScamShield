
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base

# Import models before router registration so SQLAlchemy
# can resolve all model relationships.
from app.models import (
    investigation,
    finding,
    entity,
    tenant,
    user,
)

# Import API routers
from app.api import (
    ai_routes,
    investigations,
    analysis,
    entities,
    reports,
    auth,
)

# Create missing tables for local development.
# Existing tables are NOT altered by create_all().
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication
app.include_router(auth.router, prefix="/api")

# Core API routes
app.include_router(
    investigations.router,
    prefix="/api/investigations",
)
app.include_router(
    analysis.router,
    prefix="/api/analysis",
)
app.include_router(
    entities.router,
    prefix="/api/investigations/{investigation_id}/entities",
)
app.include_router(
    reports.router,
    prefix="/api/investigations/{investigation_id}/report",
)
app.include_router(ai_routes.router, prefix="/api")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "env": settings.APP_ENV,
    }


@app.get("/")
def root():
    return {
        "message": "ScamShield API",
        "docs": "/docs",
    }
