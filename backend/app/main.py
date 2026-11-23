
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

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

# Rate limiter configuration
# Trust proxy headers only when explicitly configured
TRUSTED_PROXY_COUNT = int(settings.TRUSTED_PROXY_COUNT or 0)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000/minute"],
    storage_uri=settings.RATE_LIMIT_STORAGE_URI or "memory://",
    strategy="fixed-window",
    # Only trust X-Forwarded-For when explicitly configured
    # slowapi/limits uses trust_env for proxy header trust
    # We rely on limits library's built-in behavior
)

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
)

# Validate production configuration on startup
settings.validate_production_config()

# Add rate limit exceeded handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
