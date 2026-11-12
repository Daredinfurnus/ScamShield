from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets


class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    No API keys or secrets are hardcoded here. All values come from .env or
    the environment, which keeps secrets out of source control.
    """

    APP_NAME: str = "scamshield"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api"

    DATABASE_URL: str = "sqlite:///./scamshield.db"

    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30


    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
    ]

    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_TIMEOUT: float = 30.0
    OPENAI_MAX_TOKENS: int = 4096
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()