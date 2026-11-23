from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets
import re


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

    # Rate limiting
    RATE_LIMIT_LOGIN_ATTEMPTS: int = 5
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 60
    RATE_LIMIT_STORAGE_URI: Optional[str] = None  # e.g., redis://localhost:6379/0
    TRUSTED_PROXY_COUNT: int = 0  # Set to number of trusted proxies when behind reverse proxy

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

    def validate_production_config(self) -> None:
        """Validate production configuration safety.

        Raises:
            ValueError: If production configuration is unsafe.
        """
        if self.APP_ENV.lower() in ("production", "prod"):
            errors = []

            # 1. DEBUG must be False
            if self.DEBUG:
                errors.append("DEBUG must be False in production")

            # 2. SECRET_KEY must be explicitly provided (not generated)
            # Check if SECRET_KEY is the default generated value
            # We can't easily detect if it's the default, but we can check length
            if len(self.SECRET_KEY) < 32:
                errors.append("SECRET_KEY must be at least 32 characters (256 bits) in production")

            # 3. Production CORS must not contain wildcards with credentials
            if self.BACKEND_CORS_ORIGINS:
                for origin in self.BACKEND_CORS_ORIGINS:
                    if origin == "*" or origin.endswith("*"):
                        errors.append(f"CORS origin '{origin}' must not use wildcard when credentials are enabled")

            # 4. Production CORS must use HTTPS
            for origin in self.BACKEND_CORS_ORIGINS:
                if origin.startswith("http://") and not origin.startswith("http://localhost") and not origin.startswith("http://127.0.0.1"):
                    errors.append(f"CORS origin '{origin}' must use HTTPS in production")

            # 5. SECRET_KEY must not be the default placeholder
            if self.SECRET_KEY == "change-me-in-production" or self.SECRET_KEY == "changeme":
                errors.append("SECRET_KEY must not use placeholder value")

            if errors:
                raise ValueError(
                    "Production configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
                )


settings = Settings()