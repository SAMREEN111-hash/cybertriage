from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "CyberTriage API"
    VERSION: str = "2.0.0"
    DEBUG: bool = True

    # Database — uses SQLite locally, swap to PostgreSQL via env var
    DATABASE_URL: str = "sqlite+aiosqlite:///./cybertriage.db"

    # JWT Auth
    SECRET_KEY: str = "changeme-use-a-real-secret-in-production-32chars+"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # AbuseIPDB (optional — works without it, just skips enrichment)
    ABUSEIPDB_API_KEY: Optional[str] = None

    class Config:
        env_file = ".env"


settings = Settings()
