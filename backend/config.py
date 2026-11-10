import logging
import os
from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_CORS_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"


def parse_cors_origins(raw: str) -> List[str]:
    """Comma/newline separated origins. A wildcard is never accepted."""
    origins: List[str] = []
    for item in (raw or "").replace("\n", ",").split(","):
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        if "*" in origin:
            logger.warning(f"Ignoring CORS origin {origin!r}: wildcard origins are not allowed.")
            continue
        if origin not in origins:
            origins.append(origin)
    return origins


class Settings(BaseSettings):
    PROJECT_NAME: str = "Phantom SOAR"
    PROJECT_VERSION: str = "2.0.0"
    API_V1_STR: str = "/api"
    PHANTOM_ENV: str = os.getenv("PHANTOM_ENV", "development")

    # Database: SQLite default for local run, Postgres when DATABASE_URL is set in Docker
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR.parent / 'phantom_soar.db'}"
    )

    # Redis & Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

    # Reports directory
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", str(BASE_DIR / "reports"))

    # Deprecated: integrations read credentials through backend.integration_config
    # (Configuration page value, then these environment variables).
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_OTX_API_KEY: str = os.getenv("ALIENVAULT_OTX_API_KEY", "")
    THREATFOX_API_KEY: str = os.getenv("THREATFOX_API_KEY", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    JIRA_WEBHOOK_URL: str = os.getenv("JIRA_WEBHOOK_URL", "")

    # CORS: explicit origins from PHANTOM_CORS_ORIGINS, never "*"
    BACKEND_CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: parse_cors_origins(os.getenv("PHANTOM_CORS_ORIGINS", DEFAULT_CORS_ORIGINS))
    )

    model_config = SettingsConfigDict(case_sensitive=True, extra="allow")

settings = Settings()

# Ensure reports directory exists
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
