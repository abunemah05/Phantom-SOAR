import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "Phantom SOAR"
    PROJECT_VERSION: str = "2.0.0"
    API_V1_STR: str = "/api"
    
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
    
    # Integrations API Keys (Optional - heuristics fallbacks provided)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_OTX_API_KEY: str = os.getenv("ALIENVAULT_OTX_API_KEY", "")
    THREATFOX_API_KEY: str = os.getenv("THREATFOX_API_KEY", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    JIRA_WEBHOOK_URL: str = os.getenv("JIRA_WEBHOOK_URL", "")
    
    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*"
    ]

    model_config = SettingsConfigDict(case_sensitive=True, extra="allow")

settings = Settings()

# Ensure reports directory exists
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
