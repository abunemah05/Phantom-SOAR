import logging
import os
import threading
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

# Configure logging before backend modules load, so their import-time warnings
# (random JWT secret, ignored CORS wildcard, bootstrap password) are formatted.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

from backend.config import settings
from backend.database import engine, SessionLocal
from backend.db_migrate import prepare_database
from backend.routers import (
    webhooks_router, 
    alerts_router, 
    playbooks_router, 
    demo_router, 
    auth_router, 
    users_router,
    config_router,
    logs_router,
    reports_router,
    ingest_tokens_router,
    agent_router,
    ensure_default_user,
    ensure_default_configurations
)
from backend import integration_config, security
from backend.dependencies import get_current_user, require_ingest_token
from backend.models import Playbook
from backend.crud import create_playbook
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS

logger = logging.getLogger("phantom_soar")
_TRUE = {"1", "true", "yes", "on"}

def init_system_defaults():
    """Seed the administrator, the settings rows and the playbooks. Steps are independent: one failing never
    skips the others, and failing to create the administrator is fatal (nobody could sign in)."""
    db = SessionLocal()
    try:
        # 1. Bootstrap administrator (password from PHANTOM_BOOTSTRAP_ADMIN_PASSWORD, else a generated one-time file)
        try:
            ensure_default_user(db)
        except Exception:
            db.rollback()
            logger.exception("Could not create the bootstrap administrator")
            raise

        # 2. Integration settings rows (exactly the keys in integration_config.INTEGRATION_KEYS)
        try:
            ensure_default_configurations(db)
        except Exception:
            db.rollback()
            logger.exception("Could not seed the integration settings")

        # 3. Pre-configured SANS / MITRE IR playbooks
        try:
            if db.query(Playbook).count() == 0:
                logger.info(f"Initializing {len(PRECONFIGURED_PLAYBOOKS)} pre-configured SANS / MITRE IR playbooks...")
                for pb in PRECONFIGURED_PLAYBOOKS:
                    create_playbook(db, pb)
                logger.info("Playbooks initialized.")
        except Exception:
            db.rollback()
            logger.exception("Could not seed the playbooks")
    finally:
        db.close()

_bootstrap_lock = threading.Lock()
_bootstrapped = False


def bootstrap_database() -> None:
    """Migrate the schema and seed defaults, once per process (importing this module has no database side effects)."""
    global _bootstrapped
    with _bootstrap_lock:
        if _bootstrapped:
            return
        prepare_database(engine)  # Alembic upgrade; fast create_all when PHANTOM_ENV=test

        # Encrypt integration secrets and MFA seeds still stored in clear text (idempotent; a no-op without a key).
        try:
            from backend import crypto
            with SessionLocal() as db:
                crypto.encrypt_existing_secrets(db)
        except Exception as exc:
            logger.warning(f"Could not encrypt stored secrets at start-up: {exc}")

        init_system_defaults()
        _bootstrapped = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast on unsafe production configuration: weak JWT secret / missing encryption key
    # (raises SecurityConfigError in production, warns elsewhere).
    security.validate_security_config()
    bootstrap_database()
    # Contradictory production setup (simulation mode on next to real credentials) needs the settings table.
    errors = integration_config.production_safety_errors()
    if errors:
        raise RuntimeError("Refusing to start: " + "; ".join(errors))
    yield
    logger.info("Shutting down Phantom SOAR platform.")


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in _TRUE


def docs_enabled() -> bool:
    """/docs, /redoc and /openapi.json are served unless running in production.

    PHANTOM_ENABLE_DOCS=true turns them on in production; PHANTOM_ENABLE_DOCS=false turns them off elsewhere.
    """
    explicit = os.getenv("PHANTOM_ENABLE_DOCS", "").strip().lower()
    if explicit in _TRUE:
        return True
    if explicit in {"0", "false", "no", "off"}:
        return False
    return settings.PHANTOM_ENV.strip().lower() != "production"


_DOCS = docs_enabled()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Enterprise Security Orchestration, Automation, and Response Platform",
    lifespan=lifespan,
    docs_url="/docs" if _DOCS else None,
    redoc_url="/redoc" if _DOCS else None,
    openapi_url="/openapi.json" if _DOCS else None,
)

# CORS: explicit origins only (PHANTOM_CORS_ORIGINS). The console sends Bearer tokens, not cookies.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in settings.BACKEND_CORS_ORIGINS if "*" not in o],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if _truthy("PHANTOM_BEHIND_TLS"):
        # Only when a TLS-terminating proxy fronts the API; HSTS over plain HTTP is ignored by browsers.
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith(settings.API_V1_STR):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# Register API routers. Routers whose every route needs an operator session get the
# dependency at router level as well, so a route added without one is still protected.
# Auth, users, reports, configuration and logs declare their (stricter) dependencies per route.
_user_session = [Depends(get_current_user)]
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(users_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(config_router, prefix=settings.API_V1_STR)
app.include_router(webhooks_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_ingest_token)])
app.include_router(alerts_router, prefix=settings.API_V1_STR, dependencies=_user_session)
app.include_router(playbooks_router, prefix=settings.API_V1_STR, dependencies=_user_session)
app.include_router(demo_router, prefix=settings.API_V1_STR, dependencies=_user_session)
app.include_router(logs_router, prefix=settings.API_V1_STR)
app.include_router(ingest_tokens_router, prefix=settings.API_V1_STR)  # admin-only, per route
# AI triage: operator routes use the user session, agent routes use the service-account key (per route, not router level).
app.include_router(agent_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "status": "Operational",
        "docs_url": "/docs" if _DOCS else None
    }

@app.get("/api/health")
def health_check():
    """Unauthenticated liveness/readiness probe. Reveals no account or configuration details."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        database = "connected"
    except Exception as e:
        logger.warning(f"Health check: database unavailable ({e.__class__.__name__}).")
        database = "unavailable"
    body = {
        "status": "healthy" if database == "connected" else "degraded",
        "database": database,
        "architecture": "SANS PICERL / SOAPA",
        "version": settings.PROJECT_VERSION
    }
    return JSONResponse(body, status_code=200 if database == "connected" else 503)
