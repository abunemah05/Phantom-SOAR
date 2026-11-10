import logging
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
from backend.database import engine, Base, SessionLocal
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
    ensure_default_user,
    ensure_default_configurations
)
from backend.dependencies import get_current_user, require_ingest_token
from backend.models import Playbook
from backend.crud import create_playbook
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS

logger = logging.getLogger("phantom_soar")

def ensure_sqlite_migrations():
    """Ensure newly introduced columns are dynamically added in SQLite."""
    try:
        with engine.connect() as conn:
            if "sqlite" in str(engine.url):
                # 1. Alerts table migrations
                res = conn.execute(text("PRAGMA table_info(alerts)")).fetchall()
                col_names = [r[1] for r in res]
                if col_names:
                    if "analyst_decision" not in col_names:
                        conn.execute(text("ALTER TABLE alerts ADD COLUMN analyst_decision VARCHAR(100)"))
                    if "assigned_analyst" not in col_names:
                        conn.execute(text("ALTER TABLE alerts ADD COLUMN assigned_analyst VARCHAR(50)"))
                    if "resolved_by" not in col_names:
                        conn.execute(text("ALTER TABLE alerts ADD COLUMN resolved_by VARCHAR(50)"))
                    if "resolved_at" not in col_names:
                        conn.execute(text("ALTER TABLE alerts ADD COLUMN resolved_at DATETIME"))
                    conn.commit()

                # 2. Users table migrations
                user_res = conn.execute(text("PRAGMA table_info(users)")).fetchall()
                user_cols = [r[1] for r in user_res]
                if user_cols:
                    if "must_change_password" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0"))
                    if "is_active" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1"))
                    if "mfa_enabled" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0"))
                    if "mfa_secret" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64)"))
                    if "password_changed_at" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN password_changed_at DATETIME"))
                    if "compromised_reset_required" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN compromised_reset_required BOOLEAN DEFAULT 0"))
                    if "failed_login_attempts" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"))
                    if "locked_until" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN locked_until DATETIME"))
                    if "is_service_account" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN is_service_account BOOLEAN DEFAULT 0"))
                    if "api_key_hash" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN api_key_hash VARCHAR(255)"))
                    if "api_key_prefix" not in user_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN api_key_prefix VARCHAR(16)"))
                    conn.commit()

                # IoC artifacts: per-provider TIP evidence
                ioc_res = conn.execute(text("PRAGMA table_info(ioc_artifacts)")).fetchall()
                ioc_cols = [r[1] for r in ioc_res]
                if ioc_cols:
                    if "verdict" not in ioc_cols:
                        conn.execute(text("ALTER TABLE ioc_artifacts ADD COLUMN verdict VARCHAR(20) DEFAULT 'Unknown'"))
                    if "enrichment_status" not in ioc_cols:
                        conn.execute(text("ALTER TABLE ioc_artifacts ADD COLUMN enrichment_status VARCHAR(30) DEFAULT 'pending'"))
                    if "tip_results" not in ioc_cols:
                        conn.execute(text("ALTER TABLE ioc_artifacts ADD COLUMN tip_results JSON"))
                    conn.commit()

                # 3. Containment actions migrations
                ca_res = conn.execute(text("PRAGMA table_info(containment_actions)")).fetchall()
                ca_cols = [r[1] for r in ca_res]
                if ca_cols:
                    if "executed_by" not in ca_cols:
                        conn.execute(text("ALTER TABLE containment_actions ADD COLUMN executed_by VARCHAR(50) DEFAULT 'System'"))
                    for col, ddl in (
                        ("target", "VARCHAR(255)"),
                        ("connector", "VARCHAR(50)"),
                        ("execution_mode", "VARCHAR(20)"),
                        ("details", "JSON"),
                    ):
                        if col not in ca_cols:
                            conn.execute(text(f"ALTER TABLE containment_actions ADD COLUMN {col} {ddl}"))
                    conn.commit()
    except Exception as e:
        logger.debug(f"SQLite migration check: {e}")

# Ensure database tables exist
Base.metadata.create_all(bind=engine)
ensure_sqlite_migrations()

def init_system_defaults():
    ensure_sqlite_migrations()
    db = SessionLocal()
    try:
        # 1. Bootstrap administrator (password from PHANTOM_BOOTSTRAP_ADMIN_PASSWORD)
        ensure_default_user(db)

        # 2. Integration settings rows (exactly the keys in integration_config.INTEGRATION_KEYS)
        ensure_default_configurations(db)

        # 3. Ensure 12 pre-configured SANS / MITRE IR Playbooks
        count = db.query(Playbook).count()
        if count == 0:
            logger.info("Initializing 12 pre-configured SANS / MITRE IR Playbooks...")
            for pb in PRECONFIGURED_PLAYBOOKS:
                create_playbook(db, pb)
            logger.info("Playbooks initialized.")
    except Exception as e:
        logger.warning(f"Error during system bootstrap: {e}")
    finally:
        db.close()

# Auto-seed on startup
init_system_defaults()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    init_system_defaults()
    yield
    logger.info("Shutting down Phantom SOAR platform.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Enterprise Security Orchestration, Automation, and Response Platform",
    lifespan=lifespan
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

@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "status": "Operational",
        "docs_url": "/docs"
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
