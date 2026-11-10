import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

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
from backend.models import Playbook
from backend.crud import create_playbook
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
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
                    conn.commit()

                # 3. Containment actions migrations
                ca_res = conn.execute(text("PRAGMA table_info(containment_actions)")).fetchall()
                ca_cols = [r[1] for r in ca_res]
                if ca_cols:
                    if "executed_by" not in ca_cols:
                        conn.execute(text("ALTER TABLE containment_actions ADD COLUMN executed_by VARCHAR(50) DEFAULT 'System'"))
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
        # 1. Ensure default credentials (abunemah / Admin1)
        ensure_default_user(db)

        # 2. Ensure default API key configurations
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

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(users_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(config_router, prefix=settings.API_V1_STR)
app.include_router(webhooks_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(playbooks_router, prefix=settings.API_V1_STR)
app.include_router(demo_router, prefix=settings.API_V1_STR)
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
    return {
        "status": "healthy",
        "database": "connected",
        "default_user": "abunemah",
        "architecture": "SANS PICERL / SOAPA",
        "version": settings.PROJECT_VERSION
    }
