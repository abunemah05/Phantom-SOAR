"""Single source of truth for integration and orchestration settings.

Values saved from the Configuration page (SystemConfig rows) win; environment
variables are the fallback so Docker / CI deployments work without the UI.
An empty value in the database counts as "not set" and falls through to the
environment, then to DEFAULTS.
"""
import logging
import os
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import SystemConfig

logger = logging.getLogger(__name__)

# key_name -> (SystemConfig category, environment variable)
INTEGRATION_KEYS: Dict[str, Tuple[str, str]] = {
    # Threat intelligence
    "virustotal_api_key": ("TIP", "VIRUSTOTAL_API_KEY"),
    "abuseipdb_api_key": ("TIP", "ABUSEIPDB_API_KEY"),
    "otx_api_key": ("TIP", "ALIENVAULT_OTX_API_KEY"),
    "threatfox_api_key": ("TIP", "THREATFOX_API_KEY"),
    "nvd_api_key": ("TIP", "NVD_API_KEY"),
    # Wazuh manager API (used for ingestion context and active response)
    "siem_manager_url": ("SIEM", "WAZUH_API_URL"),
    "siem_user": ("SIEM", "WAZUH_API_USER"),
    "siem_password": ("SIEM", "WAZUH_API_PASSWORD"),
    "siem_verify_tls": ("SIEM", "WAZUH_VERIFY_TLS"),
    # Identity provider
    "okta_domain": ("IAM", "OKTA_DOMAIN"),
    "okta_api_token": ("IAM", "OKTA_API_TOKEN"),
    # ITSM / notifications
    "jira_base_url": ("ITSM", "JIRA_BASE_URL"),
    "jira_email": ("ITSM", "JIRA_EMAIL"),
    "jira_api_token": ("ITSM", "JIRA_API_TOKEN"),
    "jira_project_key": ("ITSM", "JIRA_PROJECT_KEY"),
    "jira_webhook_url": ("ITSM", "JIRA_WEBHOOK_URL"),
    "slack_webhook_url": ("ITSM", "SLACK_WEBHOOK_URL"),
    # Orchestration guardrails
    "hotl_enabled": ("ORCHESTRATION", "PHANTOM_HOTL_ENABLED"),
    "simulation_mode": ("ORCHESTRATION", "PHANTOM_SIMULATION_MODE"),
    "protected_hosts": ("ORCHESTRATION", "PHANTOM_PROTECTED_HOSTS"),
    "protected_users": ("ORCHESTRATION", "PHANTOM_PROTECTED_USERS"),
    "protected_ips": ("ORCHESTRATION", "PHANTOM_PROTECTED_IPS"),
    # AI agent guardrails
    "agent_min_confidence": ("AGENT", "PHANTOM_AGENT_MIN_CONFIDENCE"),
    "agent_autonomy": ("AGENT", "PHANTOM_AGENT_AUTONOMY"),  # recommend_only | low_impact | policy
}

DEFAULTS: Dict[str, str] = {
    "hotl_enabled": "true",
    "simulation_mode": "true",
    "siem_verify_tls": "true",
    "agent_min_confidence": "0.85",
    "agent_autonomy": "recommend_only",
}

_TRUE = {"1", "true", "yes", "on"}


def _read_db_value(db: Session, category: str, key_name: str) -> Optional[str]:
    row = (
        db.query(SystemConfig)
        .filter(SystemConfig.category == category, SystemConfig.key_name == key_name)
        .first()
    )
    return row.key_value if row else None


def get_setting(key_name: str, db: Optional[Session] = None, default: Optional[str] = None) -> str:
    """Resolve a setting: database value, then environment variable, then default."""
    category, env_var = INTEGRATION_KEYS.get(key_name, ("", key_name.upper()))

    value: Optional[str] = None
    if category:
        own_session = db is None
        session = SessionLocal() if own_session else db
        try:
            value = _read_db_value(session, category, key_name)
        except Exception as e:  # table missing during bootstrap, DB unavailable, ...
            logger.debug(f"Config lookup for {key_name} failed: {e}")
        finally:
            if own_session:
                session.close()

    if value is None or str(value).strip() == "":
        value = os.getenv(env_var, "")
    if str(value).strip() == "":
        value = default if default is not None else DEFAULTS.get(key_name, "")
    return str(value).strip()


def get_bool(key_name: str, db: Optional[Session] = None) -> bool:
    return get_setting(key_name, db=db).lower() in _TRUE


def get_list(key_name: str, db: Optional[Session] = None) -> List[str]:
    """Comma- or newline-separated setting as a list of non-empty, stripped items."""
    raw = get_setting(key_name, db=db).replace("\n", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def is_configured(*key_names: str, db: Optional[Session] = None) -> bool:
    """True when every named setting has a non-empty value."""
    return all(get_setting(k, db=db) for k in key_names)


def is_simulation_mode(db: Optional[Session] = None) -> bool:
    """Simulation mode lets unconfigured connectors record clearly-labelled simulated actions."""
    return get_bool("simulation_mode", db=db)
