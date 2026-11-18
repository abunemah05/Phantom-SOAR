"""system_configs uniqueness, wider secret columns, timezone-aware datetimes

* system_configs: remove duplicate (category, key_name) rows (keep the most recently
  updated, highest config_id on a tie), then add a unique constraint.
* users.mfa_secret String(64) -> String(255); system_configs.key_value String(1000) -> Text
  (encrypted values are longer than plain ones).
* Postgres: every naive TIMESTAMP column becomes TIMESTAMP WITH TIME ZONE; existing values
  were written as UTC, so they are reinterpreted AT TIME ZONE 'UTC'. SQLite has a single
  DATETIME type, so nothing changes there (the UTCDateTime type reads values back as UTC).
* users.password_changed_at: rows added by the legacy shim could hold NULL; fill and make NOT NULL.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-18
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

UNIQUE_NAME = "uq_system_configs_category_key_name"

# (table, column) pairs that become timezone-aware.
DATETIME_COLUMNS = (
    ("users", "password_changed_at"), ("users", "locked_until"), ("users", "created_at"),
    ("system_configs", "updated_at"),
    ("alerts", "resolved_at"), ("alerts", "created_at"),
    ("ioc_artifacts", "created_at"),
    ("playbooks", "created_at"),
    ("playbook_executions", "executed_at"),
    ("containment_actions", "timestamp"),
    ("incident_reports", "generated_at"),
    ("analyst_action_logs", "timestamp"),
    ("system_logs", "created_at"),
    ("agent_proposals", "decided_at"), ("agent_proposals", "created_at"),
)


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _dedupe_system_configs() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT config_id, category, key_name, updated_at FROM system_configs")
    ).fetchall()
    keep: dict = {}
    for config_id, category, key_name, updated_at in rows:
        rank = (str(updated_at or ""), config_id)
        key = (category, key_name)
        if key not in keep or rank > keep[key][0]:
            keep[key] = (rank, config_id)
    keep_ids = {v[1] for v in keep.values()}
    for config_id, *_ in rows:
        if config_id not in keep_ids:
            bind.execute(sa.text("DELETE FROM system_configs WHERE config_id = :i"), {"i": config_id})


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())

    # users.password_changed_at NOT NULL (legacy shim added it as nullable)
    user_cols = {c["name"]: c for c in inspector.get_columns("users")}
    if user_cols["password_changed_at"]["nullable"]:
        op.execute(sa.text(
            "UPDATE users SET password_changed_at = COALESCE(created_at, CURRENT_TIMESTAMP) "
            "WHERE password_changed_at IS NULL"
        ))
    with op.batch_alter_table("users") as batch:
        batch.alter_column("mfa_secret", existing_type=sa.String(length=64),
                           type_=sa.String(length=255), existing_nullable=True)
        if user_cols["password_changed_at"]["nullable"]:
            batch.alter_column("password_changed_at", existing_type=sa.DateTime(), nullable=False)

    _dedupe_system_configs()
    with op.batch_alter_table("system_configs") as batch:
        batch.alter_column("key_value", existing_type=sa.String(length=1000),
                           type_=sa.Text(), existing_nullable=False)
        batch.create_unique_constraint(UNIQUE_NAME, ["category", "key_name"])

    if _is_postgres():
        for table, column in DATETIME_COLUMNS:
            op.alter_column(
                table, column,
                existing_type=sa.DateTime(),
                type_=sa.DateTime(timezone=True),
                postgresql_using=f"{column} AT TIME ZONE 'UTC'",
            )


def downgrade() -> None:
    if _is_postgres():
        for table, column in DATETIME_COLUMNS:
            op.alter_column(
                table, column,
                existing_type=sa.DateTime(timezone=True),
                type_=sa.DateTime(),
                postgresql_using=f"{column} AT TIME ZONE 'UTC'",
            )
    # Narrowing key_value / mfa_secret may truncate or fail if longer values were stored.
    with op.batch_alter_table("system_configs") as batch:
        batch.drop_constraint(UNIQUE_NAME, type_="unique")
        batch.alter_column("key_value", existing_type=sa.Text(),
                           type_=sa.String(length=1000), existing_nullable=False)
    with op.batch_alter_table("users") as batch:
        batch.alter_column("mfa_secret", existing_type=sa.String(length=255),
                           type_=sa.String(length=64), existing_nullable=True)
