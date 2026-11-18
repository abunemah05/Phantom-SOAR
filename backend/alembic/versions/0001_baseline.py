"""baseline schema (pre-Alembic models)

Revision ID: 0001
Revises: 
Create Date: 2026-11-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Baseline = the schema as it was before Alembic was introduced (naive DateTime columns,
    # no system_configs uniqueness). Databases created by the old create_all() already have
    # these tables, so each one is created only when missing; backend.db_migrate adds the
    # columns the old SQLite ALTER shim used to add before this revision runs on such a database.
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'alerts' not in existing:
        op.create_table('alerts',
        sa.Column('alert_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('raw_payload', sa.JSON(), nullable=True),
        sa.Column('analyst_decision', sa.String(length=100), nullable=True),
        sa.Column('assigned_analyst', sa.String(length=50), nullable=True),
        sa.Column('resolved_by', sa.String(length=50), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('alert_id')
        )
        with op.batch_alter_table('alerts', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_alerts_alert_id'), ['alert_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_alerts_assigned_analyst'), ['assigned_analyst'], unique=False)
            batch_op.create_index(batch_op.f('ix_alerts_resolved_by'), ['resolved_by'], unique=False)
            batch_op.create_index(batch_op.f('ix_alerts_rule_id'), ['rule_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_alerts_severity'), ['severity'], unique=False)
            batch_op.create_index(batch_op.f('ix_alerts_status'), ['status'], unique=False)

    if 'playbooks' not in existing:
        op.create_table('playbooks',
        sa.Column('playbook_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=150), nullable=False),
        sa.Column('target_threat', sa.String(length=100), nullable=False),
        sa.Column('execution_mode', sa.String(length=20), nullable=False),
        sa.Column('workflow_logic', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('playbook_id')
        )
        with op.batch_alter_table('playbooks', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_playbooks_name'), ['name'], unique=False)
            batch_op.create_index(batch_op.f('ix_playbooks_playbook_id'), ['playbook_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_playbooks_target_threat'), ['target_threat'], unique=False)

    if 'system_configs' not in existing:
        op.create_table('system_configs',
        sa.Column('config_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('key_name', sa.String(length=100), nullable=False),
        sa.Column('key_value', sa.String(length=1000), nullable=False),
        sa.Column('is_secret', sa.Boolean(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('config_id')
        )
        with op.batch_alter_table('system_configs', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_system_configs_category'), ['category'], unique=False)
            batch_op.create_index(batch_op.f('ix_system_configs_config_id'), ['config_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_system_configs_key_name'), ['key_name'], unique=False)

    if 'system_logs' not in existing:
        op.create_table('system_logs',
        sa.Column('log_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('level', sa.String(length=20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('target', sa.String(length=200), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('log_id')
        )
        with op.batch_alter_table('system_logs', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_system_logs_created_at'), ['created_at'], unique=False)
            batch_op.create_index(batch_op.f('ix_system_logs_level'), ['level'], unique=False)
            batch_op.create_index(batch_op.f('ix_system_logs_log_id'), ['log_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_system_logs_source'), ['source'], unique=False)

    if 'users' not in existing:
        op.create_table('users',
        sa.Column('user_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('must_change_password', sa.Boolean(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
        sa.Column('mfa_secret', sa.String(length=64), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(), nullable=False),
        sa.Column('compromised_reset_required', sa.Boolean(), nullable=False),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.DateTime(), nullable=True),
        sa.Column('is_service_account', sa.Boolean(), nullable=False),
        sa.Column('api_key_hash', sa.String(length=255), nullable=True),
        sa.Column('api_key_prefix', sa.String(length=16), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('user_id')
        )
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_users_api_key_prefix'), ['api_key_prefix'], unique=False)
            batch_op.create_index(batch_op.f('ix_users_user_id'), ['user_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_users_username'), ['username'], unique=True)

    if 'agent_proposals' not in existing:
        op.create_table('agent_proposals',
        sa.Column('proposal_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('agent_name', sa.String(length=100), nullable=False),
        sa.Column('verdict', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('reasoning', sa.Text(), nullable=True),
        sa.Column('proposed_actions', sa.JSON(), nullable=True),
        sa.Column('policy_evaluation', sa.JSON(), nullable=True),
        sa.Column('execution_results', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('decided_by', sa.String(length=50), nullable=True),
        sa.Column('decided_at', sa.DateTime(), nullable=True),
        sa.Column('decision_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('proposal_id')
        )
        with op.batch_alter_table('agent_proposals', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_agent_proposals_agent_name'), ['agent_name'], unique=False)
            batch_op.create_index(batch_op.f('ix_agent_proposals_alert_id'), ['alert_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_agent_proposals_created_at'), ['created_at'], unique=False)
            batch_op.create_index(batch_op.f('ix_agent_proposals_proposal_id'), ['proposal_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_agent_proposals_status'), ['status'], unique=False)

    if 'analyst_action_logs' not in existing:
        op.create_table('analyst_action_logs',
        sa.Column('log_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('analyst_username', sa.String(length=50), nullable=False),
        sa.Column('action_type', sa.String(length=100), nullable=False),
        sa.Column('decision', sa.String(length=150), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('log_id')
        )
        with op.batch_alter_table('analyst_action_logs', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_analyst_action_logs_alert_id'), ['alert_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_analyst_action_logs_analyst_username'), ['analyst_username'], unique=False)
            batch_op.create_index(batch_op.f('ix_analyst_action_logs_log_id'), ['log_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_analyst_action_logs_timestamp'), ['timestamp'], unique=False)

    if 'containment_actions' not in existing:
        op.create_table('containment_actions',
        sa.Column('action_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('action_type', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('executed_by', sa.String(length=50), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=True),
        sa.Column('connector', sa.String(length=50), nullable=True),
        sa.Column('execution_mode', sa.String(length=20), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('action_id')
        )
        with op.batch_alter_table('containment_actions', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_containment_actions_action_id'), ['action_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_containment_actions_alert_id'), ['alert_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_containment_actions_executed_by'), ['executed_by'], unique=False)

    if 'incident_reports' not in existing:
        op.create_table('incident_reports',
        sa.Column('report_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('pdf_path', sa.String(length=500), nullable=False),
        sa.Column('generated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('report_id')
        )
        with op.batch_alter_table('incident_reports', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_incident_reports_alert_id'), ['alert_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_incident_reports_report_id'), ['report_id'], unique=False)

    if 'ioc_artifacts' not in existing:
        op.create_table('ioc_artifacts',
        sa.Column('artifact_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('artifact_type', sa.String(length=50), nullable=False),
        sa.Column('value', sa.String(length=500), nullable=False),
        sa.Column('threat_score', sa.Integer(), nullable=False),
        sa.Column('verdict', sa.String(length=20), nullable=False),
        sa.Column('enrichment_status', sa.String(length=30), nullable=False),
        sa.Column('tip_results', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('artifact_id')
        )
        with op.batch_alter_table('ioc_artifacts', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_ioc_artifacts_alert_id'), ['alert_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_ioc_artifacts_artifact_id'), ['artifact_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_ioc_artifacts_value'), ['value'], unique=False)

    if 'playbook_executions' not in existing:
        op.create_table('playbook_executions',
        sa.Column('execution_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('playbook_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('mttr_seconds', sa.Float(), nullable=False),
        sa.Column('executed_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['playbook_id'], ['playbooks.playbook_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('execution_id')
        )
        with op.batch_alter_table('playbook_executions', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_playbook_executions_alert_id'), ['alert_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_playbook_executions_execution_id'), ['execution_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_playbook_executions_playbook_id'), ['playbook_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('playbook_executions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_playbook_executions_playbook_id'))
        batch_op.drop_index(batch_op.f('ix_playbook_executions_execution_id'))
        batch_op.drop_index(batch_op.f('ix_playbook_executions_alert_id'))

    op.drop_table('playbook_executions')
    with op.batch_alter_table('ioc_artifacts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ioc_artifacts_value'))
        batch_op.drop_index(batch_op.f('ix_ioc_artifacts_artifact_id'))
        batch_op.drop_index(batch_op.f('ix_ioc_artifacts_alert_id'))

    op.drop_table('ioc_artifacts')
    with op.batch_alter_table('incident_reports', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_incident_reports_report_id'))
        batch_op.drop_index(batch_op.f('ix_incident_reports_alert_id'))

    op.drop_table('incident_reports')
    with op.batch_alter_table('containment_actions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_containment_actions_executed_by'))
        batch_op.drop_index(batch_op.f('ix_containment_actions_alert_id'))
        batch_op.drop_index(batch_op.f('ix_containment_actions_action_id'))

    op.drop_table('containment_actions')
    with op.batch_alter_table('analyst_action_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_analyst_action_logs_timestamp'))
        batch_op.drop_index(batch_op.f('ix_analyst_action_logs_log_id'))
        batch_op.drop_index(batch_op.f('ix_analyst_action_logs_analyst_username'))
        batch_op.drop_index(batch_op.f('ix_analyst_action_logs_alert_id'))

    op.drop_table('analyst_action_logs')
    with op.batch_alter_table('agent_proposals', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_proposals_status'))
        batch_op.drop_index(batch_op.f('ix_agent_proposals_proposal_id'))
        batch_op.drop_index(batch_op.f('ix_agent_proposals_created_at'))
        batch_op.drop_index(batch_op.f('ix_agent_proposals_alert_id'))
        batch_op.drop_index(batch_op.f('ix_agent_proposals_agent_name'))

    op.drop_table('agent_proposals')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_username'))
        batch_op.drop_index(batch_op.f('ix_users_user_id'))
        batch_op.drop_index(batch_op.f('ix_users_api_key_prefix'))

    op.drop_table('users')
    with op.batch_alter_table('system_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_system_logs_source'))
        batch_op.drop_index(batch_op.f('ix_system_logs_log_id'))
        batch_op.drop_index(batch_op.f('ix_system_logs_level'))
        batch_op.drop_index(batch_op.f('ix_system_logs_created_at'))

    op.drop_table('system_logs')
    with op.batch_alter_table('system_configs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_system_configs_key_name'))
        batch_op.drop_index(batch_op.f('ix_system_configs_config_id'))
        batch_op.drop_index(batch_op.f('ix_system_configs_category'))

    op.drop_table('system_configs')
    with op.batch_alter_table('playbooks', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_playbooks_target_threat'))
        batch_op.drop_index(batch_op.f('ix_playbooks_playbook_id'))
        batch_op.drop_index(batch_op.f('ix_playbooks_name'))

    op.drop_table('playbooks')
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_alerts_status'))
        batch_op.drop_index(batch_op.f('ix_alerts_severity'))
        batch_op.drop_index(batch_op.f('ix_alerts_rule_id'))
        batch_op.drop_index(batch_op.f('ix_alerts_resolved_by'))
        batch_op.drop_index(batch_op.f('ix_alerts_assigned_analyst'))
        batch_op.drop_index(batch_op.f('ix_alerts_alert_id'))

    op.drop_table('alerts')
