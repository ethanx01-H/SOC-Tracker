"""Index the columns the dashboard, list filters and lookups read."""

from alembic import op


revision = "0008_query_indexes"
down_revision = "0007_user_is_active"
branch_labels = None
depends_on = None

INDEXES = (
    ("fastapi_alerts", "status"),
    ("fastapi_alerts", "severity"),
    ("fastapi_alerts", "created_at"),
    ("fastapi_alerts", "assigned_to_id"),
    ("fastapi_alerts", "analyst"),
    ("fastapi_alert_events", "alert_id"),
    ("fastapi_evidence", "alert_id"),
    ("fastapi_audit_logs", "created_at"),
)


def upgrade():
    for table, column in INDEXES:
        op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    for table, column in reversed(INDEXES):
        op.drop_index(f"ix_{table}_{column}", table_name=table)
