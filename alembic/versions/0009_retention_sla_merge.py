"""Retention, SLA breach history, and duplicate links.

Adds three things the scale/maturity work needs:

* ``fastapi_alerts.closed_at`` — retention is measured from closure, so a ticket
  opened 800 days ago and closed yesterday keeps its full two years.
* ``fastapi_alerts.duplicate_of_id`` — a merged ticket stays readable and points
  at the ticket that owns the investigation.
* ``fastapi_sla_breaches`` — one row per missed SLA, written by the sweep.
"""

import sqlalchemy as sa
from alembic import op


revision = "0009_retention_sla_merge"
down_revision = "0008_query_indexes"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("fastapi_alerts") as batch_op:
        batch_op.add_column(sa.Column("closed_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("duplicate_of_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_fastapi_alerts_closed_at", ["closed_at"])
        batch_op.create_foreign_key(
            "fk_fastapi_alerts_duplicate_of_id", "fastapi_alerts", ["duplicate_of_id"], ["id"]
        )

    op.create_table(
        "fastapi_sla_breaches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("fastapi_alerts.id"), nullable=False),
        sa.Column("alert_ref", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="Medium"),
        sa.Column("due_at", sa.DateTime(), nullable=False),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("late_hours", sa.Integer(), nullable=True),
    )
    op.create_index("ix_fastapi_sla_breaches_alert_id", "fastapi_sla_breaches", ["alert_id"])
    op.create_index(
        "ix_fastapi_sla_breaches_alert_due", "fastapi_sla_breaches", ["alert_id", "due_at"], unique=True
    )


def downgrade():
    op.drop_index("ix_fastapi_sla_breaches_alert_due", table_name="fastapi_sla_breaches")
    op.drop_index("ix_fastapi_sla_breaches_alert_id", table_name="fastapi_sla_breaches")
    op.drop_table("fastapi_sla_breaches")
    with op.batch_alter_table("fastapi_alerts") as batch_op:
        batch_op.drop_constraint("fk_fastapi_alerts_duplicate_of_id", type_="foreignkey")
        batch_op.drop_index("ix_fastapi_alerts_closed_at")
        batch_op.drop_column("duplicate_of_id")
        batch_op.drop_column("closed_at")
