"""Add a unique external id so webhook replays map to the existing ticket."""

from alembic import op
import sqlalchemy as sa


revision = "0006_alert_external_id"
down_revision = "0005_informational_severity"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("fastapi_alerts") as batch_op:
        batch_op.add_column(sa.Column("external_id", sa.String(length=160), nullable=True))
        batch_op.create_index("ix_fastapi_alerts_external_id", ["external_id"], unique=True)


def downgrade():
    with op.batch_alter_table("fastapi_alerts") as batch_op:
        batch_op.drop_index("ix_fastapi_alerts_external_id")
        batch_op.drop_column("external_id")
