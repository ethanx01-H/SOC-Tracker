"""Add Informational severity and widen the severity field."""

from alembic import op
import sqlalchemy as sa


revision = "0005_informational_severity"
down_revision = "0004_password_change_policy"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("fastapi_alerts") as batch_op:
        batch_op.alter_column(
            "severity",
            existing_type=sa.String(length=10),
            type_=sa.String(length=20),
            existing_nullable=False,
        )


def downgrade():
    connection = op.get_bind()
    connection.exec_driver_sql(
        "UPDATE fastapi_alerts SET severity = 'Low' WHERE severity = 'Informational'"
    )
    with op.batch_alter_table("fastapi_alerts") as batch_op:
        batch_op.alter_column(
            "severity",
            existing_type=sa.String(length=20),
            type_=sa.String(length=10),
            existing_nullable=False,
        )
