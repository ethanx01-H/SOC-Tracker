"""Add is_active so an account can be disabled without deleting it."""

from alembic import op
import sqlalchemy as sa


revision = "0007_user_is_active"
down_revision = "0006_alert_external_id"
branch_labels = None
depends_on = None


def upgrade():
    # Postgres rejects DEFAULT 1 on a boolean column, so the literal follows the
    # dialect. SQLite keeps 1 so the existing databases do not show drift.
    default = sa.text("true") if op.get_bind().dialect.name != "sqlite" else sa.text("1")
    with op.batch_alter_table("fastapi_users") as batch_op:
        batch_op.add_column(
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=default)
        )


def downgrade():
    with op.batch_alter_table("fastapi_users") as batch_op:
        batch_op.drop_column("is_active")
