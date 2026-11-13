"""Add is_active so an account can be disabled without deleting it."""

from alembic import op
import sqlalchemy as sa


revision = "0007_user_is_active"
down_revision = "0006_alert_external_id"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("fastapi_users") as batch_op:
        batch_op.add_column(
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1"))
        )


def downgrade():
    with op.batch_alter_table("fastapi_users") as batch_op:
        batch_op.drop_column("is_active")
