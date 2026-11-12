"""Add forced password change on next login."""

from alembic import op
import sqlalchemy as sa


revision = "0004_password_change_policy"
down_revision = "0003_ticket_numbers_and_workflow"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "fastapi_users",
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade():
    op.drop_column("fastapi_users", "must_change_password")
