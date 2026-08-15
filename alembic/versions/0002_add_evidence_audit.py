"""add evidence and audit_log tables

Revision ID: 0002_add_evidence_audit
Revises: 0001_initial_fastapi_schema
Create Date: 2026-08-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0002_add_evidence_audit"
down_revision = "0001_initial_fastapi_schema"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    existing = inspect(bind).get_table_names()

    if "fastapi_evidence" not in existing:
        op.create_table(
            "fastapi_evidence",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("alert_id", sa.Integer(), sa.ForeignKey("fastapi_alerts.id"), nullable=False),
            sa.Column("uploaded_by_id", sa.Integer(), sa.ForeignKey("fastapi_users.id"), nullable=True),
            sa.Column("original_name", sa.String(length=255), nullable=False),
            sa.Column("stored_name", sa.String(length=255), nullable=False, unique=True),
            sa.Column("content_type", sa.String(length=120), nullable=False, server_default="application/octet-stream"),
            sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    if "fastapi_audit_logs" not in existing:
        op.create_table(
            "fastapi_audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("actor_id", sa.Integer(), sa.ForeignKey("fastapi_users.id"), nullable=True),
            sa.Column("action", sa.String(length=80), nullable=False),
            sa.Column("target_type", sa.String(length=80), nullable=False, server_default=""),
            sa.Column("target_id", sa.String(length=80), nullable=False, server_default=""),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("source_ip", sa.String(length=80), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_fastapi_audit_logs_created_at", "fastapi_audit_logs", ["created_at"])


def downgrade():
    op.drop_index("ix_fastapi_audit_logs_created_at", table_name="fastapi_audit_logs")
    op.drop_table("fastapi_audit_logs")
    op.drop_table("fastapi_evidence")
