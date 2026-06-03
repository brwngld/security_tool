"""create web dashboard schema

Revision ID: 20260603_0001
Revises:
Create Date: 2026-06-03
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260603_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("target_url", sa.String(length=2048), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("params_json", sa.Text(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_jobs_job_type", "jobs", ["job_type"])
    op.create_index("ix_jobs_status", "jobs", ["status"])
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=False),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("json_path", sa.String(length=2048), nullable=True),
        sa.Column("markdown_path", sa.String(length=2048), nullable=True),
        sa.Column("html_path", sa.String(length=2048), nullable=True),
        sa.Column("summary_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_reports_job_id", "reports", ["job_id"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("result", sa.String(length=64), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=255), primary_key=True),
        sa.Column("value_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_table("audit_events")
    op.drop_index("ix_reports_job_id", table_name="reports")
    op.drop_table("reports")
    op.drop_index("ix_jobs_status", table_name="jobs")
    op.drop_index("ix_jobs_job_type", table_name="jobs")
    op.drop_table("jobs")
    op.drop_table("targets")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
