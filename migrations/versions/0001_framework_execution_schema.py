"""framework execution schema

Revision ID: 0001_framework_execution_schema
Revises:
Create Date: 2026-07-11
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_framework_execution_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("organizations", sa.Column("id", sa.String(64), primary_key=True), sa.Column("name", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("targets", sa.Column("id", sa.String(64), primary_key=True), sa.Column("organization_id", sa.String(64), nullable=True), sa.Column("target_name", sa.String(255), nullable=False), sa.Column("target_type", sa.String(64), nullable=False), sa.Column("model_name", sa.String(255), nullable=True), sa.Column("visibility", sa.String(64), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("frameworks", sa.Column("id", sa.String(64), primary_key=True), sa.Column("name", sa.String(64), nullable=False), sa.Column("version", sa.String(128), nullable=True), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("health", sa.String(64), nullable=False), sa.Column("last_health_check", sa.DateTime(timezone=True), nullable=True))
    op.create_table("assessments", sa.Column("id", sa.String(64), primary_key=True), sa.Column("target_id", sa.String(64), nullable=False), sa.Column("status", sa.String(64), nullable=False), sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table("campaign_jobs", sa.Column("id", sa.String(64), primary_key=True), sa.Column("assessment_id", sa.String(64), nullable=False), sa.Column("framework_id", sa.String(64), nullable=False), sa.Column("status", sa.String(64), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("normalized_evidence", sa.Column("id", sa.String(64), primary_key=True), sa.Column("assessment_id", sa.String(64), nullable=False), sa.Column("framework", sa.String(64), nullable=False), sa.Column("target_id", sa.String(64), nullable=False), sa.Column("category", sa.String(128), nullable=False), sa.Column("confirmed", sa.Boolean(), nullable=False), sa.Column("confidence", sa.Float(), nullable=False), sa.Column("evidence_hash", sa.String(128), nullable=False), sa.Column("payload", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_targets_type", "targets", ["target_type"])
    op.create_index("ix_assessments_target", "assessments", ["target_id"])
    op.create_index("ix_evidence_framework", "normalized_evidence", ["framework"])
    op.create_index("ix_evidence_target", "normalized_evidence", ["target_id"])
    op.create_index("ix_evidence_confirmed", "normalized_evidence", ["confirmed"])


def downgrade() -> None:
    op.drop_index("ix_evidence_confirmed", table_name="normalized_evidence")
    op.drop_index("ix_evidence_target", table_name="normalized_evidence")
    op.drop_index("ix_evidence_framework", table_name="normalized_evidence")
    op.drop_index("ix_assessments_target", table_name="assessments")
    op.drop_index("ix_targets_type", table_name="targets")
    op.drop_table("normalized_evidence")
    op.drop_table("campaign_jobs")
    op.drop_table("assessments")
    op.drop_table("frameworks")
    op.drop_table("targets")
    op.drop_table("organizations")
