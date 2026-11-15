"""Initial non-destructive schema migration.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-14

This migration is deliberately hand-written and NON-DESTRUCTIVE:
- Creates missing tables (tenants, users, refresh_tokens, api_keys) with
  CREATE TABLE IF NOT EXISTS semantics so fresh databases and existing
  databases both work.
- Adds missing columns to `investigations` (tenant_id, created_by_user_id,
  is_anonymous, access_token_hash, access_token_expires_at) using
  SQLite-compatible ALTER TABLE ADD COLUMN.
- No DROP TABLE, no data deletion, no schema replacement.

Legacy investigations remain accessible: new columns are nullable, so all
existing records keep their data and are treated as non-anonymous records
with no owning tenant (globally visible legacy data preserved as-is).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(table_name: str) -> bool:
    """Return True when the given table exists in the current database."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _columns(table_name: str) -> set:
    """Return the set of existing column names for a table."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {c["name"] for c in inspector.get_columns(table_name)}


def upgrade() -> None:
    # --- tenants ---------------------------------------------------------
    if not _table_exists("tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("slug", sa.String(100), nullable=False),
            sa.Column("status", sa.String(50), nullable=False, server_default="active"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(op.f("ix_tenants_id"), "tenants", ["id"])
        op.create_index(op.f("ix_tenants_slug"), "tenants", ["slug"], unique=True)

    # --- users -----------------------------------------------------------
    if not _table_exists("users"):
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("email", sa.String(255), nullable=False),
            sa.Column("hashed_password", sa.String(255), nullable=False),
            sa.Column("role", sa.String(50), nullable=False, server_default="investigator"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(op.f("ix_users_id"), "users", ["id"])
        op.create_index(op.f("ix_users_tenant_id"), "users", ["tenant_id"])
        op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # --- refresh_tokens ---------------------------------------------------
    if not _table_exists("refresh_tokens"):
        op.create_table(
            "refresh_tokens",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("token_hash", sa.String(128), nullable=False),
            sa.Column("family_id", sa.String(64), nullable=False),
            sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(op.f("ix_refresh_tokens_id"), "refresh_tokens", ["id"])
        op.create_index(op.f("ix_refresh_tokens_user_id"), "refresh_tokens", ["user_id"])
        op.create_index(op.f("ix_refresh_tokens_token_hash"), "refresh_tokens", ["token_hash"], unique=True)
        op.create_index(op.f("ix_refresh_tokens_family_id"), "refresh_tokens", ["family_id"])

    # --- api_keys ---------------------------------------------------------
    if not _table_exists("api_keys"):
        op.create_table(
            "api_keys",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("key_prefix", sa.String(64), nullable=False),
            sa.Column("key_hash", sa.String(128), nullable=False),
            sa.Column("scopes", sa.String(255), nullable=False,
                      server_default="investigations:read,investigations:write,analysis:run"),
            sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(op.f("ix_api_keys_id"), "api_keys", ["id"])
        op.create_index(op.f("ix_api_keys_tenant_id"), "api_keys", ["tenant_id"])
        op.create_index(op.f("ix_api_keys_user_id"), "api_keys", ["user_id"])
        op.create_index(op.f("ix_api_keys_key_prefix"), "api_keys", ["key_prefix"])
        op.create_index(op.f("ix_api_keys_key_hash"), "api_keys", ["key_hash"], unique=True)

    # --- investigations: additive columns only ---------------------------
    if _table_exists("investigations"):
        existing = _columns("investigations")
        if "tenant_id" not in existing:
            op.add_column(
                "investigations",
                sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
            )
        if "created_by_user_id" not in existing:
            op.add_column(
                "investigations",
                sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            )
        if "is_anonymous" not in existing:
            op.add_column(
                "investigations",
                sa.Column("is_anonymous", sa.Boolean(), nullable=True,
                          server_default=sa.false()),
            )
        if "access_token_hash" not in existing:
            op.add_column(
                "investigations",
                sa.Column("access_token_hash", sa.String(128), nullable=True),
            )
        if "access_token_expires_at" not in existing:
            op.add_column(
                "investigations",
                sa.Column("access_token_expires_at", sa.DateTime(timezone=True), nullable=True),
            )
        # Indexes for the new columns (idempotent: create only if absent).
        inspector = sa.inspect(op.get_bind())
        existing_indexes = {ix["name"] for ix in inspector.get_indexes("investigations")}
        for ix_name, col in [
            ("ix_investigations_tenant_id", "tenant_id"),
            ("ix_investigations_created_by_user_id", "created_by_user_id"),
            ("ix_investigations_is_anonymous", "is_anonymous"),
            ("ix_investigations_access_token_hash", "access_token_hash"),
        ]:
            if ix_name not in existing_indexes:
                op.create_index(op.f(ix_name), "investigations", [col])
    else:
        # Fresh database: create the full investigations table.
        op.create_table(
            "investigations",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("title", sa.String(), nullable=False),
            sa.Column("input_type", sa.String(), nullable=False),
            sa.Column("input_content", sa.Text(), nullable=False),
            sa.Column("risk_score", sa.Float(), nullable=True, server_default="0.0"),
            sa.Column("risk_band", sa.String(), nullable=True, server_default="low"),
            sa.Column("status", sa.String(), nullable=True, server_default="pending"),
            sa.Column("is_anonymous", sa.Boolean(), nullable=True, server_default=sa.false()),
            sa.Column("access_token_hash", sa.String(128), nullable=True),
            sa.Column("access_token_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(op.f("ix_investigations_id"), "investigations", ["id"])
        op.create_index(op.f("ix_investigations_tenant_id"), "investigations", ["tenant_id"])
        op.create_index(op.f("ix_investigations_created_by_user_id"), "investigations", ["created_by_user_id"])
        op.create_index(op.f("ix_investigations_is_anonymous"), "investigations", ["is_anonymous"])
        op.create_index(op.f("ix_investigations_access_token_hash"), "investigations", ["access_token_hash"])

    # --- findings ---------------------------------------------------------
    if not _table_exists("findings"):
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("investigations.id"), nullable=False),
            sa.Column("finding_type", sa.String(), nullable=False),
            sa.Column("title", sa.String(), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("evidence_snippet", sa.Text(), nullable=True),
            sa.Column("evidence_source", sa.String(), nullable=True),
            sa.Column("score", sa.Float(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(op.f("ix_findings_id"), "findings", ["id"])

    # --- entities ---------------------------------------------------------
    if not _table_exists("entities"):
        op.create_table(
            "entities",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("investigations.id"), nullable=False),
            sa.Column("entity_type", sa.String(), nullable=False),
            sa.Column("value", sa.Text(), nullable=False),
            sa.Column("normalized_value", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(op.f("ix_entities_id"), "entities", ["id"])


def downgrade() -> None:
    # Intentionally conservative: the downgrade path only removes the
    # columns and indexes added by upgrade(); it never drops tables so no
    # investigation data can be lost by an accidental downgrade.
    existing = _columns("investigations")
    inspector = sa.inspect(op.get_bind())
    existing_indexes = {ix["name"] for ix in inspector.get_indexes("investigations")}
    for ix_name in [
        "ix_investigations_access_token_hash",
        "ix_investigations_is_anonymous",
        "ix_investigations_created_by_user_id",
        "ix_investigations_tenant_id",
    ]:
        if ix_name in existing_indexes:
            op.drop_index(op.f(ix_name), table_name="investigations")
    for col in [
        "access_token_expires_at",
        "access_token_hash",
        "is_anonymous",
        "created_by_user_id",
        "tenant_id",
    ]:
        if col in existing:
            op.drop_column("investigations", col)
