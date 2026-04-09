"""
Alembic environment configuration for AttackTrace.

Key design decisions:
- Uses the SYNC_DATABASE_URL env var (not DATABASE_URL) because Alembic's
  synchronous engine does not support asyncpg.  The sync URL uses psycopg2.
- All SQLAlchemy models are imported here so Alembic can auto-detect schema
  changes with `alembic revision --autogenerate`.
- Multi-tenant note: AttackTrace uses row-level tenancy (org_id column) rather than
  per-tenant schemas, so standard single-schema migrations apply.  If you later
  move to per-schema tenancy, see the `include_schemas` option in run_migrations_online.
"""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool, text
from alembic import context

# ─── Alembic Config object ────────────────────────────────────────────────────
# Provides access to alembic.ini values via context.config.get_main_option(...)
config = context.config

# Set up Python logging from alembic.ini [loggers] section
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ─── Import all models so Alembic sees their metadata ────────────────────────
#
# IMPORTANT: Every new model module must be imported here, otherwise
# `alembic revision --autogenerate` will not detect it and will generate DROP
# TABLE statements for tables that "appear" to be missing.
#
# The Base.metadata object collects all mapped table definitions.
from app.models.db.base import Base  # noqa: F401 — registers Base.metadata

# Individual model modules — import so their Table objects register on Base.metadata
from app.models.db import asset   # noqa: F401
from app.models.db import audit   # noqa: F401
from app.models.db import finding # noqa: F401
from app.models.db import org     # noqa: F401
from app.models.db import scan    # noqa: F401
from app.models.db import user    # noqa: F401

# MetaData object used by Alembic for autogenerate comparisons
target_metadata = Base.metadata

# ─── Database URL resolution ──────────────────────────────────────────────────
#
# Priority order:
#   1. SYNC_DATABASE_URL environment variable (explicit sync URL)
#   2. DATABASE_URL environment variable (strip asyncpg+ prefix if present)
#   3. alembic.ini sqlalchemy.url value (fallback for local dev without .env)
#
# asyncpg is an async-only driver; Alembic needs a sync driver (psycopg2).
# The SYNC_DATABASE_URL should use:  postgresql://user:pass@host:5432/dbname

def get_url() -> str:
    sync_url = os.environ.get("SYNC_DATABASE_URL")
    if sync_url:
        return sync_url

    db_url = os.environ.get("DATABASE_URL", "")
    if db_url:
        # Strip async driver prefix so psycopg2 is used instead of asyncpg
        return db_url.replace("postgresql+asyncpg://", "postgresql://")

    # Fall back to alembic.ini value (useful for local `alembic upgrade head` calls)
    return config.get_main_option("sqlalchemy.url", "")


# ─── Offline migrations (generate SQL without a live DB connection) ───────────

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    Generates a SQL script that can be applied manually — useful for:
    - Auditing what will run before applying
    - DBAs who need to review changes before applying to production
    - Environments where direct DB access from the migration host is blocked

    Usage:
        alembic upgrade head --sql > migration.sql
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Include schema-level CREATE/DROP in diffs
        include_schemas=False,
        # Compare server defaults so `server_default` changes are detected
        compare_server_default=True,
        # Compare types so column type changes are detected
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ─── Online migrations (run directly against a live DB connection) ────────────

def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode (the default).

    Creates a real DB connection and runs migrations transactionally.
    Each migration runs inside a transaction; on failure the transaction
    is rolled back and the database is left in a consistent state.

    Multi-tenant note:
    If you migrate to per-schema tenancy, iterate over tenant schemas here:

        for schema in get_tenant_schemas(connectable):
            with connectable.connect() as connection:
                connection.execute(text(f"SET search_path TO {schema}"))
                context.configure(connection=connection, ...)
                with context.begin_transaction():
                    context.run_migrations()
    """
    # Override sqlalchemy.url in the alembic config with our resolved URL.
    # This allows the env var to take precedence over alembic.ini.
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # NullPool: no connection reuse — safer for migrations
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Detect column type changes (e.g., VARCHAR(255) → TEXT)
            compare_type=True,
            # Detect server_default changes
            compare_server_default=True,
            # Render item-level diffs (column reorders, etc.)
            render_as_batch=False,
            # Transaction per migration — if one fails, only that revision rolls back
            transaction_per_migration=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ─── Entry point ─────────────────────────────────────────────────────────────

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
