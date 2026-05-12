"""
SQLAlchemy 2.x async database engine and session management.
Provides a TenantSession wrapper that enforces org_id filtering.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    pool_pre_ping=True,
    pool_recycle=3600,  # recycle connections older than 1 hour (prevents stale conn errors)
    echo=settings.DEBUG,
    connect_args={
        "command_timeout": 10,  # fail fast if DB unreachable (asyncpg-specific)
        "server_settings": {
            "statement_timeout": str(settings.DATABASE_STATEMENT_TIMEOUT_MS),
            "idle_in_transaction_session_timeout": "60000",  # kill idle txns after 60s
        },
    },
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Read replica engine — points to replica if DATABASE_READ_REPLICA_URL is set,
# otherwise falls back to the primary so existing code works without any infra change.
_replica_url = settings.DATABASE_READ_REPLICA_URL or settings.DATABASE_URL
read_engine = create_async_engine(
    _replica_url,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    pool_pre_ping=True,
    echo=settings.DEBUG,
    connect_args={
        "server_settings": {
            "statement_timeout": str(settings.DATABASE_STATEMENT_TIMEOUT_MS),
            "default_transaction_read_only": "on",
        }
    },
)

ReadSessionLocal = async_sessionmaker(
    bind=read_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_read_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides a read-only database session (replica-routed)."""
    async with ReadSessionLocal() as session:
        try:
            yield session
        except Exception:
            raise
        finally:
            await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides a raw async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


class TenantSession:
    """
    Wrapper around AsyncSession that enforces multi-tenant isolation.
    Every operation is scoped to the provided org_id.
    """

    def __init__(self, session: AsyncSession, org_id: UUID):
        self._session = session
        self.org_id = org_id

    @property
    def session(self) -> AsyncSession:
        return self._session

    async def execute(self, stmt, **kwargs):
        return await self._session.execute(stmt, **kwargs)

    async def get(self, model, ident):
        return await self._session.get(model, ident)

    def add(self, instance):
        self._session.add(instance)

    async def flush(self):
        await self._session.flush()

    async def commit(self):
        await self._session.commit()

    async def refresh(self, instance):
        await self._session.refresh(instance)

    async def delete(self, instance):
        await self._session.delete(instance)

    async def rollback(self):
        await self._session.rollback()


@asynccontextmanager
async def get_tenant_session(org_id: UUID) -> AsyncGenerator[TenantSession, None]:
    """Context manager that provides a tenant-scoped session."""
    async with AsyncSessionLocal() as session:
        tenant_session = TenantSession(session=session, org_id=org_id)
        try:
            yield tenant_session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables (for development/testing)."""
    from app.models.db.base import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the engine connection pools."""
    await engine.dispose()
    await read_engine.dispose()
