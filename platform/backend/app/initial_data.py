"""
Seed initial data: creates the first superuser, default organization,
default workspace and, in development only, an open invite code.

Run inside the backend container:
    python -m app.initial_data

Or via Makefile:
    make seed
"""

import asyncio
import os
import re
import secrets
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.security import hash_password
from app.models.db.base import Base  # noqa: F401 — ensure mappers are loaded
from app.models.db.org import InviteCode, OrgPlan, Organization, Workspace  # noqa: F401
from app.models.db.user import MemberRole, OrgMember, User  # noqa: F401

settings = get_settings()


def _slugify(name: str) -> str:
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")[:100]


async def seed() -> None:
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    email    = os.getenv("FIRST_SUPERUSER_EMAIL", "admin")
    org_name = os.getenv("FIRST_ORG_NAME", "AttackTrace")

    # Development keeps the documented admin/admin login and open invite code. Anywhere else the
    # seed must not create a well-known credential: refuse a weak password, or generate one.
    is_dev = os.getenv("ENVIRONMENT", settings.ENVIRONMENT).lower() == "development"
    password = os.getenv("FIRST_SUPERUSER_PASSWORD", "")
    generated = False
    if not is_dev:
        if not password:
            password, generated = secrets.token_urlsafe(18), True
        elif password.lower() in {"admin", "password", "changeme"} or len(password) < 12:
            print("[seed] ERROR: FIRST_SUPERUSER_PASSWORD is weak. Outside ENVIRONMENT=development it "
                  "must be at least 12 characters and not a common default (or leave it unset to "
                  "generate one).", file=sys.stderr)
            sys.exit(1)
    elif not password:
        password = "admin"
    open_invite = is_dev or os.getenv("SEED_OPEN_INVITE", "").lower() == "true"

    async with async_session() as db:
        # ── idempotent: skip if superuser already exists ─────────────────────
        existing = await db.execute(select(User).where(User.email == email))
        if existing.scalar_one_or_none():
            print(f"[seed] Superuser {email!r} already exists — skipping.")
            await engine.dispose()
            return

        # ── create org ───────────────────────────────────────────────────────
        slug = _slugify(org_name)
        # make slug unique if collision
        existing_org = await db.execute(select(Organization).where(Organization.slug == slug))
        if existing_org.scalar_one_or_none():
            slug = f"{slug}-1"

        org = Organization(
            name=org_name,
            slug=slug,
            plan=OrgPlan.ENTERPRISE,
            max_scans_per_month=9999,
        )
        db.add(org)
        await db.flush()
        await db.refresh(org)

        # ── default workspace ────────────────────────────────────────────────
        workspace = Workspace(
            org_id=org.id,
            name="Default",
            description="Default workspace",
        )
        db.add(workspace)

        # ── create superuser ─────────────────────────────────────────────────
        user = User(
            email=email,
            hashed_password=hash_password(password),
            full_name="Admin",
            is_active=True,
            is_superuser=True,
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)

        # ── add user as owner of the org ─────────────────────────────────────
        member = OrgMember(
            user_id=user.id,
            org_id=org.id,
            role=MemberRole.OWNER,
        )
        db.add(member)

        # ── open invite code so others can register ──────────────────────────
        existing_invite = await db.execute(
            select(InviteCode).where(InviteCode.code == "ATTACKTRACE")
        )
        if open_invite and not existing_invite.scalar_one_or_none():
            invite = InviteCode(
                org_id=org.id,
                created_by=user.id,
                code="ATTACKTRACE",
                role=MemberRole.ANALYST.value,
                email=None,          # open — anyone can use it
                expires_at=None,     # never expires
                is_revoked=False,
            )
            db.add(invite)

        await db.commit()

    await engine.dispose()
    print(f"[seed] Created org {org_name!r} (slug={slug})")
    if generated:
        print(f"[seed] Created superuser: {email}")
        print(f"[seed] GENERATED PASSWORD (shown once, change it after first login): {password}")
    elif is_dev:
        print(f"[seed] Created superuser: {email} / {'admin' if password == 'admin' else '(password set)'}")
        print("[seed] DEVELOPMENT defaults: do not expose this instance to a network as-is.")
    else:
        print(f"[seed] Created superuser: {email} / (password set)")
    if open_invite:
        print("[seed] Open invite code for new users: ATTACKTRACE (anyone with it can register)")
    else:
        print("[seed] No open invite code created; add members from Settings -> Team Members.")


def main() -> None:
    asyncio.run(seed())


if __name__ == "__main__":
    main()
