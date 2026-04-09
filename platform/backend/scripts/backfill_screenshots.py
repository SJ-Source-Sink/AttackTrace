"""
Backfill screenshots for existing webapp assets that don't have screenshot_url set.
Run: python3.11 scripts/backfill_screenshots.py [--limit N] [--scan-id UUID]
"""

import asyncio
import sys
import argparse
from pathlib import Path

# Add AttackTrace to path
_REPO_ROOT = Path(__file__).parents[4]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).parents[1]))

from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from attacktrace.modules.web.screenshot import capture_with_playwright

settings = get_settings()
WORKSPACE = Path(settings.ATTACKTRACE_WORKSPACE_DIR)

DB_URL = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://")


async def capture_screenshot_for_asset(asset, session: Session) -> bool:
    from app.models.db.asset import Asset

    url = asset.value
    if not url.startswith("http"):
        url = f"https://{url}"

    out_dir = WORKSPACE / str(asset.org_id) / str(asset.scan_job_id) / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{asset.id}.png"

    print(f"  Capturing {url} ...", end=" ", flush=True)
    success = await capture_with_playwright(url, out_path, timeout=15000)

    if success and out_path.exists():
        rel = out_path.relative_to(WORKSPACE)
        screenshot_url = f"/static/screenshots/{rel}"
        session.execute(
            update(Asset).where(Asset.id == asset.id).values(screenshot_url=screenshot_url)
        )
        session.commit()
        print(f"✓ ({out_path.stat().st_size // 1024}KB)")
        return True
    else:
        print("✗ failed")
        return False


async def main(limit: int, scan_id: str | None):
    from app.models.db.asset import Asset, AssetType

    engine = create_engine(DB_URL, pool_pre_ping=True)

    with Session(engine) as session:
        q = select(Asset).where(
            Asset.asset_type == AssetType.WEBAPP,
            Asset.screenshot_url == None,
            Asset.is_active == True,
        )
        if scan_id:
            from uuid import UUID
            q = q.where(Asset.scan_job_id == UUID(scan_id))
        q = q.limit(limit)

        assets = session.execute(q).scalars().all()
        print(f"Found {len(assets)} webapp assets without screenshots (limit={limit})")

        ok = 0
        for i, asset in enumerate(assets, 1):
            print(f"[{i}/{len(assets)}] {asset.value[:70]}")
            if await capture_screenshot_for_asset(asset, session):
                ok += 1

        print(f"\nDone: {ok}/{len(assets)} screenshots captured")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10, help="Max assets to process")
    parser.add_argument("--scan-id", type=str, default=None, help="Filter to specific scan")
    args = parser.parse_args()

    asyncio.run(main(args.limit, args.scan_id))
