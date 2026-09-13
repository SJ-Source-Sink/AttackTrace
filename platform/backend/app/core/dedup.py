"""
Shared cross-scan / cross-scanner finding deduplication key.

Used by both the sync Celery scan pipeline (app.workers.scan_worker) and the
async standalone-scanner ingestion path (app.services.finding_ingest) so a
vulnerability reported by two different tools on the same asset dedupes to one
Finding row instead of two.
"""
import hashlib
from uuid import UUID


def compute_dedup_hash(
    org_id: UUID | str, title: str, affected_asset: str, cve_list: list[str] | None = None
) -> str:
    """Stable 64-char dedup hash: sha256(org|title|asset|sorted_cves)."""
    sorted_cves = "|".join(sorted(cve_list or []))
    key = f"{str(org_id)}|{title}|{affected_asset}|{sorted_cves}"
    return hashlib.sha256(key.encode()).hexdigest()
