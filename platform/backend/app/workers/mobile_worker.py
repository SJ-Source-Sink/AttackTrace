"""
Mobile scanner Celery task.

Extracts APK/IPA/JAR archives, runs regex-based detection patterns,
and persists MobileFinding records to the database.
"""

import logging
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

from sqlalchemy import create_engine, or_, select
from sqlalchemy.orm import Session

from app.workers.celery_app import celery_app
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# ---------------------------------------------------------------------------
# Severity weight for risk score calculation
# ---------------------------------------------------------------------------
_SEV_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0.1}

# Max findings per pattern to prevent noise floods
_MAX_PER_PATTERN = 10

# Text file extensions to scan (binary DEX scanned separately)
_TEXT_EXTENSIONS = {
    ".java", ".kt", ".xml", ".json", ".properties", ".txt", ".cfg",
    ".gradle", ".yaml", ".yml", ".plist", ".swift", ".m", ".h",
    ".js", ".smali", ".csv", ".ini", ".conf", ".env", ".toml",
}

# ---------------------------------------------------------------------------
# Sync DB engine
# ---------------------------------------------------------------------------
_sync_engine = None


def _get_sync_engine():
    global _sync_engine
    if _sync_engine is None:
        db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
        _sync_engine = create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=3,
            max_overflow=5,
            pool_recycle=1800,
        )
    return _sync_engine


def _get_session() -> Session:
    return Session(_get_sync_engine())


# ---------------------------------------------------------------------------
# Archive extraction helpers
# ---------------------------------------------------------------------------

def _is_text_file(name: str) -> bool:
    return Path(name).suffix.lower() in _TEXT_EXTENSIONS


def _safe_read_text(zip_ref: zipfile.ZipFile, name: str, max_bytes: int = 1_000_000) -> Optional[str]:
    """Read a zip member as UTF-8 text, capped at max_bytes. Returns None on error."""
    try:
        with zip_ref.open(name) as f:
            raw = f.read(max_bytes)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _extract_files(scan_platform: str, file_path: str, tmp_dir: str) -> list[tuple[str, str]]:
    """
    Returns list of (archive_path, text_content) tuples.
    For APK/IPA/JAR: unzip and collect text files + raw bytes from .dex/.class.
    For EXE/DLL: treat as binary, do strings-style extraction.
    """
    results: list[tuple[str, str]] = []
    ext = Path(file_path).suffix.lower()

    if ext in (".exe", ".dll"):
        # Binary-only: extract printable ASCII strings
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
            # Find runs of printable ASCII >= 6 chars
            strings_text = "\n".join(
                m.group(0) for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)
            ).decode("ascii", errors="replace")
            results.append((Path(file_path).name, strings_text))
        except Exception as e:
            logger.warning(f"Binary extraction failed for {file_path}: {e}")
        return results

    # APK, APKM, XAPK, JAR, IPA are all ZIP-based
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
            for name in names:
                if name.endswith("/"):
                    continue
                suffix = Path(name).suffix.lower()
                if _is_text_file(name):
                    content = _safe_read_text(zf, name)
                    if content:
                        results.append((name, content))
                elif suffix in (".dex", ".class"):
                    # Scan raw bytes for printable string literals
                    try:
                        with zf.open(name) as f:
                            raw = f.read(2_000_000)
                        strings_text = "\n".join(
                            m.group(0) for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)
                        ).decode("ascii", errors="replace")
                        if strings_text:
                            results.append((name + "[strings]", strings_text))
                    except Exception:
                        pass
    except zipfile.BadZipFile:
        # Not a valid zip — try reading as text directly
        try:
            content = Path(file_path).read_text(errors="replace")
            results.append((Path(file_path).name, content))
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"Archive extraction failed for {file_path}: {e}")

    return results


# ---------------------------------------------------------------------------
# Main Celery task
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="app.workers.mobile_worker.run_mobile_scan",
    max_retries=1,
    default_retry_delay=30,
)
def run_mobile_scan(self, scan_id: str) -> dict:
    """Scan a mobile app file and persist findings to the database."""
    from app.models.db.mobile import MobileFinding, MobilePattern, MobileScan

    tmp_dir = tempfile.mkdtemp(prefix="mobile_scan_")

    try:
        with _get_session() as session:
            scan = session.get(MobileScan, UUID(scan_id))
            if not scan:
                logger.error(f"MobileScan {scan_id} not found")
                return {"error": "scan not found"}

            scan.status = "scanning"
            scan.progress = 5
            scan.message = "Extracting archive..."
            session.commit()

            if not scan.file_path or not Path(scan.file_path).exists():
                scan.status = "failed"
                scan.error_message = "Uploaded file not found on disk"
                scan.progress = 0
                session.commit()
                return {"error": "file not found"}

            # ── Extract files ──────────────────────────────────────────────
            try:
                file_contents = _extract_files(scan.platform, scan.file_path, tmp_dir)
            except Exception as e:
                scan.status = "failed"
                scan.error_message = f"Extraction failed: {e}"
                session.commit()
                return {"error": str(e)}

            scan.progress = 20
            scan.message = f"Scanning {len(file_contents)} files..."
            session.commit()

            # ── Load enabled patterns ──────────────────────────────────────
            patterns = session.execute(
                select(MobilePattern).where(
                    MobilePattern.is_enabled == True,  # noqa: E712
                    or_(
                        MobilePattern.platform == scan.platform,
                        MobilePattern.platform == "all",
                    ),
                    or_(
                        MobilePattern.org_id == scan.org_id,
                        MobilePattern.org_id == None,  # noqa: E711
                    ),
                )
            ).scalars().all()

            if not patterns:
                scan.status = "completed"
                scan.progress = 100
                scan.message = "No patterns loaded — add patterns in the Pattern Library."
                scan.completed_at = datetime.now(timezone.utc)
                session.commit()
                return {"findings": 0}

            # ── Scan loop ──────────────────────────────────────────────────
            # Dedup set: (pattern_id, file_path, line_number)
            seen: set[tuple] = set()
            findings_to_add: list[MobileFinding] = []
            pattern_hit_counts: dict[str, int] = {}

            total_files = len(file_contents)
            for file_idx, (archive_path, content) in enumerate(file_contents):
                if file_idx % 10 == 0:
                    pct = 20 + int((file_idx / max(total_files, 1)) * 70)
                    scan.progress = min(pct, 89)
                    scan.message = f"Scanning file {file_idx + 1}/{total_files}..."
                    session.commit()

                lines = content.splitlines()

                for pattern in patterns:
                    pid = str(pattern.id)
                    if pattern_hit_counts.get(pid, 0) >= _MAX_PER_PATTERN:
                        continue

                    try:
                        rx = re.compile(pattern.regex_pattern, re.IGNORECASE | re.MULTILINE)
                    except re.error:
                        continue

                    for line_no, line in enumerate(lines, start=1):
                        m = rx.search(line)
                        if not m:
                            continue

                        dedup_key = (pid, archive_path, line_no)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        snippet = line.strip()[:300]
                        findings_to_add.append(
                            MobileFinding(
                                scan_id=scan.id,
                                pattern_id=pattern.id,
                                title=pattern.title,
                                severity=pattern.severity,
                                category=pattern.category,
                                description=pattern.description,
                                remediation=pattern.remediation,
                                file_path=archive_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                triage_status="New",
                                cwe=pattern.cwe,
                            )
                        )

                        pattern_hit_counts[pid] = pattern_hit_counts.get(pid, 0) + 1
                        if pattern_hit_counts[pid] >= _MAX_PER_PATTERN:
                            break

            # ── Persist findings ───────────────────────────────────────────
            if findings_to_add:
                session.add_all(findings_to_add)
                session.flush()

            # ── Compute counts and risk score ──────────────────────────────
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            total_weight = 0.0
            for f in findings_to_add:
                counts[f.severity] = counts.get(f.severity, 0) + 1
                total_weight += _SEV_WEIGHT.get(f.severity, 0)

            risk_score = min(100.0, total_weight)

            scan.findings_count = counts
            scan.risk_score = round(risk_score, 1)
            scan.status = "completed"
            scan.progress = 100
            scan.message = f"Scan complete — {len(findings_to_add)} findings"
            scan.completed_at = datetime.now(timezone.utc)
            session.commit()

            logger.info(
                f"Mobile scan {scan_id} complete: {len(findings_to_add)} findings, "
                f"risk={risk_score:.1f}"
            )
            return {"findings": len(findings_to_add), "risk_score": risk_score}

    except Exception as exc:
        logger.exception(f"Mobile scan {scan_id} failed: {exc}")
        try:
            with _get_session() as session:
                scan = session.get(MobileScan, UUID(scan_id))
                if scan:
                    scan.status = "failed"
                    scan.error_message = str(exc)[:500]
                    scan.progress = 0
                    session.commit()
        except Exception:
            pass
        raise self.retry(exc=exc)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
