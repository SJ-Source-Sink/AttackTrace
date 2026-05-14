"""
SQLite persistence layer for MSRA.
Replaces in-memory _scans / _dynamic_jobs dicts so state survives restarts.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Whitelists guard against SQL injection via column-name interpolation
_SCAN_COLS: frozenset = frozenset({
    "status", "progress", "message", "package", "apk",
    "total_findings", "severity_json", "traceback",
    "created_at", "updated_at", "risk_score", "platform",
})

_JOB_COLS: frozenset = frozenset({
    "scan_id", "finding_index", "finding_title",
    "status", "progress", "message", "logcat", "evidence",
    "verdict_json", "created_at", "updated_at",
})

DB_PATH = Path(__file__).parent.parent / "msra.db"
_lock   = threading.Lock()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db() -> None:
    """Create tables if they don't exist. Safe to call multiple times."""
    with _lock:
        with _conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id       TEXT PRIMARY KEY,
                    status        TEXT NOT NULL DEFAULT 'queued',
                    progress      INTEGER DEFAULT 0,
                    message       TEXT,
                    package       TEXT,
                    apk           TEXT,
                    total_findings INTEGER DEFAULT 0,
                    severity_json TEXT,
                    traceback     TEXT,
                    created_at    REAL,
                    updated_at    REAL
                );
                CREATE TABLE IF NOT EXISTS dynamic_jobs (
                    job_id        TEXT PRIMARY KEY,
                    scan_id       TEXT REFERENCES scans(scan_id),
                    finding_index INTEGER,
                    finding_title TEXT,
                    status        TEXT NOT NULL DEFAULT 'queued',
                    progress      INTEGER DEFAULT 0,
                    message       TEXT,
                    logcat        TEXT,
                    evidence      TEXT,
                    verdict_json  TEXT,
                    created_at    REAL,
                    updated_at    REAL
                );
                CREATE TABLE IF NOT EXISTS finding_triage (
                    scan_id          TEXT NOT NULL,
                    finding_id       INTEGER NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'New',
                    suppression_note TEXT DEFAULT '',
                    updated_at       REAL,
                    PRIMARY KEY (scan_id, finding_id)
                );
            """)
            # Additive migrations — safe to run on every startup
            for _migration in [
                "ALTER TABLE scans ADD COLUMN risk_score REAL DEFAULT NULL",
                "ALTER TABLE scans ADD COLUMN platform TEXT DEFAULT 'android'",
            ]:
                try:
                    c.execute(_migration)
                except Exception:
                    pass  # column already exists


def migrate_from_files(reports_folder: Path) -> None:
    """Seed DB from existing summary.json files on first run."""
    if not reports_folder.exists():
        return
    with _lock:
        with _conn() as c:
            for d in reports_folder.iterdir():
                sf = d / "summary.json"
                if not sf.exists():
                    continue
                try:
                    data    = json.loads(sf.read_text())
                    scan_id = data.get("scan_id")
                    if not scan_id:
                        continue
                    exists = c.execute(
                        "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
                    ).fetchone()
                    if not exists:
                        mtime = sf.stat().st_mtime
                        c.execute(
                            """INSERT OR IGNORE INTO scans
                               (scan_id, status, progress, message, package, apk,
                                total_findings, severity_json, created_at, updated_at)
                               VALUES (?,?,?,?,?,?,?,?,?,?)""",
                            (
                                scan_id, "done", 100, "Migrated from filesystem",
                                data.get("package"), data.get("apk"),
                                data.get("total_findings", 0),
                                json.dumps(data.get("severity_counts", {})),
                                mtime, mtime,
                            ),
                        )
                except Exception:
                    pass


# ── Scan helpers ─────────────────────────────────────────────────────────────

def upsert_scan(scan_id: str, **kwargs: Any) -> None:
    now    = time.time()
    fields = {"updated_at": now}
    fields.update(kwargs)

    # Serialize severity_counts dict if passed
    if "severity_counts" in fields:
        fields["severity_json"] = json.dumps(fields.pop("severity_counts"))
    if "total" in fields:
        fields["total_findings"] = fields.pop("total")

    cols   = [c for c in fields.keys() if c in _SCAN_COLS]
    vals   = [fields[c] for c in cols]

    with _lock:
        with _conn() as c:
            # Ensure row exists first
            c.execute(
                "INSERT OR IGNORE INTO scans (scan_id, created_at, updated_at) VALUES (?,?,?)",
                (scan_id, now, now),
            )
            set_clause = ", ".join(f"{col} = ?" for col in cols)
            c.execute(
                f"UPDATE scans SET {set_clause} WHERE scan_id = ?",
                vals + [scan_id],
            )


def get_scan(scan_id: str) -> Optional[Dict]:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    return _scan_row(row) if row else None


def list_scans(limit: int = 500, offset: int = 0) -> List[Dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM scans ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [_scan_row(r) for r in rows]


def delete_scan(scan_id: str) -> None:
    with _lock:
        with _conn() as c:
            c.execute("DELETE FROM finding_triage WHERE scan_id = ?", (scan_id,))
            c.execute("DELETE FROM dynamic_jobs WHERE scan_id = ?", (scan_id,))
            c.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))


def _scan_row(row: sqlite3.Row) -> Dict:
    d = dict(row)
    sev_raw = d.pop("severity_json", None)
    d["severity_counts"] = json.loads(sev_raw) if sev_raw else {}
    return d


# ── Dynamic job helpers ───────────────────────────────────────────────────────

def upsert_job(job_id: str, **kwargs: Any) -> None:
    now    = time.time()
    fields = {"updated_at": now}
    fields.update(kwargs)

    if "verdict" in fields and isinstance(fields["verdict"], (dict, list)):
        fields["verdict_json"] = json.dumps(fields.pop("verdict"))
    elif "verdict" in fields:
        fields["verdict_json"] = fields.pop("verdict")

    cols = [c for c in fields.keys() if c in _JOB_COLS]
    vals = [fields[c] for c in cols]

    with _lock:
        with _conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO dynamic_jobs (job_id, created_at, updated_at) VALUES (?,?,?)",
                (job_id, now, now),
            )
            set_clause = ", ".join(f"{col} = ?" for col in cols)
            c.execute(
                f"UPDATE dynamic_jobs SET {set_clause} WHERE job_id = ?",
                vals + [job_id],
            )


def get_job(job_id: str) -> Optional[Dict]:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM dynamic_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
    return _job_row(row) if row else None


def list_jobs(limit: int = 50) -> List[Dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM dynamic_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_job_row(r) for r in rows]


def _job_row(row: sqlite3.Row) -> Dict:
    d = dict(row)
    verdict_raw = d.pop("verdict_json", None)
    d["verdict"] = json.loads(verdict_raw) if verdict_raw else None
    return d


# ── Finding triage helpers ────────────────────────────────────────────────────

def upsert_triage(scan_id: str, finding_id: int, status: str,
                  suppression_note: str = "") -> None:
    """Create or update triage status for a single finding."""
    now = time.time()
    with _lock:
        with _conn() as c:
            c.execute(
                """INSERT INTO finding_triage (scan_id, finding_id, status, suppression_note, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, finding_id)
                   DO UPDATE SET status=excluded.status,
                                 suppression_note=excluded.suppression_note,
                                 updated_at=excluded.updated_at""",
                (scan_id, finding_id, status, suppression_note, now),
            )


def get_triage_map(scan_id: str) -> Dict[int, Dict]:
    """Return {finding_id: {status, suppression_note}} for all triaged findings."""
    with _conn() as c:
        rows = c.execute(
            "SELECT finding_id, status, suppression_note FROM finding_triage WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
    return {r["finding_id"]: {"status": r["status"], "suppression_note": r["suppression_note"]}
            for r in rows}
