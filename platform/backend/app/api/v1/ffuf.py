"""
ffuf web fuzzer API — runs ffuf and streams results via SSE.
"""

import asyncio
import base64
import json
import os
import re
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.models.db.asset import AssetType
from app.models.db.audit import AuditLog
from app.models.db.user import User
from app.services.asset_upsert import upsert_asset_async

router = APIRouter(prefix="/ffuf", tags=["ffuf"])

_scan_history: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Bundled wordlists (committed to the repo — always available)
# This file lives at: {repo}/platform/backend/app/api/v1/ffuf.py
# Repo root is 5 levels up.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[5]
_BUNDLED_DIR = _REPO_ROOT / "wordlists"

# System/tool wordlist locations (resolved at runtime — only present if installed)
_HOME = Path.home()
_NUCLEI_WORDLISTS = _HOME / "nuclei-templates" / "helpers" / "wordlists"

# SecLists standard locations across macOS (brew) and Linux
_SECLISTS_ROOTS = [
    Path("/opt/homebrew/share/seclists"),   # macOS brew (Apple Silicon)
    Path("/usr/local/share/seclists"),       # macOS brew (Intel)
    Path("/usr/share/seclists"),             # Debian/Kali
    Path("/opt/SecLists"),                   # manual install
    _HOME / "SecLists",                      # home directory install
]

def _seclists() -> Path | None:
    for p in _SECLISTS_ROOTS:
        if p.is_dir():
            return p
    return None


def _w(label: str, rel: str, category: str, base: Path) -> tuple[str, str, str]:
    """Build a (label, absolute_path, category) entry if the file exists."""
    return (label, str(base / rel), category)


def _build_known_wordlists() -> list[tuple[str, str, str]]:
    """
    Build the full candidate list at import time.
    Paths are absolute; we check existence in list_wordlists() / _detect_wordlist().
    """
    entries: list[tuple[str, str, str]] = []

    # ── Bundled wordlists (always in repo) ──────────────────────────────────
    entries += [
        ("Common Paths (bundled)",     str(_BUNDLED_DIR / "web"  / "common.txt"),      "Bundled"),
        ("API Endpoints (bundled)",    str(_BUNDLED_DIR / "api"  / "endpoints.txt"),   "Bundled"),
        ("Subdomains (bundled)",       str(_BUNDLED_DIR / "dns"  / "subdomains.txt"),  "Bundled"),
    ]

    # ── Nuclei helper wordlists (if nuclei-templates installed) ─────────────
    if _NUCLEI_WORDLISTS.is_dir():
        nuclei_entries = [
            ("Adminer Paths",     "adminer-paths.txt",       "Web Content"),
            ("Grafana Plugins",   "grafana-plugins.txt",     "Web Content"),
            ("MDB Paths",         "mdb-paths.txt",           "Web Content"),
            ("URL Params",        "params.txt",              "Fuzzing"),
            ("WordPress Plugins", "wordpress-plugins.txt",   "Web Content"),
            ("WordPress Themes",  "wordpress-themes.txt",    "Web Content"),
            ("WP Users",          "wp-users.txt",            "Web Content"),
            ("WP Passwords",      "wp-passwords.txt",        "Web Content"),
            ("User List",         "user-list.txt",           "Fuzzing"),
            ("Numbers",           "numbers.txt",             "Fuzzing"),
        ]
        for label, fname, cat in nuclei_entries:
            entries.append(_w(f"{label} (nuclei)", fname, cat, _NUCLEI_WORDLISTS))

    # ── SecLists (if installed via brew / apt / manual) ─────────────────────
    sl = _seclists()
    if sl:
        seclists_entries = [
            ("Common",                   "Discovery/Web-Content/common.txt",                              "Web Content"),
            ("Big",                      "Discovery/Web-Content/big.txt",                                 "Web Content"),
            ("Directory Medium",         "Discovery/Web-Content/directory-list-2.3-medium.txt",           "Web Content"),
            ("Directory Small",          "Discovery/Web-Content/directory-list-2.3-small.txt",            "Web Content"),
            ("Raft Medium Dirs",         "Discovery/Web-Content/raft-medium-directories.txt",             "Web Content"),
            ("Raft Small Dirs",          "Discovery/Web-Content/raft-small-directories.txt",              "Web Content"),
            ("Raft Medium Files",        "Discovery/Web-Content/raft-medium-files.txt",                   "Web Content"),
            ("Raft Small Files",         "Discovery/Web-Content/raft-small-files.txt",                    "Web Content"),
            ("Raft Medium Words",        "Discovery/Web-Content/raft-medium-words.txt",                   "Web Content"),
            ("API Endpoints",            "Discovery/Web-Content/api/api-endpoints.txt",                   "API"),
            ("API Objects",              "Discovery/Web-Content/api/objects.txt",                         "API"),
            ("Subdomains Top 5000",      "Discovery/DNS/subdomains-top1million-5000.txt",                 "DNS"),
            ("Subdomains Top 20000",     "Discovery/DNS/subdomains-top1million-20000.txt",                "DNS"),
            ("Fuzz Bo0oM",               "Fuzzing/fuzz-Bo0oM.txt",                                       "Fuzzing"),
            ("LFI Linux",                "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",                   "Fuzzing"),
        ]
        for label, rel, cat in seclists_entries:
            entries.append(_w(f"{label} (SecLists)", rel, cat, sl))

    # ── DirBuster / Dirb (Kali / Debian) ────────────────────────────────────
    dirb_root = Path("/usr/share/wordlists")
    if dirb_root.is_dir():
        entries += [
            _w("Directory Medium (DirBuster)", "dirbuster/directory-list-2.3-medium.txt", "Web Content", dirb_root),
            _w("Directory Small (DirBuster)",  "dirbuster/directory-list-2.3-small.txt",  "Web Content", dirb_root),
            _w("Common (Dirb)",                "dirb/common.txt",                         "Web Content", dirb_root),
            _w("Big (Dirb)",                   "dirb/big.txt",                            "Web Content", dirb_root),
        ]

    return entries


_KNOWN_WORDLISTS: list[tuple[str, str, str]] = _build_known_wordlists()


def _discover_dynamic_wordlists() -> list[tuple[str, str, str]]:
    """Scan home-directory locations for any .txt wordlists not already known."""
    known_paths = {path for _, path, _ in _KNOWN_WORDLISTS}
    extra: list[tuple[str, str, str]] = []
    scan_dirs = [
        str(_HOME / "wordlists"),
        str(_HOME / "tools" / "wordlists"),
        "/usr/local/share/wordlists",
    ]
    for d in scan_dirs:
        if not os.path.isdir(d):
            continue
        import glob
        for txt in glob.glob(os.path.join(d, "**", "*.txt"), recursive=True):
            if txt not in known_paths and os.path.isfile(txt):
                label = os.path.basename(txt).replace(".txt", "").replace("-", " ").replace("_", " ").title()
                extra.append((f"{label} (custom)", txt, "Custom"))
    return extra


HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


class FfufScanRequest(BaseModel):
    url: str
    wordlist: str | None = None
    method: str = "GET"
    headers: dict[str, str] | None = None
    data: str | None = None
    match_codes: list[int] | None = None
    filter_codes: list[int] | None = None
    match_size: list[int] | None = None
    filter_size: list[int] | None = None
    threads: int = 40
    rate: int | None = None
    timeout: int = 10
    follow_redirects: bool = False
    recursion: bool = False
    recursion_depth: int = 2
    extensions: list[str] | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL is required")
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("URL contains invalid characters")
        if not re.match(r"^https?://", v, re.IGNORECASE):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        v = v.upper()
        if v not in HTTP_METHODS:
            raise ValueError(f"Method must be one of {HTTP_METHODS}")
        return v

    @field_validator("threads")
    @classmethod
    def validate_threads(cls, v: int) -> int:
        if not (1 <= v <= 200):
            raise ValueError("Threads must be between 1 and 200")
        return v


def _detect_wordlist() -> str | None:
    """Return the first available wordlist — bundled ones come first."""
    for _, path, _ in _KNOWN_WORDLISTS:
        if os.path.isfile(path):
            return path
    return None


def _build_ffuf_cmd(req: FfufScanRequest, wordlist_path: str, output_file: str) -> list[str]:
    ffuf_bin = shutil.which("ffuf") or "ffuf"
    cmd = [
        ffuf_bin,
        "-u", req.url,
        "-w", wordlist_path,
        # Write ejson to a temp file so we can read structured JSON results.
        # ffuf with -of ejson and no -o writes plain text to stdout (not JSON),
        # so we must use -o <file> to get JSON output.
        "-of", "ejson",
        "-o", output_file,
        "-t", str(req.threads),
        "-timeout", str(req.timeout),
        "-X", req.method,
        "-s",  # silent banner
    ]

    if req.match_codes:
        cmd.extend(["-mc", ",".join(str(c) for c in req.match_codes)])
    else:
        cmd.extend(["-mc", "200,204,301,302,307,401,403,405"])

    if req.filter_codes:
        cmd.extend(["-fc", ",".join(str(c) for c in req.filter_codes)])

    if req.match_size:
        cmd.extend(["-ms", ",".join(str(s) for s in req.match_size)])

    if req.filter_size:
        cmd.extend(["-fs", ",".join(str(s) for s in req.filter_size)])

    if req.rate:
        cmd.extend(["-rate", str(req.rate)])

    if req.follow_redirects:
        cmd.append("-r")

    if req.recursion:
        cmd.extend(["-recursion", "-recursion-depth", str(req.recursion_depth)])

    if req.extensions:
        safe_exts = [e.lstrip(".") for e in req.extensions[:10] if re.match(r"^[a-zA-Z0-9]+$", e.lstrip("."))]
        if safe_exts:
            cmd.extend(["-e", ",".join(f".{e}" for e in safe_exts)])

    if req.headers:
        for key, value in list(req.headers.items())[:20]:
            if re.match(r"^[\w\-]+$", key):
                # strip CRLF from values to prevent header injection
                safe_val = re.sub(r"[\r\n]", "", value)
                cmd.extend(["-H", f"{key}: {safe_val}"])

    if req.data and req.method in ("POST", "PUT", "PATCH"):
        cmd.extend(["-d", req.data])

    return cmd


def _decode_b64(value: str) -> str:
    """Decode a base64-encoded ffuf input value, falling back to the raw value."""
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except Exception:
        return value


def _parse_ejson_file(path: str) -> list[dict]:
    """
    Parse ffuf's ejson output file.

    ffuf -of ejson -o <file> writes a single JSON object at scan completion:
      {"commandline": "...", "results": [{...}, ...], ...}

    Each result entry has base64-encoded "input" values.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
        if not content:
            return []
        data = json.loads(content)
        raw_results = data.get("results") or []
        parsed = []
        for r in raw_results:
            fuzz_raw = r.get("input", {}).get("FUZZ", "")
            parsed.append({
                "url": r.get("url", ""),
                "input": _decode_b64(fuzz_raw) if fuzz_raw else "",
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "lines": r.get("lines", 0),
                "content_type": r.get("content-type", ""),
                "redirect_location": r.get("redirectlocation", ""),
                "duration": r.get("duration", 0),
            })
        return parsed
    except (OSError, json.JSONDecodeError, AttributeError):
        return []


async def _stream_ffuf(
    scan_id: str, req: FfufScanRequest, wordlist_path: str, request: Request,
    org_id: uuid.UUID, db: AsyncSession,
) -> AsyncGenerator[str, None]:
    # ffuf -of ejson -o <file> writes a single JSON object at exit (not streaming lines).
    # Stdout receives plain-text matched paths in real-time — useful for live progress.
    # We stream stdout as discovery events, then parse the JSON file for full results.
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".ejson", prefix="ffuf_")
    os.close(tmp_fd)

    cmd = _build_ffuf_cmd(req, wordlist_path, tmp_path)

    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _sse("start", {
        "scan_id": scan_id,
        "command": " ".join(cmd),
        "url": req.url,
        "wordlist": wordlist_path,
        "wordlist_name": os.path.basename(wordlist_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    _scan_history[scan_id] = {
        "id": scan_id,
        "url": req.url,
        "wordlist": wordlist_path,
        "command": " ".join(cmd),
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "results": [],
        "total": 0,
        "org_id": str(org_id),
    }

    results: list[dict] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if proc.stdout is None:
            raise RuntimeError("Failed to open subprocess stdout pipe")
        if proc.stderr is None:
            raise RuntimeError("Failed to open subprocess stderr pipe")

        # Queue for SSE events: stdout plain-text paths + stderr progress
        queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue()

        async def _drain_stdout() -> None:
            """Stream plain-text matched paths from stdout for live discovery events."""
            async for chunk in proc.stdout:  # type: ignore[union-attr]
                line = chunk.decode("utf-8", errors="replace").rstrip()
                if line:
                    await queue.put(("out", line))
            await queue.put(None)

        async def _drain_stderr() -> None:
            async for chunk in proc.stderr:  # type: ignore[union-attr]
                line = chunk.decode("utf-8", errors="replace").rstrip()
                if line:
                    await queue.put(("err", line))
            await queue.put(None)

        t1 = asyncio.create_task(_drain_stdout())
        t2 = asyncio.create_task(_drain_stderr())

        done_count = 0
        while done_count < 2:
            item = await queue.get()
            if item is None:
                done_count += 1
                continue

            kind, line = item
            if await request.is_disconnected():
                proc.terminate()
                return
            if kind == "out":
                # stdout: plain-text path discovered — send as a live discovery hint
                yield _sse("progress", {"message": f"Found: {line}", "scan_id": scan_id})
            else:
                # stderr: ffuf progress / status bar lines
                yield _sse("progress", {"message": line, "scan_id": scan_id})

            await asyncio.sleep(0)

        await asyncio.gather(t1, t2, return_exceptions=True)
        await proc.wait()

        # Parse the ejson output file now that ffuf has written its complete results
        results = _parse_ejson_file(tmp_path)
        _scan_history[scan_id]["results"] = results
        _scan_history[scan_id]["total"] = len(results)

        # Emit all results
        for result in results:
            yield _sse("result", result)

        _scan_history[scan_id].update({
            "status": "completed" if proc.returncode == 0 else "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "results": results,
            "total": len(results),
            "exit_code": proc.returncode,
        })

        # Persist live discovered paths onto the parent host's Asset record —
        # this was never written anywhere before (ffuf results were SSE-only
        # + an in-memory dict lost on restart).
        try:
            hostname = urlparse(req.url).hostname
            if hostname:
                discovered_paths = [
                    {"url": r["url"], "status": r["status"], "length": r["length"]}
                    for r in results if r.get("status", 0) < 400
                ][:200]
                if discovered_paths:
                    await upsert_asset_async(
                        db, org_id, AssetType.SUBDOMAIN, hostname,
                        {"discovered_paths": discovered_paths},
                    )
                    await db.commit()
        except Exception:
            await db.rollback()

        yield _sse("complete", {
            "scan_id": scan_id,
            "total": len(results),
            "exit_code": proc.returncode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        yield _sse("error", {"message": str(exc)})
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


@router.get("/wordlists", summary="List available wordlists on this server")
async def list_wordlists(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict]:
    seen: set[str] = set()
    result = []
    all_lists = _KNOWN_WORDLISTS + _discover_dynamic_wordlists()
    for label, path, category in all_lists:
        if path in seen:
            continue
        if os.path.isfile(path):
            seen.add(path)
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as f:
                    lines = sum(1 for _ in f)
            except Exception:
                size = 0
                lines = 0
            result.append({
                "label": label,
                "path": path,
                "category": category,
                "size_bytes": size,
                "line_count": lines,
            })
    return result


@router.post("/scan", summary="Run an ffuf scan and stream results via SSE")
async def run_ffuf_scan(
    payload: FfufScanRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("ffuf"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    if not shutil.which("ffuf"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ffuf is not installed. Run: brew install ffuf (macOS) or go install github.com/ffuf/ffuf/v2@latest",
        )

    wordlist = payload.wordlist
    if wordlist:
        # Resolve and validate path — must be an actual file (no directory traversal)
        resolved = Path(wordlist).resolve()
        if not resolved.is_file():
            raise HTTPException(status_code=400, detail=f"Wordlist not found: {wordlist}")
        wordlist = str(resolved)
    else:
        wordlist = _detect_wordlist()
        if not wordlist:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "No wordlist found. The bundled wordlists should always be present — "
                    "check that the repo's wordlists/ directory exists."
                ),
            )

    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.ffuf.scan",
        resource_type="ffuf_scan",
        resource_id=scan_id,
        after_state={"url": payload.url},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return StreamingResponse(
        _stream_ffuf(scan_id, payload, wordlist, request, org_id, db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans", summary="List ffuf scan history")
async def list_ffuf_scans(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scans = sorted(
        (s for s in _scan_history.values() if s.get("org_id") == str(org_id)),
        key=lambda s: s.get("started_at", ""), reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}", summary="Get ffuf scan result")
async def get_ffuf_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan or scan.get("org_id") != str(org_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
