"""
Secret Scanner API — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pure-Python secret detection scanner. Scans URLs, domains, and GitHub orgs/users
for exposed API keys, credentials, private keys, and sensitive files.

No external tools required (no TruffleHog, no Gitleaks).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.config import get_settings as _get_settings
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/secrets", tags=["Secret Scanner"])

# ── Filesystem history (org-scoped) ───────────────────────────────────────────

def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "secret_scanner" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_scan_result(org_id: str, record: dict) -> None:
    """Persist a completed scan record as JSON."""
    try:
        path = _history_dir(org_id) / f"{record['id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
    """Load scan history for an org, newest first."""
    try:
        files = sorted(
            _history_dir(org_id).glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )[:limit]
        records = []
        for f in files:
            try:
                records.append(json.loads(f.read_text()))
            except Exception:
                pass
        return records
    except Exception:
        return []


def _load_scan(org_id: str, scan_id: str) -> dict | None:
    """Load a single scan record by ID."""
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return None


def _delete_scan(org_id: str, scan_id: str) -> bool:
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            path.unlink()
            return True
    except Exception:
        pass
    return False


# ── Secret patterns ────────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # AWS
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Key", "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "severity": "critical"},
    # Generic API keys
    {"name": "Generic API Key", "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\"\s:=]+([a-zA-Z0-9_\-]{20,})", "severity": "high"},
    # JWT
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "severity": "high"},
    # Private keys
    {"name": "RSA Private Key", "pattern": r"-----BEGIN RSA PRIVATE KEY-----", "severity": "critical"},
    {"name": "Private Key", "pattern": r"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
    # Stripe
    {"name": "Stripe Secret Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "critical"},
    {"name": "Stripe Publishable Key", "pattern": r"pk_live_[0-9a-zA-Z]{24,}", "severity": "high"},
    # GitHub
    {"name": "GitHub Token", "pattern": r"ghp_[0-9a-zA-Z]{36}", "severity": "critical"},
    {"name": "GitHub OAuth", "pattern": r"gho_[0-9a-zA-Z]{36}", "severity": "critical"},
    # Google
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    # Slack
    {"name": "Slack Token", "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "severity": "high"},
    # Generic secrets
    {"name": "Generic Secret", "pattern": r"(?i)(secret|password|passwd|pwd)['\"\s:=]+['\"]([^'\"]{8,})['\"]", "severity": "medium"},
    # Database URLs
    {"name": "Database URL", "pattern": r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]{10,}", "severity": "high"},
    # Private IP leakage
    {"name": "Internal IP", "pattern": r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b", "severity": "low"},
    # Source map
    {"name": "Source Map Exposed", "pattern": r"sourceMappingURL=(.+\.map)", "severity": "medium"},
]

# Pre-compile patterns once
_COMPILED_PATTERNS = [
    {**p, "_re": re.compile(p["pattern"])}
    for p in SECRET_PATTERNS
]

# Sensitive file paths to probe
SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/secrets.json",
    "/credentials.json",
    "/aws.json",
    "/database.yml",
    "/wp-config.php",
    "/settings.py",
    "/local_settings.py",
    "/application.properties",
    "/application.yml",
    "/appsettings.json",
]

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB
REQUEST_TIMEOUT = 10.0


# ── Helper utilities ───────────────────────────────────────────────────────────

def _truncate_match(m: str) -> str:
    """Truncate a secret match to first 8 chars for safe display."""
    if len(m) <= 8:
        return m + "..."
    return m[:8] + "..."


def _extract_context(content: str, match_start: int, match_end: int, window: int = 80) -> str:
    """Extract surrounding context around a match, truncated."""
    start = max(0, match_start - window)
    end = min(len(content), match_end + window)
    snippet = content[start:end].replace("\n", " ").strip()
    if len(snippet) > 200:
        snippet = snippet[:200] + "..."
    return snippet


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _is_binary_content_type(ct: str) -> bool:
    ct = ct.lower()
    binary_types = (
        "image/", "audio/", "video/", "application/octet-stream",
        "application/zip", "application/gzip", "application/pdf",
        "application/wasm", "font/",
    )
    return any(ct.startswith(b) for b in binary_types)


def _extract_domain(target: str) -> str:
    """Extract bare domain from a URL or return as-is."""
    if target.startswith("http"):
        return urlparse(target).netloc.split(":")[0]
    return target.split("/")[0].split(":")[0]


def _ensure_scheme(url: str) -> str:
    if not url.startswith("http"):
        return "https://" + url
    return url


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ── Core scanning logic ────────────────────────────────────────────────────────

def _scan_content_for_secrets(content: str, source_url: str) -> list[dict]:
    """Run all patterns against text content, return list of findings."""
    findings = []
    seen: set[str] = set()

    for pat in _COMPILED_PATTERNS:
        for m in pat["_re"].finditer(content):
            raw = m.group(0)
            dedup_key = f"{pat['name']}:{source_url}:{raw[:16]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            line_num = _get_line_number(content, m.start())
            context = _extract_context(content, m.start(), m.end())

            findings.append({
                "type": "secret",
                "name": pat["name"],
                "severity": pat["severity"],
                "url": source_url,
                "match": _truncate_match(raw),
                "line_number": line_num,
                "context": context,
            })

    return findings


async def _fetch_text(client: httpx.AsyncClient, url: str) -> tuple[str | None, int]:
    """
    Fetch URL, return (text_content, status_code).
    Returns (None, status_code) for binary, too-large, or error responses.
    """
    try:
        async with client.stream("GET", url, timeout=REQUEST_TIMEOUT, follow_redirects=True) as resp:
            if resp.status_code != 200:
                return None, resp.status_code

            ct = resp.headers.get("content-type", "")
            if _is_binary_content_type(ct):
                return None, resp.status_code

            chunks = []
            size = 0
            async for chunk in resp.aiter_bytes(8192):
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    break
                chunks.append(chunk)

            raw_bytes = b"".join(chunks)
            try:
                return raw_bytes.decode("utf-8", errors="replace"), resp.status_code
            except Exception:
                return None, resp.status_code
    except Exception:
        return None, 0


async def _fetch_json(client: httpx.AsyncClient, url: str) -> dict | list | None:
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    """Parse HTML for <script src="..."> tags and return absolute JS URLs."""
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        abs_url = urljoin(base_url, src)
        if abs_url.startswith("http") and abs_url not in urls:
            urls.append(abs_url)
    return urls


# ── SSE stream generator ───────────────────────────────────────────────────────

async def _stream_secret_scan(
    scan_id: str,
    org_id: str,
    req: "SecretScanRequest",
    request: Request,
) -> AsyncGenerator[str, None]:
    start_time = time.monotonic()
    findings: list[dict] = []
    files_scanned = 0

    def _disconnected_check() -> bool:
        return False  # checked via request.is_disconnected() below

    async def _check_disconnect() -> bool:
        try:
            return await request.is_disconnected()
        except Exception:
            return False

    yield _sse("start", {
        "scan_id": scan_id,
        "target": req.target,
        "scan_type": req.scan_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    headers: dict[str, str] = {
        "User-Agent": "AttackTrace-SecretScanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml,application/json,*/*",
    }
    if req.github_token:
        headers["Authorization"] = f"token {req.github_token}"

    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:

        # ── Phase 1: JS File Discovery (URL/domain targets) ────────────────────
        js_urls: list[str] = []

        if req.scan_type in ("url", "github_repo"):
            target_url = _ensure_scheme(req.target)
            domain = _extract_domain(target_url)

            yield _sse("progress", {
                "phase": "js_discovery",
                "message": f"Probing {target_url} for JS files...",
                "count": 0,
            })

            # Probe common root paths
            probe_paths = ["/", "/app.js", "/bundle.js", "/main.js", "/index.js",
                           "/static/js/main.js", "/assets/index.js", "/js/app.js",
                           "/dist/bundle.js", "/build/static/js/main.js"]

            for path in probe_paths:
                if await _check_disconnect():
                    return
                url = urljoin(target_url, path)
                text, code = await _fetch_text(client, url)
                if text is None:
                    continue

                if path == "/" or path.endswith(".html"):
                    # Parse HTML for script tags
                    extracted = _extract_js_urls(text, target_url)
                    for js_url in extracted:
                        if js_url not in js_urls and len(js_urls) < req.max_js_files:
                            js_urls.append(js_url)
                            yield _sse("progress", {
                                "phase": "js_discovery",
                                "message": f"Found JS file: {js_url}",
                                "count": len(js_urls),
                            })
                elif url.endswith(".js") and url not in js_urls and len(js_urls) < req.max_js_files:
                    js_urls.append(url)
                    yield _sse("progress", {
                        "phase": "js_discovery",
                        "message": f"Found JS file: {url}",
                        "count": len(js_urls),
                    })

                await asyncio.sleep(0)

            # ── Phase 2: Wayback Machine URLs ──────────────────────────────────
            if req.include_wayback:
                yield _sse("progress", {
                    "phase": "wayback",
                    "message": f"Querying Wayback CDX for {domain}...",
                    "count": len(js_urls),
                })

                wb_url = (
                    f"http://web.archive.org/cdx/search/cdx"
                    f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=500"
                )
                try:
                    wb_data = await _fetch_json(client, wb_url)
                    if isinstance(wb_data, list):
                        interesting_exts = {".js", ".json", ".env", ".config", ".xml", ".yaml", ".yml", ".ts"}
                        for row in wb_data[1:]:  # skip header row
                            if not row:
                                continue
                            wb_file_url = row[0] if isinstance(row, list) else row
                            if not isinstance(wb_file_url, str):
                                continue
                            ext = "." + wb_file_url.rsplit(".", 1)[-1].split("?")[0].lower() if "." in wb_file_url else ""
                            if ext in interesting_exts and wb_file_url not in js_urls and len(js_urls) < req.max_js_files:
                                js_urls.append(wb_file_url)
                                yield _sse("progress", {
                                    "phase": "wayback",
                                    "message": f"Wayback: {wb_file_url}",
                                    "count": len(js_urls),
                                })
                        await asyncio.sleep(0)
                except Exception:
                    pass

        # ── Phase 3: Secret Detection ──────────────────────────────────────────
        yield _sse("progress", {
            "phase": "secret_scan",
            "message": f"Scanning {len(js_urls)} files for secrets...",
            "count": 0,
        })

        for file_url in js_urls:
            if await _check_disconnect():
                return

            text, code = await _fetch_text(client, file_url)
            if text is None:
                continue

            files_scanned += 1
            new_findings = _scan_content_for_secrets(text, file_url)

            for f in new_findings:
                findings.append(f)
                yield _sse("finding", {"data": f})

            yield _sse("progress", {
                "phase": "secret_scan",
                "message": f"Scanned: {file_url}",
                "count": files_scanned,
            })
            await asyncio.sleep(0)

        # ── Phase 4: .git Directory & Sensitive File Check ─────────────────────
        if req.scan_type in ("url",):
            target_url = _ensure_scheme(req.target)

            yield _sse("progress", {
                "phase": "exposed_files",
                "message": "Checking for exposed .git directory and sensitive files...",
                "count": files_scanned,
            })

            git_paths = ["/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG"]
            for gp in git_paths:
                if await _check_disconnect():
                    return
                url = urljoin(target_url, gp)
                text, code = await _fetch_text(client, url)
                if text is not None and code == 200:
                    finding = {
                        "type": "exposure",
                        "name": "Git Repository Exposed",
                        "severity": "critical",
                        "url": url,
                        "match": gp + " (accessible)",
                        "line_number": None,
                        "context": text[:200].strip(),
                    }
                    findings.append(finding)
                    yield _sse("finding", {"data": finding})
                await asyncio.sleep(0)

            for sp in SENSITIVE_PATHS:
                if await _check_disconnect():
                    return
                url = urljoin(target_url, sp)
                text, code = await _fetch_text(client, url)
                if text is not None and code == 200 and len(text.strip()) > 0:
                    files_scanned += 1
                    # Scan the sensitive file for secrets
                    new_findings = _scan_content_for_secrets(text, url)
                    for f in new_findings:
                        findings.append(f)
                        yield _sse("finding", {"data": f})

                    if not new_findings:
                        # Still report the file is accessible even if no secrets matched
                        finding = {
                            "type": "exposure",
                            "name": f"Sensitive File Exposed: {sp}",
                            "severity": "high",
                            "url": url,
                            "match": sp + " (accessible)",
                            "line_number": None,
                            "context": text[:200].strip(),
                        }
                        findings.append(finding)
                        yield _sse("finding", {"data": finding})

                    yield _sse("progress", {
                        "phase": "exposed_files",
                        "message": f"Sensitive file found: {url}",
                        "count": files_scanned,
                    })
                await asyncio.sleep(0)

        # ── Phase 5: GitHub Org/User Scan ──────────────────────────────────────
        if req.scan_type in ("github_org", "github_user"):
            target_name = req.target.strip("/").split("/")[-1]

            if req.scan_type == "github_org":
                repos_url = f"https://api.github.com/orgs/{target_name}/repos?per_page=100&type=public"
            else:
                repos_url = f"https://api.github.com/users/{target_name}/repos?per_page=100&type=public"

            gh_headers = {"Accept": "application/vnd.github+json"}
            if req.github_token:
                gh_headers["Authorization"] = f"Bearer {req.github_token}"

            yield _sse("progress", {
                "phase": "github_enum",
                "message": f"Enumerating public repos for {target_name}...",
                "count": 0,
            })

            try:
                resp = await client.get(repos_url, headers=gh_headers, timeout=REQUEST_TIMEOUT)
                repos = resp.json() if resp.status_code == 200 else []
                if not isinstance(repos, list):
                    repos = []
            except Exception:
                repos = []

            sensitive_filenames = {
                ".env", ".env.local", ".env.production", "secrets.json",
                "credentials.json", "config.json", "aws.json", ".aws/credentials",
                "service-account.json", "keyfile.json", "private.pem",
            }

            for repo in repos[:50]:  # cap at 50 repos
                if await _check_disconnect():
                    return
                if not isinstance(repo, dict):
                    continue

                repo_name = repo.get("name", "")
                default_branch = repo.get("default_branch", "main")
                full_name = repo.get("full_name", f"{target_name}/{repo_name}")

                yield _sse("progress", {
                    "phase": "github_enum",
                    "message": f"Checking repo: {full_name}",
                    "count": files_scanned,
                })

                # Check description and README for secrets
                desc = repo.get("description") or ""
                if desc:
                    new_findings = _scan_content_for_secrets(desc, f"https://github.com/{full_name}")
                    for f in new_findings:
                        findings.append(f)
                        yield _sse("finding", {"data": f})

                # Use GitHub tree API to find sensitive files
                tree_url = (
                    f"https://api.github.com/repos/{full_name}/git/trees/{default_branch}"
                    f"?recursive=1"
                )
                try:
                    tree_resp = await client.get(tree_url, headers=gh_headers, timeout=REQUEST_TIMEOUT)
                    if tree_resp.status_code == 200:
                        tree_data = tree_resp.json()
                        for item in (tree_data.get("tree") or []):
                            item_path = item.get("path", "")
                            filename = item_path.split("/")[-1].lower()
                            if filename in sensitive_filenames:
                                raw_url = (
                                    f"https://raw.githubusercontent.com/{full_name}"
                                    f"/{default_branch}/{item_path}"
                                )
                                text, code = await _fetch_text(client, raw_url)
                                if text and code == 200:
                                    files_scanned += 1
                                    new_findings = _scan_content_for_secrets(text, raw_url)
                                    for f in new_findings:
                                        findings.append(f)
                                        yield _sse("finding", {"data": f})

                                    if not new_findings:
                                        # Report accessible sensitive file even without pattern match
                                        f = {
                                            "type": "exposure",
                                            "name": f"Sensitive File in Repo: {filename}",
                                            "severity": "high",
                                            "url": raw_url,
                                            "match": item_path + " (accessible)",
                                            "line_number": None,
                                            "context": text[:200].strip(),
                                        }
                                        findings.append(f)
                                        yield _sse("finding", {"data": f})

                                    yield _sse("progress", {
                                        "phase": "github_enum",
                                        "message": f"Found sensitive file: {item_path} in {full_name}",
                                        "count": files_scanned,
                                    })
                                await asyncio.sleep(0)
                except Exception:
                    pass

                await asyncio.sleep(0)

    # ── Finalize ───────────────────────────────────────────────────────────────
    duration = round(time.monotonic() - start_time, 2)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1

    stats = {**severity_counts, "files_scanned": files_scanned}

    record = {
        "id": scan_id,
        "org_id": org_id,
        "target": req.target,
        "scan_type": req.scan_type,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "stats": stats,
        "duration_seconds": duration,
    }
    _save_scan_result(org_id, record)

    yield _sse("complete", {
        "scan_id": scan_id,
        "total_findings": len(findings),
        **severity_counts,
        "files_scanned": files_scanned,
        "duration_seconds": duration,
    })


# ── Request schema ─────────────────────────────────────────────────────────────

class SecretScanRequest(BaseModel):
    target: str
    scan_type: str = "url"  # "url", "github_org", "github_user", "git_repo"
    github_token: str | None = None
    include_wayback: bool = True
    max_js_files: int = 100


# ── History endpoints ──────────────────────────────────────────────────────────

@router.get("/history", summary="List secret scan history")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: str = Depends(get_current_org_id),
) -> dict:
    records = _load_history(str(org_id))
    # Return lightweight summaries (no full findings list)
    summaries = []
    for r in records:
        summaries.append({
            "id": r.get("id"),
            "target": r.get("target"),
            "scan_type": r.get("scan_type"),
            "started_at": r.get("started_at"),
            "completed_at": r.get("completed_at"),
            "stats": r.get("stats", {}),
            "duration_seconds": r.get("duration_seconds"),
        })
    return {"items": summaries, "total": len(summaries)}


@router.get("/history/{scan_id}", summary="Get single secret scan result")
async def get_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: str = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a secret scan result")
async def delete_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: str = Depends(get_current_org_id),
) -> dict:
    deleted = _delete_scan(str(org_id), scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"ok": True, "scan_id": scan_id}


# ── Scan endpoint ──────────────────────────────────────────────────────────────

@router.post("/scan", summary="Start a secret scan and stream results via SSE")
async def run_secret_scan(
    payload: SecretScanRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: str = Depends(get_current_org_id),
) -> StreamingResponse:
    if not payload.target.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target is required",
        )

    # Clamp max_js_files to a safe upper bound
    payload.max_js_files = min(payload.max_js_files, 500)

    scan_id = str(_uuid_mod.uuid4())

    return StreamingResponse(
        _stream_secret_scan(scan_id, str(org_id), payload, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
