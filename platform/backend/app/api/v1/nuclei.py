"""
Nuclei scanner API — runs nuclei and streams results via SSE.
"""

import asyncio
import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.core.dependencies import get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/nuclei", tags=["Nuclei"])

_scan_history: dict[str, dict] = {}

TEMPLATE_CATEGORIES = [
    "cves",
    "exposures",
    "misconfiguration",
    "takeovers",
    "technologies",
    "default-logins",
    "fuzzing",
    "workflows",
    "network",
    "dns",
    "ssl",
    "headless",
    "file",
    "code",
]


class NucleiScanRequest(BaseModel):
    target: str
    templates: list[str] | None = None          # specific template IDs
    categories: list[str] | None = None          # category tags
    custom_template_dir: str | None = None
    concurrency: int = 25
    rate_limit: int = 150
    timeout: int = 10
    follow_redirects: bool = True
    severity: list[str] | None = None           # filter by severity

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Target contains invalid characters")
        return v

    @field_validator("concurrency")
    @classmethod
    def validate_concurrency(cls, v: int) -> int:
        if not (1 <= v <= 200):
            raise ValueError("Concurrency must be between 1 and 200")
        return v

    @field_validator("rate_limit")
    @classmethod
    def validate_rate_limit(cls, v: int) -> int:
        if not (1 <= v <= 1000):
            raise ValueError("Rate limit must be between 1 and 1000")
        return v


def _find_templates_dir() -> Path | None:
    """Locate the nuclei-templates directory on this machine."""
    home = Path.home()
    candidates = [
        home / "nuclei-templates",
        home / ".local" / "nuclei-templates",
        Path("/nuclei-templates"),
        Path("/opt/nuclei-templates"),
    ]
    # Check for known nuclei-templates subdirectories (fast, no rglob needed)
    _marker_dirs = {"http", "dns", "ssl", "cves", "network", "file"}
    for d in candidates:
        if d.is_dir() and any((d / sub).is_dir() for sub in _marker_dirs):
            return d
    return None


def _build_nuclei_cmd(req: NucleiScanRequest) -> list[str]:
    nuclei_bin = shutil.which("nuclei") or "nuclei"
    # -j:       JSONL findings to stdout (NOT -json-export which writes to a file)
    # -stats:   progress stats to stderr
    # -no-color: clean stderr output (no ANSI escape codes)
    cmd = [nuclei_bin, "-target", req.target, "-j", "-stats", "-no-color"]

    templates_dir = _find_templates_dir()

    if req.custom_template_dir:
        safe_dir = Path(req.custom_template_dir)
        if safe_dir.is_dir():
            cmd.extend(["-t", str(safe_dir)])
    elif req.templates:
        # template browser returns IDs — use -id flag (requires nuclei to know templates dir)
        if templates_dir:
            cmd.extend(["-t", str(templates_dir)])
        for t in req.templates[:50]:
            cmd.extend(["-id", t])
    elif req.categories:
        # -tags needs a base templates dir to search within
        if templates_dir:
            cmd.extend(["-t", str(templates_dir)])
        for c in req.categories:
            if c in TEMPLATE_CATEGORIES:
                cmd.extend(["-tags", c])
    else:
        # All templates — explicitly point at the templates directory
        if templates_dir:
            cmd.extend(["-t", str(templates_dir)])
        # If no templates dir found, nuclei will error with a clear message

    if req.severity:
        valid_severities = [s for s in req.severity if s in ("critical", "high", "medium", "low", "info")]
        if valid_severities:
            cmd.extend(["-severity", ",".join(valid_severities)])

    cmd.extend([
        "-c", str(req.concurrency),
        "-rl", str(req.rate_limit),
        "-timeout", str(req.timeout),
    ])

    if req.follow_redirects:
        cmd.append("-follow-redirects")

    return cmd


def _parse_nuclei_line(line: str) -> dict | None:
    """Parse a single JSON line from nuclei -json-export output."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        return {
            "template_id": data.get("template-id", ""),
            "name": data.get("info", {}).get("name", ""),
            "severity": data.get("info", {}).get("severity", "info"),
            "matched_url": data.get("matched-at", data.get("host", "")),
            "extracted_results": data.get("extracted-results", []),
            "matcher_name": data.get("matcher-name", ""),
            "type": data.get("type", ""),
            "ip": data.get("ip", ""),
            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "tags": data.get("info", {}).get("tags", []),
            "author": data.get("info", {}).get("authors", []),
            "reference": data.get("info", {}).get("reference", []),
            "curl_command": data.get("curl-command", ""),
            "raw": line,
        }
    except json.JSONDecodeError:
        return None


async def _stream_nuclei(scan_id: str, req: NucleiScanRequest) -> AsyncGenerator[str, None]:
    cmd = _build_nuclei_cmd(req)

    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _sse("start", {
        "scan_id": scan_id,
        "command": " ".join(cmd),
        "target": req.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    _scan_history[scan_id] = {
        "id": scan_id,
        "target": req.target,
        "command": " ".join(cmd),
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }

    findings: list[dict] = []
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert proc.stdout is not None
        assert proc.stderr is not None

        # Merge stdout (JSONL findings) and stderr (progress/stats) into one queue
        queue: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue()

        async def _drain_stdout() -> None:
            async for chunk in proc.stdout:  # type: ignore[union-attr]
                await queue.put(("out", chunk))
            await queue.put(None)  # sentinel

        async def _drain_stderr() -> None:
            async for chunk in proc.stderr:  # type: ignore[union-attr]
                await queue.put(("err", chunk))
            await queue.put(None)  # sentinel

        t1 = asyncio.create_task(_drain_stdout())
        t2 = asyncio.create_task(_drain_stderr())

        done_count = 0
        while done_count < 2:
            item = await queue.get()
            if item is None:
                done_count += 1
                continue

            kind, raw = item
            line = raw.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue

            if kind == "out":
                finding = _parse_nuclei_line(line)
                if finding:
                    findings.append(finding)
                    sev = finding.get("severity", "info").lower()
                    counts[sev] = counts.get(sev, 0) + 1
                    _scan_history[scan_id]["findings"] = findings
                    _scan_history[scan_id]["counts"] = counts
                    yield _sse("finding", finding)
            else:
                # stderr: nuclei progress/stats/errors — forward as progress event
                yield _sse("progress", {"message": line, "scan_id": scan_id})

            await asyncio.sleep(0)

        await asyncio.gather(t1, t2, return_exceptions=True)
        await proc.wait()

        _scan_history[scan_id].update({
            "status": "completed" if proc.returncode == 0 else "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "counts": counts,
            "exit_code": proc.returncode,
        })

        yield _sse("complete", {
            "scan_id": scan_id,
            "total": len(findings),
            "counts": counts,
            "exit_code": proc.returncode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        yield _sse("error", {"message": str(exc)})


@router.post("/scan", summary="Run a nuclei scan and stream results")
async def run_nuclei_scan(
    payload: NucleiScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    if not shutil.which("nuclei"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="nuclei is not installed on this server",
        )
    scan_id = str(uuid.uuid4())
    return StreamingResponse(
        _stream_nuclei(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans", summary="List nuclei scan history")
async def list_nuclei_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scans = sorted(
        _scan_history.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}", summary="Get nuclei scan result")
async def get_nuclei_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/templates/categories", summary="List template categories")
async def list_template_categories(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return {"categories": TEMPLATE_CATEGORIES}


_templates_cache: list[dict] | None = None
_templates_loading: bool = False


def _load_templates_sync() -> list[dict]:
    """Walk nuclei-templates directory and parse YAML metadata (blocking I/O)."""
    global _templates_cache
    if _templates_cache is not None:
        return _templates_cache

    import yaml  # type: ignore[import]

    home = Path.home()
    templates_dirs = [
        home / "nuclei-templates",
        home / ".local" / "nuclei-templates",
        Path("/nuclei-templates"),
    ]

    templates_dir: Path | None = None
    for d in templates_dirs:
        if d.is_dir():
            templates_dir = d
            break

    if not templates_dir:
        _templates_cache = []
        return []

    results: list[dict] = []
    for yaml_file in templates_dir.rglob("*.yaml"):
        parts = yaml_file.parts
        if any(p in {"helpers", "profiles"} for p in parts):
            continue
        try:
            with open(yaml_file, "r", errors="replace") as f:
                doc = yaml.safe_load(f)
            if not isinstance(doc, dict) or "id" not in doc:
                continue
            info = doc.get("info", {}) or {}
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            rel = str(yaml_file.relative_to(templates_dir)).replace("\\", "/")
            template_id = doc.get("id", rel.replace(".yaml", ""))

            results.append({
                "id": template_id,
                "path": rel,
                "name": info.get("name", template_id),
                "severity": (info.get("severity") or "info").lower(),
                "tags": tags,
                "author": info.get("author") or [],
                "description": (info.get("description") or "")[:200],
            })
        except Exception:
            continue

    results.sort(key=lambda t: (t["severity"], t["id"]))
    _templates_cache = results
    return results


async def preload_templates() -> None:
    """Kick off template loading in a thread pool — call from app lifespan."""
    global _templates_loading
    if _templates_cache is not None or _templates_loading:
        return
    _templates_loading = True
    try:
        await asyncio.to_thread(_load_templates_sync)
    finally:
        _templates_loading = False


async def _get_templates() -> list[dict]:
    """Return templates, loading them in a thread if not yet cached."""
    if _templates_cache is not None:
        return _templates_cache
    return await asyncio.to_thread(_load_templates_sync)


@router.get("/templates", summary="List and search nuclei templates")
async def list_templates(
    search: str = "",
    severity: str = "",
    category: str = "",
    page: int = 1,
    per_page: int = 50,
    current_user: Annotated[User, Depends(get_current_user)] = None,
) -> dict:
    templates = await _get_templates()

    # Filter
    filtered = templates
    if search:
        q = search.lower()
        filtered = [
            t for t in filtered
            if q in t["id"].lower() or q in t["name"].lower() or q in " ".join(t["tags"]).lower()
        ]
    if severity:
        sev = severity.lower()
        filtered = [t for t in filtered if t["severity"] == sev]
    if category:
        cat = category.lower()
        filtered = [t for t in filtered if cat in t["path"].lower() or cat in " ".join(t["tags"]).lower()]

    total = len(filtered)
    start = (page - 1) * per_page
    page_items = filtered[start : start + per_page]

    return {"items": page_items, "total": total, "page": page, "per_page": per_page}
