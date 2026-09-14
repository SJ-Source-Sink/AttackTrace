"""
Nuclei scanner API — runs nuclei and streams results via SSE.
"""

import asyncio
import json
import re
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator
from uuid import UUID

import httpx
import yaml  # type: ignore[import]
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.models.db.audit import AuditLog
from app.models.db.user import User
from app.services.enrichment_service import enrich_cve, batch_enrich_cves, get_kev_catalog

_settings = get_settings()

# Cache CVSS scores to avoid hammering NVD for duplicate CVEs across scans
_cvss_cache: dict[str, dict | None] = {}

# Circuit breaker: skip NVD lookups after 3 consecutive failures for 5 minutes
_cvss_fail_count = 0
_cvss_fail_until: float = 0.0

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


async def _lookup_cvss(cve_id: str) -> dict:
    """
    Fetch CVSS scores from NIST NVD (free tier, no API key required).

    Returns a dict:
        {
            "v3_score":  float | None,  # CVSS v3.1 or v3.0 base score
            "v4_score":  float | None,  # CVSS v4.0 base score
            "v4_vector": str   | None,  # CVSS v4.0 vector string
        }
    """
    cve_upper = cve_id.upper()
    if cve_upper in _cvss_cache:
        cached = _cvss_cache[cve_upper]
        return cached if cached is not None else {"v3_score": None, "v4_score": None, "v4_vector": None}

    result: dict = {"v3_score": None, "v4_score": None, "v4_vector": None}
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_upper}"
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=4.0, read=8.0, write=4.0, pool=4.0)) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})

                    # CVSS v3.1 / v3.0 / v2 (pick highest-priority hit)
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        entries = metrics.get(key, [])
                        if entries:
                            score = entries[0].get("cvssData", {}).get("baseScore")
                            if score is not None:
                                result["v3_score"] = float(score)
                                break

                    # CVSS v4.0
                    v40_entries = metrics.get("cvssMetricV40", [])
                    if v40_entries:
                        cvss_data = v40_entries[0].get("cvssData", {})
                        raw_score = cvss_data.get("baseScore")
                        raw_vector = cvss_data.get("vectorString")
                        if raw_score is not None:
                            result["v4_score"] = float(raw_score)
                        if raw_vector:
                            result["v4_vector"] = str(raw_vector)

    except Exception:
        pass

    # Evict if cache is too large
    if len(_cvss_cache) > 4096:
        for k in list(_cvss_cache.keys())[:512]:
            del _cvss_cache[k]
    _cvss_cache[cve_upper] = result
    return result


def _extract_cves(finding: dict) -> list[str]:
    """Extract CVE IDs from Nuclei finding tags and references."""
    found: set[str] = set()
    # Tags like ["cve", "cve-2021-44228"] or ["cve2021-44228"]
    for tag in finding.get("tags", []):
        matches = _CVE_PATTERN.findall(tag)
        found.update(m.upper() for m in matches)
    # References: URLs like https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    for ref in finding.get("reference", []):
        matches = _CVE_PATTERN.findall(ref)
        found.update(m.upper() for m in matches)
    # Template ID: e.g. "CVE-2021-44228"
    tid = finding.get("template_id", "")
    matches = _CVE_PATTERN.findall(tid)
    found.update(m.upper() for m in matches)
    return sorted(found)

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
        info = data.get("info", {}) or {}
        tags = info.get("tags", []) or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        references = info.get("reference", []) or []
        if isinstance(references, str):
            references = [references]
        return {
            "template_id": data.get("template-id", ""),
            "name": info.get("name", ""),
            "description": info.get("description", ""),
            "severity": info.get("severity", "info"),
            "matched_url": data.get("matched-at", data.get("host", "")),
            "extracted_results": data.get("extracted-results", []),
            "matcher_name": data.get("matcher-name", ""),
            "type": data.get("type", ""),
            "ip": data.get("ip", ""),
            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "tags": tags,
            "author": info.get("authors", []) or [],
            "reference": references,
            "curl_command": data.get("curl-command", ""),
            "cve": [],        # populated async after parsing
            "cvss_score": None,  # populated async after CVE lookup
            "raw": line,
        }
    except json.JSONDecodeError:
        return None


async def _stream_nuclei(scan_id: str, req: NucleiScanRequest, request: Request, org_id: uuid.UUID) -> AsyncGenerator[str, None]:
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
        "org_id": str(org_id),
    }

    findings: list[dict] = []
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

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

            if await request.is_disconnected():
                proc.terminate()
                return

            if kind == "out":
                finding = _parse_nuclei_line(line)
                if finding:
                    # Extract CVE IDs synchronously; enrich CVSS + EPSS + KEV async
                    cves = _extract_cves(finding)
                    finding["cve"] = cves

                    # Default enrichment fields
                    finding["cvss_score"] = None
                    finding["cvss_v4_score"] = None
                    finding["cvss_v4_vector"] = None
                    finding["epss_score"] = None
                    finding["epss_percentile"] = None
                    finding["is_kev"] = False
                    finding["kev_date_added"] = None

                    if cves:
                        global _cvss_fail_count, _cvss_fail_until
                        if time.monotonic() < _cvss_fail_until:
                            cvss_dict: dict = {"v3_score": None, "v4_score": None, "v4_vector": None}
                        else:
                            try:
                                cvss_dict = await asyncio.wait_for(
                                    _lookup_cvss(cves[0]), timeout=5.0
                                )
                                _cvss_fail_count = 0
                            except (asyncio.TimeoutError, Exception):
                                _cvss_fail_count += 1
                                if _cvss_fail_count >= 3:
                                    _cvss_fail_until = time.monotonic() + 300
                                cvss_dict = {"v3_score": None, "v4_score": None, "v4_vector": None}

                        finding["cvss_score"] = cvss_dict.get("v3_score")
                        finding["cvss_v4_score"] = cvss_dict.get("v4_score")
                        finding["cvss_v4_vector"] = cvss_dict.get("v4_vector")

                        # EPSS + KEV enrichment via enrichment_service
                        try:
                            enrichment = await asyncio.wait_for(
                                enrich_cve(cves[0]), timeout=6.0
                            )
                            finding["epss_score"] = enrichment.get("epss_score")
                            finding["epss_percentile"] = enrichment.get("epss_percentile")
                            finding["is_kev"] = enrichment.get("is_kev", False)
                            finding["kev_date_added"] = enrichment.get("kev_date_added")
                            # Prefer enrichment_service CVSS v4 if our NVD call missed
                            if finding["cvss_v4_score"] is None:
                                finding["cvss_v4_score"] = enrichment.get("cvss_v4_score")
                            if finding["cvss_v4_vector"] is None:
                                finding["cvss_v4_vector"] = enrichment.get("cvss_v4_vector")
                        except (asyncio.TimeoutError, Exception):
                            pass  # leave defaults

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

        # Build enrichment summary for the history record
        kev_findings = [f for f in findings if f.get("is_kev")]
        epss_max = max(
            (f.get("epss_score") or 0.0 for f in findings if f.get("epss_score") is not None),
            default=None,
        )
        _scan_history[scan_id].update({
            "status": "completed" if proc.returncode == 0 else "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "counts": counts,
            "exit_code": proc.returncode,
            "enrichment_summary": {
                "kev_count": len(kev_findings),
                "max_epss_score": epss_max,
                "findings_with_cvss_v4": sum(1 for f in findings if f.get("cvss_v4_score") is not None),
            },
        })

        yield _sse("complete", {
            "scan_id": scan_id,
            "total": len(findings),
            "counts": counts,
            "exit_code": proc.returncode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "enrichment_summary": _scan_history[scan_id].get("enrichment_summary", {}),
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        yield _sse("error", {"message": str(exc)})


@router.post("/scan", summary="Run a nuclei scan and stream results")
async def run_nuclei_scan(
    payload: NucleiScanRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("nuclei"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    if not shutil.which("nuclei"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="nuclei is not installed on this server",
        )
    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.nuclei.scan",
        resource_type="nuclei_scan",
        resource_id=scan_id,
        after_state={"target": payload.target},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return StreamingResponse(
        _stream_nuclei(scan_id, payload, request, org_id),
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
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scans = sorted(
        (s for s in _scan_history.values() if s.get("org_id") == str(org_id)),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}", summary="Get nuclei scan result")
async def get_nuclei_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan or scan.get("org_id") != str(org_id):
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


def _extract_yaml_field(content: str, field: str) -> str | None:
    """Extract a top-level YAML field value via regex (avoids full parse for speed)."""
    pattern = rf"^{re.escape(field)}:\s*(.+)$"
    match = re.search(pattern, content, re.MULTILINE)
    return match.group(1).strip().strip("\"'") if match else None


@router.get("/templates/browse", summary="Browse nuclei templates with enable/disable state")
async def browse_templates(
    search: str = "",
    category: str = "",
    page: int = 1,
    per_page: int = 50,
    current_user: Annotated[User, Depends(get_current_user)] = ...,  # type: ignore[assignment]
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    """Browse nuclei templates from the templates directory with per-org enable/disable config."""
    templates_dir = _find_templates_dir()
    if not templates_dir:
        return {"items": [], "total": 0, "page": page, "per_page": per_page}

    # Read per-org template enable/disable config
    config_path = (
        Path(_settings.ATTACKTRACE_WORKSPACE_DIR) / str(org_id) / "nuclei_template_config.json"
    )
    config: dict = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
        except Exception:
            config = {}

    templates = []
    for yaml_file in Path(templates_dir).rglob("*.yaml"):
        # Skip helpers/profiles
        if any(p in {"helpers", "profiles"} for p in yaml_file.parts):
            continue
        try:
            content = yaml_file.read_text(errors="replace")[:2000]
            template_id = _extract_yaml_field(content, "id")
            if not template_id:
                continue

            name = _extract_yaml_field(content, "name") or template_id
            severity = _extract_yaml_field(content, "severity")
            tags_raw = _extract_yaml_field(content, "tags")
            category_val = str(yaml_file.parent.name)

            # Apply search filter
            if search:
                q = search.lower()
                if q not in name.lower() and q not in template_id.lower():
                    continue
            if category and category.lower() not in category_val.lower():
                continue

            templates.append({
                "id": template_id,
                "name": name,
                "severity": severity.lower() if severity else "unknown",
                "category": category_val,
                "tags": [t.strip() for t in (tags_raw or "").split(",") if t.strip()][:5],
                "enabled": config.get(template_id, True),
                "path": str(yaml_file.relative_to(templates_dir)),
            })
        except Exception:
            continue

    total = len(templates)
    offset = (page - 1) * per_page
    return {
        "items": templates[offset : offset + per_page],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.post("/templates/{template_id}/toggle", summary="Enable or disable a nuclei template for this org")
async def toggle_template(
    template_id: str,
    body: dict,
    current_user: Annotated[User, Depends(get_current_user)] = ...,  # type: ignore[assignment]
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    """Toggle a nuclei template on or off for the current org. Body: {"enabled": bool}"""
    config_path = (
        Path(_settings.ATTACKTRACE_WORKSPACE_DIR) / str(org_id) / "nuclei_template_config.json"
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config: dict = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
        except Exception:
            config = {}
    config[template_id] = bool(body.get("enabled", True))
    config_path.write_text(json.dumps(config, indent=2))
    return {"template_id": template_id, "enabled": config[template_id]}


@router.post("/templates/upload", summary="Upload a custom nuclei template")
async def upload_template(
    file: UploadFile,
    current_user: Annotated[User, Depends(get_current_user)] = ...,  # type: ignore[assignment]
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    """Upload a custom YAML nuclei template for the org. Must have a valid 'id' field."""
    if not (file.filename or "").endswith(".yaml"):
        raise HTTPException(status_code=400, detail="Only .yaml files accepted")

    content = await file.read()
    try:
        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict) or not parsed.get("id"):
            raise HTTPException(status_code=400, detail="Template must have a top-level 'id' field")
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    import os
    safe_name = os.path.basename(file.filename or "custom.yaml")
    # Only allow alphanumeric, dash, underscore, dot
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9_\-\.]+\.yaml$', safe_name):
        raise HTTPException(status_code=400, detail="Invalid filename. Use alphanumeric, dash, underscore only, with .yaml extension.")

    custom_dir = (
        Path(_settings.ATTACKTRACE_WORKSPACE_DIR) / str(org_id) / "custom-templates"
    )
    custom_dir.mkdir(parents=True, exist_ok=True)
    dest = custom_dir / safe_name
    # Verify dest is under custom_dir (extra safety)
    if not str(dest.resolve()).startswith(str(custom_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid file path")
    dest.write_bytes(content)
    return {"filename": safe_name, "status": "uploaded", "path": str(dest)}


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
