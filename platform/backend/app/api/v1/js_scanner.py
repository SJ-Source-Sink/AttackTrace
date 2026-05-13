"""
JavaScript Analysis Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━
Crawls a target URL, discovers JS files, and analyzes them for:
  1. API endpoint extraction
  2. Secret / credential detection
  3. DOM XSS sink detection
  4. Source-map exposure
  5. GraphQL introspection exposure
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, AsyncGenerator
from urllib.parse import urljoin, urlparse
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.config import get_settings as _get_settings
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/js-scanner", tags=["JS Scanner"])

# ──────────────────────────────────────────────────────────────────────────────
# Filesystem history helpers
# ──────────────────────────────────────────────────────────────────────────────

def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "js_scanner" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_scan_result(org_id: str, record: dict) -> None:
    try:
        path = _history_dir(org_id) / f"{record['id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
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
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return None


def _delete_scan_record(org_id: str, scan_id: str) -> bool:
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            path.unlink()
            return True
    except Exception:
        pass
    return False


# ──────────────────────────────────────────────────────────────────────────────
# SSE helper
# ──────────────────────────────────────────────────────────────────────────────

def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic model
# ──────────────────────────────────────────────────────────────────────────────

class JSScanRequest(BaseModel):
    target: str           # base URL like https://target.com
    max_depth: int = 2    # link-following depth
    max_files: int = 50   # max JS files to analyze
    include_source_maps: bool = True
    include_subdomains: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Detection patterns
# ──────────────────────────────────────────────────────────────────────────────

ENDPOINT_PATTERNS: list[tuple[str, str]] = [
    (r'["\'`](/api/[^\s"\'`]{3,})',                             "api_path"),
    (r'["\'`](/v\d+/[^\s"\'`]{3,})',                           "versioned_path"),
    (r'fetch\(["\']([^"\']{5,})["\']',                          "fetch_call"),
    (r'axios\.[a-z]+\(["\']([^"\']{5,})["\']',                 "axios_call"),
    (r'url:\s*["\']([^"\']{5,})["\']',                         "url_property"),
    (r'baseURL:\s*["\']([^"\']{5,})["\']',                     "base_url"),
    (r'["\'`](https?://[^\s"\'`]{10,})',                        "full_url"),
    (r'(GraphQL|graphql.*?query|graphql.*?mutation)',            "graphql"),
]

JS_SECRET_PATTERNS: list[dict] = [
    {"name": "AWS Access Key",       "pattern": r"AKIA[0-9A-Z]{16}",                                                    "severity": "critical"},
    {"name": "Stripe Secret Key",    "pattern": r"sk_live_[0-9a-zA-Z]{24,}",                                            "severity": "critical"},
    {"name": "Stripe Test Key",      "pattern": r"sk_test_[0-9a-zA-Z]{24,}",                                            "severity": "medium"},
    {"name": "Google API Key",       "pattern": r"AIza[0-9A-Za-z\-_]{35}",                                              "severity": "high"},
    {"name": "GitHub Token",         "pattern": r"ghp_[0-9a-zA-Z]{36}",                                                 "severity": "critical"},
    {"name": "JWT Token",            "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",     "severity": "high"},
    {"name": "Hardcoded Password",   "pattern": r'(?i)password\s*[=:]\s*["\']([^"\']{6,})["\']',                        "severity": "high"},
    {"name": "Private Key",          "pattern": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",                            "severity": "critical"},
    {"name": "Generic API Key",      "pattern": r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',          "severity": "high"},
    {"name": "Slack Token",          "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",                                      "severity": "high"},
    {"name": "Internal URL",         "pattern": r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|127\.0\.0\.1)[/\w]*", "severity": "medium"},
]

DOM_XSS_SINKS: list[dict] = [
    {"name": "innerHTML Assignment",        "pattern": r"\.innerHTML\s*=(?!=)",              "severity": "high"},
    {"name": "outerHTML Assignment",        "pattern": r"\.outerHTML\s*=(?!=)",              "severity": "high"},
    {"name": "document.write",             "pattern": r"document\.write\s*\(",              "severity": "high"},
    {"name": "eval()",                     "pattern": r"\beval\s*\(",                       "severity": "critical"},
    {"name": "setTimeout with string",     "pattern": r"setTimeout\s*\(\s*['\"]",           "severity": "high"},
    {"name": "setInterval with string",    "pattern": r"setInterval\s*\(\s*['\"]",          "severity": "high"},
    {"name": "postMessage handler",        "pattern": r"\.addEventListener\s*\(\s*['\"]message['\"]", "severity": "medium"},
    {"name": "location.hash usage",        "pattern": r"location\.hash",                   "severity": "medium"},
    {"name": "document.location assignment", "pattern": r"document\.location\s*=",         "severity": "high"},
]

GRAPHQL_INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name } } }"
})

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/query"]

MAX_JS_BYTES = 2 * 1024 * 1024  # 2 MB

# Common extra paths to probe for JS bundles
COMMON_JS_PATHS = [
    "/static/js/main.chunk.js",
    "/static/js/bundle.js",
    "/static/js/vendors~main.chunk.js",
    "/assets/index.js",
    "/manifest.json",
    "/asset-manifest.json",
]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _truncate_match(m: str, keep: int = 8) -> str:
    return m[:keep] + "..." if len(m) > keep else m


def _base_origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _is_same_origin(url: str, origin: str, include_subdomains: bool) -> bool:
    p = urlparse(url)
    o = urlparse(origin)
    if not p.netloc:
        return True  # relative URL
    if p.netloc == o.netloc:
        return True
    if include_subdomains and p.netloc.endswith("." + o.netloc):
        return True
    return False


def _resolve_js_url(src: str, base: str) -> str | None:
    if not src or src.startswith("data:"):
        return None
    if src.startswith("//"):
        src = urlparse(base).scheme + ":" + src
    if src.startswith("http"):
        return src
    return urljoin(base, src)


def _line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _analyze_js_content(
    content: str,
    file_url: str,
) -> tuple[list[dict], list[dict], list[dict], bool]:
    """
    Returns (endpoints, secrets, dom_xss_findings, has_graphql).
    """
    endpoints: list[dict] = []
    secrets: list[dict] = []
    dom_xss: list[dict] = []
    has_graphql = False
    seen_endpoints: set[str] = set()

    # --- Endpoint extraction ---
    for pattern, kind in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content):
            raw = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            if kind == "graphql":
                has_graphql = True
                continue
            if raw in seen_endpoints:
                continue
            seen_endpoints.add(raw)
            endpoints.append({
                "url": raw,
                "kind": kind,
                "file": file_url,
                "line": _line_number(content, m.start()),
            })

    # Also check for GraphQL keyword separately
    if re.search(r'(?i)(graphql|gql`|useQuery|useMutation)', content):
        has_graphql = True

    # --- Secret detection ---
    for spec in JS_SECRET_PATTERNS:
        for m in re.finditer(spec["pattern"], content):
            raw = m.group(0)
            line = _line_number(content, m.start())
            secrets.append({
                "type": "secret",
                "name": spec["name"],
                "severity": spec["severity"],
                "file_url": file_url,
                "match": _truncate_match(raw),
                "line_number": line,
                "recommendation": f"Remove hardcoded {spec['name']} from JavaScript. Use server-side environment variables.",
            })

    # --- DOM XSS sinks ---
    for sink in DOM_XSS_SINKS:
        for m in re.finditer(sink["pattern"], content):
            line = _line_number(content, m.start())
            dom_xss.append({
                "type": "dom_xss",
                "name": sink["name"],
                "severity": sink["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 30),
                "line_number": line,
                "recommendation": f"Avoid using {sink['name']} with untrusted input. Use safe DOM APIs or DOMPurify for sanitization.",
            })

    return endpoints, secrets, dom_xss, has_graphql


# ──────────────────────────────────────────────────────────────────────────────
# Main scan generator
# ──────────────────────────────────────────────────────────────────────────────

async def _run_js_scan(
    request: JSScanRequest,
    scan_id: str,
    org_id: str,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()
    start_ts = asyncio.get_event_loop().time()
    target = request.target.rstrip("/")
    origin = _base_origin(target)

    # Accumulated findings for history
    all_findings: list[dict] = []
    all_endpoints: list[dict] = []
    js_files_scanned = 0
    secrets_count = 0
    dom_xss_count = 0
    source_map_count = 0
    graphql_count = 0
    graphql_detected = False

    yield _sse("start", {"scan_id": scan_id, "target": target})

    # ── Phase 1: Crawl & JS discovery ────────────────────────────────────────

    yield _sse("progress", {"phase": "discovery", "message": "Fetching target page..."})

    discovered_js: list[str] = []  # absolute URLs
    seen_urls: set[str] = set()

    async def _safe_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
        try:
            r = await client.get(url, follow_redirects=True, timeout=10.0)
            return r
        except Exception:
            return None

    async with httpx.AsyncClient(
        headers={"User-Agent": "AttackTrace-JSScanner/1.0"},
        follow_redirects=True,
        timeout=10.0,
    ) as client:

        # Fetch main page
        main_resp = await _safe_get(client, target)
        inline_scripts: list[str] = []

        if main_resp and main_resp.status_code == 200:
            html = main_resp.text

            # <script src="...">
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                url = _resolve_js_url(m.group(1), target)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    discovered_js.append(url)

            # <link rel="preload" as="script">
            for m in re.finditer(r'<link[^>]+rel=["\']preload["\'][^>]+as=["\']script["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
                url = _resolve_js_url(m.group(1), target)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    discovered_js.append(url)
            for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+as=["\']script["\']', html, re.IGNORECASE):
                url = _resolve_js_url(m.group(1), target)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    discovered_js.append(url)

            # Inline <script> blocks
            for m in re.finditer(r'<script(?:[^>]*)>([\s\S]*?)</script>', html, re.IGNORECASE):
                block = m.group(1).strip()
                if block:
                    inline_scripts.append(block)

            # Internal URLs in inline scripts
            for block in inline_scripts:
                for m in re.finditer(r'(?:window\.location|fetch|axios\.(?:get|post|put|delete|patch))\s*[=(,]\s*["\']([^"\']{5,})["\']', block):
                    url = _resolve_js_url(m.group(1), target)
                    if url and _is_same_origin(url, origin, request.include_subdomains) and url not in seen_urls:
                        seen_urls.add(url)

        # Probe common JS paths
        async def _probe_path(path: str) -> None:
            url = origin + path
            if url in seen_urls:
                return
            r = await _safe_get(client, url)
            if r is None:
                return
            ct = r.headers.get("content-type", "")
            if r.status_code == 200:
                if "javascript" in ct or path.endswith(".js"):
                    seen_urls.add(url)
                    discovered_js.append(url)
                elif "json" in ct and path.endswith(".json"):
                    # Parse asset-manifest / manifest
                    try:
                        manifest = r.json()
                        for key, val in manifest.items():
                            if isinstance(val, str) and val.endswith(".js"):
                                js_url = _resolve_js_url(val, target)
                                if js_url and js_url not in seen_urls:
                                    seen_urls.add(js_url)
                                    discovered_js.append(js_url)
                        # Next.js: "files" key
                        for val in manifest.get("files", {}).values():
                            if isinstance(val, str) and val.endswith(".js"):
                                js_url = _resolve_js_url(val, target)
                                if js_url and js_url not in seen_urls:
                                    seen_urls.add(js_url)
                                    discovered_js.append(js_url)
                    except Exception:
                        pass

        probe_tasks = [_probe_path(p) for p in COMMON_JS_PATHS]
        await asyncio.gather(*probe_tasks)

        # Cap at max_files
        discovered_js = discovered_js[: request.max_files]

        yield _sse("progress", {
            "phase": "discovery",
            "message": f"Found {len(discovered_js)} JS files + {len(inline_scripts)} inline scripts",
            "urls": discovered_js[:50],  # cap for SSE payload size
        })

        # ── Phase 2: Analyze inline scripts ──────────────────────────────────

        for idx, block in enumerate(inline_scripts):
            label = f"inline-script-{idx + 1}"
            eps, secs, xss, gql = _analyze_js_content(block, label)

            for ep in eps:
                yield _sse("endpoint", {"url": ep["url"], "file": label, "line": ep["line"]})
                all_endpoints.append(ep)

            for s in secs:
                yield _sse("finding", s)
                all_findings.append(s)
                secrets_count += 1

            for x in xss:
                yield _sse("finding", x)
                all_findings.append(x)
                dom_xss_count += 1

            if gql:
                graphql_detected = True

        # ── Phase 3: Fetch & analyze JS files concurrently ───────────────────

        semaphore = asyncio.Semaphore(8)  # max 8 concurrent fetches

        async def _fetch_and_analyze(js_url: str, file_index: int, total: int) -> list[str]:
            """Fetch one JS file, analyze it, yield SSE payloads as strings."""
            events: list[str] = []
            async with semaphore:
                try:
                    resp = await client.get(js_url, follow_redirects=True, timeout=10.0)
                except Exception as exc:
                    events.append(_sse("progress", {
                        "phase": "analysis",
                        "message": f"[{file_index}/{total}] Failed to fetch {js_url}: {exc}",
                    }))
                    return events

                ct = resp.headers.get("content-type", "")
                # Skip non-text / binary
                if resp.status_code != 200 or ("image" in ct or "font" in ct or "audio" in ct or "video" in ct):
                    return events

                # Size guard
                raw = resp.content
                if len(raw) > MAX_JS_BYTES:
                    events.append(_sse("progress", {
                        "phase": "analysis",
                        "message": f"[{file_index}/{total}] Skipping {js_url} — too large ({len(raw) // 1024} KB)",
                    }))
                    return events

                try:
                    content = raw.decode("utf-8", errors="replace")
                except Exception:
                    return events

                events.append(_sse("progress", {
                    "phase": "analysis",
                    "message": f"[{file_index}/{total}] Analyzing {js_url}",
                }))

                eps, secs, xss, gql = _analyze_js_content(content, js_url)

                for ep in eps:
                    events.append(_sse("endpoint", {"url": ep["url"], "file": js_url, "line": ep["line"]}))

                for s in secs:
                    events.append(_sse("finding", s))

                for x in xss:
                    events.append(_sse("finding", x))

                if gql:
                    events.append(_sse("_internal_gql", {"detected": True}))

                # Source map detection
                if request.include_source_maps:
                    map_match = re.search(r"//# sourceMappingURL=(.+)$", content, re.MULTILINE)
                    if map_match:
                        map_ref = map_match.group(1).strip()
                        map_url = _resolve_js_url(map_ref, js_url) if not map_ref.startswith("data:") else None
                        if map_url:
                            try:
                                map_resp = await client.get(map_url, timeout=10.0)
                                if map_resp.status_code == 200 and len(map_resp.content) > 100:
                                    finding = {
                                        "type": "source_map",
                                        "name": "JavaScript Source Map Exposed",
                                        "severity": "critical",
                                        "file_url": map_url,
                                        "match": map_url[:50] + "..." if len(map_url) > 50 else map_url,
                                        "line_number": _line_number(content, map_match.start()),
                                        "recommendation": "Remove sourceMappingURL comments from production JS. Do not deploy .map files publicly.",
                                    }
                                    events.append(_sse("finding", finding))
                                    events.append(_sse("_internal_sourcemap", {}))
                            except Exception:
                                pass

                return events, eps, secs, xss, gql  # type: ignore[return-value]

        total = len(discovered_js)
        tasks = [_fetch_and_analyze(url, i + 1, total) for i, url in enumerate(discovered_js)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                continue
            if not isinstance(res, tuple):
                # old path — just events list
                for ev in res:
                    yield ev
                continue

            events_list, eps, secs, xss, gql = res
            for ev in events_list:
                # Intercept internal markers
                if '"_internal_gql"' in ev:
                    graphql_detected = True
                    continue
                if '"_internal_sourcemap"' in ev:
                    source_map_count += 1
                    continue
                yield ev

            all_endpoints.extend(eps)
            for s in secs:
                all_findings.append(s)
                secrets_count += 1
            for x in xss:
                all_findings.append(x)
                dom_xss_count += 1
            js_files_scanned += 1
            if gql:
                graphql_detected = True

        # ── Phase 4: GraphQL introspection check ─────────────────────────────

        if graphql_detected:
            yield _sse("progress", {"phase": "graphql", "message": "GraphQL patterns detected — testing introspection..."})

            for gql_path in GRAPHQL_PATHS:
                gql_url = origin + gql_path
                try:
                    gql_resp = await client.post(
                        gql_url,
                        content=GRAPHQL_INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                        timeout=10.0,
                    )
                    if gql_resp.status_code == 200:
                        body = gql_resp.text
                        if "__schema" in body or '"types"' in body:
                            finding = {
                                "type": "graphql",
                                "name": "GraphQL Introspection Enabled",
                                "severity": "high",
                                "file_url": gql_url,
                                "match": gql_url,
                                "line_number": 0,
                                "recommendation": "Disable GraphQL introspection in production. Introspection exposes the full API schema to attackers.",
                            }
                            yield _sse("finding", finding)
                            all_findings.append(finding)
                            graphql_count += 1
                            break
                except Exception:
                    continue

        # ── Completion ────────────────────────────────────────────────────────

        duration = round(asyncio.get_event_loop().time() - start_ts, 2)
        completed_at = datetime.now(timezone.utc).isoformat()

        completion = {
            "scan_id": scan_id,
            "js_files_scanned": js_files_scanned,
            "endpoints_found": len(all_endpoints),
            "secrets_found": secrets_count,
            "dom_xss_sinks": dom_xss_count,
            "source_maps_exposed": source_map_count,
            "graphql_issues": graphql_count,
            "duration_seconds": duration,
        }
        yield _sse("complete", completion)

        # Persist to history
        record = {
            "id": scan_id,
            "target": target,
            "started_at": started_at,
            "completed_at": completed_at,
            "options": {
                "max_depth": request.max_depth,
                "max_files": request.max_files,
                "include_source_maps": request.include_source_maps,
                "include_subdomains": request.include_subdomains,
            },
            "findings": all_findings,
            "endpoints": all_endpoints,
            "summary": {
                "js_files_scanned": js_files_scanned,
                "endpoints_found": len(all_endpoints),
                "secrets_found": secrets_count,
                "dom_xss_sinks": dom_xss_count,
                "source_maps_exposed": source_map_count,
                "graphql_issues": graphql_count,
                "duration_seconds": duration,
            },
        }
        _save_scan_result(org_id, record)


# ──────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/scan", summary="Analyze JavaScript files on a target")
async def scan_js(
    payload: JSScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    if not payload.target.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target is required",
        )
    scan_id = str(_uuid.uuid4())
    return StreamingResponse(
        _run_js_scan(payload, scan_id=scan_id, org_id=str(org_id)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/history", summary="List previous JS scanner scans")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    records = _load_history(str(org_id), limit=limit)
    summaries = []
    for r in records:
        summaries.append({
            "id": r.get("id"),
            "target": r.get("target"),
            "started_at": r.get("started_at"),
            "completed_at": r.get("completed_at"),
            "summary": r.get("summary", {}),
        })
    return {"items": summaries, "total": len(summaries)}


@router.get("/history/{scan_id}", summary="Get full details of a previous JS scan")
async def get_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a previous JS scan record")
async def delete_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    deleted = _delete_scan_record(str(org_id), scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True, "scan_id": scan_id}
