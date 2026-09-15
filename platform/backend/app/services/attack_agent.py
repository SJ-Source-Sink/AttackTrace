"""
Attack Suite AI Agent — a bounded, real tool-use Claude loop that plans and
executes security testing autonomously, reusing existing scanner code as
tools instead of generating its own commands.

Built per the user's explicit "fully autonomous within scope" decision: there
is no per-tool-call human approval gate, so these compensating controls are
load-bearing, not optional:
  - hard scope enforcement — every tool call's target host must resolve to an
    existing Asset for this org, checked in code before the tool runs, not
    left to the model's judgement. An out-of-scope attempt is rejected AND
    written to AuditLog.
  - a fixed safety envelope — tools are fixed Python functions with fixed,
    non-destructive behavior (read-only probes, benign payloads). The model
    chooses which tool and which parameters, it never gets arbitrary
    code/shell execution.
  - a bounded budget — max tool-call turns and max wall-clock time.
  - a full audit trail — every tool call and result is written to AuditLog.
  - a kill switch — a Redis-backed run record's "stop" flag (see `_run_set`/
    `_run_get`/`_run_update` below), flipped by the stop endpoint and checked
    between turns. Redis-backed, not an in-process dict, because this runs
    across multiple FastAPI worker processes and Celery worker processes
    (run_ai_agent_after_scan) — an in-memory store would be invisible across
    processes and silently unable to stop most runs.

Confidence is computed server-side from the oracle the model honestly reports
(app.core.finding_confidence.grade_confidence), not accepted at face value —
this makes the Hunt Harness false-positive-gate doctrine a hard constraint on
what the agent can claim, not just prompt text.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dashboard import invalidate_dashboard_cache
from app.core.config import get_settings
from app.core.finding_confidence import grade_confidence
from app.models.db.asset import Asset
from app.models.db.audit import AuditLog
from app.services import llm_client
from app.services.ai_service import _cb_is_open, _cb_record_failure, _cb_record_success
from app.services.cve_lookup import lookup_recent_cves
from app.services.enumeration_context import _asset_matches_target, build_context
from app.services.finding_ingest import ingest_findings
from app.services.validation_service import check_endpoint_live, check_port_live

settings = get_settings()

MAX_TOOL_TURNS = 20
MAX_WALL_SECONDS = 480
_AGENT_MAX_TOKENS = 1536

# --- Context/memory management (see 2026-09-14 audit: unbounded raw message
# history was the most likely cause of runs going silently shallow on long
# Qwen budgets — a context-overflow error looked identical to "model stopped
# calling tools"). Turns beyond _COMPACT_THRESHOLD_TURNS get folded into a
# rolling text digest instead of resent raw every turn; the most recent
# _KEEP_RECENT_TURNS always stay verbatim. _MAX_DIGEST_LINES caps how much
# the digest itself can grow across a very long (Qwen: up to 500-turn) run.
_KEEP_RECENT_TURNS = 6
_COMPACT_THRESHOLD_TURNS = 10
_MAX_DIGEST_LINES = 80
_CONTEXT_ERROR_MARKERS = (
    "context_length_exceeded", "maximum context length", "context window",
    "context length is", "too many tokens", "reduce the length", "prompt is too long",
)
# Every this-many turns, nudge the model to explicitly restate its plan given
# what it's learned so far — the "meta-prompting" pattern that a 2026-09-14
# research pass found outperformed splitting into many narrow single-purpose
# agents on XBOW's own published benchmark. Cheap (no extra LLM call — folded
# into the next regular turn) and keeps the current strategy visible near the
# top of context instead of buried in old turns that get compacted away.
_PLAN_REFLECTION_INTERVAL = 6

# Run registry — status polling + the kill switch. MUST be Redis-backed, not
# an in-process dict: the FastAPI app runs with multiple worker processes
# (uvicorn --workers), and run_ai_agent_after_scan (app/workers/scan_worker.py)
# launches run_agent() from a separate Celery worker process entirely — an
# in-memory dict here would make the stop endpoint/status polling blind to
# runs started in any other process (a confirmed, critical bug: the kill
# switch silently no-op'd for auto-triggered runs 100% of the time). Redis
# is shared across every process, so this is the only correct store.
_RUN_TTL_SECONDS = 2 * 24 * 3600  # comfortably longer than the largest possible budget (Qwen: 24h)


def _run_key(run_id: str) -> str:
    return f"attack_agent:run:{run_id}"


async def _run_set(run_id: str, data: dict) -> None:
    from app.services.scan_service import _get_redis
    r = _get_redis()
    await r.set(_run_key(run_id), json.dumps(data), ex=_RUN_TTL_SECONDS)


async def _run_get(run_id: str) -> Optional[dict]:
    from app.services.scan_service import _get_redis
    r = _get_redis()
    raw = await r.get(_run_key(run_id))
    if raw is None:
        return None
    return json.loads(raw)


async def _run_update(run_id: str, **fields) -> None:
    from app.services.scan_service import _get_redis
    r = _get_redis()
    raw = await r.get(_run_key(run_id))
    if raw is None:
        return
    data = json.loads(raw)
    data.update(fields)
    await r.set(_run_key(run_id), json.dumps(data), ex=_RUN_TTL_SECONDS)

_METADATA_MARKERS = [
    "ami-id", "instance-id", "iam/security-credentials", "computeMetadata",
    "Metadata-Flavor", "compute/v1/instances", "azEnvironment",
]
_SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"valid MySQL result", r"MySqlClient\.",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result", r"Npgsql\.",
    r"Driver.*SQL[\-_ ]*Server", r"OLE DB.*SQL Server", r"SQLServer JDBC Driver",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
    r"ORA-[0-9]{4,5}", r"Oracle error", r"Oracle.*Driver",
]

AGENT_TOOLS = [
    {
        "name": "query_enumeration_context",
        "description": (
            "Fetch this org's current known assets (ports, services, discovered paths) "
            "and open findings, optionally filtered to one target domain. Call again if "
            "you discover a new subdomain and want its enumeration data."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Domain to filter to, or omit for everything in scope."}},
        },
    },
    {
        "name": "check_port_open",
        "description": "Raw TCP connect check — confirms whether host:port is actually open right now, rather than trusting a past scan.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["host", "port"],
        },
    },
    {
        "name": "probe_http_endpoint",
        "description": (
            "GET a URL and return its live status code, headers, and body hash/length. Use to "
            "confirm a discovered path is still live before testing it further. Pass "
            "include_body=true when you specifically want to actually read the page content "
            "(e.g. an interesting error page, a debug endpoint, something the fixed probe "
            "signals wouldn't catch) — omit it for a routine liveness check to save context."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "include_body": {"type": "boolean", "description": "Return up to ~3000 chars of the actual response body. Default false."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "run_secret_scan",
        "description": "Fetch a URL (JS bundle, config endpoint, exposed-file candidate) and scan its content for hardcoded secrets/API keys using the platform's pattern library.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "run_ssrf_probe",
        "description": (
            "Test a URL query parameter for server-side request forgery: substitutes it with "
            "a cloud-metadata address and a closed-local-port canary, diffs the response against "
            "a baseline, and reports raw signal (status/timing/body markers) for you to judge. "
            "Read-only GET requests only, non-destructive."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "param": {"type": "string", "description": "Query parameter name to test."}},
            "required": ["url", "param"],
        },
    },
    {
        "name": "run_injection_probe",
        "description": (
            "Send one benign, non-destructive probe payload for the given injection class "
            "(sqli, xss, or ssti) in a URL query parameter and report the raw signal (error "
            "strings matched, reflection, arithmetic evaluation). This tool does not decide "
            "whether a finding is confirmed — you judge that against the false-positive gate."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "injection_class": {"type": "string", "enum": ["sqli", "xss", "ssti"]},
            },
            "required": ["url", "param", "injection_class"],
        },
    },
    {
        "name": "record_finding",
        "description": (
            "Record a finding into the platform's Finding table. Only call this with real "
            "evidence gathered from your own tool calls in this conversation — never fabricate. "
            "Your confidence label is computed server-side from the 'oracle' you honestly report, "
            "per the false-positive gate doctrine — it is not accepted at face value."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "category": {"type": "string"},
                "affected_asset": {"type": "string", "description": "Host, host:port, or URL this finding applies to — must be in scope."},
                "evidence": {"type": "string", "description": "Concrete evidence: request/response details, matched strings, tool outputs. Write this as a full sentence a reader unfamiliar with the scan can understand — do not assume they can see your tool calls."},
                "location_url": {
                    "type": "string",
                    "description": "The EXACT URL/file where this was found, if different from affected_asset (e.g. affected_asset is the site's hostname, but the secret was in a specific .js file at a different path/subdomain). Omit if affected_asset already is the exact location.",
                },
                "location_line": {
                    "type": "integer",
                    "description": "Line number within the file/response where the evidence appears, if applicable (e.g. a line in a JS bundle, a header's position). Omit if not applicable.",
                },
                "location_snippet": {
                    "type": "string",
                    "description": "The exact matched text/code — the literal substring or line that triggered this finding (e.g. the actual regex match, the exact header value, the exact vulnerable code line). This is what a reviewer would grep for to find it themselves. Omit only if genuinely not applicable (e.g. a port-open finding).",
                },
                "remediation": {"type": "string"},
                "oracle": {
                    "type": "string",
                    "enum": [
                        "dom-exec", "extracted-value", "oob-dns", "oob-http", "api-confirmed",
                        "two-signal", "differential", "status-flip", "redirect-location",
                        "pattern-entropy", "timing", "timing-x3", "error-string", "reflected", "bare-signal",
                    ],
                    "description": "How this was confirmed — pick honestly, this determines your reported confidence.",
                },
                "cve": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["title", "severity", "category", "affected_asset", "description", "oracle"],
        },
    },
]


def _host_of(value: str) -> str:
    """Extract a bare host from a URL, host:port, or bare hostname."""
    value = (value or "").strip()
    if "://" in value:
        return urlparse(value).hostname or ""
    return value.split(":")[0]


async def _is_in_scope(db: AsyncSession, org_id, host: str) -> bool:
    """Hard, code-level scope check — the compensating control for running the
    agent's active tools with no per-action human approval. In scope only if
    the host is exactly an existing Asset's value, or a dotted subdomain of
    one, for this org.

    Deliberately one-directional (host must narrow to an asset, never the
    reverse) — matching the other way would let a single known subdomain
    asset (e.g. mail.test.com) widen scope to an arbitrary broader host
    (e.g. test.com, or any other domain an attacker crafts to contain it),
    which is a real scope-escalation path, not just a theoretical one.
    """
    host = (host or "").lower().strip()
    if not host:
        return False
    result = await db.execute(select(Asset.value).where(Asset.org_id == org_id, Asset.is_active.is_(True)))
    for (value,) in result:
        if _asset_matches_target(host, value):
            return True
    return False


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


async def _timed_get(client: httpx.AsyncClient, url: str) -> dict:
    start = time.monotonic()
    try:
        resp = await client.get(url)
        return {
            "status_code": resp.status_code,
            "elapsed": round(time.monotonic() - start, 3),
            "length": len(resp.content),
            "body_sample": resp.text[:2000],
        }
    except Exception as exc:
        return {"status_code": None, "elapsed": round(time.monotonic() - start, 3), "error": str(exc)}


async def _run_ssrf_probe(url: str, param: str) -> dict:
    # verify=False is intentional: this probes arbitrary in-scope pentest targets, not
    # the platform's own trusted resources — see validation_service.py for the same
    # established rationale (a self-signed/misconfigured cert must not read as unreachable).
    timeout = httpx.Timeout(connect=4.0, read=6.0, write=6.0, pool=5.0)
    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
        baseline = await _timed_get(client, _with_param(url, param, "1"))
        metadata_probe = await _timed_get(client, _with_param(url, param, "http://169.254.169.254/latest/meta-data/"))
        closed_port_probe = await _timed_get(client, _with_param(url, param, "http://127.0.0.1:1/"))
    body = metadata_probe.get("body_sample") or ""
    markers_found = [m for m in _METADATA_MARKERS if m.lower() in body.lower()]
    return {
        "baseline": {k: v for k, v in baseline.items() if k != "body_sample"},
        "metadata_probe": {k: v for k, v in metadata_probe.items() if k != "body_sample"},
        "closed_port_probe": {k: v for k, v in closed_port_probe.items() if k != "body_sample"},
        "metadata_markers_found": markers_found,
        "timing_delta_seconds": round((closed_port_probe.get("elapsed") or 0) - (baseline.get("elapsed") or 0), 3),
    }


async def _run_injection_probe(url: str, param: str, injection_class: str) -> dict:
    # follow_redirects=False: the in-scope target itself could otherwise redirect this
    # server's outbound request to an internal/private address (SSRF via redirect) — a
    # 3xx response is reported as-is for the model to reason about, never auto-followed.
    timeout = httpx.Timeout(connect=4.0, read=6.0, write=6.0, pool=5.0)
    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
        baseline = await _timed_get(client, _with_param(url, param, "1"))
        if injection_class == "sqli":
            probe = await _timed_get(client, _with_param(url, param, "1'"))
            body = probe.get("body_sample") or ""
            matched = [p for p in _SQLI_ERROR_PATTERNS if re.search(p, body, re.IGNORECASE)]
            return {
                "injection_class": "sqli", "baseline_status": baseline.get("status_code"),
                "probe_status": probe.get("status_code"), "error_signatures_matched": matched,
            }
        if injection_class == "xss":
            canary = f"atkxss{uuid.uuid4().hex[:8]}"
            payload = f"<svg/onload={canary}()>"
            probe = await _timed_get(client, _with_param(url, param, payload))
            body = probe.get("body_sample") or ""
            reflected_raw = payload in body
            reflected_encoded = (not reflected_raw) and (canary in body)
            return {"injection_class": "xss", "reflected_unescaped": reflected_raw, "reflected_but_encoded": reflected_encoded}
        if injection_class == "ssti":
            probe = await _timed_get(client, _with_param(url, param, "{{7*7}}"))
            body = probe.get("body_sample") or ""
            evaluated = "49" in body and "{{7*7}}" not in body
            return {"injection_class": "ssti", "arithmetic_evaluated": evaluated, "probe_status": probe.get("status_code")}
        return {"error": f"unknown injection_class '{injection_class}'"}


def _downgrade_confidence(confidence: str) -> str:
    """One notch down the false-positive-gate ladder — never up. Used when a
    finding's evidence location wasn't the subject of any real tool call this
    session (see the provenance check in record_finding below): the oracle
    the model reported may be honest, but we have no independent way to
    confirm the evidence text actually came from a live probe in this
    conversation rather than the model writing a plausible-sounding
    description, so the reported confidence gets capped down a level."""
    ladder = {"certain": "high", "high": "medium", "medium": "low", "low": "low"}
    return ladder.get(confidence, confidence)


def _summarize_tool_call(name: str, tool_input: dict, result: dict) -> str:
    """One compact line describing what a tool call did and found. This is
    what survives into the rolling progress digest once a turn ages out of
    the raw message history (see _compact_messages) — so it must carry
    enough for the model to know "already tested, don't repeat" without the
    full raw request/response."""
    if result.get("error") == "out_of_scope":
        return f"{name}({tool_input}) -> BLOCKED (out of scope)"
    if name == "query_enumeration_context":
        return f"query_enumeration_context(target={tool_input.get('target', 'all')}) -> {result.get('asset_count', '?')} assets, {result.get('finding_count', '?')} findings known"
    if name == "check_port_open":
        return f"check_port_open({tool_input.get('host')}:{tool_input.get('port')}) -> open={result.get('open')}"
    if name == "probe_http_endpoint":
        return f"probe_http_endpoint({tool_input.get('url')}) -> live={result.get('live')} status={result.get('status_code')}"
    if name == "run_secret_scan":
        n = len(result.get("secrets_found") or [])
        return f"run_secret_scan({tool_input.get('url')}) -> {n} secret(s) found" if n else f"run_secret_scan({tool_input.get('url')}) -> none found"
    if name == "run_ssrf_probe":
        markers = result.get("metadata_markers_found") or []
        return f"run_ssrf_probe({tool_input.get('url')}, param={tool_input.get('param')}) -> " + (f"MARKERS FOUND: {markers}" if markers else "no signal")
    if name == "run_injection_probe":
        cls = tool_input.get("injection_class")
        loc = f"{tool_input.get('url')}, param={tool_input.get('param')}"
        if cls == "sqli":
            sig = result.get("error_signatures_matched") or []
            return f"run_injection_probe(sqli, {loc}) -> " + (f"matched: {sig}" if sig else "no signal")
        if cls == "xss":
            return f"run_injection_probe(xss, {loc}) -> reflected_unescaped={result.get('reflected_unescaped')} reflected_encoded={result.get('reflected_but_encoded')}"
        if cls == "ssti":
            return f"run_injection_probe(ssti, {loc}) -> arithmetic_evaluated={result.get('arithmetic_evaluated')}"
        return f"run_injection_probe({cls}, {loc}) -> {json.dumps(result, default=str)[:150]}"
    if name == "record_finding":
        return f"record_finding('{str(tool_input.get('title', ''))[:60]}') -> recorded={result.get('recorded')}, confidence={result.get('confidence')}"
    return f"{name}({json.dumps(tool_input, default=str)[:100]}) -> {json.dumps(result, default=str)[:150]}"


def _is_context_overflow_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(marker in msg for marker in _CONTEXT_ERROR_MARKERS)


def _compact_messages(
    messages: list[dict], turn_boundaries: list[tuple[int, int]], turn_summaries: list[str],
    digest_lines: list[str], keep_recent: int, initial_instruction: str,
) -> tuple[list[dict], list[tuple[int, int]], list[str], int]:
    """Fold all but the most recent `keep_recent` turns into a single rolling
    text digest instead of resending every raw tool-call/result message every
    turn — the fix for the audit's #1 finding (unbounded message-history
    growth silently causing context-overflow errors on long runs, which the
    generic exception handler then reported as an opaque "AI call failed").

    Never splits a turn's messages apart — each turn's assistant+tool-result
    messages are always folded or kept as a complete unit, which is required
    for both providers' tool_use/tool_result pairing to stay structurally
    valid. The digest is rebuilt fresh into a single message (index 0,
    initial_instruction + digest text) rather than appended as a separate
    message each time, so repeated compactions across a very long run don't
    pile up multiple digest messages — and _MAX_DIGEST_LINES caps how far
    back the digest itself remembers, since testing from hundreds of turns
    ago is rarely still decision-relevant and an unbounded digest would
    eventually become its own context problem.

    Returns (new_messages, new_turn_boundaries, new_digest_lines, offset) —
    `offset` is how much every OLD absolute message index shifted by, so a
    caller tracking its own in-progress index (e.g. run_agent's turn_start_idx
    for a turn that hasn't been added to turn_boundaries yet) can remap it
    with `idx -= offset` rather than duplicating this function's slicing math.
    """
    if len(turn_boundaries) <= keep_recent:
        return messages, turn_boundaries, digest_lines, 0

    fold_count = len(turn_boundaries) - keep_recent
    digest_lines = (digest_lines + turn_summaries[:fold_count])[-_MAX_DIGEST_LINES:]

    kept_start = turn_boundaries[fold_count][0]
    digest_text = (
        "\n\nPROGRESS DIGEST — turns already completed, compacted here to manage context. "
        "Do NOT re-test anything already covered below unless you have a specific reason to "
        "recheck it:\n" + "\n".join(digest_lines)
    )
    new_messages = [{"role": "user", "content": initial_instruction + digest_text}] + messages[kept_start:]

    offset = kept_start - 1
    new_boundaries = [(s - offset, e - offset) for s, e in turn_boundaries[fold_count:]]
    return new_messages, new_boundaries, digest_lines, offset


async def _prior_testing_digest(db: AsyncSession, org_id, target: str, limit: int = 60) -> str:
    """Best-effort summary of what this org's PAST agent runs already tried
    against this target, built entirely from AuditLog rows the agent already
    writes per tool call — no new schema. Addresses the audit's finding that
    a fresh run has no memory of prior runs and can burn turns re-probing
    dead ends a previous run already ruled out. Bounded and best-effort:
    any failure here must never block a run from starting."""
    try:
        stmt = (
            select(AuditLog.action, AuditLog.before_state, AuditLog.created_at)
            .where(
                AuditLog.org_id == org_id,
                AuditLog.resource_type == "attack_agent_run",
                AuditLog.action.like("tool.attack_agent.%"),
            )
            .order_by(AuditLog.created_at.desc())
            .limit(500)
        )
        rows = (await db.execute(stmt)).all()
    except Exception:
        return ""

    host_target = (target or "").lower()
    if not host_target:
        return ""

    lines: list[str] = []
    for action, before, created_at in rows:
        input_data = (before or {}).get("input", {}) if isinstance(before, dict) else {}
        if host_target not in json.dumps(input_data, default=str).lower():
            continue
        tool = action.replace("tool.attack_agent.", "").replace(".blocked_out_of_scope", "")
        lines.append(f"- [{created_at.strftime('%Y-%m-%d')}] {tool}: {json.dumps(input_data, default=str)[:120]}")
        if len(lines) >= limit:
            break

    if not lines:
        return ""
    return (
        "\n\nPRIOR TESTING ALREADY DONE (from earlier agent runs against this target — "
        "avoid blindly repeating these unless you have a specific reason to recheck):\n"
        + "\n".join(lines)
    )


# Reuses the classic Attack Suite scanner's existing header/body signature
# table (app.api.v1.attack_patterns.TECH_SIGNATURES) rather than a new
# detector — same signals, so tech identified by one part of the platform is
# recognized consistently everywhere else that reads Asset.metadata_["tech"].
def _extract_tech_signals(headers: dict, body_sample: str = "") -> list[str]:
    from app.api.v1.attack_patterns import TECH_SIGNATURES
    headers_str = str(headers).lower()
    body_lower = (body_sample or "")[:5000].lower()
    found = []
    for tech, sig in TECH_SIGNATURES.items():
        for signal in sig["signals"]:
            if signal.lower() in headers_str or signal.lower() in body_lower:
                found.append(tech)
                break
    return found


async def _record_tech_signal(db: AsyncSession, org_id, host: str, headers: dict, body_sample: str = "") -> list[str]:
    """Write detected tech back onto the matching Asset row so it's available
    immediately in future runs' enumeration context — fixing the audit's
    finding that Asset.metadata_["tech"] had a read path (enumeration_context.py)
    but nothing ever wrote to it, so the agent's own context always showed it
    empty and every run had to rediscover the tech stack from scratch. Returns
    the list of newly-detected tech names (for injecting into THIS run's
    context immediately, not just future ones). Best-effort — never raises."""
    try:
        tech_found = _extract_tech_signals(headers, body_sample)
        server_hdr = (headers or {}).get("server") or (headers or {}).get("Server")
        powered_by = (headers or {}).get("x-powered-by") or (headers or {}).get("X-Powered-By")
        if not tech_found and not server_hdr and not powered_by:
            return []

        # Asset.value is only unique per (org_id, value, asset_type) — the
        # same host string legitimately exists as more than one asset_type
        # row (e.g. both IP and SUBDOMAIN), so this must tolerate multiple
        # matches rather than assume at most one. A bare .scalar_one_or_none()
        # here would raise MultipleResultsFound on any such host, which the
        # blanket `except Exception: return []` below would then silently
        # swallow — found live: exactly this happened testing against a real
        # multi-asset_type host, and the write-back quietly did nothing.
        # Update every matching row so no asset_type view of this host misses
        # the tech data.
        result = await db.execute(select(Asset).where(Asset.org_id == org_id, Asset.value == host))
        matches = result.scalars().all()
        if not matches:
            return tech_found  # nothing to persist to, but still worth returning for this run's own context

        for asset in matches:
            meta = dict(asset.metadata_ or {})
            existing_tech = set(meta.get("tech") or [])
            meta["tech"] = sorted(existing_tech | set(tech_found))
            if server_hdr:
                meta["server_header"] = server_hdr
            if powered_by:
                meta["x_powered_by"] = powered_by
            asset.metadata_ = meta
            db.add(asset)
        return tech_found
    except Exception:
        return []


async def _audit(db: AsyncSession, org_id, user_id, run_id: str, action: str, input_data: dict, result_data: dict) -> None:
    db.add(AuditLog(
        org_id=org_id, user_id=user_id,
        action=f"tool.attack_agent.{action}",
        resource_type="attack_agent_run",
        resource_id=run_id,
        before_state={"input": input_data},
        after_state=result_data,
    ))


async def _reject_out_of_scope(db: AsyncSession, org_id, user_id, run_id: str, action: str, input_data: dict) -> dict:
    await _audit(db, org_id, user_id, run_id, f"{action}.blocked_out_of_scope", input_data, {"blocked": True})
    return {
        "error": "out_of_scope",
        "message": "This target is not a known asset for this organization — refusing to execute (scope enforcement).",
    }


async def _execute_tool(
    db: AsyncSession, org_id, user_id, run_id: str, name: str, tool_input: dict,
    grounded_hosts: Optional[set[str]] = None,
) -> dict:
    """grounded_hosts, when passed, is mutated in place to record which hosts
    were the subject of a real (non-out-of-scope-blocked) testing tool call
    this run — used by record_finding's provenance check below."""
    try:
        if name == "query_enumeration_context":
            ctx = await build_context(db, org_id, target=tool_input.get("target"))
            await _audit(db, org_id, user_id, run_id, name, tool_input,
                         {"asset_count": ctx["asset_count"], "finding_count": ctx["finding_count"]})
            return ctx

        if name == "check_port_open":
            host = tool_input.get("host", "")
            if not await _is_in_scope(db, org_id, _host_of(host)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            is_open = await check_port_live(host, int(tool_input.get("port", 0)))
            result = {"host": host, "port": tool_input.get("port"), "open": is_open}
            await _audit(db, org_id, user_id, run_id, name, tool_input, result)
            if grounded_hosts is not None:
                grounded_hosts.add(_host_of(host))
            return result

        if name == "probe_http_endpoint":
            url = tool_input.get("url", "")
            if not await _is_in_scope(db, org_id, _host_of(url)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            include_body = bool(tool_input.get("include_body"))
            result = await check_endpoint_live(url, follow_redirects=False, capture_body=include_body)
            await _audit(db, org_id, user_id, run_id, name, tool_input,
                         {k: v for k, v in result.items() if k not in ("headers", "body_sample")})
            if grounded_hosts is not None:
                grounded_hosts.add(_host_of(url))
            if result.get("live") and result.get("headers"):
                newly_found_tech = await _record_tech_signal(
                    db, org_id, _host_of(url), result["headers"], result.get("body_sample", ""),
                )
                if newly_found_tech:
                    result["tech_detected"] = newly_found_tech
            return result

        if name == "run_secret_scan":
            url = tool_input.get("url", "")
            if not await _is_in_scope(db, org_id, _host_of(url)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            from app.api.v1.secrets import _scan_content_for_secrets
            # Deliberately not reusing secrets.py's _fetch_text here: it hardcodes
            # follow_redirects=True at the request level (overriding any client-level
            # default), which would let an in-scope target redirect this unattended,
            # repeated tool call to an internal address (SSRF via redirect) and have
            # its content scanned and returned. Fetch directly instead, redirects off.
            timeout = httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)
            content, status_code = None, 0
            try:
                async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
                    resp = await client.get(url)
                    status_code = resp.status_code
                    ct = resp.headers.get("content-type", "")
                    is_text_like = any(marker in ct for marker in ("text", "javascript", "json"))
                    if status_code == 200 and is_text_like:
                        content = resp.text
            except Exception:
                pass
            secrets_found = _scan_content_for_secrets(content, url) if content else []
            result = {"url": url, "status_code": status_code, "secrets_found": secrets_found}
            await _audit(db, org_id, user_id, run_id, name, tool_input, {"status_code": status_code, "count": len(secrets_found)})
            if grounded_hosts is not None:
                grounded_hosts.add(_host_of(url))
            return result

        if name == "run_ssrf_probe":
            url = tool_input.get("url", "")
            if not await _is_in_scope(db, org_id, _host_of(url)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            result = await _run_ssrf_probe(url, tool_input.get("param", ""))
            await _audit(db, org_id, user_id, run_id, name, tool_input, result)
            if grounded_hosts is not None:
                grounded_hosts.add(_host_of(url))
            return result

        if name == "run_injection_probe":
            url = tool_input.get("url", "")
            if not await _is_in_scope(db, org_id, _host_of(url)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            result = await _run_injection_probe(url, tool_input.get("param", ""), tool_input.get("injection_class", ""))
            await _audit(db, org_id, user_id, run_id, name, tool_input, result)
            if grounded_hosts is not None:
                grounded_hosts.add(_host_of(url))
            return result

        if name == "record_finding":
            asset = tool_input.get("affected_asset", "")
            if not await _is_in_scope(db, org_id, _host_of(asset)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            oracle = tool_input.get("oracle", "bare-signal")
            confidence = grade_confidence(oracle)
            # Provenance check: only meaningful when we're actually tracking
            # grounded_hosts for this run. The claimed evidence location must
            # have been the subject of a real testing tool call THIS session —
            # the system prompt already tells the model evidence must come
            # from its own tool calls, not fabricated, but nothing previously
            # verified that. A finding whose location was never actually
            # probed gets its confidence capped a notch down and an explicit
            # caveat recorded, rather than trusting the model's free-text
            # evidence description at face value.
            provenance_host = _host_of(tool_input.get("location_url") or asset)
            if grounded_hosts is not None and provenance_host and provenance_host not in grounded_hosts:
                confidence = _downgrade_confidence(confidence)
                provenance_note = (
                    f"NOTE: {provenance_host} was not the subject of any testing tool call in this "
                    f"session — this evidence could not be independently confirmed as freshly gathered."
                )
            else:
                provenance_note = None
            # Deliberately NOT keyed "file"/"line"/"snippet" — EvidenceBlock's
            # frontend renderer switches to an MSRA-only display for that
            # exact shape and would silently drop `raw`/`oracle` alongside
            # it. "location_*" keys fall through to the generic key/value
            # table instead, showing everything together (which is what a
            # reader asking "what/where/how was this found" actually wants).
            evidence: dict = {"raw": tool_input.get("evidence", ""), "oracle": oracle}
            if provenance_note:
                evidence["provenance_warning"] = provenance_note
            if tool_input.get("location_url"):
                evidence["location_url"] = tool_input["location_url"]
            if tool_input.get("location_line") is not None:
                evidence["location_line"] = tool_input["location_line"]
            if tool_input.get("location_snippet"):
                evidence["location_snippet"] = tool_input["location_snippet"]
            finding_dict = {
                "title": tool_input.get("title"),
                "description": tool_input.get("description"),
                "severity": tool_input.get("severity", "info"),
                "category": tool_input.get("category") or "attack-suite-agent",
                "affected_asset": asset,
                "evidence": evidence,
                "remediation": tool_input.get("remediation", ""),
                "cve": tool_input.get("cve") or [],
                "confidence": confidence,
            }
            ingest_result = await ingest_findings(db, org_id, "attack_suite_agent", run_id, [finding_dict])
            await _audit(db, org_id, user_id, run_id, name, tool_input, {**ingest_result, "confidence": confidence})
            return {
                "recorded": ingest_result.get("inserted", 0) > 0 or ingest_result.get("updated", 0) > 0,
                "confidence": confidence, **ingest_result,
            }

        return {"error": f"unknown tool '{name}'"}
    except Exception as exc:
        return {"error": str(exc)}


def _build_system_prompt(
    target: str, objective: Optional[str], context: dict,
    prior_testing_digest: str = "", cve_context: str = "",
) -> str:
    from app.api.v1.attack_suite import _HUNT_SKILL_CONTEXT

    return (
        "You are an autonomous security-testing agent operating under the Hunt Harness "
        "methodology below. You have been granted FULL AUTONOMY within a fixed scope and "
        "a fixed toolset for this engagement — no human approves individual actions, so "
        "you must self-govern strictly within these hard rules:\n"
        "1. SCOPE: you may only test the target and assets already enumerated for this "
        "organization (see ENUMERATION CONTEXT below). Every tool call is scope-checked "
        "in code — an out-of-scope call is rejected and logged, not silently ignored.\n"
        "2. SAFETY: tools are fixed, non-destructive functions — you choose which tool "
        "and which benign parameters, you never get arbitrary code/shell execution. Never "
        "attempt destructive actions (no deletes, no real transactions, no persistence).\n"
        "3. EVIDENCE: only call record_finding with real evidence from your own tool calls "
        "in this conversation — never fabricate. Report the 'oracle' honestly; your "
        "confidence label is computed from it server-side, not accepted at face value. A "
        "finding whose location was never actually tested by one of your own tool calls this "
        "session will have its confidence automatically capped lower — so test before you claim.\n"
        "4. BUDGET: you have a limited number of tool-call turns and a wall-clock budget. "
        "Prioritize the highest-yield checks first (see PRIORITY ORDER below). Stop calling "
        "tools once you've covered the highest-value checks or exhausted useful leads.\n"
        "5. ADAPT: as you learn real facts about this target (its tech stack, a WAF, an "
        "unexpected framework), update your OWN priorities accordingly rather than following "
        "a fixed checklist blindly — you will periodically be asked to briefly restate your "
        "current plan given what you've actually found so far.\n\n"
        + _HUNT_SKILL_CONTEXT
        + f"\n\nTARGET: {target}\nOBJECTIVE: {objective or 'General in-depth security assessment.'}\n\n"
        "ENUMERATION CONTEXT (assets and findings this org's scans already know about):\n"
        + json.dumps(context, indent=2, default=str)[:8000]
        + prior_testing_digest
        + cve_context
    )


async def stop_run(run_id: str) -> bool:
    run = await _run_get(run_id)
    if run is None:
        return False
    await _run_update(run_id, stop=True)
    return True


async def get_run_status(run_id: str) -> Optional[dict]:
    return await _run_get(run_id)


async def run_agent(
    db: AsyncSession,
    org_id,
    user_id,
    target: str,
    objective: Optional[str] = None,
    ai_config: Optional[dict] = None,
    max_turns: int = MAX_TOOL_TURNS,
    max_seconds: int = MAX_WALL_SECONDS,
) -> AsyncGenerator[dict, None]:
    """Run the bounded tool-use agent loop against `target`. Yields event dicts
    of shape {"event": ..., "data": ...} for the caller to stream over SSE."""
    run_id = str(uuid.uuid4())
    await _run_set(run_id, {
        "stop": False, "status": "running", "org_id": str(org_id), "target": target,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })
    yield {"event": "start", "data": {"run_id": run_id, "target": target}}

    if not await _is_in_scope(db, org_id, _host_of(target)):
        await _run_update(run_id, status="rejected")
        yield {"event": "error", "data": {
            "run_id": run_id,
            "message": f"Target '{target}' is not a known asset for this organization — refusing to start (scope enforcement).",
        }}
        return

    cfg = ai_config or {}
    if cfg.get("provider", "anthropic") != "qwen" and not (cfg.get("api_key") or settings.ANTHROPIC_API_KEY):
        await _run_update(run_id, status="error")
        yield {"event": "error", "data": {"run_id": run_id, "message": "ANTHROPIC_API_KEY is not configured"}}
        return
    if cfg.get("provider") == "qwen" and not cfg.get("base_url"):
        await _run_update(run_id, status="error")
        yield {"event": "error", "data": {"run_id": run_id, "message": "Qwen base_url is not configured"}}
        return

    domain_guess = _host_of(target)
    context = await build_context(db, org_id, target=domain_guess)

    # Cross-run memory + CVE grounding — both best-effort, both bounded, both
    # must never block a run from starting on failure.
    prior_digest = await _prior_testing_digest(db, org_id, target)

    cve_context = ""
    known_tech = sorted({t for a in context.get("assets", []) for t in (a.get("tech") or [])})
    if known_tech:
        cve_sections = []
        for tech in known_tech[:2]:  # bounded — NVD has a low unauthenticated rate limit
            try:
                cves = await lookup_recent_cves(tech)
            except Exception:
                cves = []
            if cves:
                cve_sections.append(
                    f"{tech}: " + "; ".join(f"{c['cve_id']} (CVSS {c['cvss_score']}): {c['description'][:150]}" for c in cves)
                )
        if cve_sections:
            cve_context = (
                "\n\nPOTENTIALLY RELEVANT CVES for this target's detected tech stack (free-text "
                "keyword match, NOT confirmed version-applicable — verify before assuming any of "
                "these apply, but use them to prioritize what to test for):\n" + "\n".join(cve_sections)
            )

    system_prompt = _build_system_prompt(target, objective, context, prior_digest, cve_context)
    yield {"event": "context", "data": {
        "run_id": run_id, "asset_count": context["asset_count"], "finding_count": context["finding_count"],
        "known_tech": known_tech, "cve_context_included": bool(cve_context),
        "prior_testing_found": bool(prior_digest),
    }}

    initial_instruction = (
        f"Begin autonomous testing of {target}. Objective: "
        f"{objective or 'general in-depth security assessment, prioritized by the Hunt Harness methodology.'}"
    )
    messages: list[dict] = [{"role": "user", "content": initial_instruction}]

    # Structured memory for the current run (see _compact_messages/_summarize_tool_call):
    # turn_boundaries[i] = (start_idx, end_idx) into `messages` for completed turn i+1;
    # turn_summaries[i] is that turn's one-line digest entry; digest_lines is the rolling,
    # length-capped fold of turn_summaries once turns age out of the raw window.
    turn_boundaries: list[tuple[int, int]] = []
    turn_summaries: list[str] = []
    digest_lines: list[str] = []
    # Hosts that were the subject of a real testing tool call this run — the
    # provenance check in _execute_tool's record_finding branch reads this.
    grounded_hosts: set[str] = set()

    start = time.monotonic()
    turn = 0
    findings_recorded = 0

    while True:
        run_state = await _run_get(run_id)
        if run_state is None or run_state.get("stop"):
            await _run_update(run_id, status="stopped")
            yield {"event": "stopped", "data": {"run_id": run_id, "turns": turn}}
            return
        if turn >= max_turns or (time.monotonic() - start) >= max_seconds:
            await _run_update(run_id, status="budget_exhausted")
            yield {"event": "budget_exhausted", "data": {"run_id": run_id, "turns": turn, "elapsed_seconds": round(time.monotonic() - start, 1)}}
            break

        turn += 1
        if await _cb_is_open():
            await _run_update(run_id, status="error")
            yield {"event": "error", "data": {"run_id": run_id, "message": "AI circuit breaker open — Anthropic API is currently degraded"}}
            break

        turn_start_idx = len(messages)
        # Meta-prompting reflection nudge (Tier 5): periodically ask the model
        # to explicitly restate its plan given what it's actually found so
        # far, rather than following a fixed checklist blindly — no extra LLM
        # call, just folded into this turn's normal prompt. Captured as part
        # of turn_start_idx above so it travels with this turn as one unit
        # through any future compaction, never orphaned.
        if turn > 1 and turn % _PLAN_REFLECTION_INTERVAL == 0:
            messages.append({
                "role": "user",
                "content": (
                    "Before continuing: in 1-2 sentences, what's your current read on this "
                    "target given everything you've found or ruled out so far, and what will "
                    "you prioritize next? Then continue testing."
                ),
            })

        try:
            turn_result = await llm_client.chat_turn(cfg, system_prompt, messages, AGENT_TOOLS, _AGENT_MAX_TOKENS, label="attack_suite_agent")
            await _cb_record_success()
        except Exception as exc:
            if _is_context_overflow_error(exc) and len(turn_boundaries) > 2:
                # Self-heal: a context-overflow on a long run is a harness
                # limitation, not a real reason to end an otherwise-productive
                # run — aggressively compact (keep only the last 2 turns) and
                # retry once before giving up. This is the direct fix for the
                # audit's top finding: this exact failure mode previously hit
                # the generic `except Exception` below and looked identical to
                # "the model decided to stop," when it may really have been
                # silently erroring out once context filled.
                yield {"event": "context_compacted", "data": {"run_id": run_id, "turn": turn, "reason": "overflow_recovery"}}
                messages, turn_boundaries, digest_lines, offset = _compact_messages(
                    messages, turn_boundaries, turn_summaries, digest_lines,
                    keep_recent=2, initial_instruction=initial_instruction,
                )
                turn_start_idx -= offset
                try:
                    turn_result = await llm_client.chat_turn(cfg, system_prompt, messages, AGENT_TOOLS, _AGENT_MAX_TOKENS, label="attack_suite_agent")
                    await _cb_record_success()
                except Exception as exc2:
                    await _cb_record_failure()
                    await _run_update(run_id, status="error")
                    yield {"event": "error", "data": {"run_id": run_id, "message": f"AI call failed after context-overflow recovery attempt: {exc2}"}}
                    break
            else:
                await _cb_record_failure()
                await _run_update(run_id, status="error")
                yield {"event": "error", "data": {"run_id": run_id, "message": f"AI call failed: {exc}"}}
                break

        messages.append(turn_result["assistant_message"])

        if turn_result["text"]:
            yield {"event": "reasoning", "data": {"run_id": run_id, "turn": turn, "text": "\n".join(turn_result["text"])}}

        tool_calls = turn_result["tool_calls"]
        if not tool_calls:
            await _run_update(run_id, status="completed")
            yield {"event": "done", "data": {"run_id": run_id, "reason": "model stopped calling tools", "turns": turn}}
            break

        tool_results = []
        turn_call_summaries = []
        turn_recorded_finding = False
        for tc in tool_calls:
            run_state = await _run_get(run_id)
            if run_state is None or run_state.get("stop"):
                break
            result = await _execute_tool(db, org_id, user_id, run_id, tc["name"], tc["input"], grounded_hosts)
            if tc["name"] == "record_finding" and result.get("recorded"):
                findings_recorded += 1
                turn_recorded_finding = True
            yield {"event": "tool_call", "data": {"run_id": run_id, "turn": turn, "tool": tc["name"], "input": tc["input"], "result": result}}
            tool_results.append({"id": tc["id"], "content": json.dumps(result, default=str)[:4000]})
            turn_call_summaries.append(_summarize_tool_call(tc["name"], tc["input"], result))

        await db.commit()
        if turn_recorded_finding:
            await invalidate_dashboard_cache(org_id)

        run_state = await _run_get(run_id)
        if run_state is None or run_state.get("stop"):
            await _run_update(run_id, status="stopped")
            yield {"event": "stopped", "data": {"run_id": run_id, "turns": turn}}
            return

        messages.extend(llm_client.build_tool_result_messages(cfg, tool_results))

        turn_boundaries.append((turn_start_idx, len(messages)))
        reasoning_snippet = (" | ".join(turn_result["text"])[:150] + " — ") if turn_result["text"] else ""
        turn_summaries.append(f"Turn {turn}: {reasoning_snippet}" + "; ".join(turn_call_summaries))

        # Routine compaction (distinct from the overflow-recovery path above) —
        # keeps context bounded proactively on every turn once the raw window
        # grows past threshold, rather than waiting to hit an actual overflow.
        if len(turn_boundaries) > _COMPACT_THRESHOLD_TURNS:
            before_len = len(messages)
            messages, turn_boundaries, digest_lines, _offset = _compact_messages(
                messages, turn_boundaries, turn_summaries, digest_lines,
                keep_recent=_KEEP_RECENT_TURNS, initial_instruction=initial_instruction,
            )
            if len(messages) < before_len:
                yield {"event": "context_compacted", "data": {
                    "run_id": run_id, "turn": turn, "reason": "routine",
                    "kept_turns": len(turn_boundaries), "digest_lines": len(digest_lines),
                }}

    final_state = await _run_get(run_id)
    yield {"event": "summary", "data": {
        "run_id": run_id, "turns": turn, "findings_recorded": findings_recorded,
        "status": final_state["status"] if final_state else "unknown", "elapsed_seconds": round(time.monotonic() - start, 1),
    }}
