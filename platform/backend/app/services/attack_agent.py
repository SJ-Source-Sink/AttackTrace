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

from app.core.config import get_settings
from app.core.finding_confidence import grade_confidence
from app.models.db.asset import Asset
from app.models.db.audit import AuditLog
from app.services import llm_client
from app.services.ai_service import _cb_is_open, _cb_record_failure, _cb_record_success
from app.services.enumeration_context import _asset_matches_target, build_context
from app.services.finding_ingest import ingest_findings
from app.services.validation_service import check_endpoint_live, check_port_live

settings = get_settings()

MAX_TOOL_TURNS = 20
MAX_WALL_SECONDS = 480
_AGENT_MAX_TOKENS = 1536

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
        "description": "GET a URL and return its live status code, headers, and body hash/length. Use to confirm a discovered path is still live before testing it further.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
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
                "evidence": {"type": "string", "description": "Concrete evidence: request/response details, matched strings, tool outputs."},
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


async def _execute_tool(db: AsyncSession, org_id, user_id, run_id: str, name: str, tool_input: dict) -> dict:
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
            return result

        if name == "probe_http_endpoint":
            url = tool_input.get("url", "")
            if not await _is_in_scope(db, org_id, _host_of(url)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            result = await check_endpoint_live(url, follow_redirects=False)
            await _audit(db, org_id, user_id, run_id, name, tool_input,
                         {k: v for k, v in result.items() if k != "headers"})
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
            return result

        if name == "run_ssrf_probe":
            url = tool_input.get("url", "")
            if not await _is_in_scope(db, org_id, _host_of(url)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            result = await _run_ssrf_probe(url, tool_input.get("param", ""))
            await _audit(db, org_id, user_id, run_id, name, tool_input, result)
            return result

        if name == "run_injection_probe":
            url = tool_input.get("url", "")
            if not await _is_in_scope(db, org_id, _host_of(url)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            result = await _run_injection_probe(url, tool_input.get("param", ""), tool_input.get("injection_class", ""))
            await _audit(db, org_id, user_id, run_id, name, tool_input, result)
            return result

        if name == "record_finding":
            asset = tool_input.get("affected_asset", "")
            if not await _is_in_scope(db, org_id, _host_of(asset)):
                return await _reject_out_of_scope(db, org_id, user_id, run_id, name, tool_input)
            oracle = tool_input.get("oracle", "bare-signal")
            confidence = grade_confidence(oracle)
            finding_dict = {
                "title": tool_input.get("title"),
                "description": tool_input.get("description"),
                "severity": tool_input.get("severity", "info"),
                "category": tool_input.get("category") or "attack-suite-agent",
                "affected_asset": asset,
                "evidence": {"raw": tool_input.get("evidence", ""), "oracle": oracle},
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


def _build_system_prompt(target: str, objective: Optional[str], context: dict) -> str:
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
        "confidence label is computed from it server-side, not accepted at face value.\n"
        "4. BUDGET: you have a limited number of tool-call turns and a wall-clock budget. "
        "Prioritize the highest-yield checks first (see PRIORITY ORDER below). Stop calling "
        "tools once you've covered the highest-value checks or exhausted useful leads.\n\n"
        + _HUNT_SKILL_CONTEXT
        + f"\n\nTARGET: {target}\nOBJECTIVE: {objective or 'General in-depth security assessment.'}\n\n"
        "ENUMERATION CONTEXT (assets and findings this org's scans already know about):\n"
        + json.dumps(context, indent=2, default=str)[:8000]
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
    system_prompt = _build_system_prompt(target, objective, context)
    yield {"event": "context", "data": {
        "run_id": run_id, "asset_count": context["asset_count"], "finding_count": context["finding_count"],
    }}

    messages: list[dict] = [{
        "role": "user",
        "content": f"Begin autonomous testing of {target}. Objective: {objective or 'general in-depth security assessment, prioritized by the Hunt Harness methodology.'}",
    }]

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
        try:
            turn_result = await llm_client.chat_turn(cfg, system_prompt, messages, AGENT_TOOLS, _AGENT_MAX_TOKENS, label="attack_suite_agent")
            await _cb_record_success()
        except Exception as exc:
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
        for tc in tool_calls:
            run_state = await _run_get(run_id)
            if run_state is None or run_state.get("stop"):
                break
            result = await _execute_tool(db, org_id, user_id, run_id, tc["name"], tc["input"])
            if tc["name"] == "record_finding" and result.get("recorded"):
                findings_recorded += 1
            yield {"event": "tool_call", "data": {"run_id": run_id, "turn": turn, "tool": tc["name"], "input": tc["input"], "result": result}}
            tool_results.append({"id": tc["id"], "content": json.dumps(result, default=str)[:4000]})

        await db.commit()

        run_state = await _run_get(run_id)
        if run_state is None or run_state.get("stop"):
            await _run_update(run_id, status="stopped")
            yield {"event": "stopped", "data": {"run_id": run_id, "turns": turn}}
            return

        messages.extend(llm_client.build_tool_result_messages(cfg, tool_results))

    final_state = await _run_get(run_id)
    yield {"event": "summary", "data": {
        "run_id": run_id, "turns": turn, "findings_recorded": findings_recorded,
        "status": final_state["status"] if final_state else "unknown", "elapsed_seconds": round(time.monotonic() - start, 1),
    }}
