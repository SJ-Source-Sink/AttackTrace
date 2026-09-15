"""
Declarative template engine for the classic Attack Suite scanner's additive
custom-check surface (`_module_custom_templates` in `attack_suite.py`). New
detection checks can be added as YAML data under `app/scanner_templates/`
instead of hand-written Python — the 39 existing hand-coded modules stay as
they are (too much individually-reasoned baseline/oracle logic per check,
built up across this session's Tier 1-3 work, to safely auto-convert). This
is a companion, additive engine, not a replacement.

Deliberately smaller and more opinionated than Nuclei's own template schema
(this codebase already wraps real Nuclei separately, see `nuclei.py`) — only
the primitives this session's work actually proved out: a benign baseline
request compared against an injected one, timing repeated N times against a
threshold, and simple header/body presence checks. Not an attempt to cover
everything Nuclei supports.

Service-layer module: deliberately has NO import from `app.api.v1` — the
`_module_custom_templates` wrapper in `attack_suite.py` translates the plain
dicts this module yields into `_finding()`/`_probe()` calls, keeping the
oracle-driven confidence grading (`app.core.finding_confidence.grade_confidence`)
as the single source of truth, unchanged by this file.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

import httpx
import yaml

logger = logging.getLogger(__name__)

_VALID_MATCHER_TYPES = {
    "header-absent",
    "header-value-contains",
    "status-and-body-contains",
    "word-not-in-baseline",
    "response-time-threshold",
}

_REQUIRED_FIELDS = (
    "id", "name", "severity", "category", "description",
    "remediation", "oracle", "request", "matcher",
)


@dataclass
class Template:
    id: str
    name: str
    severity: str
    category: str
    description: str
    remediation: str
    oracle: str
    request: dict[str, Any]
    matcher: dict[str, Any]
    references: list[str] = field(default_factory=list)
    baseline: Optional[dict[str, Any]] = None
    payloads: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    source_path: str = ""


def _parse_template(doc: dict, source_path: str) -> Optional[Template]:
    """Validate + build a Template from a parsed YAML dict. Returns None
    (and logs a warning) on any structural problem — one bad template file
    must never take down the whole custom-templates module."""
    missing = [f for f in _REQUIRED_FIELDS if f not in doc]
    if missing:
        logger.warning("scanner_templates: %s missing required field(s) %s — skipped", source_path, missing)
        return None

    matcher = doc["matcher"]
    if not isinstance(matcher, dict) or matcher.get("type") not in _VALID_MATCHER_TYPES:
        logger.warning("scanner_templates: %s has invalid/unknown matcher.type — skipped", source_path)
        return None
    if matcher["type"] == "word-not-in-baseline" and not doc.get("baseline"):
        logger.warning(
            "scanner_templates: %s uses word-not-in-baseline but has no baseline block — skipped", source_path)
        return None

    request = doc["request"]
    if not isinstance(request, dict) or "method" not in request or "path" not in request:
        logger.warning("scanner_templates: %s has invalid request block — skipped", source_path)
        return None

    try:
        return Template(
            id=str(doc["id"]),
            name=str(doc["name"]),
            severity=str(doc["severity"]),
            category=str(doc["category"]),
            description=str(doc["description"]),
            remediation=str(doc["remediation"]),
            oracle=str(doc["oracle"]),
            request=request,
            matcher=matcher,
            references=list(doc.get("references") or []),
            baseline=doc.get("baseline"),
            payloads=list(doc.get("payloads") or []),
            params=list(doc.get("params") or []),
            headers=list(doc.get("headers") or []),
            source_path=source_path,
        )
    except Exception as e:
        logger.warning("scanner_templates: %s failed to build Template: %s — skipped", source_path, e)
        return None


def load_templates(dir_path: Path) -> list[Template]:
    """Parse every *.yaml file under dir_path into a Template. Malformed
    files are logged and skipped, never raised."""
    if not dir_path.is_dir():
        return []
    templates: list[Template] = []
    for yaml_file in sorted(dir_path.glob("*.yaml")):
        try:
            doc = yaml.safe_load(yaml_file.read_text())
        except yaml.YAMLError as e:
            logger.warning("scanner_templates: %s is invalid YAML: %s — skipped", yaml_file, e)
            continue
        if not isinstance(doc, dict):
            logger.warning("scanner_templates: %s is not a YAML mapping — skipped", yaml_file)
            continue
        parsed = _parse_template(doc, str(yaml_file))
        if parsed:
            templates.append(parsed)
    return templates


def _build_url(target: str, path: str) -> str:
    return target.rstrip("/") + (path if path.startswith("/") else f"/{path}")


def _iter_injection_points(template: Template) -> list[tuple[str, str]]:
    """(location, name) pairs to inject a value into — 'query' for a URL
    param, 'header' for a request header. v1 supports only these two
    locations; json_body/path-segment injection are explicitly not
    implemented (a template using them simply has no injection points and
    yields nothing, rather than silently misbehaving)."""
    return [("query", p) for p in template.params] + [("header", h) for h in template.headers]


async def _send(client: httpx.AsyncClient, method: str, url: str,
                 location: str, name: str, value: str) -> httpx.Response:
    if location == "query" and name:
        return await client.request(method, url, params={name: value}, timeout=8)
    if location == "header" and name:
        return await client.request(method, url, headers={name: value}, timeout=8)
    return await client.request(method, url, timeout=8)


async def _run_header_absent(template: Template, target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    url = _build_url(target, template.request["path"])
    method = template.request.get("method", "GET")
    header_name = str(template.matcher.get("header", "")).lower()
    yield {"type": "probe", "method": method, "url": url, "note": f"checking for {header_name} header"}
    try:
        r = await client.request(method, url, timeout=8)
    except httpx.HTTPError:
        return
    headers_lower = {k.lower() for k in r.headers.keys()}
    if header_name and header_name not in headers_lower:
        yield {
            "type": "finding",
            "description": template.description,
            "evidence": f"URL: {url}\nResponse headers present: {list(r.headers.keys())[:10]}",
            "url": url,
        }


async def _run_header_value_contains(template: Template, target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    url = _build_url(target, template.request["path"])
    method = template.request.get("method", "GET")
    header_name = str(template.matcher.get("header", ""))
    substr = str(template.matcher.get("contains", ""))
    yield {"type": "probe", "method": method, "url": url, "note": f"checking {header_name} header value"}
    try:
        r = await client.request(method, url, timeout=8)
    except httpx.HTTPError:
        return
    value = r.headers.get(header_name, "")
    if substr and substr.lower() in value.lower():
        yield {
            "type": "finding",
            "description": f"{template.description} ({header_name}: {value})",
            "evidence": f"URL: {url}\n{header_name}: {value}",
            "url": url,
        }


async def _run_status_and_body_contains(template: Template, target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    url = _build_url(target, template.request["path"])
    method = template.request.get("method", "GET")
    expected_status = template.matcher.get("status", 200)
    any_of = [str(s).lower() for s in template.matcher.get("any_of", [])]
    yield {"type": "probe", "method": method, "url": url, "note": "status+body check"}
    try:
        r = await client.request(method, url, timeout=8)
    except httpx.HTTPError:
        return
    if r.status_code != expected_status:
        return
    body_lower = r.text.lower()
    matched = [s for s in any_of if s in body_lower]
    if matched:
        yield {
            "type": "finding",
            "description": f"{template.description} (matched: {matched})",
            "evidence": f"URL: {url}\nStatus: {r.status_code}\nMatched indicators: {matched}\nSnippet: {r.text[:300]}",
            "url": url,
        }


async def _run_word_not_in_baseline(template: Template, target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    url = _build_url(target, template.request["path"])
    method = template.request.get("method", "GET")
    injection_points = _iter_injection_points(template)
    if not injection_points:
        return
    words = [str(w).lower() for w in template.matcher.get("words", [])]
    baseline_value = str((template.baseline or {}).get("value", "probe"))

    for location, name in injection_points:
        yield {"type": "probe", "method": method, "url": url, "note": f"baseline for {location}={name}"}
        try:
            base_r = await _send(client, method, url, location, name, baseline_value)
            baseline_body = base_r.text.lower()
        except httpx.HTTPError:
            continue
        for payload in template.payloads:
            try:
                r = await _send(client, method, url, location, name, payload)
            except httpx.HTTPError:
                continue
            bl = r.text.lower()
            for w in words:
                if w in bl and w not in baseline_body:
                    yield {
                        "type": "finding",
                        "description": f"{template.description} (matched pattern `{w}`, via {location}={name})",
                        "evidence": (f"URL: {url}\n{location}={name}\nPayload: {payload}\n"
                                     f"Matched pattern: {w}\nResponse: {r.text[:300]}"),
                        "url": url,
                    }
                    break


async def _run_response_time_threshold(template: Template, target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    url = _build_url(target, template.request["path"])
    method = template.request.get("method", "GET")
    injection_points = _iter_injection_points(template)
    if not injection_points:
        return
    threshold = float(template.matcher.get("threshold_seconds", 4.0))
    repeat = int(template.matcher.get("repeat", 1))

    for location, name in injection_points:
        for payload in template.payloads:
            confirmations = 0
            last_elapsed = 0.0
            for _ in range(repeat):
                yield {"type": "probe", "method": method, "url": url, "note": f"timing probe {location}={name}"}
                try:
                    t0 = time.monotonic()
                    await _send(client, method, url, location, name, payload)
                    elapsed = time.monotonic() - t0
                except httpx.HTTPError:
                    break
                last_elapsed = elapsed
                if elapsed >= threshold:
                    confirmations += 1
                else:
                    break  # one fast response disqualifies this attempt
            if confirmations >= repeat:
                yield {
                    "type": "finding",
                    "description": (f"{template.description} (confirmed {confirmations}x, "
                                     f"last elapsed {last_elapsed:.1f}s, via {location}={name})"),
                    "evidence": (f"URL: {url}\n{location}={name}\nPayload: {payload}\n"
                                 f"Threshold: {threshold}s\nConfirmations: {confirmations}/{repeat}"),
                    "url": url,
                }


_MATCHER_RUNNERS = {
    "header-absent": _run_header_absent,
    "header-value-contains": _run_header_value_contains,
    "status-and-body-contains": _run_status_and_body_contains,
    "word-not-in-baseline": _run_word_not_in_baseline,
    "response-time-threshold": _run_response_time_threshold,
}


async def run_template(template: Template, target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Execute one template against one target. Yields plain dicts —
    {"type": "probe", ...} or {"type": "finding", "description", "evidence",
    "url"} — never raises on a single request failure (each matcher runner
    catches httpx.HTTPError internally and simply yields nothing for that
    attempt)."""
    runner = _MATCHER_RUNNERS.get(template.matcher["type"])
    if runner is None:
        return
    async for event in runner(template, target, client):
        yield event
