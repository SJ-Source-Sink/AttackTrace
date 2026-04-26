"""
MCP (Model Context Protocol) Server Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects unauthenticated MCP server exposures.
MCP servers exposed without authentication leak tool definitions,
system prompts, and may allow arbitrary tool execution.

Detection: probe known MCP endpoint patterns for unauthenticated
list_tools JSON-RPC calls.
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, AsyncGenerator
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/mcp-scanner", tags=["MCP Scanner"])

# MCP server endpoint patterns
MCP_ENDPOINTS = [
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
]

# MCP JSON-RPC probe payloads
MCP_PROBES = [
    {
        "name": "list_tools",
        "payload": {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1},
        "indicator_keys": ["tools", "result"],
        "severity": "critical",
        "description": "Unauthenticated tools/list exposes all available MCP tools and their schemas",
    },
    {
        "name": "initialize",
        "payload": {"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "scanner", "version": "1.0"}}, "id": 1},
        "indicator_keys": ["protocolVersion", "serverInfo", "capabilities"],
        "severity": "high",
        "description": "Server responds to unauthenticated initialize handshake",
    },
    {
        "name": "list_resources",
        "payload": {"jsonrpc": "2.0", "method": "resources/list", "params": {}, "id": 1},
        "indicator_keys": ["resources", "result"],
        "severity": "high",
        "description": "Unauthenticated resources/list may expose sensitive data sources",
    },
    {
        "name": "list_prompts",
        "payload": {"jsonrpc": "2.0", "method": "prompts/list", "params": {}, "id": 1},
        "indicator_keys": ["prompts", "result"],
        "severity": "medium",
        "description": "Unauthenticated prompts/list exposes system prompt templates",
    },
]

# SSE endpoint patterns (MCP over SSE transport)
MCP_SSE_ENDPOINTS = [
    "/mcp/sse",
    "/sse",
    "/events",
    "/mcp/events",
    "/api/sse",
]


def _check_mcp_response(resp: httpx.Response, probe: dict) -> dict:
    """Check if response indicates a real MCP server."""
    try:
        body = resp.json()
    except Exception:
        body = {}

    body_str = str(body).lower()
    indicators = []
    exposed_tools = []

    for key in probe["indicator_keys"]:
        if key in body or key in body_str:
            indicators.append(f"Response contains '{key}' field")

    # Extract tool names if available
    if "result" in body and isinstance(body.get("result"), dict):
        result = body["result"]
        if "tools" in result and isinstance(result["tools"], list):
            exposed_tools = [t.get("name", "unknown") for t in result["tools"][:10]]
            indicators.append(f"Exposed {len(result['tools'])} tools")
        if "resources" in result and isinstance(result.get("resources"), list):
            indicators.append(f"Exposed {len(result['resources'])} resources")
        if "prompts" in result and isinstance(result.get("prompts"), list):
            indicators.append(f"Exposed {len(result['prompts'])} prompts")
        if "serverInfo" in result:
            indicators.append(f"Server info: {result.get('serverInfo', {})}")

    # Check for jsonrpc response structure
    is_mcp = bool(body.get("jsonrpc") == "2.0") or len(indicators) > 0

    return {
        "is_mcp": is_mcp,
        "indicators": indicators,
        "exposed_tools": exposed_tools,
        "response_preview": json.dumps(body)[:300] if body else resp.text[:300],
    }


class MCPScanRequest(BaseModel):
    target: str = ""
    target_url: str = ""
    timeout: int = 10
    check_sse: bool = True

    @property
    def resolved_target(self) -> str:
        return (self.target_url or self.target).rstrip("/")


async def _run_mcp_scan(target_url: str, timeout: int, check_sse: bool) -> AsyncGenerator[str, None]:
    target = target_url.rstrip("/")
    total_probes = len(MCP_ENDPOINTS) * len(MCP_PROBES)
    if check_sse:
        total_probes += len(MCP_SSE_ENDPOINTS)

    yield f"data: {json.dumps({'type': 'start', 'target': target, 'probes': total_probes})}\n\n"

    findings = []

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # Phase 1: JSON-RPC probes
        for endpoint_path in MCP_ENDPOINTS:
            url = f"{target}{endpoint_path}"
            for probe in MCP_PROBES:
                try:
                    resp = await client.post(
                        url,
                        json=probe["payload"],
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.status_code in (404, 405, 502, 503):
                        continue

                    check = _check_mcp_response(resp, probe)

                    if check["is_mcp"] and resp.status_code in (200, 201):
                        finding = {
                            "type": "mcp_exposure",
                            "url": url,
                            "probe": probe["name"],
                            "severity": probe["severity"],
                            "description": probe["description"],
                            "indicators": check["indicators"],
                            "exposed_tools": check["exposed_tools"],
                            "response_preview": check["response_preview"],
                            "remediation": "Add authentication to your MCP server. Use API keys, OAuth2, or IP allowlisting.",
                        }
                        findings.append(finding)
                        yield f"data: {json.dumps(finding)}\n\n"
                    else:
                        yield f"data: {json.dumps({'type': 'probe', 'url': url, 'probe': probe['name'], 'status': resp.status_code, 'result': 'no_mcp'})}\n\n"
                except Exception as e:
                    yield f"data: {json.dumps({'type': 'probe_error', 'url': url, 'error': str(e)[:100]})}\n\n"

        # Phase 2: SSE transport detection
        if check_sse:
            yield f"data: {json.dumps({'type': 'sse_phase_start'})}\n\n"
            for sse_path in MCP_SSE_ENDPOINTS:
                url = f"{target}{sse_path}"
                try:
                    # Use a short timeout for SSE - just check if it connects
                    async with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as stream:
                        content_type = stream.headers.get("content-type", "")
                        is_sse = "text/event-stream" in content_type

                        first_chunk = ""
                        async for chunk in stream.aiter_text():
                            first_chunk = chunk[:200]
                            break

                        if is_sse or "data:" in first_chunk:
                            finding = {
                                "type": "mcp_sse_exposure",
                                "url": url,
                                "severity": "high",
                                "description": "Unauthenticated MCP SSE transport endpoint detected",
                                "indicators": ["SSE endpoint responds without authentication"],
                                "response_preview": first_chunk,
                                "remediation": "Add authentication middleware before SSE endpoint",
                            }
                            findings.append(finding)
                            yield f"data: {json.dumps(finding)}\n\n"
                except Exception:
                    pass

    # Summary
    critical = len([f for f in findings if f.get("severity") == "critical"])
    high = len([f for f in findings if f.get("severity") == "high"])
    yield f"data: {json.dumps({'type': 'complete', 'total_findings': len(findings), 'critical': critical, 'high': high, 'summary': 'MCP server scan complete'})}\n\n"


@router.post(
    "/scan",
    summary="Scan target for unauthenticated MCP server exposures",
    description="Probes for exposed Model Context Protocol servers and tests for unauthenticated tool listing.",
)
async def scan_mcp_server(
    payload: MCPScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    if not payload.resolved_target:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="target or target_url is required")
    return StreamingResponse(
        _run_mcp_scan(payload.resolved_target, payload.timeout, payload.check_sse),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
