"""
AI Attack Suite API — Shannon AI security scanner integration.

Shannon is a Node.js CLI tool installed via `npx @keygraph/shannon`.
It requires Docker and a local repo path, and produces a Markdown security report.
"""

import asyncio
import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/ai-attack-suite", tags=["AIAttackSuite"])

_scan_history: dict[str, dict] = {}

settings = get_settings()


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class ShannonScanRequest(BaseModel):
    target_url: str
    repo_path: str
    app_description: str = ""
    login_url: str = ""
    login_type: str = "form"  # form, basic, token
    username: str = ""
    password: str = ""
    token: str = ""
    avoid_paths: list[str] = []
    focus_paths: list[str] = []
    max_concurrent_pipelines: int = 2

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target_url is required")
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v

    @field_validator("repo_path")
    @classmethod
    def validate_repo_path(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("repo_path is required")
        p = Path(v)
        if not p.exists():
            raise ValueError(f"repo_path does not exist: {v}")
        if not p.is_dir():
            raise ValueError(f"repo_path must be a directory: {v}")
        return str(p.resolve())

    @field_validator("app_description")
    @classmethod
    def validate_app_description(cls, v: str) -> str:
        return v[:500]

    @field_validator("max_concurrent_pipelines")
    @classmethod
    def validate_max_concurrent_pipelines(cls, v: int) -> int:
        if not (1 <= v <= 10):
            raise ValueError("max_concurrent_pipelines must be between 1 and 10")
        return v


# ---------------------------------------------------------------------------
# Shannon config YAML builder
# ---------------------------------------------------------------------------

def _build_shannon_config(req: ShannonScanRequest) -> str:
    """Build Shannon YAML config from the request."""
    config: dict = {}

    if req.app_description:
        config["description"] = req.app_description

    # Auth section — only if login_url is provided
    if req.login_url:
        auth: dict = {
            "login_type": req.login_type,
            "login_url": req.login_url,
        }
        credentials: dict = {}
        if req.username:
            credentials["username"] = req.username
        if req.password:
            credentials["password"] = req.password
        if req.token:
            credentials["token"] = req.token
        if credentials:
            auth["credentials"] = credentials
        config["authentication"] = auth

    # Rules section
    rules: dict = {}

    if req.avoid_paths:
        rules["avoid"] = [
            {"description": "Avoid path", "type": "path", "url_path": p}
            for p in req.avoid_paths
        ]

    if req.focus_paths:
        rules["focus"] = [
            {"description": "Focus path", "type": "path", "url_path": p}
            for p in req.focus_paths
        ]

    if rules:
        config["rules"] = rules

    config["pipeline"] = {
        "retry_preset": "subscription",
        "max_concurrent_pipelines": req.max_concurrent_pipelines,
    }

    return yaml.dump(config, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Shannon binary detection
# ---------------------------------------------------------------------------

def _get_shannon_cmd() -> list[str] | None:
    """Return the command prefix to invoke Shannon, or None if unavailable."""
    shannon = shutil.which("shannon")
    if shannon:
        return [shannon]
    npx = shutil.which("npx")
    if npx:
        return [npx, "@keygraph/shannon"]
    return None


def _find_latest_shannon_report() -> str | None:
    """Find the most recently modified Shannon comprehensive report."""
    workspace_dir = Path.home() / ".shannon" / "workspaces"
    if not workspace_dir.exists():
        return None

    reports = list(workspace_dir.glob("*/deliverables/comprehensive_security_assessment_report.md"))
    if not reports:
        return None

    # Sort by modification time, newest first
    reports.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    try:
        return reports[0].read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main streaming function
# ---------------------------------------------------------------------------

async def _stream_shannon(scan_id: str, req: ShannonScanRequest) -> AsyncGenerator[str, None]:
    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    timestamp = datetime.now(timezone.utc).isoformat()

    yield _sse("start", {
        "scan_id": scan_id,
        "target_url": req.target_url,
        "repo_path": req.repo_path,
        "timestamp": timestamp,
    })

    _scan_history[scan_id] = {
        "id": scan_id,
        "target_url": req.target_url,
        "repo_path": req.repo_path,
        "status": "running",
        "started_at": timestamp,
        "report": None,
    }

    config_path: str | None = None

    try:
        # Write Shannon config to temp file
        config_yaml = _build_shannon_config(req)
        config_fd, config_path = tempfile.mkstemp(suffix=".yaml", prefix="shannon_")
        try:
            os.write(config_fd, config_yaml.encode("utf-8"))
        finally:
            os.close(config_fd)

        yield _sse("progress", {
            "message": f"Shannon config written to {config_path}",
            "scan_id": scan_id,
        })

        # Build command
        shannon_cmd = _get_shannon_cmd()
        if not shannon_cmd:
            raise RuntimeError("Shannon (or npx) is not available on this server")

        cmd = shannon_cmd + [
            "start",
            "-u", req.target_url,
            "-r", req.repo_path,
            "-c", config_path,
        ]

        yield _sse("progress", {
            "message": f"Starting Shannon: {' '.join(cmd)}",
            "scan_id": scan_id,
        })

        # Build environment — pass ANTHROPIC_API_KEY
        env = os.environ.copy()
        if settings.ANTHROPIC_API_KEY:
            env["ANTHROPIC_API_KEY"] = settings.ANTHROPIC_API_KEY

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        assert proc.stdout is not None
        assert proc.stderr is not None

        # Drain stdout + stderr concurrently into one queue (same pattern as nuclei.py)
        queue: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue()

        async def _drain_stdout() -> None:
            async for chunk in proc.stdout:  # type: ignore[union-attr]
                await queue.put(("out", chunk))
            await queue.put(None)

        async def _drain_stderr() -> None:
            async for chunk in proc.stderr:  # type: ignore[union-attr]
                await queue.put(("err", chunk))
            await queue.put(None)

        t1 = asyncio.create_task(_drain_stdout())
        t2 = asyncio.create_task(_drain_stderr())

        done_count = 0
        while done_count < 2:
            item = await queue.get()
            if item is None:
                done_count += 1
                continue

            _, raw = item
            line = raw.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue

            yield _sse("progress", {"message": line, "scan_id": scan_id})
            await asyncio.sleep(0)

        await asyncio.gather(t1, t2, return_exceptions=True)
        await proc.wait()

        # Find the most recent Shannon report
        report_content = _find_latest_shannon_report()

        if report_content:
            _scan_history[scan_id]["report"] = report_content
            yield _sse("report_ready", {"content": report_content})
        else:
            yield _sse("progress", {
                "message": "No Shannon report found in ~/.shannon/workspaces/",
                "scan_id": scan_id,
            })

        _scan_history[scan_id].update({
            "status": "completed" if proc.returncode == 0 else "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "exit_code": proc.returncode,
        })

        yield _sse("complete", {
            "scan_id": scan_id,
            "exit_code": proc.returncode,
            "report_available": report_content is not None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        yield _sse("error", {"message": str(exc)})

    finally:
        # Clean up temp config
        if config_path and os.path.exists(config_path):
            try:
                os.unlink(config_path)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", summary="Run a Shannon AI security scan and stream results")
async def run_shannon_scan(
    payload: ShannonScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    if not shutil.which("shannon") and not shutil.which("npx"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Neither 'shannon' nor 'npx' is installed on this server. Install Node.js to use Shannon.",
        )

    scan_id = str(uuid.uuid4())
    return StreamingResponse(
        _stream_shannon(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans", summary="List Shannon scan history")
async def list_shannon_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scans = sorted(
        _scan_history.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}", summary="Get Shannon scan result")
async def get_shannon_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/requirements", summary="Check Shannon prerequisites")
async def check_shannon_requirements(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return {
        "shannon_available": shutil.which("shannon") is not None,
        "npx_available": shutil.which("npx") is not None,
        "docker_available": shutil.which("docker") is not None,
        "anthropic_api_key_set": bool(settings.ANTHROPIC_API_KEY),
    }
