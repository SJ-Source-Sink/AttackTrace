"""
AttackTrace FastAPI application.

Configures lifespan (startup/shutdown), CORS, error handlers,
OpenAPI metadata, and mounts all API routers.
"""

import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from pathlib import Path

import structlog
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Sensitive field patterns to scrub from log output
_SENSITIVE_FIELDS_RE = re.compile(
    r'("(?:password|token|secret|api_key|authorization|cookie|'
    r'access_token|refresh_token|key_hash|anthropic_api_key)"\s*:\s*)"[^"]{4,}"',
    re.IGNORECASE,
)

from app.core.config import get_settings
from app.core.database import close_db, init_db

settings = get_settings()

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# --- Structured logging ---
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        logging.DEBUG if settings.DEBUG else logging.INFO
    ),
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logger = structlog.get_logger("attacktrace.platform")

# --- Rate limiter ---
# Global: 200/min per IP  |  Auth endpoints: 10/min per IP (brute-force protection)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200/minute"],
    application_limits=[],
)


# --- Request timeout middleware ---
# Prevents a hung request (stuck DB query, hung external call) from holding a
# connection open forever, WITHOUT cutting off legitimate long-running SSE
# streams. Previously did this by matching the path against a fixed list of
# suffixes ("/stream", "/events", "/scan") and skipping the timeout entirely
# for matches — fragile (any new streaming endpoint not ending in one of
# those three strings silently inherits the hard cutoff) and confirmed
# broken in practice: POST /attack-suite/agent/run streams via SSE but
# doesn't match any suffix, so a real agent run past 60s got its connection
# killed by this middleware mid-stream, and a scan of every StreamingResponse
# route in the app found 11 other pre-existing endpoints with the same gap.
#
# Correct behavior-based fix: only enforce the timeout on time-to-first-byte.
# Once the wrapped app has sent its response headers (started producing
# output at all — the case for every streaming endpoint, which all emit
# an SSE "start" event almost immediately), the request is no longer "hung"
# by definition and runs to completion with no further time limit. A request
# that never produces so much as a first byte within the timeout is aborted
# with a 504, exactly as before.
class TimeoutMiddleware:
    def __init__(self, app, timeout: float = 60.0):
        self.app = app
        self.timeout = timeout

    async def __call__(self, scope, receive, send):
        import asyncio
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = asyncio.Event()

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                started.set()
            await send(message)

        app_task = asyncio.ensure_future(self.app(scope, receive, wrapped_send))
        started_task = asyncio.ensure_future(started.wait())
        try:
            await asyncio.wait(
                {app_task, started_task}, timeout=self.timeout, return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            if not started_task.done():
                started_task.cancel()

        if app_task.done():
            exc = app_task.exception()
            if exc:
                raise exc
            return

        if started.is_set():
            # Response has started — no longer "hung"; let it run to completion.
            await app_task
            return

        # Neither the app finished nor produced any output within the timeout.
        app_task.cancel()
        try:
            await app_task
        except (asyncio.CancelledError, Exception):
            pass
        body = b'{"detail":"Request timed out","code":"GATEWAY_TIMEOUT"}'
        await send({"type": "http.response.start", "status": 504,
                    "headers": [[b"content-type", b"application/json"],
                                [b"content-length", str(len(body)).encode()]]})
        await send({"type": "http.response.body", "body": body})


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown tasks."""
    logger.info(f"Starting AttackTrace {settings.APP_VERSION} ({settings.ENVIRONMENT})")

    # Only create tables in development; in production, use Alembic migrations
    if settings.ENVIRONMENT == "development":
        await init_db()
        logger.info("Database tables created (development mode)")

    # Pre-load nuclei templates in background (12k+ YAML files, ~20s blocking I/O)
    import asyncio as _asyncio
    from app.api.v1.nuclei import preload_templates
    app.state.preload_task = _asyncio.create_task(preload_templates())
    logger.info("Nuclei template pre-loading started in background")

    # On startup: recover scans that were PENDING or RUNNING when the server last died.
    # This catches tasks lost during deployments or crashes without waiting for the watchdog.
    try:
        from app.workers.scan_worker import recover_stuck_scans
        recover_stuck_scans.apply_async(queue="default")
        logger.info("Startup scan recovery triggered")
    except Exception as _e:
        logger.warning(f"Could not trigger startup scan recovery: {_e}")

    yield

    logger.info("Shutting down AttackTrace")
    await close_db()


app = FastAPI(
    title="AttackTrace API",
    description=(
        "Enterprise API for the AttackTrace platform. "
        "Provides multi-tenant scan management, real-time progress streaming, "
        "AI-powered triage, and security finding lifecycle management."
    ),
    version=settings.APP_VERSION,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    lifespan=lifespan,
    generate_unique_id_function=lambda route: route.name,
    contact={
        "name": "AttackTrace",
        "url": "https://github.com/attacktrace-platform",
    },
    license_info={
        "name": "MIT",
    },
    openapi_tags=[
        {"name": "Authentication", "description": "JWT auth, registration, token refresh"},
        {"name": "Organizations", "description": "Org CRUD, workspaces, members, API keys, credentials"},
        {"name": "Scans", "description": "Scan lifecycle management and SSE streaming"},
        {"name": "Assets", "description": "Discovered asset inventory with filtering"},
        {"name": "Findings", "description": "Security finding lifecycle and comment threads"},
        {"name": "Reports", "description": "HTML report generation"},
        {"name": "AI", "description": "Claude-powered triage, NL search, and executive summaries"},
    ],
)

# --- Rate limiter ---
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- Request timeout (60s for all non-streaming endpoints) ---
app.add_middleware(TimeoutMiddleware, timeout=60.0)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining", "X-Response-Time-Ms"],
)


# Paths that require stricter per-IP rate limiting (brute-force targets)
_AUTH_RATE_PATHS = frozenset({"/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh"})
# In-process auth rate limit: simple token-bucket per IP in Redis via slowapi
# Declared here so auth router can reference it via app.state.auth_limiter
from slowapi import Limiter as _Limiter
_auth_limiter = _Limiter(key_func=get_remote_address, default_limits=[f"{settings.AUTH_RATE_LIMIT_PER_MINUTE}/minute"])


# --- Request ID + timing + security headers middleware ---
@app.middleware("http")
async def request_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    # Bind request_id into structlog context for all log statements in this request
    import structlog
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        remote_ip=request.client.host if request.client else "unknown",
    )

    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-Ms"] = f"{duration_ms:.1f}"

    # Security headers — applied to every response
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
    )
    # API responses have no need to embed in frames or load external resources
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if settings.ENVIRONMENT != "development":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

    # Log slow requests (>2s non-streaming) at WARN level
    path = request.url.path
    is_streaming = any(path.endswith(s) for s in ("/stream", "/events", "/scan", "/start"))
    if not is_streaming and duration_ms > 2000:
        logger.warning(
            "slow_request",
            duration_ms=round(duration_ms),
            status=response.status_code,
        )

    return response


# --- Error handlers ---
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return consistent validation error shape."""
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error.get("loc", []))
        errors.append({"field": field, "message": error.get("msg"), "type": error.get("type")})

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": errors,
            }
        },
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": {"code": "NOT_FOUND", "message": "The requested resource was not found"}},
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.exception(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred"}},
    )


# --- Static files (screenshots) ---
_screenshots_root = Path(settings.ATTACKTRACE_WORKSPACE_DIR)
_screenshots_root.mkdir(parents=True, exist_ok=True)


class _ScreenshotFiles(StaticFiles):
    """Serve only screenshot images from the scan workspace.

    The workspace also holds every scanner's history JSON, reports and org config, so the
    mount must not expose anything beyond ``<...>/screenshots/<file>.<image ext>``. <img>
    tags can't send auth headers, so access relies on the unguessable org/scan UUID path.
    """

    _IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp")

    async def get_response(self, path, scope):
        parts = path.replace("\\", "/").split("/")
        if "screenshots" not in parts[:-1] or not path.lower().endswith(self._IMAGE_EXTS):
            raise HTTPException(status_code=404)
        return await super().get_response(path, scope)


app.mount("/static/screenshots", _ScreenshotFiles(directory=str(_screenshots_root)), name="screenshots")

# --- Routers ---
from app.api.v1.router import api_router

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


# --- Health / readiness endpoints ---
@app.get("/health", tags=["Health"], summary="Health check")
async def health_check() -> dict:
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/ready", tags=["Health"], summary="Readiness check (DB + Redis + Celery connectivity)")
async def readiness_check() -> dict:
    import asyncio as _asyncio
    from sqlalchemy import text
    from app.core.database import engine
    import redis.asyncio as aioredis

    checks: dict[str, Any] = {}

    async def _check_db():
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as e:
            checks["database"] = f"error: {e}"

    async def _check_redis():
        try:
            r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
            await r.ping()
            await r.aclose()
            checks["redis"] = "ok"
        except Exception as e:
            checks["redis"] = f"error: {e}"

    async def _check_celery():
        # Check Celery broker reachability via an async Redis PING.
        # A direct kombu inspect in a thread pool is unreliable in production
        # (kombu borrows connections that may not be thread-safe in all setups).
        # Broker reachable ≈ workers can receive tasks; deeper worker-alive checks
        # belong in a separate metrics endpoint.
        try:
            broker_url = settings.CELERY_BROKER_URL
            r = aioredis.from_url(broker_url, socket_connect_timeout=2)
            await r.ping()
            await r.aclose()
            checks["celery_broker"] = "ok"
        except Exception as e:
            checks["celery_broker"] = f"error: {e}"

    await _asyncio.gather(_check_db(), _check_redis(), _check_celery())

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ready" if all_ok else "degraded", "checks": checks},
    )
