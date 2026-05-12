"""
AttackTrace FastAPI application.

Configures lifespan (startup/shutdown), CORS, error handlers,
OpenAPI metadata, and mounts all API routers.
"""

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from pathlib import Path

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

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
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# --- Request timeout middleware ---
# Prevents slow DB queries or hung external calls from holding connections open indefinitely.
# SSE streaming endpoints are excluded (they intentionally run for minutes).
class TimeoutMiddleware:
    """Abort non-streaming requests that take longer than REQUEST_TIMEOUT_SECONDS."""

    def __init__(self, app, timeout: float = 60.0):
        self.app = app
        self.timeout = timeout

    async def __call__(self, scope, receive, send):
        import asyncio
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        # SSE streams and long-poll endpoints must not be cut off
        if path.endswith("/stream") or path.endswith("/events"):
            await self.app(scope, receive, send)
            return
        try:
            await asyncio.wait_for(self.app(scope, receive, send), timeout=self.timeout)
        except asyncio.TimeoutError:
            if scope["type"] == "http":
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
    _asyncio.create_task(preload_templates())
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


# --- Request ID + timing + security headers middleware ---
@app.middleware("http")
async def request_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start = time.perf_counter()

    response = await call_next(request)

    duration_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-Ms"] = f"{duration_ms:.1f}"
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if settings.ENVIRONMENT != "development":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
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
app.mount("/static/screenshots", StaticFiles(directory=str(_screenshots_root)), name="screenshots")

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
