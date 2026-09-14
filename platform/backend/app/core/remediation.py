"""
Shared remediation-text lookup for scanners that don't already have their own
(cspm.py, takeover.py, container_scanner.py, firewall.py, mcp_scanner.py, and
supply_chain.py all have good per-check remediation dicts already — call those
directly rather than this module). This exists for secrets.py, exposure_scanner.py,
email_security.py, api_scanner.py, ai_scanner.py, and the core orchestrated scan
pipeline (scan_worker.py), none of which had any.

Lookup order in get_remediation(): exact category key, then a substring match
against _KEYWORD_REMEDIATION (for scanners whose finding titles are dynamic
strings rather than a fixed check-id), then a generic fallback.
"""

# Keyed by an exact category/check-name string (secrets.py pattern names,
# exposure_scanner.py EXPOSED_PATHS categories).
_CATEGORY_REMEDIATION: dict[str, str] = {
    # secrets.py SECRET_PATTERNS names
    "AWS Access Key": "Revoke the exposed AWS access key immediately in IAM, rotate any dependent credentials, and audit CloudTrail for unauthorized use before the key was revoked.",
    "AWS Secret Key": "Revoke the exposed AWS secret key immediately in IAM, rotate any dependent credentials, and audit CloudTrail for unauthorized use before the key was revoked.",
    "Generic API Key": "Rotate the exposed API key immediately and move it to a secrets manager (e.g. AWS Secrets Manager, Vault) rather than source code or client-side bundles.",
    "JWT Token": "If this is a live signing/session token, revoke it and force re-authentication. Never embed long-lived JWTs in client-side code or public repos.",
    "RSA Private Key": "Rotate the exposed private key and revoke/reissue any certificates or trust relying on it immediately.",
    "Private Key": "Rotate the exposed private key and revoke/reissue any certificates or trust relying on it immediately.",
    "Stripe Secret Key": "Roll the Stripe secret key immediately in the Stripe dashboard — a live secret key grants full account access to charges and payouts.",
    "Stripe Publishable Key": "Publishable keys are meant to be public, but confirm this wasn't paired with a leaked secret key nearby, and restrict it to expected domains in the Stripe dashboard.",
    "GitHub Token": "Revoke the exposed GitHub token immediately in Settings > Developer settings and audit recent repository activity for unauthorized access.",
    "GitHub OAuth": "Revoke the exposed GitHub OAuth token immediately and audit recent repository/organization activity for unauthorized access.",
    "Google API Key": "Restrict or regenerate the exposed Google API key in Google Cloud Console, and add HTTP referrer / IP restrictions to limit its use.",
    "Slack Token": "Revoke the exposed Slack token in the Slack app management console immediately — it can read/post messages and access workspace data.",
    "Generic Secret": "Rotate the exposed credential and move it to a secrets manager rather than source code or client-side bundles.",
    "Database URL": "Rotate the database credentials embedded in this connection string immediately and move it to an environment variable or secrets manager.",
    "Internal IP": "Confirm this internal IP disclosure doesn't reveal network topology useful for an attacker; low severity on its own but review surrounding context.",
    "Source Map Exposed": "Remove source maps from production builds, or restrict access to them — they can reveal original source code and internal comments.",
    "Git Repository Exposed": "Remove the publicly accessible .git directory from the web server immediately — it can leak full source history including past secrets.",

    # exposure_scanner.py EXPOSED_PATHS categories
    "version_control": "Remove exposed version-control metadata (.git, .svn, .hg) from the web root — it can leak full source history including past secrets.",
    "environment_files": "Remove exposed environment files (.env, .env.local, etc.) from the web root immediately and rotate any credentials they contained.",
    "backup_files": "Remove exposed backup files from the web root — they often contain full application source or database dumps.",
    "config_files": "Remove exposed configuration files from the web root and move sensitive config to environment variables outside the document root.",
    "credentials": "Remove exposed credential files from the web root immediately and rotate any credentials they contained.",
    "debug_info": "Disable debug/verbose error output in production — stack traces and debug endpoints can leak internal paths, versions, and logic.",
    "logs": "Remove exposed log files from the web root — they can leak internal paths, session tokens, or user data.",
    "cloud": "Restrict access to exposed cloud metadata/config endpoints and confirm they don't leak credentials or internal topology.",

    # cloud.py (Cloud Discovery / cloudlist) resource-exposure categories
    "cloud-storage-exposure": "Confirm this storage bucket/container's access policy is not allUsers/AllUsers or AllAuthenticatedUsers-readable; restrict it to explicit IAM principals and enable the provider's bucket-level public-access-block setting.",
    "cloud-data-exposure": "Move this database/cache resource into a private subnet with no public IP, restrict its security group/firewall rules to known application hosts only, and confirm authentication is enforced (not just network-level control).",
    "cloud-cluster-exposure": "Restrict the cluster's API/management endpoint to a private network or an allowlisted set of admin IPs, and confirm RBAC/authentication is enforced on the exposed endpoint.",
    "cloud-admin-exposure": "Move this admin/management interface behind a VPN or bastion host rather than exposing it directly to the internet, and confirm it requires strong authentication (MFA where supported).",
    "cloud-compute-exposure": "Confirm this compute resource genuinely needs a public IP; if not, remove it and route access through a load balancer, bastion, or VPN instead of exposing the instance directly.",
    "cloud-exposure": "Review why this cloud resource is directly reachable from the public internet and restrict its network exposure if that wasn't intentional.",

    # attack_suite.py classic scanner module categories — fallback only.
    # Every `_finding()` call site in attack_suite.py already carries a
    # specific, per-check remediation string written inline at the point of
    # detection (checked: all 153 call sites, none empty), so these entries
    # are a defensive backstop for a future module that forgets to pass one,
    # keyed by the same "attack-suite-{module}" category the adapter builds.
    "attack-suite-xss": "HTML-encode all user-supplied input before reflecting it in a response, and implement a strict Content-Security-Policy as defense in depth.",
    "attack-suite-sqli": "Use parameterized queries / prepared statements for all database access; never build SQL from string concatenation with user input.",
    "attack-suite-ssrf": "Validate and allowlist destination hosts for any server-side outbound request; block requests to internal/link-local/cloud-metadata IP ranges (169.254.169.254, RFC1918, ::1).",
    "attack-suite-idor": "Enforce object-level authorization on every request — verify the authenticated user owns or is permitted to access the specific resource ID requested, not just that they're authenticated.",
    "attack-suite-cors": "Do not reflect arbitrary Origin values in Access-Control-Allow-Origin, especially alongside Access-Control-Allow-Credentials: true; use an explicit origin allowlist.",
    "attack-suite-csrf": "Require a per-session, unpredictable CSRF token on all state-changing requests and validate it server-side; set cookies with SameSite=Lax or Strict.",
    "attack-suite-headers": "Add the missing security headers (Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options/frame-ancestors, Referrer-Policy).",
    "attack-suite-jwt": "Enforce a fixed, expected signing algorithm server-side (reject alg=none and algorithm-confusion attempts), use a strong random signing secret/key, and validate all standard claims (exp, iss, aud).",
    "attack-suite-graphql": "Disable introspection in production, enforce query depth/complexity/cost limits, and apply the same object-level authorization checks to GraphQL resolvers as REST endpoints.",
    "attack-suite-privilege": "Enforce role/permission checks server-side on every privileged action and never trust a client-supplied role/permission field (mass-assignment guard on update endpoints).",
    "attack-suite-account": "Require re-authentication (current password or step-up MFA) before allowing email/password changes, and validate password-reset tokens are single-use, short-lived, and bound to the requesting account.",
    "attack-suite-cache": "Normalize and strip unkeyed request inputs (headers, query params) before they can influence a cached response, or exclude dynamic responses from caching entirely.",
    "attack-suite-race": "Use database-level locking, unique constraints, or atomic increment/decrement operations for any operation involving balances, quotas, or limited-use resources instead of read-then-write logic.",
    "attack-suite-business": "Re-validate all business-logic invariants (price, quantity, totals) server-side from trusted source data — never trust client-submitted values for anything affecting money or inventory.",
    "attack-suite-auth_bypass": "Ensure authentication/authorization middleware applies uniformly to all paths and cannot be bypassed via path manipulation, alternate headers, or internal-only routing assumptions.",
    "attack-suite-takeover": "Remove the dangling DNS record pointing at the deprovisioned service, or reclaim the resource at the target provider before an attacker can claim it.",
    "attack-suite-nosql": "Sanitize and type-check all user input before it reaches a NoSQL query (reject operator-like objects, e.g. $ne/$gt, in fields expecting scalars).",
    "attack-suite-ssti": "Never render user-supplied input through a template engine's evaluation path; use a logic-less template mode or sandboxed environment that cannot execute arbitrary expressions.",
    "attack-suite-redirect": "Validate redirect destinations against an allowlist of known-safe paths/domains rather than accepting an arbitrary user-supplied URL.",
    "attack-suite-2fa_bypass": "Ensure the MFA/2FA verification step cannot be skipped by manipulating client-side state, response codes, or by omitting the second-factor request entirely.",
    "attack-suite-oauth": "Validate the redirect_uri against an exact allowlist, always use and verify the `state` parameter, and never accept unsigned or unverified tokens from the client.",
    "attack-suite-oauth_advanced": "Validate the redirect_uri against an exact allowlist, always use and verify the `state`/PKCE parameters, and ensure authorization codes/tokens cannot be replayed or substituted across clients.",
    "attack-suite-smuggling": "Ensure front-end proxy and back-end server agree exactly on how Content-Length and Transfer-Encoding are parsed; prefer HTTP/2 end-to-end or a proxy that normalizes/rejects ambiguous requests.",
    "attack-suite-crlf": "Strip or reject CR/LF characters from any user input that is later placed into an HTTP header or log line to prevent header/log injection.",
    "attack-suite-hpp": "Explicitly define how duplicate query/body parameters are handled server-side (reject or consistently take first/last) rather than relying on framework-default, inconsistent behavior.",
    "attack-suite-saml": "Enforce and validate XML signature verification on every SAML assertion, reject unsigned assertions, and disable XML external entity processing in the SAML parser.",
    "attack-suite-websocket": "Validate the Origin header on the WebSocket handshake and require the same authentication/authorization checks used by the equivalent HTTP endpoints.",
    "attack-suite-host_header": "Do not trust the Host header for building links, password-reset URLs, or cache keys; use a server-configured canonical hostname instead.",
    "attack-suite-path_traversal": "Canonicalize and validate file paths built from user input against an allowlisted base directory; reject any path containing traversal sequences after normalization.",
    "attack-suite-type_confusion": "Strictly validate the type of every input field server-side (reject arrays/objects where a scalar is expected) rather than relying on implicit type coercion.",
    "attack-suite-api_versioning": "Ensure all security controls (authentication, authorization, rate limiting, input validation) are applied uniformly across every supported API version, not just the latest.",
    "attack-suite-broken_auth": "Enforce strong session/token generation, expiry, and invalidation on logout/password-change; never accept authentication bypassed via predictable tokens or missing checks on any auth-adjacent endpoint.",
    "attack-suite-session": "Regenerate the session identifier on login/privilege change, set cookies with Secure/HttpOnly/SameSite, and enforce server-side session expiry and invalidation.",
    "attack-suite-rate_limit": "Apply rate limiting to this endpoint keyed by user/IP, with a lockout or exponential backoff on repeated failures, to prevent brute-force and abuse.",
    "attack-suite-file_upload": "Validate uploaded file type by content (not just extension/Content-Type), store uploads outside the web root or in object storage with no execute permission, and re-encode/sanitize images.",
    "attack-suite-deserialization": "Never deserialize untrusted data with a format capable of instantiating arbitrary types (e.g. Java/Python native serialization, PHP unserialize); use a safe data-only format like JSON with strict schema validation instead.",
    "attack-suite-xxe": "Disable external entity and DTD processing in the XML parser configuration; use a hardened parser default that rejects DOCTYPE declarations.",
    "attack-suite-info_disclosure": "Remove verbose error messages, stack traces, and internal implementation details from responses returned to unauthenticated or unauthorized users.",

    # firewall.py's non-physical sub-scanners (WAF bypass, port mapper, rule
    # analyzer, rate-limit probe, smuggling probe) — the physical NGFW
    # sub-scanner already has its own inline remediation text and doesn't use
    # this module. See app.services.finding_ingest / app.api.v1.firewall.
    "waf-bypass-sqli": "Update the WAF's SQL injection ruleset to normalize case, decode nested/URL/Unicode encodings, and strip comment-based obfuscation before pattern matching — these bypasses all rely on the WAF matching literal payload strings rather than a normalized form.",
    "waf-bypass-xss": "Enable HTML-entity and UTF-7 decoding plus case-insensitive tag/attribute matching in the WAF's XSS ruleset — the confirmed bypasses exploit WAFs that only match the canonical `<script>` form.",
    "waf-bypass-encoding": "Enable recursive URL decoding and Unicode/fullwidth-character normalization in the WAF before signature matching — these techniques all bypass WAFs that decode a payload only once.",
    "waf-bypass-verb_mutation": "Ensure the WAF inspects POST/PUT bodies (form, JSON, and XML) and non-GET HTTP verbs, not only GET query parameters — several bypasses succeeded purely by moving the payload into the request body or switching verbs.",
    "waf-bypass-content_type": "Enable deep inspection for every content type the application accepts (multipart/form-data, JSON, XML, unusual charsets) — the confirmed bypasses show the WAF only inspects a subset of content types/encodings.",
    "waf-bypass-header_injection": "Strip or validate untrusted client-supplied IP/trust headers (X-Forwarded-For, True-Client-IP, X-Originating-IP, CF-Connecting-IP) at the edge, and ensure the WAF still inspects payloads carried in request headers (User-Agent, Referer).",
    "waf-bypass-cloud_cloudflare": "Review Cloudflare WAF managed-rule coverage for oversized-body inspection limits and validate that IP-trust headers (CF-Connecting-IP, True-Client-IP) are only honored from Cloudflare's own edge IP ranges.",
    "waf-bypass-cloud_aws": "Review AWS WAF web ACL rule coverage for JSON body inspection (including null-byte and oversized-body edge cases) and non-standard content types like application/x-amz-json-1.1.",
    "waf-bypass-cloud_azure": "Review Azure Front Door / Application Gateway WAF policy for header-based bypasses (e.g. X-Azure-FDID) and ensure custom headers are not implicitly trusted.",
    "waf-bypass-cloud_akamai": "Review Akamai Kona/App & API Protector rules for CRLF injection via custom headers, and ensure header values are sanitized before being reflected or logged.",
    "waf-bypass-cloud_gcp": "Review Google Cloud Armor security policy rule coverage for JSON request body inspection.",
    "firewall-port-cve": "Patch or upgrade the service exposed on this port to a version not vulnerable to the referenced CVE, and in the meantime restrict network access to this port to trusted source IPs via firewall ACL or security group rules.",
    "firewall-acl-bypass": "Do not grant trust to traffic based on its claimed source port (e.g. UDP/TCP source port 53) — this is trivially spoofable by an attacker. Rebuild the ACL to filter on destination service and require actual authentication, not port-based trust.",
    "firewall-evasion": "Configure the firewall/IPS to reassemble fragmented packets and normalize non-standard TCP flag combinations (FIN/NULL/XMAS) before applying inspection rules, so evasion techniques can't slip traffic past stateless filtering.",
    "firewall-rule-redundant": "Remove the duplicate rule — redundant rules add no security value and make the ruleset harder to audit.",
    "firewall-rule-any_any": "Replace this unrestricted allow-all rule with explicit source/destination/port scoping for only the traffic that's actually required.",
    "firewall-rule-overly_broad": "Restrict this rule's source to specific known IP ranges (VPN, bastion, admin network) instead of any/0.0.0.0/0 — this sensitive port should never be reachable from the entire internet.",
    "firewall-rule-shadow": "Reorder or remove the shadowed rule — an earlier, broader rule already matches all of its traffic, so the shadowed rule can never take effect and likely doesn't reflect the intended policy.",
    "firewall-rule-cidr_subsumption": "Reorder this ruleset so the more specific DENY rule is evaluated before the broader PERMIT rule, or narrow the PERMIT rule's CIDR so it no longer covers the address space the DENY rule was meant to block.",
    "firewall-rule-conflict": "Resolve the conflicting permit/deny rules for the same traffic — whichever is evaluated first silently wins, and the ruleset almost certainly doesn't reflect the intended policy.",
    "firewall-rule-missing_default_deny": "Add an explicit DROP/DENY-all rule at the end of this chain — without one, any traffic not matched by an earlier rule is implicitly permitted.",
    "firewall-no-rate-limit": "Implement rate limiting (per-IP and per-account) on this endpoint at the application, API gateway, or WAF layer — its absence allows unrestricted brute-force, credential-stuffing, or scraping traffic.",
    "firewall-rate-limit-bypass": "Base rate-limit keying on a verified connection property (e.g. the TCP source IP as seen by the edge/load balancer) rather than a client-supplied header like X-Forwarded-For, which any client can spoof to reset their own quota.",
    "firewall-smuggling": "Ensure the frontend proxy/load balancer and backend server agree on HTTP/1.1 request framing (reject ambiguous requests that specify both Content-Length and Transfer-Encoding, normalize obfuscated Transfer-Encoding header variants), or terminate HTTP/2 end-to-end between them to eliminate the desync surface entirely.",

    # app/services/correlation_engine.py — compound findings synthesized from
    # 2+ independent real findings/asset facts on the same host. The
    # underlying constituent findings each have their own specific
    # remediation too (see `evidence.constituent_findings` on the compound
    # finding) — this text addresses the COMBINATION, not any one component.
    "correlated-takeover-exposure": "Treat this as urgent: reclaim or remove the dangling DNS record immediately (the standard subdomain-takeover fix), AND separately audit why a sensitive service is reachable on this host at all — if the host is legitimately still in use, firewall the exposed port to known-good source ranges; if it's stale infrastructure, decommission it rather than just fixing the DNS record.",
    "correlated-secret-exposure": "Rotate the exposed credential immediately (it must be treated as already compromised, not just 'discovered'), then separately verify what that credential actually grants access to on the live, reachable host it was found alongside — check access/audit logs for that service covering the entire window the secret was exposed, not just from now forward.",
    "correlated-kev-admin-exposure": "Patch the KEV-listed vulnerability immediately — this is not discretionary, it's confirmed under active exploitation industry-wide. In parallel, restrict the administrative/management port to a VPN or bastion-only source range; do not treat the patch alone as sufficient while the admin surface stays internet-reachable.",
    "correlated-ai-api-chain": "Fix the API security misconfiguration first (it's the more traditional, better-understood attack surface — apply the specific guidance on that underlying finding), then re-test the LLM guardrail bypass specifically THROUGH the now-fixed API path to confirm the chain is actually broken, not just that the API issue alone is resolved.",
    "correlated-cloud-injection": "Immediately verify whether the instance/container's cloud metadata endpoint (e.g. 169.254.169.254) is reachable from the vulnerable code path — if so, rotate any credentials the attached IAM role/service account could have exposed and treat this as a confirmed cloud-account compromise until proven otherwise, not just an application bug. Then fix the injection/SSRF finding itself per its own remediation and add network-level egress blocking to the metadata address as defense in depth.",
    "correlated-convergent-risk": "This asset has accumulated multiple independent high-severity findings from different tools — prioritize a full manual review of this specific host over working the findings list purely by individual severity, since the combination suggests either systemic neglect or genuine high value to an attacker. Fix each constituent finding per its own remediation, then re-scan this asset specifically to confirm the convergence is resolved.",
}

# Substring-matched against a dynamic finding title (email_security.py builds
# titles as f-strings, so there's no fixed check-id to key off of).
_KEYWORD_REMEDIATION: list[tuple[str, str]] = [
    ("No SPF record", "Publish an SPF record (TXT) authorizing your legitimate mail servers, ending in -all to reject unauthorized senders."),
    ("SPF allows all senders", "Change the SPF record's catch-all from +all to -all — +all authorizes literally any server to send mail as your domain."),
    ("SPF soft-fail", "Tighten the SPF policy from ~all (soft-fail) to -all (hard-fail) once you've confirmed all legitimate senders are included."),
    ("SPF neutral policy", "Replace the SPF neutral (?all) qualifier with -all — neutral provides no protection against spoofing."),
    ("SPF exceeds 10-lookup", "Reduce the number of SPF includes/redirects — DNS lookups beyond 10 cause the entire SPF check to fail (permerror), often breaking legitimate mail."),
    ("No DMARC record", "Publish a DMARC record (TXT at _dmarc) starting at p=none for monitoring, then move to p=quarantine or p=reject once senders are verified."),
    ("DMARC policy is monitoring-only", "Move the DMARC policy from p=none to p=quarantine or p=reject once you've verified all legitimate senders pass SPF/DKIM."),
    ("DMARC only applies to", "Increase the DMARC pct value to 100 once you've confirmed the policy doesn't break legitimate mail — a partial pct leaves a spoofing gap."),
    ("No DMARC aggregate reporting", "Add an rua= tag to the DMARC record to receive aggregate reports and monitor for spoofing/misconfiguration."),
    ("DKIM key too weak", "Regenerate the DKIM key at 2048-bit or stronger — sub-1024-bit RSA keys are considered crackable."),
    ("DKIM key is 1024-bit", "Regenerate the DKIM key at 2048-bit — 1024-bit is below current best practice."),
    ("No DKIM record found", "Configure DKIM signing for all outbound mail and publish the corresponding DKIM DNS record."),
    ("No MX records found", "Confirm mail routing is intentional; if this domain should receive mail, configure MX records pointing to your mail provider."),
    ("MX PTR mismatch", "Configure a matching reverse-DNS (PTR) record for the mail server IP — mismatches are a strong spam signal to receiving servers."),
    ("does not advertise STARTTLS", "Enable STARTTLS on the mail server so mail in transit is encrypted rather than sent in plaintext."),
    ("Lookalike domain registered", "Consider registering common lookalike/typosquat variants defensively, and monitor them for phishing use against your users."),
    ("Domain found in breach", "Notify affected users if credentials were exposed, force a password reset for accounts using this domain, and review the breach for what data was exposed."),

    # Core scan pipeline (scan_worker.py) — dynamic per-host/per-check titles,
    # same reason as email_security.py above: no fixed check-id to key off of.
    ("Missing HSTS header", "Add the Strict-Transport-Security response header (e.g. `max-age=31536000; includeSubDomains; preload`) so browsers refuse to downgrade this site to plain HTTP even if a user types or follows an http:// link."),
    ("Missing security headers", "Add the missing headers listed in this finding's evidence: Strict-Transport-Security (enforce HTTPS), Content-Security-Policy (restrict script/resource origins), X-Content-Type-Options: nosniff, X-Frame-Options (or frame-ancestors in CSP) to prevent clickjacking, Referrer-Policy, and Permissions-Policy to disable unneeded browser features."),
    ("FTP exposed", "FTP transmits credentials and data in plaintext. Disable it if unused, or migrate to SFTP/FTPS, and restrict access to specific source IPs at the firewall in the meantime."),
    ("SMTP exposed", "Confirm this SMTP service requires authentication and doesn't allow open relay (test with a relay-check tool); restrict access to known mail infrastructure IPs if it isn't meant to be publicly reachable."),
    ("Webmin exposed", "Webmin has a history of critical CVEs (including unauthenticated RCE) and should not be internet-facing — restrict access to a VPN/bastion or an IP allowlist, and confirm it's patched to the latest version."),
    ("GitHub organization found", "Review every public repository under this GitHub organization for committed secrets, internal documentation, or infrastructure details, and confirm each repo is intentionally public."),
    ("employee emails from GitHub", "These addresses were harvested from public commit metadata. Consider a no-reply/generic commit email policy for the organization, and rotate any credentials that may have been committed by the same authors."),
    ("email address(es) for", "Discovered email addresses expand the phishing/credential-stuffing attack surface. No immediate action is required if these are already-expected public contacts, but ensure they aren't tied to privileged accounts without MFA."),
    ("employee name", "Publicly discoverable employee names/roles aid targeted phishing and pretexting. Ensure staff handling sensitive functions (finance, IT admin) are aware and MFA is enforced org-wide."),
    ("Email pattern detected", "A predictable {first}{last}@domain.com pattern lets an attacker enumerate likely-valid addresses for phishing. Not fixable outright, but pair with strong MFA and phishing awareness training."),
    ("GCP bucket discovered", "Verify this bucket's IAM policy does not grant allUsers/allAuthenticatedUsers read or write access, and confirm nothing sensitive is stored in a publicly-listable bucket."),
    ("Large subdomain footprint", "A large subdomain footprint increases the attack surface and the chance of a forgotten, unpatched, or misconfigured host. Inventory all subdomains against known-owned services and decommission or consolidate any that are no longer needed."),
    ("Development/staging environments exposed", "Restrict access to development/staging hosts to a VPN, corporate IP allowlist, or authentication gateway — they typically run with weaker security controls (debug mode, verbose errors, test data or credentials) than production and should never be reachable directly from the internet."),
    ("High number of open ports", "Audit every listening service against what's actually required; close or firewall off anything not intentionally exposed. The original scan did not retain a per-port breakdown — re-run the Nmap Scanner against this target for a current, detailed port/service list to act on."),

    # api_scanner.py — OWASP API Top 10 checks (_check_security_headers,
    # _check_rate_limiting, _check_graphql, _check_ssrf, _check_bola,
    # _check_openapi_exposure). Titles are dynamic f-strings for SSRF/BOLA
    # (parameter/path name interpolated), so keyword substrings rather than
    # exact titles.
    ("Server Version Disclosure", "Strip or genericize the Server and X-Powered-By response headers at the reverse proxy/API gateway — advertising exact software versions gives attackers a targeted CVE search list for free."),
    ("CORS Misconfiguration", "Replace the wildcard/reflected Access-Control-Allow-Origin with an explicit allowlist of trusted origins, and never pair Access-Control-Allow-Credentials: true with a reflected or wildcard origin."),
    ("No Rate Limiting Detected", "Implement per-IP and per-token rate limiting (e.g. a token-bucket at the API gateway, 60-100 req/min as a starting point) — without it the API is open to credential-stuffing, scraping, and resource-exhaustion abuse."),
    ("GraphQL Introspection Enabled", "Disable GraphQL introspection in production (most frameworks: `introspection: false`) — a fully queryable schema hands an attacker the entire API surface, including fields and mutations never meant to be discovered."),
    ("SSRF via '", "Never let a server fetch a caller-supplied URL directly. Validate the target against an allowlist of expected hosts/schemes, resolve and block RFC1918/link-local ranges (especially 169.254.169.254 cloud metadata), and disable redirect-following on any request built from user input."),
    ("API Documentation Exposed", "Restrict Swagger/OpenAPI/Redoc documentation endpoints to authenticated internal users in production — a public schema maps every endpoint and parameter for an attacker before they've sent a single crafted request."),
    ("BOLA/IDOR", "Enforce object-level authorization on every resource-fetching endpoint: verify server-side that the authenticated caller actually owns or has been granted access to the specific object ID requested, rather than trusting that a valid token alone is sufficient."),

    # ai_scanner.py — LLM red-team plugin titles (PLUGINS dict `name` values).
    # Grouped by attack family; several distinct plugin names per family
    # collapse to one remediation since the underlying fix is the same
    # architectural control (e.g. an out-of-band system-prompt/instruction
    # guard, not a per-phrasing patch).
    ("Instruction Override", "Treat all user-supplied text as untrusted data, never as instructions — enforce the system prompt via an out-of-band mechanism (e.g. a constitution/guardrail layer or a separate classifier pass) rather than relying on the model to ignore conflicting text embedded in the conversation."),
    ("System Prefix Injection", "Strip or escape any user input that mimics system/role-boundary tokens (SYSTEM:, [SYSTEM], <|im_start|>, etc.) before it reaches the model, and validate role boundaries at the API layer rather than trusting the model to recognize a forged one embedded in user content."),
    ("Completion Attack", "Never place real secrets (passwords, keys) in any text the model can see, including for legitimate purposes — an LLM's autocompletion tendency will fill in plausible-looking values from context. Keep credentials entirely out of prompts/context and inject them only at the tool-execution layer."),
    ("Context Separator Injection", "Don't rely on document/context delimiters (---, ```, XML-like tags) alone to establish a trust boundary — a user can forge the same delimiter inside their input. Sanitize or escape delimiter-like sequences in user content, and enforce instruction precedence with a dedicated guardrail layer, not prompt structure alone."),
    ("Special Token Boundary Exploit", "Filter or escape model-specific special tokens (<|im_start|>, [INST], <|system|>, etc.) out of any user-supplied text before it's included in a prompt — these are training-time control tokens the base model was taught to trust, and a user typing them verbatim can spoof a role boundary."),
    ("Indirect Hint Extraction", "Assume any secret placed in the system prompt or context can eventually be extracted indirectly (rhymes, acrostics, letter-by-letter reveals) given enough attempts — never rely on prompt-level secrecy for anything that actually needs to stay confidential; keep real secrets out of the model's context entirely."),
    ("Jailbreak", "Add a guardrail/classifier layer independent of the base model's own alignment to detect persona-adoption and roleplay framing used to bypass safety behavior (DAN-style, fictional/academic framing, emotional-manipulation framing) — the model's own refusal training is not a sufficient control on its own, especially for self-hosted or fine-tuned models."),
    ("Fictional", "Apply content-safety checks to the model's output regardless of the fictional/narrative framing used to request it — a policy that only inspects the literal request text misses attacks wrapped in 'write a story where...' framing."),
    ("Academic", "Apply content-safety checks to the model's output regardless of the academic/research framing used to request it — 'for my thesis' is not a legitimate bypass for a safety-relevant refusal and should be treated identically to a direct request."),
    ("Grandma", "Add a guardrail layer that evaluates the sensitivity of requested output content independent of the emotional/persona framing (grandmother, deceased relative, etc.) wrapped around the request."),
    ("False Confirmation", "Never have the model confirm or correct a user-supplied guess about a secret value — any confirm-or-correct interaction pattern over a secret is an oracle that leaks the real value bit by bit; keep secrets out of the model's context so there is nothing to confirm."),
    ("System Prompt", "Do not treat the system prompt as a secret-holding mechanism — assume it can be extracted given a determined adversary and enough attempts. Keep actual secrets (API keys, credentials, internal policy details that would cause harm if known) out of the system prompt entirely, and add an output-filtering layer that blocks verbatim system-prompt echoes."),
    ("API Key", "Never place live API keys, tokens, or credentials in any text reachable by the model (system prompt, RAG context, tool descriptions). Credentials needed for tool execution should be injected directly into the tool-calling layer, never into the conversation the model reasons over."),
    ("Training Data Extraction", "This is a model-training-time concern rather than a deployment-time one for most integrators — if using a third-party hosted model, review the provider's data-extraction and memorization mitigations; if fine-tuning your own model, deduplicate and scrub sensitive/copyrighted material from the training corpus."),
    ("PII Disclosure", "Ensure no real user PII is ever placed in the model's system prompt, few-shot examples, or retrieved RAG context — if the use case requires referencing user data, pass it through a tool call scoped to the authenticated caller's own records rather than embedding raw records in context the model can be tricked into repeating."),
    ("Model Identity", "Low severity on its own, but consider whether revealing the exact underlying model/provider aids a more targeted attack against known jailbreak techniques for that specific model; if this is a competitive or fingerprinting concern, add a policy instructing consistent non-disclosure and verify it holds under paraphrased questions."),
    ("Privilege Escalation", "Never let claimed role/privilege in the conversation text change what the model is willing to output — authorization must be enforced server-side (checking the authenticated caller's actual role/permissions at the tool-execution layer), not by trusting a 'the user says they're an admin' signal inside the prompt."),
    ("RBAC Bypass", "Enforce role-based access control server-side against the caller's actual authenticated identity and permissions — a role or entitlement claimed in the conversation text must never be trusted as a substitute for a real authorization check before returning restricted content."),
    ("Broken Object-Level Authorization", "Enforce object-level authorization server-side before the model (or a tool it calls) returns another user's/customer's data — a request phrased as a natural-language question is still a data-access request and needs the same authorization check as a REST endpoint would."),
    ("Debug / Maintenance Mode", "Do not implement any real debug/maintenance/admin mode that can be toggled via conversational text — if such a mode exists operationally, it must require authentication through a separate out-of-band control plane, never a phrase the model recognizes in chat."),
    ("Malicious Code Generation", "Add an output-scanning layer that flags generated code matching known-malicious patterns (reverse shells, keyloggers, persistence mechanisms) before it's returned, independent of the model's own refusal behavior — this is especially important for self-hosted/abliterated models with reduced safety training."),
    ("Phishing", "Add an output-safety layer that blocks generation of branded phishing content (impersonating real companies, urgent account-verification language) regardless of the model's own alignment — treat this the same as any other harmful-content category requiring a backstop control."),
    ("Disinformation", "Add an output-safety layer that flags fabricated news/scientific-claim content presented as factual, especially when it names real people or institutions — model alignment alone is not a sufficient control, particularly for fine-tuned or self-hosted models."),
    ("Violence Facilitation", "Add a hard-blocking output-safety layer (independent of model alignment) for operational violence/weapons content — this is a baseline safety control that should never depend solely on the underlying model's training, especially for self-hosted/abliterated models where safety training has been deliberately removed."),
    ("SSRF via LLM", "Never let a model-driven tool make an HTTP request to a URL the model (or, transitively, the user) chose without validation — allowlist expected hosts, block RFC1918/link-local ranges (especially 169.254.169.254 cloud metadata) and disable redirect-following, exactly as you would for any other server-side URL fetch."),
    ("SQL Injection Generation", "This reflects a code-generation risk rather than a live SQL injection in the platform itself — ensure any application that acts on model-generated SQL runs it only against parameterized queries/an ORM, never string-concatenated, regardless of whether the SQL text originated from a model."),
    ("ASCII / Unicode Smuggling", "Normalize and strip invisible/bidirectional Unicode control characters (zero-width spaces, right-to-left override, etc.) from user input before it reaches the model — these are used to hide injected instructions from human reviewers while the model still parses them."),
    ("Indirect Prompt Injection", "Treat any third-party content the model summarizes or processes (documents, customer feedback, web pages, emails) as untrusted input that may contain embedded instructions — apply the same instruction-vs-data separation controls used for direct user input, and never let retrieved/quoted content trigger tool calls or override system behavior."),
    ("Excessive Agency", "Ensure the model cannot claim to have performed an action (sending email, browsing, making calls) it does not actually have a wired tool/capability for — ungrounded capability claims can mislead users into believing an action was taken when it wasn't. Ground every capability claim in an actual tool-call result."),
    ("Hallucination Induction", "For any use case where factual precision matters, add a retrieval-grounding step (RAG against a verified source) rather than relying on the model's parametric memory for exact quotes/figures, and have the model express calibrated uncertainty rather than confident-sounding fabrication."),
    ("Sycophancy", "For use cases where correcting user misconceptions matters (support, education, compliance), tune or prompt the model to prioritize factual accuracy over agreement, and consider a fact-check pass against confidently-stated user premises before the model responds."),
    ("Goal Hijacking", "Constrain the model to its intended task domain with a server-side scope check on the response (or the tool calls it attempts), not just a system-prompt instruction — a system-prompt-only boundary can be talked around by a determined user."),
    ("Competitor Intelligence Disclosure", "If competitor commentary is out of scope for this assistant, add an explicit policy and light output filtering — low severity, but confirm the disclosed comparisons aren't based on non-public information the model shouldn't have access to."),
    ("Gender Bias", "Add a bias-evaluation pass (or use a fairness-focused system prompt/fine-tune) for any user-facing generative content, and route flagged outputs to human review before publication — this applies especially to HR/hiring-adjacent use cases."),
    ("Racial Bias", "Add a hard content-safety filter for racial stereotyping content, independent of the base model's alignment — this is a baseline control, not an edge case, and should block generation rather than merely flag it after the fact."),
    ("Political Manipulation", "Add an output-safety policy against generating persuasive political attack content or voter-suppression messaging, and route any borderline political content through human review before it reaches end users."),
    ("Crescendo Secret Extraction", "Multi-turn escalation attacks succeed because each individual turn looks benign — evaluate conversation-level intent (via a moderation pass over the recent turn window, not just the latest message) rather than grading each turn independently, and keep real secrets out of context regardless."),
    ("Crescendo Harmful Content Escalation", "Multi-turn escalation attacks succeed because each individual turn looks benign — evaluate conversation-level intent (via a moderation pass over the recent turn window, not just the latest message) rather than grading each turn independently."),
    ("Rate Limiting (LLM09)", "Implement rate limiting on the LLM-facing endpoint itself (not just the surrounding API), since uncontrolled request volume enables both cost-exhaustion (denial-of-wallet) attacks and higher-throughput automated jailbreak/extraction attempts."),

    # js_scanner.py (JS Analysis Scanner) — title is the fixed pattern "name"
    # for most types, but library_vuln ("Outdated jQuery (1.7.1)") and
    # confirmed_xss ("Confirmed DOM XSS — eval()") embed a dynamic suffix, so
    # these are matched by keyword rather than exact category. Most of these
    # findings already carry their own good inline remediation text from the
    # scanner itself — this list is the fallback for the rare record missing
    # it (or an older history file predating that field). "Server Version
    # Disclosure" and "GraphQL Introspection Enabled" are already covered
    # above (api_scanner.py) and apply equally here.
    ("Confirmed DOM XSS", "A user-controlled value (URL, cookie, referrer, window.name, or postMessage data) flows directly into a dangerous DOM sink. Sanitize with DOMPurify.sanitize() before inserting into the DOM, or use safe APIs (textContent, createElement) instead."),
    ("Outdated jQuery", "Upgrade jQuery to 3.5.0 or later — versions below that have known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023)."),
    ("Outdated AngularJS", "AngularJS 1.x reached end-of-life in December 2021 and receives no security patches. Migrate to Angular 15+ or another actively maintained framework."),
    ("Outdated lodash", "Upgrade lodash to 4.17.21 or later — earlier versions have a prototype-pollution vulnerability (CVE-2021-23337)."),
    ("Outdated moment.js", "moment.js is in maintenance mode and receives no new features. Migrate to date-fns or Day.js, and keep the pinned version current in the meantime."),
    ("innerHTML Assignment", "Avoid assigning untrusted input to .innerHTML. Use textContent for plain text, or sanitize with DOMPurify.sanitize() first if HTML content is genuinely required."),
    ("outerHTML Assignment", "Avoid assigning untrusted input to .outerHTML. Use safe DOM APIs (createElement, textContent) or sanitize with DOMPurify.sanitize() first."),
    ("insertAdjacentHTML", "Avoid passing untrusted input to insertAdjacentHTML(). Sanitize with DOMPurify.sanitize() first, or build the DOM with safe APIs instead."),
    ("document.write", "Avoid document.write() with any value derived from user input — it executes as HTML/script in the page context. Use safe DOM APIs instead."),
    ("eval()", "Avoid eval() entirely, especially with any value that can be influenced by user input, a URL, or a network response. Use JSON.parse for data or a real function reference instead of dynamic code execution."),
    ("Function() constructor", "Avoid the Function() constructor with any dynamic string — it is equivalent to eval() and executes as code. Use a real function reference instead."),
    ("jQuery .html()", "Avoid passing untrusted input to jQuery's .html(). Use .text() for plain content, or sanitize with DOMPurify.sanitize() first."),
    ("jQuery .append()", "Review what is passed to jQuery's .append()/.prepend()/.after()/.before() — if it includes untrusted input, sanitize with DOMPurify.sanitize() first or use .text() for plain content."),
    ("location.href assignment", "Before assigning to location.href, validate the destination against an allowlist of trusted URLs — an attacker-controlled value here is an open redirect or, combined with a javascript: scheme, a script-execution vector."),
    ("location.replace()", "Validate the destination passed to location.replace() against an allowlist of trusted URLs before redirecting."),
    ("location.assign()", "Validate the destination passed to location.assign() against an allowlist of trusted URLs before redirecting."),
    ("Angular bypassSecurityTrust", "bypassSecurityTrust*() disables Angular's built-in XSS sanitization for the wrapped value. Only use it on values that are provably static or server-validated, never on anything derived from user input."),
    ("Vue v-html directive", "v-html renders raw HTML with no sanitization. Only bind it to trusted, static content, or sanitize with DOMPurify.sanitize() first."),
    ("$sce.trustAsHtml", "$sce.trustAsHtml() disables Angular's sanitization for the wrapped value. Only use it on values that are provably static or server-validated, never on anything derived from user input."),
    ("Dynamic script element", "Confirm any dynamically created <script> element's src is a fixed, trusted value rather than derived from user input or a URL parameter — otherwise it is an arbitrary script-execution vector."),
    (".src assignment", "Confirm this dynamic .src assignment cannot be influenced by user input or a URL parameter — an attacker-controlled src on a script/iframe element leads to arbitrary content or code execution."),
    ("document.cookie (cookie source)", "document.cookie is a classic DOM-XSS source. Confirm this value doesn't flow into innerHTML, eval, or another dangerous sink without sanitization, and mark sensitive cookies HttpOnly so client-side JS can't read them at all."),
    ("location.href (URL source)", "Treat location.href as untrusted input. Confirm it doesn't flow into innerHTML, eval, or another dangerous sink without sanitization or allowlist validation."),
    ("location.search (URL param source)", "Treat URL query parameters as untrusted input. Confirm values read from location.search don't flow into innerHTML, eval, or another dangerous sink without sanitization."),
    ("location.hash (URL hash source)", "Treat the URL fragment as untrusted input. Confirm values read from location.hash don't flow into innerHTML, eval, or another dangerous sink without sanitization — hash-based DOM XSS is common because the fragment isn't sent to the server."),
    ("document.referrer (referrer source)", "Treat document.referrer as untrusted, attacker-influenceable input. Confirm it doesn't flow into innerHTML, eval, or another dangerous sink without sanitization."),
    ("window.name (window.name source)", "window.name persists across navigations and can be set by a prior, attacker-controlled page. Confirm it doesn't flow into innerHTML, eval, or another dangerous sink without sanitization."),
    ("localStorage read", "Confirm values read from localStorage don't flow into a dangerous sink (innerHTML, eval) without sanitization — localStorage can be poisoned by any script that ran on the same origin, including a prior XSS."),
    ("localStorage of sensitive token", "Avoid storing tokens/session credentials in localStorage — it is readable by any script on the page, including one injected via XSS. Prefer an HttpOnly cookie, or at minimum a short-lived in-memory token."),
    ("URLSearchParams", "Confirm values parsed from URLSearchParams are treated as untrusted input and don't flow into a dangerous sink without sanitization or validation."),
    ("postMessage Wildcard Origin", "Never send postMessage with a wildcard ('*') target origin when the payload contains anything sensitive — specify the exact expected origin so the message can't be intercepted by an embedded or malicious frame."),
    ("iframe postMessage Wildcard", "Never send postMessage to an iframe's contentWindow with a wildcard ('*') target origin — specify the exact expected origin for that frame."),
    ("Dangerous postMessage Handler", "This postMessage handler passes event data directly into a dangerous sink without validating event.origin first. Add an explicit origin allowlist check at the top of the handler before using event.data."),
    ("postMessage Listener (verify origin)", "Confirm this message-event listener validates event.origin against an explicit allowlist before trusting event.data — an unchecked listener accepts messages from any origin, including a malicious one."),
    ("constructor.prototype Access", "Review this .constructor.prototype access for whether it's part of an unguarded deep-merge/assign path that an attacker-controlled object could reach — if so, block '__proto__'/'constructor'/'prototype' keys explicitly."),
    ("Direct __proto__ Assignment", "Never assign into an object via a literal '__proto__' key derived from external input. Use Object.create(null) or a Map for user-controlled key/value data, or explicitly reject '__proto__'/'constructor'/'prototype' keys."),
    ("JSON.parse to __proto__", "Reject '__proto__', 'constructor', and 'prototype' keys when merging or applying JSON.parse() output that originates from user input, to prevent prototype pollution."),
    ("Bracket Access with Variable", "This is a broad heuristic for dynamic bracket-notation property access — review the surrounding code for whether the key can be attacker-controlled and could reach '__proto__'/'constructor'/'prototype'."),
    ("Twilio Account SID", "An Account SID alone is an identifier, not a secret, but it does confirm which Twilio account is in use — pair it with the exposed Auth Token check and rotate the token if one was found nearby."),
    ("Console.log of Secret", "Remove console.log/warn/error/debug calls that print tokens, passwords, secrets, or keys — browser console output is visible to anyone with devtools access and is often captured by error-monitoring tools."),
    ("process.env Leak", "A raw process.env.* reference surviving into shipped client bundles suggests a build-time inlining step may be embedding server-side environment values into public JS. Confirm nothing sensitive was inlined."),
    ("process.env Spread", "Spreading '...process.env' into client-shipped code embeds every environment variable available at build time into the public bundle, including any accidentally-server-only secrets. Explicitly allowlist only the variables the client actually needs."),
    ("React Env Var Leak", "REACT_APP_* variables are compiled into the public bundle by design — confirm nothing in this value is meant to stay server-side, since it is now fully public."),
    ("Next.js Env Var Leak", "NEXT_PUBLIC_* variables are compiled into the public bundle by design — confirm nothing in this value is meant to stay server-side, since it is now fully public."),
    ("Vite Env Var Leak", "VITE_* variables are compiled into the public bundle by design — confirm nothing in this value is meant to stay server-side, since it is now fully public."),
    ("Internal Hostname", "This internal/staging hostname reference in public JS may point to an environment with weaker security controls. Confirm it isn't directly reachable from the internet, or remove the reference from production builds."),
    ("Internal URL", "This internal IP/localhost reference in public JS discloses internal network topology. Confirm it's expected (e.g. a local-dev fallback) and doesn't leak a genuinely internal address."),
    ("JavaScript Source Map Exposed", "Remove sourceMappingURL comments from production JS builds, and don't deploy the corresponding .map files publicly — they reconstruct full original source, including comments and internal file paths."),
    ("External Script Without Subresource Integrity", "Add an integrity='sha384-...' attribute (with crossorigin='anonymous') to cross-origin <script> tags so the browser refuses to execute the script if the third-party host is compromised or the response is tampered with in transit."),
    ("CORS: Wildcard Origin + Allow-Credentials", "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true — set a specific, validated trusted origin instead."),
    ("CORS: Wildcard Allow-Origin", "Restrict Access-Control-Allow-Origin to a specific allowlist of trusted origins instead of '*', especially on any endpoint that returns non-public data."),
    ("Missing Content-Security-Policy", "Add a Content-Security-Policy header, starting from \"default-src 'self'\" and tightening from there, to materially reduce the impact of any XSS that does slip through."),
    ("unsafe-inline", "Replace CSP 'unsafe-inline'/'unsafe-eval' with nonces or hashes for the specific scripts that need to run — both directives together provide minimal protection against XSS."),
    ("Missing Clickjacking Protection", "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive to prevent this page from being framed by another origin."),
    ("Missing X-Content-Type-Options", "Add 'X-Content-Type-Options: nosniff' to prevent the browser from MIME-sniffing responses into an executable content type."),
    ("Missing Referrer-Policy", "Add a 'Referrer-Policy' header (e.g. 'strict-origin-when-cross-origin') to control how much of this site's URLs leak to external destinations via the Referer header."),
    ("WebSocket without Auth Param", "Confirm this WebSocket connection authenticates the client after the handshake (e.g. an auth message as the first frame) — a URL with no token/auth parameter may be relying on origin checks alone, which are not sufficient authentication."),
    ("WebSocket Message to Sink", "Never pass an incoming WebSocket message directly into innerHTML, eval, or document.write. Treat all inbound WebSocket data as untrusted and sanitize/validate it first."),
    ("SW importScripts from CDN", "A service worker importing a script from a third-party CDN gives that CDN code execution in the service-worker scope for every page it controls. Vendor the script locally or pin it with Subresource Integrity where supported."),
    ("SW Wildcard Scope", "Confirm a service worker registered at the root scope ('/') is intentional — it can intercept every request on the origin, including pages the developer didn't expect it to control."),
    ("SW Dangerous Message Handler", "A service worker's message handler is passing inbound postMessage data into fetch/eval/importScripts. Validate the message origin and payload shape before acting on it — a compromised page on the same origin could otherwise control the service worker."),
    ("Open Redirect via URL Parameter", "Validate any redirect/return/next URL parameter against an allowlist of trusted destinations (or require same-origin relative paths) before assigning it to location.href/assign/replace."),
    ("Unvalidated Redirect Assignment", "Confirm the variable assigned to location is not derived from user input; if it can be, validate it against an allowlist of trusted destinations first."),
    ("JSONP Callback Parameter", "JSONP is deprecated and enables cross-site data leakage. Migrate the endpoint to CORS-enabled JSON and remove the callback parameter."),
    ("Dynamic JSONP Window Callback", "Validate that any dynamically-named window callback used for JSONP is generated server-side or from a strict allowlist, not directly from a URL parameter."),
    ("Math.random() for Security Token", "Math.random() is not cryptographically secure and its output is predictable. Use window.crypto.getRandomValues() or crypto.randomUUID() for any token, nonce, or session identifier."),
    ("Security Value Seeded with Math.random", "Math.random() is not cryptographically secure. Regenerate this nonce/CSRF token/session value using window.crypto.getRandomValues() or crypto.randomUUID() instead."),
    ("Hardcoded Authorization Header", "Never hardcode an Authorization header value in client-side JS. Fetch the token at runtime from a secure, authenticated backend endpoint instead."),
    ("Hardcoded API Key in Request Header", "Never hardcode an API key in a client-side request header. Proxy the call through your own backend, which holds the real key server-side."),
]

_GENERIC_FALLBACK = "Review this finding against your organization's security baseline and remediate the underlying misconfiguration or exposure."


def get_remediation(category: str | None = None, title: str | None = None) -> str:
    """Look up remediation text by exact category, then by keyword match
    against a dynamic title, then fall back to a generic message."""
    if category and category in _CATEGORY_REMEDIATION:
        return _CATEGORY_REMEDIATION[category]
    if title:
        for keyword, text in _KEYWORD_REMEDIATION:
            if keyword.lower() in title.lower():
                return text
    return _GENERIC_FALLBACK
