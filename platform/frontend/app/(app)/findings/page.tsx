"use client";

import React, { useState, useEffect, useMemo } from "react";
import { ShieldAlert, ChevronLeft, ChevronRight, X, Plus, AlertTriangle, Lock, Clock, Search, Download, CheckSquare, FileText, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/shared/empty-state";
import { FindingRow } from "@/components/findings/finding-row";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useFindings } from "@/hooks/use-findings";
import { useCreateFinding } from "@/hooks/use-findings";
import { toast } from "sonner";
import type { FindingFilters, FindingSeverity, FindingStatus } from "@/types";
import { API_BASE } from "@/lib/api";
import { getAccessToken, fetchWithAuth } from "@/lib/auth";

const SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: FindingStatus[] = ["open", "in_progress", "remediated", "accepted_risk", "false_positive"];
const PER_PAGE = 25;

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-zinc-400",
};

interface CreateFindingForm {
  title: string;
  severity: string;
  category: string;
  affected_asset: string;
  description: string;
  evidence_text: string;
  remediation: string;
  cve_text: string;
  cvss_score: string;
  references_text: string;
  status: string;
  ticket_ref: string;
}

const EMPTY_FORM: CreateFindingForm = {
  title: "",
  severity: "high",
  category: "",
  affected_asset: "",
  description: "",
  evidence_text: "",
  remediation: "",
  cve_text: "",
  cvss_score: "",
  references_text: "",
  status: "open",
  ticket_ref: "",
};

// ─── Vulnerability Templates ────────────────────────────────────────────────
interface VulnTemplate {
  id: string;
  title: string;
  severity: string;
  category: string;
  cvss_score: string;
  cve_text: string;
  description: string;
  remediation: string;
  references_text: string;
}

const VULN_TEMPLATES: VulnTemplate[] = [
  {
    id: "sqli",
    title: "SQL Injection",
    severity: "critical",
    category: "Injection",
    cvss_score: "9.8",
    cve_text: "",
    description: `The application is vulnerable to SQL Injection. User-supplied input is incorporated into SQL queries without adequate sanitization or parameterization, allowing an attacker to manipulate the query logic.

An attacker can exploit this to:
- Bypass authentication
- Exfiltrate sensitive data from the database
- Modify or delete database records
- In some configurations, execute OS-level commands`,
    remediation: `1. Use parameterized queries / prepared statements for all database operations
2. Apply an ORM (SQLAlchemy, Hibernate, ActiveRecord) and avoid raw query construction
3. Validate and whitelist all user input on the server side
4. Apply the principle of least privilege to database accounts
5. Enable WAF rules to detect common SQL injection payloads
6. Conduct regular code reviews and use SAST tools to catch new instances`,
    references_text: `https://owasp.org/www-community/attacks/SQL_Injection
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/89.html`,
  },
  {
    id: "xss-reflected",
    title: "Reflected Cross-Site Scripting (XSS)",
    severity: "high",
    category: "XSS",
    cvss_score: "6.1",
    cve_text: "",
    description: `The application reflects user-supplied data in HTTP responses without proper escaping, enabling an attacker to inject arbitrary JavaScript that executes in the victim's browser.

Reflected XSS requires the victim to click a crafted link. Impact includes:
- Session hijacking via cookie theft
- Keylogging and credential harvesting
- Redirection to phishing pages
- Defacement of web content`,
    remediation: `1. HTML-encode all user-controlled output before rendering it in responses
2. Use a Content Security Policy (CSP) header to restrict script execution
3. Set HttpOnly and Secure flags on session cookies
4. Use modern frameworks that auto-escape by default (React, Angular, Vue)
5. Validate and sanitize input on the server using an allowlist approach
6. Enable X-XSS-Protection and X-Content-Type-Options headers`,
    references_text: `https://owasp.org/www-community/attacks/xss/
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/79.html`,
  },
  {
    id: "xss-stored",
    title: "Stored Cross-Site Scripting (XSS)",
    severity: "high",
    category: "XSS",
    cvss_score: "8.0",
    cve_text: "",
    description: `Malicious scripts submitted by an attacker are persistently stored in the application's database or file system and later served to other users, executing in their browsers without interaction beyond visiting the page.

This is more dangerous than reflected XSS because:
- No victim interaction (link click) required
- Affects all users who view the affected page
- Can be used for account takeover at scale`,
    remediation: `1. Sanitize all user input before storing it (use DOMPurify or server-side sanitizers)
2. HTML-encode stored content when rendering it to the page
3. Implement a strict Content Security Policy (CSP)
4. Separate user content from application content using subdomains or sandboxed iframes
5. Validate inputs against an allowlist of expected formats`,
    references_text: `https://owasp.org/www-community/attacks/xss/#stored-xss-attacks
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/79.html`,
  },
  {
    id: "ssrf",
    title: "Server-Side Request Forgery (SSRF)",
    severity: "high",
    category: "SSRF",
    cvss_score: "8.6",
    cve_text: "",
    description: `The application fetches a remote resource using a URL supplied by the user without adequate validation. An attacker can coerce the server to make requests to internal services, cloud metadata endpoints, or arbitrary external hosts.

Common targets include:
- AWS/GCP/Azure instance metadata (http://169.254.169.254)
- Internal REST APIs not exposed externally
- Redis, Elasticsearch, or other unauthenticated internal services
- Localhost services (port scanning via SSRF)`,
    remediation: `1. Validate and strictly allowlist URLs/IP ranges that the server is permitted to fetch
2. Block requests to private IP ranges (RFC 1918), loopback, and cloud metadata addresses
3. Disable unnecessary URL-fetching features or require authentication for them
4. Use a server-side proxy that enforces allowlists
5. In cloud environments, restrict metadata endpoint access with IMDSv2 (AWS)`,
    references_text: `https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/918.html`,
  },
  {
    id: "idor",
    title: "Insecure Direct Object Reference (IDOR)",
    severity: "high",
    category: "Broken Access Control",
    cvss_score: "7.5",
    cve_text: "",
    description: `The application exposes internal object identifiers (IDs, UUIDs, filenames) in requests and does not verify that the authenticated user is authorized to access the referenced object.

An attacker can modify the identifier in a request to access or modify data belonging to another user:
- Horizontal privilege escalation (accessing other users' data)
- Vertical privilege escalation (accessing admin resources)
- Mass data extraction by iterating predictable IDs`,
    remediation: `1. Implement server-side authorization checks for every resource access — verify ownership
2. Use indirect references (map user-specific tokens to actual IDs server-side)
3. Apply an access control framework and enforce it at the service layer, not just the UI
4. Log and alert on access patterns that suggest enumeration (sequential ID guessing)
5. Use UUIDs instead of sequential integers to reduce guessability (defense-in-depth only)`,
    references_text: `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/639.html`,
  },
  {
    id: "xxe",
    title: "XML External Entity Injection (XXE)",
    severity: "high",
    category: "Injection",
    cvss_score: "7.5",
    cve_text: "",
    description: `The application parses XML input that includes a reference to an external entity. An attacker can exploit this to:
- Read arbitrary files from the server filesystem (e.g., /etc/passwd, application config)
- Perform SSRF attacks via external entity URIs
- Cause denial of service via billion-laughs entity expansion
- In some parsers, execute remote code`,
    remediation: `1. Disable external entity processing in your XML parser (most parsers support this as a configuration option)
2. Use simpler data formats (JSON) where XML is not required
3. Validate and sanitize XML input before parsing
4. Apply server-side input validation and content-type checks
5. Update XML parsing libraries to patched versions`,
    references_text: `https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/611.html`,
  },
  {
    id: "csrf",
    title: "Cross-Site Request Forgery (CSRF)",
    severity: "medium",
    category: "CSRF",
    cvss_score: "6.5",
    cve_text: "",
    description: `The application does not require state-changing requests to include an unpredictable, user-specific token. An attacker can craft a malicious page that causes a logged-in victim's browser to make authenticated requests on their behalf.

Impact depends on the actions available:
- Account modification (email/password change)
- Fund transfers or order placement
- Data deletion or privilege changes`,
    remediation: `1. Implement synchronizer token pattern (CSRF token in every state-changing form/request)
2. Use the SameSite=Strict or SameSite=Lax cookie attribute
3. Validate the Origin and Referer request headers for sensitive actions
4. Require re-authentication for critical operations
5. Use custom request headers (e.g., X-Requested-With) for AJAX calls`,
    references_text: `https://owasp.org/www-community/attacks/csrf
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/352.html`,
  },
  {
    id: "path-traversal",
    title: "Path Traversal",
    severity: "high",
    category: "Injection",
    cvss_score: "7.5",
    cve_text: "",
    description: `The application uses user-supplied input to construct file system paths without sufficient canonicalization or validation. An attacker can use sequences such as "../" to escape the intended directory and read or write arbitrary files.

Common impacts:
- Disclosure of sensitive configuration files and credentials
- Source code exposure
- Overwriting critical files (web shells, configuration)`,
    remediation: `1. Validate and canonicalize all file paths before use (resolve to an absolute path and verify it starts with the expected base directory)
2. Use an allowlist of permitted filenames rather than blocking traversal sequences
3. Run the web application with the minimum filesystem permissions required
4. Avoid passing user-controlled input to filesystem APIs where possible`,
    references_text: `https://owasp.org/www-community/attacks/Path_Traversal
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/22.html`,
  },
  {
    id: "cmd-injection",
    title: "Command Injection",
    severity: "critical",
    category: "Injection",
    cvss_score: "9.8",
    cve_text: "",
    description: `The application passes user-supplied input to a shell command without proper sanitization, allowing an attacker to append or inject additional OS commands that execute with the web server's privileges.

This typically results in full server compromise:
- Remote code execution
- Data exfiltration
- Lateral movement within the internal network
- Persistence via backdoors`,
    remediation: `1. Avoid calling OS commands with user-supplied input entirely — use library equivalents instead
2. If shell execution is unavoidable, use parameterized APIs (e.g., execvp with argument arrays, not shell=True)
3. Strictly allowlist permitted input characters
4. Run the application under a least-privilege OS account
5. Apply AppArmor / seccomp profiles to restrict available syscalls`,
    references_text: `https://owasp.org/www-community/attacks/Command_Injection
https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/78.html`,
  },
  {
    id: "open-redirect",
    title: "Open Redirect",
    severity: "medium",
    category: "Redirect",
    cvss_score: "6.1",
    cve_text: "",
    description: `The application accepts a user-controlled URL parameter and redirects the browser to it without validation. Attackers abuse this to redirect victims from a trusted domain to a malicious site, often as part of phishing campaigns.

Common abuse scenarios:
- OAuth token theft via redirect_uri manipulation
- Bypassing referrer-based access controls
- Luring victims into entering credentials on attacker-controlled pages`,
    remediation: `1. Avoid using user-supplied URLs in redirects entirely
2. If redirects are necessary, use an allowlist of approved destination URLs or domains
3. For OAuth flows, register and strictly validate redirect_uri values server-side
4. Warn users before redirecting to external domains`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/601.html`,
  },
  {
    id: "ssti",
    title: "Server-Side Template Injection (SSTI)",
    severity: "critical",
    category: "Injection",
    cvss_score: "9.8",
    cve_text: "",
    description: `User-supplied input is embedded directly into a server-side template and evaluated by the template engine. Depending on the engine (Jinja2, Twig, Freemarker, etc.), this can lead to remote code execution.

An attacker can:
- Execute arbitrary OS commands
- Read sensitive files and environment variables
- Pivot to internal infrastructure`,
    remediation: `1. Never pass user input directly to template rendering functions
2. Use a sandbox-aware template engine and enable its sandboxing features
3. Validate and encode all user input before including it in templates
4. Apply least-privilege to the process running the template engine
5. Prefer logic-less templates (Mustache, Handlebars in strict mode) for user-facing content`,
    references_text: `https://portswigger.net/research/server-side-template-injection
https://cwe.mitre.org/data/definitions/94.html`,
  },
  {
    id: "jwt-alg",
    title: "JWT Algorithm Confusion / None Algorithm",
    severity: "critical",
    category: "Broken Authentication",
    cvss_score: "9.1",
    cve_text: "",
    description: `The JWT implementation accepts tokens signed with an unexpected algorithm, such as "none" (no signature) or RS256 public keys used as HMAC secrets. An attacker can forge valid tokens and impersonate any user, including administrators.

Common variants:
- alg: none — signature validation skipped entirely
- RS256→HS256 confusion — public key used as HMAC secret
- Key injection via JWK Set header`,
    remediation: `1. Explicitly allowlist accepted algorithms in JWT verification code
2. Never accept "none" as a valid algorithm
3. Use a well-maintained JWT library and keep it updated
4. Validate token claims (iss, aud, exp) in addition to the signature
5. Rotate signing keys regularly and support key ID (kid) validation`,
    references_text: `https://portswigger.net/web-security/jwt
https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
https://cwe.mitre.org/data/definitions/347.html`,
  },
  {
    id: "cors",
    title: "CORS Misconfiguration",
    severity: "high",
    category: "Access Control",
    cvss_score: "7.4",
    cve_text: "",
    description: `The application's CORS policy is overly permissive. The server either reflects the request's Origin header verbatim, allows null origins, or permits wildcard origins on authenticated endpoints.

An attacker can host a malicious page that makes cross-origin requests to the API on behalf of an authenticated victim, reading the response and exfiltrating sensitive data.`,
    remediation: `1. Maintain an explicit allowlist of trusted origins; never reflect arbitrary origins
2. Do not use Access-Control-Allow-Origin: * on endpoints that require credentials
3. Never allow the null origin on production APIs
4. Set Access-Control-Allow-Credentials: true only when necessary and only with a specific origin
5. Review CORS headers in all API responses, including error responses`,
    references_text: `https://portswigger.net/web-security/cors
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/942.html`,
  },
  {
    id: "sec-headers",
    title: "Missing Security Headers",
    severity: "medium",
    category: "Security Misconfiguration",
    cvss_score: "5.3",
    cve_text: "",
    description: `The application does not set one or more critical HTTP security headers, weakening its defense against common client-side attacks.

Commonly missing headers and their risk:
- Content-Security-Policy — no XSS mitigation layer
- X-Frame-Options / frame-ancestors — clickjacking risk
- Strict-Transport-Security — downgrade to HTTP possible
- X-Content-Type-Options — MIME sniffing attacks
- Referrer-Policy — sensitive URL leakage in Referer header`,
    remediation: `1. Add Content-Security-Policy with a policy appropriate for the application
2. Set X-Frame-Options: DENY or CSP frame-ancestors 'none'
3. Enable Strict-Transport-Security with a long max-age (≥1 year) and includeSubDomains
4. Set X-Content-Type-Options: nosniff
5. Set Referrer-Policy: strict-origin-when-cross-origin
6. Set Permissions-Policy to restrict access to sensitive browser APIs`,
    references_text: `https://owasp.org/www-project-secure-headers/
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
https://securityheaders.com`,
  },
  {
    id: "broken-auth",
    title: "Broken Authentication / Weak Session Management",
    severity: "critical",
    category: "Broken Authentication",
    cvss_score: "9.0",
    cve_text: "",
    description: `The application's authentication or session management is flawed, allowing attackers to compromise passwords, keys, or session tokens and assume users' identities.

Common issues include:
- Weak/default credentials permitted
- Missing account lockout after failed attempts
- Session tokens not invalidated on logout
- Credentials transmitted over HTTP
- Predictable or short-lived session tokens`,
    remediation: `1. Enforce strong password policies and offer MFA
2. Implement account lockout or progressive delays after failed login attempts
3. Invalidate session tokens server-side on logout and password change
4. Use cryptographically random, sufficiently long session identifiers
5. Transmit credentials only over TLS; set Secure cookie flag
6. Store passwords using bcrypt, Argon2, or scrypt`,
    references_text: `https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/287.html`,
  },
  {
    id: "sensitive-exposure",
    title: "Sensitive Data Exposure",
    severity: "high",
    category: "Sensitive Data",
    cvss_score: "7.5",
    cve_text: "",
    description: `The application exposes sensitive data (credentials, PII, API keys, internal paths, stack traces) in HTTP responses, logs, error messages, or client-side code.

Common sources:
- Debug error pages with stack traces in production
- API responses returning more fields than necessary
- Secrets committed to version control or returned in JS bundles
- Verbose server headers revealing version information`,
    remediation: `1. Disable debug mode and verbose error messages in production
2. Implement field-level response filtering — return only what the client needs
3. Audit logs for sensitive data and redact before storing
4. Rotate any exposed credentials immediately
5. Use secrets management tools (Vault, AWS Secrets Manager) instead of env files
6. Suppress Server, X-Powered-By, and similar version-revealing headers`,
    references_text: `https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/200.html`,
  },
  {
    id: "file-upload",
    title: "Unrestricted File Upload",
    severity: "high",
    category: "File Upload",
    cvss_score: "8.8",
    cve_text: "",
    description: `The application allows users to upload files without adequately validating their type or content, enabling an attacker to upload a web shell or malicious script that can be executed on the server.

Exploitation requires:
1. Uploading a file with a dangerous extension or MIME type
2. Accessing the uploaded file via a known or guessable URL`,
    remediation: `1. Validate file type using magic bytes (file content), not just extension or MIME header
2. Allowlist permitted file extensions and content types
3. Rename uploaded files to random names and remove their execute permissions
4. Store uploaded files outside the web root or on a separate storage service (S3, GCS)
5. Serve uploaded files through a proxy that sets Content-Disposition: attachment
6. Scan uploaded files with antivirus/malware detection`,
    references_text: `https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/434.html`,
  },
  {
    id: "subdomain-takeover",
    title: "Subdomain Takeover",
    severity: "high",
    category: "DNS",
    cvss_score: "7.4",
    cve_text: "",
    description: `A DNS record (CNAME, A, or NS) for a subdomain points to an external service (GitHub Pages, Heroku, AWS S3, Fastly, etc.) that is no longer claimed by the organization. An attacker can register the unclaimed resource and serve content under the organization's subdomain.

This enables:
- Phishing attacks with legitimate-looking URLs
- Cookie theft (if the subdomain shares a parent domain cookie scope)
- OAuth redirect_uri hijacking
- Bypassing HSTS or CSP policies`,
    remediation: `1. Remove DNS records for decommissioned services immediately
2. Implement a subdomain inventory process and audit DNS records regularly
3. Use subdomain takeover scanners (subjack, nuclei, AttackTrace Takeover Checker) in CI/CD
4. For services that support it, verify domain ownership before deprovisioning`,
    references_text: `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
https://cwe.mitre.org/data/definitions/116.html`,
  },
  {
    id: "host-header",
    title: "Host Header Injection",
    severity: "medium",
    category: "Injection",
    cvss_score: "6.5",
    cve_text: "",
    description: `The application uses the Host header from incoming requests in security-sensitive operations (password reset links, cache keys, redirect URLs) without validating that it matches the expected hostname.

An attacker can poison a password reset email to point to an attacker-controlled domain, capturing the reset token when the victim clicks the link.`,
    remediation: `1. Hardcode the application's canonical hostname in password reset and email links — never use the Host header directly
2. Validate the Host header against an allowlist of known hostnames
3. Configure the web server to reject requests with unexpected Host headers
4. Implement a reverse proxy that sets a trusted X-Forwarded-Host header`,
    references_text: `https://portswigger.net/web-security/host-header
https://cwe.mitre.org/data/definitions/20.html`,
  },
  {
    id: "rate-limit",
    title: "Missing Rate Limiting",
    severity: "medium",
    category: "Security Misconfiguration",
    cvss_score: "5.3",
    cve_text: "",
    description: `The endpoint does not implement rate limiting or request throttling, allowing an attacker to send an unlimited number of requests. This can enable:
- Brute-force attacks on authentication endpoints
- OTP / PIN enumeration
- Resource exhaustion (DoS)
- Mass data harvesting via API enumeration`,
    remediation: `1. Implement rate limiting per IP (and per user when authenticated) using a token bucket or sliding window algorithm
2. Apply progressive delays or CAPTCHA challenges after N failed attempts
3. Use a WAF or API gateway to enforce global rate limits
4. Return 429 Too Many Requests with a Retry-After header
5. Alert on abnormal request volumes from a single source`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/307.html`,
  },
  {
    id: "insecure-deserialization",
    title: "Insecure Deserialization",
    severity: "critical",
    category: "Injection",
    cvss_score: "9.8",
    cve_text: "",
    description: `The application deserializes untrusted data (from cookies, API parameters, message queues) using an unsafe deserialization library or without integrity verification. An attacker can craft a malicious serialized payload that triggers remote code execution, privilege escalation, or denial of service during deserialization.`,
    remediation: `1. Avoid deserializing data from untrusted sources in native formats (Java serialization, pickle, PHP serialize)
2. Use safe, type-safe formats like JSON with strict schema validation
3. If native serialization is required, verify a cryptographic signature before deserializing
4. Run deserialization in a sandboxed context with minimal privileges
5. Monitor for deserialization gadget chains in dependency trees`,
    references_text: `https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/502.html`,
  },
];

const TEMPLATE_CATEGORIES = ["All", ...Array.from(new Set(VULN_TEMPLATES.map((t) => t.category)))];

const SEV_BG: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

function TemplatePicker({
  onSelect,
  onClose,
}: {
  onSelect: (t: VulnTemplate) => void;
  onClose: () => void;
}) {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");

  const filtered = useMemo(() => {
    return VULN_TEMPLATES.filter((t) => {
      const matchCat = category === "All" || t.category === category;
      const q = search.toLowerCase();
      const matchSearch =
        !q ||
        t.title.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        t.severity.toLowerCase().includes(q);
      return matchCat && matchSearch;
    });
  }, [search, category]);

  return (
    <div className="fixed inset-0 z-60 flex items-center justify-center p-4" style={{ zIndex: 60 }}>
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className="relative w-full max-w-2xl max-h-[80vh] flex flex-col bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800 shrink-0">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-orange-400" />
            <h3 className="text-sm font-semibold text-zinc-100">Select Vulnerability Template</h3>
            <span className="text-xs text-zinc-500 ml-1">{filtered.length} templates</span>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Search + Category filter */}
        <div className="px-5 py-3 border-b border-zinc-800 shrink-0 space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
            <input
              autoFocus
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search templates..."
              className="w-full pl-9 pr-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {TEMPLATE_CATEGORIES.map((cat) => (
              <button
                key={cat}
                onClick={() => setCategory(cat)}
                className={`px-2.5 py-1 rounded-md text-xs transition-colors ${
                  category === cat
                    ? "bg-orange-600 text-white"
                    : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700"
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Template list */}
        <div className="flex-1 overflow-y-auto p-3 grid grid-cols-1 gap-2">
          {filtered.length === 0 && (
            <div className="text-center py-10 text-zinc-500 text-sm">No templates match your search</div>
          )}
          {filtered.map((t) => (
            <button
              key={t.id}
              onClick={() => { onSelect(t); onClose(); }}
              className="w-full text-left px-4 py-3 rounded-lg border border-zinc-800 hover:border-zinc-600 hover:bg-zinc-900 transition-colors group"
            >
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-zinc-200 group-hover:text-white truncate">{t.title}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-zinc-500">{t.category}</span>
                    {t.cvss_score && (
                      <span className="text-xs text-zinc-600">CVSS {t.cvss_score}</span>
                    )}
                  </div>
                </div>
                <span className={`shrink-0 px-2 py-0.5 rounded text-xs font-medium border ${SEV_BG[t.severity] ?? ""}`}>
                  {t.severity}
                </span>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function CreateFindingDrawer({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [form, setForm] = useState<CreateFindingForm>(EMPTY_FORM);
  const [showPicker, setShowPicker] = useState(false);
  const createFinding = useCreateFinding();

  const set = (field: keyof CreateFindingForm) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => setForm((f) => ({ ...f, [field]: e.target.value }));

  const applyTemplate = (t: VulnTemplate) => {
    setForm((f) => ({
      ...f,
      title: t.title,
      severity: t.severity,
      category: t.category,
      description: t.description,
      remediation: t.remediation,
      references_text: t.references_text,
      cvss_score: t.cvss_score,
      cve_text: t.cve_text,
      // evidence left blank — tester fills this in
    }));
    toast.success(`Template applied: ${t.title}`);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.title.trim()) {
      toast.error("Title is required");
      return;
    }

    const cvssNum = form.cvss_score ? parseFloat(form.cvss_score) : undefined;
    if (cvssNum !== undefined && (isNaN(cvssNum) || cvssNum < 0 || cvssNum > 10)) {
      toast.error("CVSS score must be between 0 and 10");
      return;
    }

    const payload = {
      title: form.title.trim(),
      severity: form.severity,
      category: form.category.trim(),
      affected_asset: form.affected_asset.trim(),
      description: form.description.trim(),
      evidence: form.evidence_text.trim() ? { content: form.evidence_text.trim() } : undefined,
      remediation: form.remediation.trim(),
      cve: form.cve_text
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
      cvss_score: cvssNum,
      references: form.references_text
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      status: form.status,
      ticket_ref: form.ticket_ref.trim() || undefined,
    };

    createFinding.mutate(payload, {
      onSuccess: () => {
        setForm(EMPTY_FORM);
        onClose();
      },
    });
  };

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Template picker (renders above drawer) */}
      {showPicker && (
        <TemplatePicker
          onSelect={applyTemplate}
          onClose={() => setShowPicker(false)}
        />
      )}

      {/* Drawer */}
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl flex flex-col bg-zinc-950 border-l border-zinc-800 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800 shrink-0">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" />
            <h2 className="text-base font-semibold text-zinc-100">Create Manual Finding</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowPicker(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-zinc-700 bg-zinc-900 hover:bg-zinc-800 text-xs text-zinc-300 transition-colors"
            >
              <FileText className="h-3.5 w-3.5 text-orange-400" />
              Use Template
              <ChevronDown className="h-3 w-3 text-zinc-500" />
            </button>
            <button
              onClick={onClose}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {/* Title */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
              Title <span className="text-red-400">*</span>
            </label>
            <input
              value={form.title}
              onChange={set("title")}
              placeholder="e.g. SQL Injection in /api/users endpoint"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              required
            />
          </div>

          {/* Severity + Status row */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                Severity <span className="text-red-400">*</span>
              </label>
              <select
                value={form.severity}
                onChange={set("severity")}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-zinc-500"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s} className={SEV_COLORS[s]}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Status</label>
              <select
                value={form.status}
                onChange={set("status")}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-zinc-500"
              >
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Category + Affected Asset */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Category</label>
              <input
                value={form.category}
                onChange={set("category")}
                placeholder="e.g. injection, auth"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Affected Asset</label>
              <input
                value={form.affected_asset}
                onChange={set("affected_asset")}
                placeholder="e.g. https://api.example.com"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
          </div>

          {/* Description */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Description</label>
            <textarea
              value={form.description}
              onChange={set("description")}
              rows={3}
              placeholder="Describe the vulnerability, its impact, and how it was found..."
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 resize-none"
            />
          </div>

          {/* Evidence — always filled by tester, never pre-populated by templates */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Evidence</label>
              <span className="text-xs text-orange-400 font-medium">Tester input required</span>
            </div>
            <textarea
              value={form.evidence_text}
              onChange={set("evidence_text")}
              rows={4}
              placeholder="Paste request/response, screenshots, payload output, or PoC steps here..."
              className="w-full rounded-lg border border-orange-500/30 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-orange-500/60 font-mono resize-none"
            />
          </div>

          {/* Remediation */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Remediation</label>
            <textarea
              value={form.remediation}
              onChange={set("remediation")}
              rows={3}
              placeholder="Steps to fix this vulnerability (one per line)..."
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 resize-none"
            />
          </div>

          {/* CVE + CVSS */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">CVE IDs</label>
              <textarea
                value={form.cve_text}
                onChange={set("cve_text")}
                rows={2}
                placeholder="CVE-2024-1234&#10;CVE-2024-5678"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 font-mono resize-none"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">CVSS Score (0–10)</label>
              <input
                value={form.cvss_score}
                onChange={set("cvss_score")}
                type="number"
                min={0}
                max={10}
                step={0.1}
                placeholder="e.g. 8.1"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
          </div>

          {/* References */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">References (one URL per line)</label>
            <textarea
              value={form.references_text}
              onChange={set("references_text")}
              rows={2}
              placeholder="https://owasp.org/...&#10;https://cve.mitre.org/..."
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 resize-none"
            />
          </div>

          {/* Ticket Ref */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Ticket Reference</label>
            <input
              value={form.ticket_ref}
              onChange={set("ticket_ref")}
              placeholder="e.g. JIRA-1234 or GitHub #42"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
            />
          </div>
        </form>

        {/* Footer */}
        <div className="shrink-0 flex items-center justify-end gap-3 px-6 py-4 border-t border-zinc-800 bg-zinc-950">
          <Button variant="ghost" onClick={onClose} className="text-zinc-400">
            Cancel
          </Button>
          <Button
            onClick={(e) => {
              e.preventDefault();
              const formEl = document.querySelector("form");
              formEl?.requestSubmit();
            }}
            disabled={createFinding.isPending}
            className="bg-orange-600 hover:bg-orange-500 text-white"
          >
            {createFinding.isPending ? "Creating…" : "Create Finding"}
          </Button>
        </div>
      </div>
    </>
  );
}

export default function FindingsPage() {
  const [viewMode, setViewMode] = useState<'active' | 'suppressed'>('active');
  const [filters, setFilters] = useState<FindingFilters>({ statuses: ["open", "in_progress"] });
  const [kevOnly, setKevOnly] = useState(false);
  const [confidenceFilter, setConfidenceFilter] = useState("");
  const [secretsOnly, setSecretsOnly] = useState(false);
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkLoading, setBulkLoading] = useState(false);

  // Build query params based on view mode + filters
  const activeQueryFilters: FindingFilters & { page?: number; per_page?: number; category?: string; overdue?: boolean } = viewMode === 'active'
    ? {
        ...filters,
        suppressed: false,
        kev_only: kevOnly || undefined,
        confidence: confidenceFilter || undefined,
        category: secretsOnly ? "exposed_secret" : undefined,
        overdue: overdueOnly || undefined,
        page,
        per_page: PER_PAGE,
      }
    : {
        suppressed: true,
        page,
        per_page: PER_PAGE,
      };

  const { data, isLoading } = useFindings(activeQueryFilters);
  const findings = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PER_PAGE);

  // Fetch suppressed count for the badge
  const { data: suppressedData } = useFindings({ suppressed: true, per_page: 1, page: 1 });
  const suppressedCount = suppressedData?.total ?? 0;

  const toggleSeverity = (severity: FindingSeverity) => {
    const current = filters.severities ?? [];
    const updated = current.includes(severity)
      ? current.filter((s) => s !== severity)
      : [...current, severity];
    setFilters((f) => ({ ...f, severities: updated.length > 0 ? updated : undefined }));
    setPage(1);
  };

  const toggleStatus = (status: FindingStatus) => {
    const current = filters.statuses ?? [];
    const updated = current.includes(status)
      ? current.filter((s) => s !== status)
      : [...current, status];
    setFilters((f) => ({ ...f, statuses: updated.length > 0 ? updated : undefined }));
    setPage(1);
  };

  const clearFilters = () => {
    setFilters({});
    setKevOnly(false);
    setConfidenceFilter("");
    setSecretsOnly(false);
    setOverdueOnly(false);
    setPage(1);
  };

  // Search filter applied client-side on the current page's findings
  const filteredFindings = searchQuery.trim()
    ? findings.filter((f) =>
        f.title?.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : findings;

  // Select all visible (filtered) findings on current page
  const allVisibleSelected =
    filteredFindings.length > 0 &&
    filteredFindings.every((f) => selectedIds.has(f.id));

  const toggleSelectAll = () => {
    if (allVisibleSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filteredFindings.forEach((f) => next.delete(f.id));
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filteredFindings.forEach((f) => next.add(f.id));
        return next;
      });
    }
  };

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleBulkStatus = async (status: string) => {
    if (selectedIds.size === 0) return;
    setBulkLoading(true);
    try {
      const resp = await fetchWithAuth(`${API_BASE}/findings/bulk-status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_ids: Array.from(selectedIds), status }),
      });
      if (!resp.ok) throw new Error("Bulk status update failed");
      toast.success(`Marked ${selectedIds.size} finding(s) as ${status.replace("_", " ")}`);
      setSelectedIds(new Set());
    } catch {
      toast.error("Failed to update findings");
    } finally {
      setBulkLoading(false);
    }
  };

  const handleExportSelected = async () => {
    if (selectedIds.size === 0) return;
    try {
      const ids = Array.from(selectedIds).join(",");
      const url = `${API_BASE}/findings/export?fmt=csv&finding_ids=${encodeURIComponent(ids)}`;
      const resp = await fetchWithAuth(url);
      if (!resp.ok) { toast.error("Export failed"); return; }
      const blob = await resp.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "findings-selected.csv";
      a.click();
    } catch {
      toast.error("Export failed");
    }
  };

  const handleExportAll = async () => {
    try {
      const resp = await fetchWithAuth(`${API_BASE}/findings/export?fmt=csv`);
      if (!resp.ok) { toast.error("Export failed"); return; }
      const blob = await resp.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "findings-all.csv";
      a.click();
    } catch {
      toast.error("Export failed");
    }
  };

  const hasFilters =
    (filters.severities?.length ?? 0) > 0 ||
    (filters.statuses?.length ?? 0) > 0 ||
    !!filters.has_cve ||
    kevOnly ||
    !!confidenceFilter ||
    secretsOnly ||
    overdueOnly;

  const SEVERITY_COLORS: Record<FindingSeverity, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-400",
    info: "text-gray-400",
  };

  const handleViewModeChange = (mode: 'active' | 'suppressed') => {
    setViewMode(mode);
    setPage(1);
  };

  return (
    <div className="flex gap-6 h-full">
      {/* Filter sidebar — only show in active mode */}
      {viewMode === 'active' && (
        <div className="w-52 shrink-0 space-y-5 rounded-lg border border-zinc-800 bg-zinc-900 p-4 self-start">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-zinc-300">Filters</h3>
            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFilters}
                className="h-6 text-xs text-zinc-500 gap-1 px-2"
              >
                <X className="h-3 w-3" />
                Clear
              </Button>
            )}
          </div>

          {/* KEV Only toggle */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Threat Intel</Label>
            <button
              onClick={() => { setKevOnly(!kevOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors w-full justify-start ${
                kevOnly
                  ? 'bg-red-900/50 border-red-500/50 text-red-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-red-500/50 hover:text-red-300'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${kevOnly ? 'bg-red-400 animate-pulse' : 'bg-zinc-600'}`} />
              KEV Only
            </button>

            {/* Secrets quick-filter */}
            <button
              onClick={() => { setSecretsOnly(!secretsOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors w-full justify-start ${
                secretsOnly
                  ? 'bg-amber-900/50 border-amber-500/50 text-amber-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-amber-500/50 hover:text-amber-300'
              }`}
            >
              <Lock className="h-3 w-3" />
              Secrets Only
            </button>

            {/* Overdue quick-filter */}
            <button
              onClick={() => { setOverdueOnly(!overdueOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors w-full justify-start ${
                overdueOnly
                  ? 'bg-orange-900/50 border-orange-500/50 text-orange-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-orange-500/50 hover:text-orange-300'
              }`}
            >
              <Clock className="h-3 w-3" />
              Overdue
            </button>
          </div>

          <Separator />

          {/* Confidence filter */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Confidence</Label>
            <select
              value={confidenceFilter}
              onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
              className="w-full rounded-lg border border-zinc-600 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-300"
            >
              <option value="">All Confidence</option>
              <option value="certain">Certain</option>
              <option value="firm">Firm</option>
              <option value="tentative">Tentative</option>
            </select>
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Severity</Label>
            {SEVERITIES.map((severity) => (
              <div key={severity} className="flex items-center gap-2">
                <Checkbox
                  id={`sev-${severity}`}
                  checked={(filters.severities ?? []).includes(severity)}
                  onCheckedChange={() => toggleSeverity(severity)}
                />
                <label
                  htmlFor={`sev-${severity}`}
                  className={`text-sm cursor-pointer capitalize font-medium ${SEVERITY_COLORS[severity]}`}
                >
                  {severity}
                </label>
              </div>
            ))}
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Status</Label>
            {STATUSES.map((status) => (
              <div key={status} className="flex items-center gap-2">
                <Checkbox
                  id={`status-${status}`}
                  checked={(filters.statuses ?? []).includes(status)}
                  onCheckedChange={() => toggleStatus(status)}
                />
                <label
                  htmlFor={`status-${status}`}
                  className="text-sm cursor-pointer text-zinc-300 capitalize"
                >
                  {status.replace("_", " ")}
                </label>
              </div>
            ))}
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">CVE / CVSS</Label>
            <div className="flex items-center gap-2">
              <Checkbox
                id="has-cve"
                checked={!!filters.has_cve}
                onCheckedChange={(checked) => {
                  setFilters((f) => ({ ...f, has_cve: checked ? true : undefined }));
                  setPage(1);
                }}
              />
              <label htmlFor="has-cve" className="text-sm cursor-pointer text-zinc-300">
                Has CVE ID
              </label>
            </div>
          </div>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 min-w-0 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Findings</h1>
            <p className="text-sm text-zinc-400 mt-0.5">
              {total.toLocaleString()} findings {hasFilters && viewMode === 'active' && "matching filters"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {/* Search bar */}
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings..."
                className="pl-8 pr-3 py-1.5 rounded-md border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 w-52"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
            {/* Export All CSV */}
            <Button
              variant="outline"
              size="sm"
              onClick={handleExportAll}
              className="gap-1.5 border-zinc-700 text-zinc-300 hover:text-zinc-100"
            >
              <Download className="h-3.5 w-3.5" />
              Export CSV
            </Button>
            <Button
              onClick={() => setDrawerOpen(true)}
              className="bg-orange-600 hover:bg-orange-500 text-white gap-1.5"
              size="sm"
            >
              <Plus className="h-4 w-4" />
              Create Finding
            </Button>
          </div>
        </div>

        {/* Active / Suppressed tab bar */}
        <div className="flex gap-1 rounded-lg bg-gray-800/50 p-1 w-fit">
          <button
            onClick={() => handleViewModeChange('active')}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'active'
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Active Findings
          </button>
          <button
            onClick={() => handleViewModeChange('suppressed')}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'suppressed'
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Suppressed
            {suppressedCount > 0 && (
              <span className="ml-1.5 rounded-full bg-gray-600 px-1.5 py-0.5 text-xs">
                {suppressedCount}
              </span>
            )}
          </button>
        </div>

        {isLoading ? (
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <div className="h-3.5 w-3.5 rounded bg-zinc-800 animate-pulse shrink-0" />
                <div className="h-6 w-20 rounded bg-zinc-800 animate-pulse shrink-0" />
                <div className="flex-1 space-y-1.5">
                  <div className="h-4 w-64 rounded bg-zinc-800 animate-pulse" />
                  <div className="h-3 w-40 rounded bg-zinc-800 animate-pulse" />
                </div>
                <div className="h-6 w-24 rounded bg-zinc-800 animate-pulse shrink-0" />
              </div>
            ))}
          </div>
        ) : filteredFindings.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" />}
            title={
              searchQuery
                ? "No findings match your search"
                : viewMode === 'suppressed' ? "No suppressed findings" : "No findings"
            }
            description={
              searchQuery
                ? `No findings matched "${searchQuery}". Try a different search term.`
                : viewMode === 'suppressed'
                  ? "No findings have been suppressed or marked as false positive."
                  : "No findings match your current filters. Run a scan or create a manual finding."
            }
          />
        ) : (
          <div className="rounded-lg border border-zinc-800 overflow-hidden divide-y divide-zinc-800">
            {/* Select-all header row */}
            <div className="flex items-center gap-3 px-4 py-2 bg-zinc-900/60 border-b border-zinc-800">
              <Checkbox
                checked={allVisibleSelected}
                onCheckedChange={toggleSelectAll}
                aria-label="Select all findings"
              />
              <span className="text-xs text-zinc-500">
                {selectedIds.size > 0
                  ? `${selectedIds.size} selected`
                  : `Select all (${filteredFindings.length})`}
              </span>
            </div>
            {filteredFindings.map((f) => (
              <div key={f.id} className="flex items-start gap-3 px-4 group">
                <div className="flex items-center pt-3.5 shrink-0">
                  <Checkbox
                    checked={selectedIds.has(f.id)}
                    onCheckedChange={() => toggleSelectOne(f.id)}
                    aria-label={`Select finding ${f.title}`}
                  />
                </div>
                <div className="flex-1 min-w-0">
                  <FindingRow finding={f} />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm text-zinc-500">
            <span>
              Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of{" "}
              {total.toLocaleString()}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="h-8"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-zinc-400">
                {page} / {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="h-8"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Floating bulk action bar */}
      {selectedIds.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 bg-zinc-800 border border-zinc-600 rounded-xl px-5 py-3 shadow-2xl">
          <span className="text-sm font-medium text-zinc-200 flex items-center gap-1.5">
            <CheckSquare className="h-4 w-4 text-blue-400" />
            {selectedIds.size} selected
          </span>
          <div className="w-px h-5 bg-zinc-600" />
          <button
            onClick={() => handleBulkStatus("remediated")}
            disabled={bulkLoading}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-green-700 hover:bg-green-600 text-white disabled:opacity-50 transition-colors"
          >
            Mark as Remediated
          </button>
          <button
            onClick={() => handleBulkStatus("accepted_risk")}
            disabled={bulkLoading}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-yellow-700 hover:bg-yellow-600 text-white disabled:opacity-50 transition-colors"
          >
            Mark as Accepted Risk
          </button>
          <button
            onClick={handleExportSelected}
            disabled={bulkLoading}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-zinc-700 hover:bg-zinc-600 text-zinc-200 disabled:opacity-50 transition-colors flex items-center gap-1"
          >
            <Download className="h-3.5 w-3.5" />
            Export Selected (CSV)
          </button>
          <div className="w-px h-5 bg-zinc-600" />
          <button
            onClick={() => setSelectedIds(new Set())}
            className="text-zinc-400 hover:text-zinc-200 transition-colors"
            aria-label="Clear selection"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      <CreateFindingDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  );
}
