"""
Shared remediation-text lookup for scanners that don't already have their own
(cspm.py, takeover.py, container_scanner.py, firewall.py, mcp_scanner.py, and
supply_chain.py all have good per-check remediation dicts already — call those
directly rather than this module). This exists for secrets.py, exposure_scanner.py,
email_security.py, and the core orchestrated scan pipeline (scan_worker.py),
none of which had any.

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
