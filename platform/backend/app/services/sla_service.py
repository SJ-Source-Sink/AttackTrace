"""
SLA deadline computation and compliance tag mapping.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

DEFAULT_SLA_DAYS = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}

# OWASP Top 10 2021 + PCI DSS + SOC2 compliance tag mapping
# Each entry: (keyword_patterns, compliance_tags)
# Patterns use word boundaries to avoid false positives (e.g. "session" won't match "sessionless").
COMPLIANCE_RULES = [
    (["sql injection", "sqli"], ["OWASP-A03", "PCI-DSS-6.2.4", "SOC2-CC7"]),
    (["xss", r"cross.site scripting"], ["OWASP-A03", "PCI-DSS-6.2.4"]),
    (["broken access", "idor", "privilege escalation", "authorization"], ["OWASP-A01", "SOC2-CC6"]),
    (["cryptographic", "tls", "ssl", r"weak cipher", "certificate"], ["OWASP-A02", "PCI-DSS-4.2", "SOC2-CC6"]),
    (["injection", r"command injection", "rce", r"remote code"], ["OWASP-A03", "PCI-DSS-6.2.4"]),
    (["insecure design", r"business logic"], ["OWASP-A04"]),
    (["misconfiguration", r"exposed admin", r"default credential", r"directory listing"], ["OWASP-A05", "PCI-DSS-2.2", "SOC2-CC6"]),
    (["vulnerable component", "outdated", "cve-"], ["OWASP-A06", "PCI-DSS-6.3.3"]),
    (["authentication", "session", "password", r"brute force", "mfa"], ["OWASP-A07", "PCI-DSS-8.3", "SOC2-CC6"]),
    (["data exposure", r"sensitive data", "pii", "leak"], ["OWASP-A02", "PCI-DSS-3.4", "SOC2-CC6"]),
    (["ssrf", r"server.side request forgery"], ["OWASP-A10", "PCI-DSS-6.2.4"]),
    (["cors", r"cross.origin"], ["OWASP-A05"]),
    (["open redirect"], ["OWASP-A01"]),
    (["exposed secret", r"api key", "token", "credential"], ["OWASP-A02", "SOC2-CC6", "PCI-DSS-3.4"]),
    (["subdomain takeover"], ["OWASP-A05"]),
    (["xxe", r"xml injection"], ["OWASP-A03", "PCI-DSS-6.2.4"]),
    (["deserialization"], ["OWASP-A08"]),
    (["ssti", r"template injection"], ["OWASP-A03"]),
    (["csrf", r"cross.site request forgery"], ["OWASP-A01"]),
    (["path traversal", r"directory traversal", "lfi", "rfi"], ["OWASP-A01", "PCI-DSS-6.2.4"]),
    (["nosql", r"ldap injection"], ["OWASP-A03"]),
]

# Pre-compiled patterns for performance: wrap each keyword in word boundaries
# using \b for whole-word matching and allow hyphens inside via non-word chars.
_COMPILED_RULES: list[tuple[list[re.Pattern], list[str]]] = []
for _keywords, _tags in COMPLIANCE_RULES:
    patterns = []
    for kw in _keywords:
        # If keyword already contains regex metacharacters (like \.) use as-is,
        # otherwise escape and wrap in word boundaries.
        if any(c in kw for c in r"\.+*?[](){}^$|"):
            patterns.append(re.compile(kw, re.IGNORECASE))
        else:
            # Escape special chars then wrap in word-boundary anchors
            patterns.append(re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE))
    _COMPILED_RULES.append((patterns, _tags))


def compute_sla_deadline(severity: str, org_sla_config: Optional[dict]) -> datetime:
    days_map = org_sla_config or DEFAULT_SLA_DAYS
    days = days_map.get(severity.lower(), DEFAULT_SLA_DAYS.get(severity.lower(), 90))
    return datetime.now(timezone.utc) + timedelta(days=int(days))


def apply_compliance_tags(title: str, category: str = "", description: str = "") -> list[str]:
    """Match pre-compiled word-boundary patterns against title + category + description.

    Uses word-boundary regex so 'session' matches 'session management' but not
    'sessionless' or 'multisession'. CVE patterns (e.g. 'cve-') are matched as
    prefix patterns since they're always followed by digits.
    """
    text = f"{title} {category} {description}"
    tags: set[str] = set()
    for patterns, compliance in _COMPILED_RULES:
        if any(p.search(text) for p in patterns):
            tags.update(compliance)
    return sorted(tags)
