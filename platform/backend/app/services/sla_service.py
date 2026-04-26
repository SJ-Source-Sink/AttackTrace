"""
SLA deadline computation and compliance tag mapping.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

DEFAULT_SLA_DAYS = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}

# OWASP Top 10 2021 + PCI DSS + SOC2 compliance tag mapping
COMPLIANCE_RULES = [
    # (keywords_in_title_or_category, tags)
    (["sql injection", "sqli"], ["OWASP-A03", "PCI-DSS-6.2.4", "SOC2-CC7"]),
    (["xss", "cross-site scripting"], ["OWASP-A03", "PCI-DSS-6.2.4"]),
    (["broken access", "idor", "privilege escalation", "authorization"], ["OWASP-A01", "SOC2-CC6"]),
    (["cryptographic", "tls", "ssl", "weak cipher", "certificate"], ["OWASP-A02", "PCI-DSS-4.2", "SOC2-CC6"]),
    (["injection", "command injection", "rce", "remote code"], ["OWASP-A03", "PCI-DSS-6.2.4"]),
    (["insecure design", "business logic"], ["OWASP-A04"]),
    (["misconfiguration", "exposed admin", "default credential", "directory listing"], ["OWASP-A05", "PCI-DSS-2.2", "SOC2-CC6"]),
    (["vulnerable component", "outdated", "cve-"], ["OWASP-A06", "PCI-DSS-6.3.3"]),
    (["authentication", "session", "password", "brute force", "mfa"], ["OWASP-A07", "PCI-DSS-8.3", "SOC2-CC6"]),
    (["data exposure", "sensitive data", "pii", "leak"], ["OWASP-A02", "PCI-DSS-3.4", "SOC2-CC6"]),
    (["ssrf", "server-side request forgery"], ["OWASP-A10", "PCI-DSS-6.2.4"]),
    (["cors", "cross-origin"], ["OWASP-A05"]),
    (["open redirect"], ["OWASP-A01"]),
    (["exposed secret", "api key", "token", "credential"], ["OWASP-A02", "SOC2-CC6", "PCI-DSS-3.4"]),
    (["subdomain takeover"], ["OWASP-A05"]),
    (["xxe", "xml injection"], ["OWASP-A03", "PCI-DSS-6.2.4"]),
    (["deserialization"], ["OWASP-A08"]),
    (["ssti", "template injection"], ["OWASP-A03"]),
    (["csrf", "cross-site request forgery"], ["OWASP-A01"]),
    (["path traversal", "directory traversal", "lfi", "rfi"], ["OWASP-A01", "PCI-DSS-6.2.4"]),
    (["nosql", "ldap injection"], ["OWASP-A03"]),
]


def compute_sla_deadline(severity: str, org_sla_config: Optional[dict]) -> datetime:
    days_map = org_sla_config or DEFAULT_SLA_DAYS
    days = days_map.get(severity.lower(), DEFAULT_SLA_DAYS.get(severity.lower(), 90))
    return datetime.now(timezone.utc) + timedelta(days=int(days))


def apply_compliance_tags(title: str, category: str = "", description: str = "") -> list[str]:
    text = f"{title} {category} {description}".lower()
    tags: set[str] = set()
    for keywords, compliance in COMPLIANCE_RULES:
        if any(kw in text for kw in keywords):
            tags.update(compliance)
    return sorted(tags)
