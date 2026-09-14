"""
Email Security Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Analyses a domain's email security posture:
SPF · DMARC · DKIM · MX/STARTTLS · Lookalike domains · Breach checks.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import socket
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.core.remediation import get_remediation
from app.api.v1.dashboard import invalidate_dashboard_cache
from app.services.finding_ingest import ingest_findings
from app.models.db.user import User

# ── Filesystem history ────────────────────────────────────────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "email_security" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_history_path(org_id: str, scan_id: str) -> Path:
    """Build and confine the history file path to the org's history directory."""
    _validate_uuid(scan_id, "scan_id")
    base = _history_dir(org_id)
    candidate = (base / f"{scan_id}.json").resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise HTTPException(status_code=400, detail="Invalid scan_id")
    return candidate


def _save_scan_result(org_id: str, record: dict) -> None:
    try:
        path = _history_dir(org_id) / f"{record['id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
    try:
        files = sorted(
            _history_dir(org_id).glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )[:limit]
        records = []
        for f in files:
            try:
                records.append(json.loads(f.read_text()))
            except Exception:
                pass
        return records
    except Exception:
        return []


def _load_scan(org_id: str, scan_id: str) -> dict | None:
    try:
        path = _safe_history_path(org_id, scan_id)
        if path.exists():
            return json.loads(path.read_text())
    except HTTPException:
        raise
    except Exception:
        pass
    return None


def _delete_scan(org_id: str, scan_id: str) -> bool:
    try:
        path = _safe_history_path(org_id, scan_id)
        if path.exists():
            path.unlink()
            return True
    except HTTPException:
        raise
    except Exception:
        pass
    return False


router = APIRouter(prefix="/email-security", tags=["Email Security"])

# ── SSE helper ────────────────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


# ── DNS helpers ───────────────────────────────────────────────────────────────

def _dns_txt(name: str) -> list[str]:
    """Return all TXT record strings for a DNS name (synchronous)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
        results = []
        for rdata in answers:
            results.append("".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings))
        return results
    except Exception:
        return []


def _dns_mx(domain: str) -> list[tuple[int, str]]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=10)
        return sorted((int(r.preference), str(r.exchange).rstrip(".")) for r in answers)
    except Exception:
        return []


def _dns_a(name: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "A", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def _dns_aaaa(name: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "AAAA", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def _dns_ptr(ip: str) -> str | None:
    try:
        import dns.reversename
        import dns.resolver
        rev = dns.reversename.from_address(ip)
        ans = dns.resolver.resolve(rev, "PTR", lifetime=5)
        return str(list(ans)[0]).rstrip(".")
    except Exception:
        return None


# ── Phase helpers ─────────────────────────────────────────────────────────────

def _analyse_spf(domain: str) -> tuple[list[dict], dict]:
    """Returns (findings, spf_detail)"""
    findings: list[dict] = []
    txt_records = _dns_txt(domain)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        findings.append({
            "phase": "spf",
            "severity": "high",
            "title": "No SPF record",
            "detail": f"No SPF TXT record found at {domain}. Anyone can forge email from this domain.",
        })
        return findings, {"record": None, "policy": "none"}

    spf = spf_records[0]
    spf_detail = {"record": spf, "policy": "unknown"}

    if "+all" in spf:
        findings.append({
            "phase": "spf",
            "severity": "critical",
            "title": "SPF allows all senders (+all)",
            "detail": f"Anyone can send email as {domain} — SPF is completely open.",
        })
        spf_detail["policy"] = "+all"
    elif "~all" in spf:
        findings.append({
            "phase": "spf",
            "severity": "medium",
            "title": "SPF soft-fail (~all)",
            "detail": "SPF is in soft-fail mode. Consider upgrading to -all for strict enforcement.",
        })
        spf_detail["policy"] = "~all"
    elif "-all" in spf:
        findings.append({
            "phase": "spf",
            "severity": "info",
            "title": "SPF is properly configured (-all)",
            "detail": "SPF rejects unauthorized senders. Good.",
        })
        spf_detail["policy"] = "-all"
    elif "?all" in spf:
        findings.append({
            "phase": "spf",
            "severity": "medium",
            "title": "SPF neutral policy (?all)",
            "detail": "SPF neutral policy provides no protection. Use -all or ~all.",
        })
        spf_detail["policy"] = "?all"

    # Count DNS lookup mechanisms
    import re
    lookups = len(re.findall(r"\b(include:|a:|mx:|ptr:|exists:)", spf))
    if lookups > 10:
        findings.append({
            "phase": "spf",
            "severity": "medium",
            "title": f"SPF exceeds 10-lookup limit ({lookups} lookups)",
            "detail": "Too many DNS lookups in SPF record may cause PermError and delivery failures.",
        })

    return findings, spf_detail


def _analyse_dmarc(domain: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    txt_records = _dns_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        findings.append({
            "phase": "dmarc",
            "severity": "high",
            "title": "No DMARC record",
            "detail": f"No DMARC policy at _dmarc.{domain}. Spoofed emails will be delivered without detection.",
        })
        return findings, {"record": None, "policy": "none"}

    dmarc = dmarc_records[0]
    dmarc_detail = {"record": dmarc, "policy": "unknown"}

    import re

    # Policy
    p_match = re.search(r"p=(\w+)", dmarc, re.IGNORECASE)
    policy = p_match.group(1).lower() if p_match else "none"
    dmarc_detail["policy"] = policy

    if policy == "none":
        findings.append({
            "phase": "dmarc",
            "severity": "high",
            "title": "DMARC policy is monitoring-only (p=none)",
            "detail": "Spoofed emails are delivered. Set p=quarantine or p=reject.",
        })
    elif policy == "quarantine":
        findings.append({
            "phase": "dmarc",
            "severity": "medium",
            "title": "DMARC quarantine policy (p=quarantine)",
            "detail": "Suspicious email is quarantined, not rejected. Consider upgrading to p=reject.",
        })
    elif policy == "reject":
        findings.append({
            "phase": "dmarc",
            "severity": "info",
            "title": "DMARC reject policy (p=reject)",
            "detail": "DMARC is fully enforced. Spoofed emails are rejected.",
        })

    # Percentage
    pct_match = re.search(r"pct=(\d+)", dmarc, re.IGNORECASE)
    if pct_match:
        pct = int(pct_match.group(1))
        dmarc_detail["pct"] = pct
        if pct < 100:
            findings.append({
                "phase": "dmarc",
                "severity": "medium",
                "title": f"DMARC only applies to {pct}% of email",
                "detail": f"DMARC policy (pct={pct}) does not cover all messages. Set pct=100.",
            })

    # Reporting
    if "rua=" not in dmarc.lower():
        findings.append({
            "phase": "dmarc",
            "severity": "low",
            "title": "No DMARC aggregate reporting configured",
            "detail": "Add rua= tag to receive DMARC aggregate reports.",
        })

    return findings, dmarc_detail


def _analyse_dkim(domain: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    # Expanded selector list covering major ESPs and common custom names.
    # Note: Amazon SES, Brevo, Klaviyo and others use random/auto-generated selectors
    # that cannot be enumerated; a "not found" result may be a scanner limitation.
    selectors = [
        # Generic
        "default", "dkim", "dkim1", "dkim2", "mail", "email", "postmaster",
        # Google Workspace
        "google", "20161025", "20230601",
        # Microsoft 365 / Exchange Online
        "selector1", "selector2",
        # SendGrid
        "s1", "s2", "sg", "smtpapi",
        # Mailchimp / Mandrill
        "k1", "k2", "mandrill1", "mte1", "mte2",
        # Postmark
        "pm1", "pm2", "20171214",
        # Mailgun
        "mx",
        # Amazon SES (common custom names; random selectors can't be enumerated)
        "ses", "amazonses", "amazon",
        # Zoho / ProtonMail / Fastmail
        "zoho", "protonmail", "fm1", "fm2", "fm3",
        # Generic numeric / legacy
        "ed1", "ed2", "mxvault", "key1", "key2",
    ]
    found_selectors: list[dict] = []

    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        records = _dns_txt(name)
        for rec in records:
            if "p=" in rec.lower():
                # Extract key and estimate size
                import re
                p_match = re.search(r"p=([A-Za-z0-9+/=]+)", rec)
                key_bits = 0
                key_severity = "info"
                if p_match:
                    key_b64 = p_match.group(1)
                    try:
                        key_bytes = base64.b64decode(key_b64 + "==")
                        # Rough RSA key length from DER-encoded public key
                        key_bits = len(key_bytes) * 8
                        # Adjust: actual key bit length is shorter than raw byte count
                        # DER overhead is ~38 bytes for RSA; subtract and multiply by ~4 for rough bit count
                        estimated_bits = max((len(key_bytes) - 38) * 8, 512)
                        key_bits = estimated_bits
                    except Exception:
                        key_bits = 0

                if key_bits > 0 and key_bits < 1024:
                    key_severity = "critical"
                    findings.append({
                        "phase": "dkim",
                        "severity": "critical",
                        "title": f"DKIM key too weak (<1024 bit) — selector: {sel}",
                        "detail": f"DKIM key for selector '{sel}' is ~{key_bits} bits. Minimum is 1024.",
                    })
                elif key_bits >= 1024 and key_bits < 2048:
                    key_severity = "high"
                    findings.append({
                        "phase": "dkim",
                        "severity": "high",
                        "title": f"DKIM key is 1024-bit — selector: {sel}",
                        "detail": f"Selector '{sel}' uses a 1024-bit key. Upgrade to 2048-bit.",
                    })
                else:
                    findings.append({
                        "phase": "dkim",
                        "severity": "info",
                        "title": f"DKIM key found — selector: {sel}",
                        "detail": f"Valid DKIM record at {name}.",
                    })

                found_selectors.append({
                    "selector": sel,
                    "name": name,
                    "key_bits": key_bits,
                    "severity": key_severity,
                    "record_preview": rec[:120],
                })
                break  # one match per selector is enough

    if not found_selectors:
        findings.append({
            "phase": "dkim",
            "severity": "medium",
            "title": "No DKIM record found via common selectors",
            "detail": (
                f"Checked {len(selectors)} common DKIM selectors — none returned a valid record. "
                "If you use Amazon SES, Klaviyo, Brevo, or another ESP with auto-generated selectors, "
                "DKIM may still be configured. Verify by checking your ESP dashboard or running: "
                "dig TXT <selector>._domainkey." + domain
            ),
        })

    return findings, {"selectors_found": found_selectors}


def _analyse_mx(domain: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    mx_records = _dns_mx(domain)

    if not mx_records:
        findings.append({
            "phase": "mx",
            "severity": "high",
            "title": "No MX records found",
            "detail": f"Domain {domain} has no MX records — email cannot be received.",
        })
        return findings, {"mx_records": []}

    mx_detail: list[dict] = []

    for pref, host in mx_records[:5]:  # cap at 5 to avoid long delays
        entry: dict = {"preference": pref, "host": host, "ptr": None, "starttls": False, "banner": ""}
        # PTR lookup on first A record
        a_records = _dns_a(host)
        if a_records:
            ptr = _dns_ptr(a_records[0])
            entry["ptr"] = ptr
            if ptr and domain not in ptr and host.rstrip(".") not in ptr:
                findings.append({
                    "phase": "mx",
                    "severity": "low",
                    "title": f"MX PTR mismatch — {host}",
                    "detail": f"PTR record ({ptr}) does not match MX hostname. May affect deliverability.",
                })

        # SMTP banner + STARTTLS check
        try:
            with socket.create_connection((host, 25), timeout=5) as sock:
                banner = sock.recv(512).decode(errors="replace").strip()
                entry["banner"] = banner[:120]
                sock.sendall(b"EHLO attacktrace-scan.local\r\n")
                ehlo_resp = sock.recv(2048).decode(errors="replace")
                if "STARTTLS" in ehlo_resp.upper():
                    entry["starttls"] = True
                else:
                    findings.append({
                        "phase": "mx",
                        "severity": "medium",
                        "title": f"MX server does not advertise STARTTLS — {host}",
                        "detail": "Email may be transmitted unencrypted to this mail server.",
                    })
                sock.sendall(b"QUIT\r\n")
        except Exception:
            # Port 25 often blocked; not a finding by itself
            entry["banner"] = "(connection refused or timeout)"

        mx_detail.append(entry)

    return findings, {"mx_records": mx_detail}


def generate_lookalikes(domain: str, max_lookalikes: int = 50) -> list[str]:
    try:
        name, tld = domain.rsplit(".", 1)
    except ValueError:
        return []

    lookalikes: set[str] = set()

    # Prefix / suffix additions
    for prefix in ["secure-", "login-", "my-", "portal-", "auth-", "www-"]:
        lookalikes.add(f"{prefix}{name}.{tld}")
    for suffix in ["-secure", "-login", "-portal", "-auth", "-verify"]:
        lookalikes.add(f"{name}{suffix}.{tld}")

    # TLD variations
    for alt_tld in ["com", "net", "org", "io", "co", "app"]:
        if alt_tld != tld:
            lookalikes.add(f"{name}.{alt_tld}")

    # Typos — double characters
    for i, char in enumerate(name):
        lookalikes.add(f"{name[:i]}{char}{char}{name[i+1:]}.{tld}")

    # Transpositions
    for i in range(len(name) - 1):
        transposed = name[:i] + name[i+1] + name[i] + name[i+2:]
        lookalikes.add(f"{transposed}.{tld}")

    # Character substitutions
    substitutions: dict[str, list[str]] = {
        "a": ["4", "@"], "e": ["3"], "i": ["1", "l"],
        "o": ["0"], "s": ["5", "$"], "l": ["1", "i"],
    }
    for i, char in enumerate(name.lower()):
        if char in substitutions:
            for sub in substitutions[char]:
                lookalikes.add(f"{name[:i]}{sub}{name[i+1:]}.{tld}")

    # Omit one character
    for i in range(len(name)):
        if len(name) > 3:
            lookalikes.add(f"{name[:i]}{name[i+1:]}.{tld}")

    # Remove original domain itself
    lookalikes.discard(domain)

    return list(lookalikes)[:max_lookalikes]


async def _check_lookalike(
    lookalike: str,
    client: httpx.AsyncClient,
) -> dict | None:
    """Returns a finding dict if the lookalike resolves, else None."""
    # DNS A/AAAA
    loop = asyncio.get_event_loop()
    a_records = await loop.run_in_executor(None, _dns_a, lookalike)
    aaaa_records = await loop.run_in_executor(None, _dns_aaaa, lookalike)

    if not a_records and not aaaa_records:
        return None

    # Try HTTP
    serves_http = False
    for scheme in ["https", "http"]:
        try:
            resp = await client.get(f"{scheme}://{lookalike}/", timeout=4)
            if resp.status_code < 500:
                serves_http = True
                break
        except Exception:
            pass

    if serves_http:
        return {
            "domain": lookalike,
            "ips": a_records[:2],
            "serves_http": True,
            "severity": "critical",
            "detail": f"Lookalike domain {lookalike} is live and serving web content — potential phishing site.",
        }
    return {
        "domain": lookalike,
        "ips": a_records[:2],
        "serves_http": False,
        "severity": "high",
        "detail": f"Lookalike domain {lookalike} is registered and resolves via DNS.",
    }


# ── Score computation ─────────────────────────────────────────────────────────

def _compute_score(findings: list[dict]) -> int:
    """0–100: higher is better.

    Lookalike-domain findings are threat intelligence (they reflect
    what attackers have registered, not misconfiguration of this domain).
    They are capped at 20 points total so they don't dominate the score.
    All other findings are summed without cap.
    """
    deductions = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}
    total = 100
    lookalike_deducted = 0
    for f in findings:
        sev = f.get("severity", "")
        if sev not in deductions:
            continue
        if f.get("phase") == "lookalikes":
            # Each lookalike domain is critical but cap total lookalike deduction
            if lookalike_deducted < 20:
                d = min(deductions[sev], 20 - lookalike_deducted)
                lookalike_deducted += d
                total -= d
        else:
            total -= deductions[sev]
    return max(0, min(100, total))


# ── Core scan generator ───────────────────────────────────────────────────────

def _adapt_email_findings(findings: list[dict], domain: str) -> list[dict]:
    """Normalize email_security.py findings for finding_ingest.

    Confidence: SPF/DMARC/DKIM/MX findings are direct DNS-record-confirmed
    facts ("certain"). Lookalike-domain registration is DNS-confirmed too, but
    registration alone doesn't prove phishing intent ("medium"). A breach
    listing is a confirmed HIBP match ("high").
    """
    confidence_by_phase = {
        "spf": "certain", "dmarc": "certain", "dkim": "certain", "mx": "certain",
        "lookalikes": "medium", "breaches": "high",
    }
    adapted = []
    for f in findings:
        phase = f.get("phase", "")
        adapted.append({
            "title": f.get("title", "Email security finding"),
            "description": f.get("detail", ""),
            "severity": f.get("severity", "medium"),
            "category": f"email-{phase}",
            "affected_asset": domain,
            "evidence": {k: f[k] for k in ("raw_record", "selectors_found", "mx_records") if k in f},
            "remediation": get_remediation(title=f.get("title", "")),
            "confidence": confidence_by_phase.get(phase, "medium"),
        })
    return adapted


async def _run_email_scan(
    domain: str,
    check_lookalikes: bool,
    max_lookalikes: int,
    db: AsyncSession,
    org_id: str | None = None,
) -> AsyncGenerator[str, None]:
    scan_id = str(_uuid_mod.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    all_findings: list[dict] = []

    yield _sse("start", {"domain": domain, "scan_id": scan_id})

    loop = asyncio.get_event_loop()

    # ── Phase 1: SPF ──────────────────────────────────────────────────────────
    yield _sse("phase", {"phase": "spf", "message": f"Analysing SPF record for {domain}..."})
    try:
        spf_findings, spf_detail = await loop.run_in_executor(None, _analyse_spf, domain)
        for f in spf_findings:
            f["raw_record"] = spf_detail.get("record")
        all_findings.extend(spf_findings)
        for f in spf_findings:
            yield _sse("finding", f)
        yield _sse("phase_result", {"phase": "spf", "detail": spf_detail, "count": len(spf_findings)})
    except Exception as e:
        yield _sse("phase_result", {"phase": "spf", "error": str(e)[:120]})

    # ── Phase 2: DMARC ────────────────────────────────────────────────────────
    yield _sse("phase", {"phase": "dmarc", "message": f"Analysing DMARC record for _dmarc.{domain}..."})
    try:
        dmarc_findings, dmarc_detail = await loop.run_in_executor(None, _analyse_dmarc, domain)
        for f in dmarc_findings:
            f["raw_record"] = dmarc_detail.get("record")
        all_findings.extend(dmarc_findings)
        for f in dmarc_findings:
            yield _sse("finding", f)
        yield _sse("phase_result", {"phase": "dmarc", "detail": dmarc_detail, "count": len(dmarc_findings)})
    except Exception as e:
        yield _sse("phase_result", {"phase": "dmarc", "error": str(e)[:120]})

    # ── Phase 3: DKIM ────────────────────────────────────────────────────────
    yield _sse("phase", {"phase": "dkim", "message": "Checking common DKIM selectors..."})
    try:
        dkim_findings, dkim_detail = await loop.run_in_executor(None, _analyse_dkim, domain)
        for f in dkim_findings:
            f["selectors_found"] = dkim_detail.get("selectors_found")
        all_findings.extend(dkim_findings)
        for f in dkim_findings:
            yield _sse("finding", f)
        yield _sse("phase_result", {"phase": "dkim", "detail": dkim_detail, "count": len(dkim_findings)})
    except Exception as e:
        yield _sse("phase_result", {"phase": "dkim", "error": str(e)[:120]})

    # ── Phase 4: MX ──────────────────────────────────────────────────────────
    yield _sse("phase", {"phase": "mx", "message": f"Analysing MX records and SMTP capabilities for {domain}..."})
    try:
        mx_findings, mx_detail = await loop.run_in_executor(None, _analyse_mx, domain)
        for f in mx_findings:
            f["mx_records"] = mx_detail.get("mx_records")
        all_findings.extend(mx_findings)
        for f in mx_findings:
            yield _sse("finding", f)
        yield _sse("phase_result", {"phase": "mx", "detail": mx_detail, "count": len(mx_findings)})
    except Exception as e:
        yield _sse("phase_result", {"phase": "mx", "error": str(e)[:120]})

    # ── Phase 5: Lookalike domains ────────────────────────────────────────────
    lookalike_results: list[dict] = []
    if check_lookalikes:
        yield _sse("phase", {"phase": "lookalikes", "message": "Generating and checking lookalike domains..."})
        candidates = generate_lookalikes(domain, max_lookalikes)
        yield _sse("phase", {"phase": "lookalikes", "message": f"Checking {len(candidates)} lookalike domains..."})
        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (AttackTrace Email Security Scanner)"},
        ) as client:
            # Check in batches of 10 to avoid overwhelming DNS
            batch_size = 10
            for i in range(0, len(candidates), batch_size):
                batch = candidates[i:i + batch_size]
                tasks = [_check_lookalike(lk, client) for lk in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, dict):
                        lookalike_results.append(result)
                        finding = {
                            "phase": "lookalikes",
                            "severity": result["severity"],
                            "title": f"Lookalike domain registered: {result['domain']}",
                            "detail": result["detail"],
                        }
                        all_findings.append(finding)
                        yield _sse("finding", finding)
                        yield _sse("lookalike_found", result)
        yield _sse("phase_result", {
            "phase": "lookalikes",
            "detail": {"candidates_checked": len(candidates), "registered": len(lookalike_results)},
            "count": len(lookalike_results),
        })

    # ── Phase 6: Breach check ─────────────────────────────────────────────────
    yield _sse("phase", {"phase": "breaches", "message": f"Checking HaveIBeenPwned for domain breaches..."})
    breach_findings: list[dict] = []
    try:
        async with httpx.AsyncClient(
            timeout=10,
            headers={
                "User-Agent": "AttackTrace-Email-Security-Scanner",
                "hibp-api-key": "",  # public endpoint — no key needed for domain search v2
            },
        ) as client:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v2/breachedaccount/{domain}",
                timeout=10,
            )
            if resp.status_code == 200:
                breaches = resp.json()
                if isinstance(breaches, list):
                    for breach in breaches:
                        name = breach.get("Name", "Unknown")
                        date = breach.get("BreachDate", "Unknown")
                        count = breach.get("PwnCount", 0)
                        f = {
                            "phase": "breaches",
                            "severity": "high",
                            "title": f"Domain found in breach: {name} ({date})",
                            "detail": f"{count:,} accounts affected in the '{name}' breach on {date}.",
                        }
                        breach_findings.append(f)
                        all_findings.append(f)
                        yield _sse("finding", f)
            elif resp.status_code == 404:
                pass  # no breaches — good
    except Exception:
        pass  # HIBP may be unreachable; skip silently

    if not breach_findings:
        info_f = {
            "phase": "breaches",
            "severity": "info",
            "title": "No domain breaches found in HIBP",
            "detail": f"Domain {domain} was not found in any HaveIBeenPwned breach records.",
        }
        all_findings.append(info_f)
        yield _sse("finding", info_f)

    yield _sse("phase_result", {
        "phase": "breaches",
        "detail": {"breaches_found": len(breach_findings)},
        "count": len(breach_findings),
    })

    # ── Score + summary ───────────────────────────────────────────────────────
    score = _compute_score(all_findings)
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_phase: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        if sev in by_severity:
            by_severity[sev] += 1
        phase = f.get("phase", "unknown")
        by_phase[phase] = by_phase.get(phase, 0) + 1

    complete_payload = {
        "scan_id": scan_id,
        "domain": domain,
        "score": score,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "by_phase": by_phase,
        "lookalikes_found": len(lookalike_results),
    }
    yield _sse("complete", complete_payload)

    # Persist
    if org_id:
        _save_scan_result(org_id, {
            "id":            scan_id,
            "domain":        domain,
            "started_at":    started_at,
            "completed_at":  datetime.now(timezone.utc).isoformat(),
            "score":         score,
            "total_findings": len(all_findings),
            "by_severity":   by_severity,
            "by_phase":      by_phase,
            "findings":      all_findings,
            "lookalikes":    lookalike_results,
        })
        try:
            adapted = _adapt_email_findings(all_findings, domain)
            await ingest_findings(db, org_id, source="email_security", source_scan_id=scan_id, findings=adapted)
            await db.commit()
            await invalidate_dashboard_cache(org_id)
        except Exception:
            await db.rollback()


# ── Request model ─────────────────────────────────────────────────────────────

class EmailSecurityScanRequest(BaseModel):
    domain: str
    check_lookalikes: bool = True
    max_lookalikes: int = 50


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/scan", summary="Analyse email security posture of a domain")
async def run_email_scan(
    payload: EmailSecurityScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    domain = payload.domain.strip().lower().lstrip("https://").lstrip("http://").rstrip("/")
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="domain is required",
        )
    return StreamingResponse(
        _run_email_scan(
            domain=domain,
            check_lookalikes=payload.check_lookalikes,
            max_lookalikes=min(payload.max_lookalikes, 200),
            db=db,
            org_id=str(org_id),
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/history", summary="List previous email security scans for this org")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    limit: int = 50,
) -> dict:
    records = _load_history(str(org_id), limit=limit)
    items = []
    for r in records:
        items.append({
            "id":             r["id"],
            "domain":         r["domain"],
            "started_at":     r.get("started_at"),
            "completed_at":   r.get("completed_at"),
            "score":          r.get("score", 0),
            "total_findings": r.get("total_findings", 0),
            "by_severity":    r.get("by_severity", {}),
            "lookalikes_found": r.get("lookalikes_found", 0) if "lookalikes_found" in r else len(r.get("lookalikes", [])),
        })
    return {"items": items, "total": len(items)}


@router.get("/history/{scan_id}", summary="Get full details of a previous email security scan")
async def get_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a previous email security scan record")
async def delete_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    if not _delete_scan(str(org_id), scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}
