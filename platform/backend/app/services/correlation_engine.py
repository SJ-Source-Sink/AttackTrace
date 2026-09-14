"""
Cross-scanner correlation engine.

AttackTrace has ~40 independent scanners that each report findings in
isolation — a subdomain-takeover candidate from `takeover.py`, an open
database port from `nmap.py` (stored on `Asset.metadata_`, not a Finding),
an exposed credential from `secrets.py`, a KEV-flagged CVE from the
enrichment pipeline — with no mechanism that looks across them for the same
asset. Two or three individually medium-severity signals on the same host
are often a genuine, higher-confidence attack path (e.g. a dangling CNAME
takeover candidate PLUS a live admin port on that same host is materially
worse than either fact alone) — this module finds those combinations and
synthesizes a new, clearly-labeled "compound finding" that always cites the
real underlying Finding rows it was derived from (`correlated_finding_ids`),
never asserting anything the constituent evidence doesn't support. This is
the same false-positive-gate discipline `app.core.finding_confidence` already
enforces for the AI agent, applied to correlation instead of AI-reported
oracles.

Design note (see the 2026-09-14 research pass in CLAUDE.md): the "attack
path" literature converges on a property graph (nodes=assets, edges=
relationships) for anything more elaborate than this. AttackTrace's existing
schema (`Finding` + `Asset.metadata_` JSONB) is deliberately reused as-is
rather than introducing a graph store — the rule table below groups findings
by `asset_id`/hostname and reads `Asset.metadata_` directly for enrichment
context (open ports, from nmap). This handles every rule worth shipping
today; a real edge table only becomes worth the schema/migration cost once
rules need to reason about MULTI-HOP paths (asset A trusts asset B trusts
asset C) rather than single-asset signal co-occurrence.

Entry point: `run_correlation(db, org_id)`, invoked both after every scan
completes (`app.workers.scan_worker`) and on a periodic Celery Beat pass
(`app.workers.correlation_worker`) so correlations also form across findings
discovered by different scans/tools run at different times, not just within
one scan's batch.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dedup import compute_dedup_hash
from app.core.remediation import get_remediation
from app.models.db.asset import Asset
from app.models.db.finding import Finding, FindingSeverity, FindingStatus
from app.services.notification_service import dispatch_notifications

logger = logging.getLogger(__name__)

SOURCE = "correlation_engine"
_NOTIFY_SEVERITIES = (FindingSeverity.CRITICAL, FindingSeverity.HIGH)

_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 4, FindingSeverity.HIGH: 3,
    FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 1, FindingSeverity.INFO: 0,
}

_SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 1433: "MSSQL", 5984: "CouchDB",
    9092: "Kafka", 11211: "Memcached", 2375: "Docker API",
}
_ADMIN_PORTS = {22, 3389, 8080, 8443, 9090, 10000, 2375, 2376}


@dataclass
class _AssetGroup:
    asset: Optional[Asset]
    findings: list[Finding] = field(default_factory=list)


def _open_ports(asset: Optional[Asset]) -> list[dict]:
    if asset is None or not asset.metadata_:
        return []
    ports = asset.metadata_.get("ports") or []
    return ports if isinstance(ports, list) else []


def _has_category_containing(findings: list[Finding], *keywords: str) -> list[Finding]:
    kws = [k.lower() for k in keywords]
    return [f for f in findings if any(k in (f.category or "").lower() for k in kws)]


def _finding_ref(f: Finding) -> str:
    return f"{f.title} ({f.severity.value}, {f.source})"


# --- Rules ------------------------------------------------------------
# Each rule takes an asset group and returns a compound-finding spec dict
# (title, description, severity, category, remediation_category,
# constituent findings) or None if it doesn't fire. Rules are intentionally
# simple, hand-written pattern matches over real category/evidence shapes
# already produced by this codebase's scanners — not ML, matching what even
# mature commercial exposure-management tools actually ship as a starting
# rule set (per the research pass, ~10-20 hand-written rules is standard).

def _rule_takeover_plus_exposed_service(group: _AssetGroup) -> Optional[dict]:
    takeovers = _has_category_containing(group.findings, "takeover")
    if not takeovers:
        return None
    ports = _open_ports(group.asset)
    sensitive = [p for p in ports if p.get("port") in _SENSITIVE_PORTS or p.get("port") in _ADMIN_PORTS]
    if not sensitive:
        return None
    port_list = ", ".join(f"{p['port']}/{p.get('service') or _SENSITIVE_PORTS.get(p['port'], '?')}" for p in sensitive[:5])
    return {
        "title": f"Subdomain takeover candidate with exposed sensitive service on {group.asset.value}",
        "description": (
            f"{group.asset.value} was flagged as a subdomain-takeover candidate AND has "
            f"live, reachable sensitive service(s) on it ({port_list}). A takeover of this "
            f"host would grant an attacker direct access to those services, not just "
            f"defacement/phishing capability — this materially raises real-world impact "
            f"over either finding alone."
        ),
        "severity": FindingSeverity.CRITICAL,
        "category": "correlated-takeover-exposure",
        "constituents": takeovers,
        "affected_asset": group.asset.value,
    }


def _rule_secret_on_reachable_host(group: _AssetGroup) -> Optional[dict]:
    """Deliberately requires a SENSITIVE/admin port, not just any open port —
    virtually every web asset has 80/443 open, so gating on "any port" would
    fire on nearly 100% of secret findings and add no signal. The genuinely
    useful correlation is a secret plus a live service the secret could
    plausibly grant direct access to (DB, admin panel, SSH/RDP)."""
    secrets = _has_category_containing(group.findings, "exposed_secret", "secrets")
    if not secrets:
        return None
    ports = _open_ports(group.asset)
    sensitive = [p for p in ports if p.get("port") in _SENSITIVE_PORTS or p.get("port") in _ADMIN_PORTS]
    if not sensitive:
        return None
    port_list = ", ".join(f"{p['port']}/{p.get('service') or _SENSITIVE_PORTS.get(p['port'], '?')}" for p in sensitive[:5])
    return {
        "title": f"Exposed credential/secret on a host with a live sensitive service: {group.asset.value}",
        "description": (
            f"A credential/secret was discovered associated with {group.asset.value}, and "
            f"that same host has a live, reachable sensitive service ({port_list}) the "
            f"credential could plausibly grant direct access to. This should be treated as "
            f"immediately actionable by an attacker, not just a hygiene issue — rotate the "
            f"credential and confirm whether it was actually used against that service."
        ),
        "severity": FindingSeverity.CRITICAL,
        "category": "correlated-secret-exposure",
        "constituents": secrets,
        "affected_asset": group.asset.value,
    }


def _rule_kev_on_admin_exposed_host(group: _AssetGroup) -> Optional[dict]:
    kev_findings = [f for f in group.findings if f.kev_status]
    if not kev_findings:
        return None
    ports = _open_ports(group.asset)
    admin = [p for p in ports if p.get("port") in _ADMIN_PORTS]
    if not admin:
        return None
    return {
        "title": f"CISA KEV-listed vulnerability on an administratively-exposed host: {group.asset.value}",
        "description": (
            f"{group.asset.value} has a finding for a vulnerability on CISA's Known "
            f"Exploited Vulnerabilities list (actively exploited in the wild right now) "
            f"AND has an administrative/management port reachable "
            f"({', '.join(str(p['port']) for p in admin[:5])}). This combination — a known-"
            f"weaponized flaw plus direct admin-surface exposure — should be treated as an "
            f"immediate priority ahead of other CRITICAL findings without this combination."
        ),
        "severity": FindingSeverity.CRITICAL,
        "category": "correlated-kev-admin-exposure",
        "constituents": kev_findings,
        "affected_asset": group.asset.value,
    }


def _rule_ai_bypass_plus_api_surface(group: _AssetGroup) -> Optional[dict]:
    ai_findings = _has_category_containing(group.findings, "jailbreak", "prompt injection", "access control")
    api_findings = _has_category_containing(group.findings, "api1", "api2", "api3", "api4", "api5",
                                             "api6", "api7", "api8", "api9", "api10")
    if not ai_findings or not api_findings:
        return None
    return {
        "title": f"AI/LLM guardrail bypass reachable via an exposed API surface: {group.asset.value}",
        "description": (
            f"{group.asset.value} has both a confirmed LLM guardrail bypass (jailbreak/"
            f"prompt-injection/access-control failure) and a separate API security "
            f"misconfiguration (OWASP API Top-10 finding). An attacker with API-level "
            f"access combined with the ability to manipulate the model's behavior is a "
            f"materially different, higher-impact scenario than either finding assessed "
            f"in isolation — e.g. using the API weakness to reach the model, then the "
            f"jailbreak to exfiltrate data the model shouldn't disclose."
        ),
        "severity": FindingSeverity.CRITICAL,
        "category": "correlated-ai-api-chain",
        "constituents": ai_findings + api_findings,
        "affected_asset": group.asset.value,
    }


def _rule_injection_on_cloud_asset(group: _AssetGroup) -> Optional[dict]:
    if group.asset is None or group.asset.asset_type.value != "cloud":
        return None
    injection = _has_category_containing(
        group.findings, "ssrf", "injection", "sqli", "attack-suite", "attack_suite"
    )
    if not injection:
        return None
    return {
        "title": f"Injection/SSRF-class finding on a cloud-hosted asset: {group.asset.value}",
        "description": (
            f"{group.asset.value} is a discovered cloud resource with a confirmed "
            f"injection/SSRF-class finding. On cloud infrastructure this class of bug "
            f"routinely escalates to cloud credential theft via the instance metadata "
            f"service (e.g. 169.254.169.254) — treat as a potential cloud-account "
            f"compromise path, not just an application-layer bug, until ruled out."
        ),
        "severity": FindingSeverity.CRITICAL,
        "category": "correlated-cloud-injection",
        "constituents": injection,
        "affected_asset": group.asset.value,
    }


def _rule_convergent_risk(group: _AssetGroup) -> Optional[dict]:
    """Softer, asset-level aggregation rule: 3+ independent HIGH-or-worse
    findings (from different sources, so it's not just one noisy scanner)
    on the same asset — worth flagging for prioritization even without a
    specific exploit-chain narrative."""
    high_plus = [f for f in group.findings if _SEVERITY_RANK.get(f.severity, 0) >= 3]
    distinct_sources = {f.source for f in high_plus}
    if len(high_plus) < 3 or len(distinct_sources) < 2:
        return None
    return {
        "title": f"Convergent risk: {len(high_plus)} independent high-severity findings on {group.asset.value}",
        "description": (
            f"{group.asset.value} has {len(high_plus)} independent CRITICAL/HIGH findings "
            f"from {len(distinct_sources)} different scanners/tools ({', '.join(sorted(distinct_sources))}). "
            f"A single asset accumulating this many independent high-severity issues is "
            f"itself a signal worth prioritizing — it suggests either a systemically "
            f"under-maintained host or a genuinely high-value target worth an attacker's "
            f"extra effort."
        ),
        "severity": FindingSeverity.HIGH,
        "category": "correlated-convergent-risk",
        "constituents": high_plus,
        "affected_asset": group.asset.value,
    }


_RULES: list[Callable[[_AssetGroup], Optional[dict]]] = [
    _rule_takeover_plus_exposed_service,
    _rule_secret_on_reachable_host,
    _rule_kev_on_admin_exposed_host,
    _rule_ai_bypass_plus_api_surface,
    _rule_injection_on_cloud_asset,
    _rule_convergent_risk,
]


async def run_correlation(db: AsyncSession, org_id: UUID | str) -> dict:
    """Run all correlation rules for one org's current open findings.
    Idempotent: re-running with the same underlying findings produces the
    same dedup_hash and upserts rather than duplicating. Does not commit —
    caller commits (matching app.services.finding_ingest's convention)."""
    findings = (
        await db.execute(
            select(Finding).where(
                Finding.org_id == org_id,
                Finding.status == FindingStatus.OPEN,
                Finding.suppressed.is_(False),
                Finding.false_positive.is_(False),
                Finding.source != SOURCE,
            )
        )
    ).scalars().all()

    if not findings:
        return {"status": "no_findings", "created": 0, "updated": 0}

    asset_ids = {f.asset_id for f in findings if f.asset_id}
    assets_by_id: dict[UUID, Asset] = {}
    if asset_ids:
        rows = (await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))).scalars().all()
        assets_by_id = {a.id: a for a in rows}

    groups: dict[str, _AssetGroup] = {}
    for f in findings:
        if not f.asset_id or f.asset_id not in assets_by_id:
            continue  # rules below all need real Asset context (ports/type) — skip unlinked findings
        key = str(f.asset_id)
        if key not in groups:
            groups[key] = _AssetGroup(asset=assets_by_id[f.asset_id])
        groups[key].findings.append(f)

    created = 0
    updated = 0
    newly_created_critical_high: list[Finding] = []

    for group in groups.values():
        # No blanket "needs 2+ findings" gate here — several rules combine
        # just ONE Finding with Asset-level context (e.g. a takeover finding
        # plus Asset.metadata_.ports), which is a real 1-Finding co-occurrence,
        # not a single isolated signal. Each rule enforces its own actual
        # trigger condition (see e.g. _rule_convergent_risk's explicit 3+
        # check) rather than a one-size-fits-all count here.
        for rule in _RULES:
            try:
                spec = rule(group)
            except Exception as exc:
                logger.warning(f"Correlation rule {rule.__name__} raised: {exc}")
                continue
            if not spec:
                continue

            constituents: list[Finding] = spec["constituents"]
            constituent_ids = sorted(str(f.id) for f in constituents)
            dedup = compute_dedup_hash(org_id, spec["title"], spec["affected_asset"], [])

            existing = (
                await db.execute(select(Finding).where(Finding.org_id == org_id, Finding.dedup_hash == dedup))
            ).scalar_one_or_none()

            remediation = get_remediation(spec["category"], spec["title"]) or (
                "Review and remediate each underlying finding listed below; this compound "
                "finding exists because their combination raises real-world risk beyond any "
                "one of them individually."
            )
            evidence = {
                "rule": rule.__name__,
                "constituent_findings": [_finding_ref(f) for f in constituents],
                "constituent_finding_ids": constituent_ids,
            }

            if existing is None:
                new_finding = Finding(
                    org_id=org_id,
                    scan_job_id=None,
                    source=SOURCE,
                    source_scan_id=None,
                    title=spec["title"],
                    description=spec["description"],
                    severity=spec["severity"],
                    category=spec["category"],
                    affected_asset=spec["affected_asset"],
                    evidence=evidence,
                    remediation=remediation,
                    references=[],
                    cve=[],
                    status=FindingStatus.OPEN,
                    confidence="high",
                    correlated_finding_ids=constituent_ids,
                    dedup_hash=dedup,
                )
                db.add(new_finding)
                created += 1
                if spec["severity"] in _NOTIFY_SEVERITIES:
                    newly_created_critical_high.append(new_finding)
            else:
                if existing.correlated_finding_ids != constituent_ids:
                    existing.correlated_finding_ids = constituent_ids
                    existing.evidence = evidence
                    updated += 1

    if newly_created_critical_high:
        try:
            await db.flush()
            for nf in newly_created_critical_high:
                try:
                    await dispatch_notifications(
                        org_id=str(org_id),
                        event_type="finding.critical",
                        payload={
                            "finding_id": str(nf.id),
                            "scan_id": "",
                            "org_id": str(org_id),
                            "title": nf.title,
                            "severity": nf.severity.value,
                            "affected_asset": nf.affected_asset or "",
                        },
                        db_session=db,
                    )
                except Exception as exc:
                    logger.warning(f"Correlation engine: dispatch_notifications failed for finding {nf.id}: {exc}")
        except Exception as exc:
            logger.warning(f"Correlation engine: notification dispatch setup failed: {exc}")

    logger.info(f"Correlation engine for org {org_id}: {created} created, {updated} updated")
    return {"status": "completed", "created": created, "updated": updated, "asset_groups_considered": len(groups)}
