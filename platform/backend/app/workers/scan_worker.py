"""
Celery scan worker task.

Runs the AttackTrace orchestrator in a subprocess thread, publishes progress events
to Redis pub/sub for SSE streaming, and persists results to the database.
"""

import asyncio
import hashlib
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from app.workers.celery_app import celery_app
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Track running subprocess PIDs so they can be cleaned up on SIGTERM
_running_pids: dict[str, int] = {}  # scan_id -> subprocess PID


def _handle_sigterm(signum, frame):
    """Gracefully kill any running scan subprocesses on worker shutdown."""
    for scan_id, pid in list(_running_pids.items()):
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent SIGTERM to scan subprocess PID {pid} (scan {scan_id})")
        except ProcessLookupError:
            pass
    # Re-raise to let Celery handle shutdown
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGTERM)


signal.signal(signal.SIGTERM, _handle_sigterm)

# Ensure AttackTrace root is on sys.path (repo root, 5 levels up from this file)
_ATTACKTRACE_ROOT = Path(__file__).parents[5]
if str(_ATTACKTRACE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ATTACKTRACE_ROOT))


# --- Sync DB session for Celery workers ---

def _get_sync_engine():
    db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    from sqlalchemy import create_engine
    return create_engine(db_url, pool_pre_ping=True, pool_size=3)


def _get_session_factory(engine):
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(bind=engine, expire_on_commit=False)


# --- Redis publisher ---

def _get_sync_redis():
    import redis
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


def _publish_event(r, scan_id: str, event_type: str, data: dict) -> None:
    payload = json.dumps({
        "event_type": event_type,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    })
    try:
        r.publish(f"scan:{scan_id}", payload)
        # Persist structural events (not findings) in a replay list so clients that
        # navigate away and come back can catch up without seeing a false restart.
        # TTL 24 h — enough to cover any reasonable scan duration.
        if event_type != "finding":
            replay_key = f"scan:{scan_id}:events"
            r.rpush(replay_key, payload)
            r.expire(replay_key, 86_400)
    except Exception as e:
        logger.warning(f"Failed to publish event to Redis: {e}")


# --- AttackTrace module registration (mirrors cli.py _register_modules) ---

def _register_modules(orchestrator) -> None:
    """Register all AttackTrace discovery modules with the orchestrator."""
    from attacktrace.modules.domain.subdomain_enum import run as subdomain_run
    from attacktrace.modules.domain.dns_resolver import run as dns_run
    from attacktrace.modules.infrastructure.port_scanner import run as port_scan_run
    from attacktrace.modules.cloud.cloud_enum import run as cloud_enum_run
    from attacktrace.correlation.correlator import run as correlator_run

    orchestrator.register_module("seed", _combined_seed_module)
    orchestrator.register_module("domain", subdomain_run)
    orchestrator.register_module("dns", dns_run)
    orchestrator.register_module("infrastructure", port_scan_run)
    orchestrator.register_module("enrichment", _combined_enrichment_module)
    orchestrator.register_module("intel", _combined_intel_module)
    orchestrator.register_module("osint", _combined_osint_module)
    orchestrator.register_module("web", _combined_web_module)
    orchestrator.register_module("cloud", cloud_enum_run)
    orchestrator.register_module("correlation", correlator_run)


async def _combined_seed_module(session, config, orchestrator):
    from attacktrace.modules.seed.cert_transparency import run as cert_run
    from attacktrace.modules.seed.whois_lookup import run as whois_run
    from attacktrace.modules.seed.asn_discovery import run as asn_run
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="seed")

    whois_result = await whois_run(session, config, orchestrator)
    if whois_result:
        result.domains.extend(whois_result.domains)

    cert_result = await cert_run(session, config, orchestrator)
    if cert_result:
        result.subdomains.extend(cert_result.subdomains)
        result.certificates.extend(cert_result.certificates)

    asn_result = await asn_run(session, config, orchestrator)
    if asn_result:
        result.ip_addresses.extend(asn_result.ip_addresses)
        result.findings.extend(asn_result.findings)

    # Email security checks (DNS-based, always safe to run)
    try:
        from attacktrace.modules.seed.email_security import run as email_security_run
        email_result = await email_security_run(session, config, orchestrator)
        if email_result:
            result.findings.extend(email_result.findings)
    except Exception as e:
        logger.warning(f"Email security module skipped: {e}")

    result.items_discovered = len(result.domains) + len(result.subdomains) + len(result.ip_addresses)
    return result


async def _combined_enrichment_module(session, config, orchestrator):
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="enrichment")

    if config.api_keys.shodan:
        try:
            from attacktrace.modules.enrichment.shodan_client import run as shodan_run
            shodan_result = await shodan_run(session, config, orchestrator)
            if shodan_result:
                result.ip_addresses.extend(shodan_result.ip_addresses)
                result.findings.extend(shodan_result.findings)
        except Exception as e:
            logger.warning(f"Shodan enrichment failed: {e}")

    if config.api_keys.censys_id and config.api_keys.censys_secret:
        try:
            from attacktrace.modules.enrichment.censys_client import run as censys_run
            censys_result = await censys_run(session, config, orchestrator)
            if censys_result:
                result.ip_addresses.extend(censys_result.ip_addresses)
                result.certificates.extend(censys_result.certificates)
                result.findings.extend(censys_result.findings)
        except Exception as e:
            logger.warning(f"Censys enrichment failed: {e}")

    if config.api_keys.securitytrails:
        try:
            from attacktrace.modules.enrichment.securitytrails_client import run as st_run
            st_result = await st_run(session, config, orchestrator)
            if st_result:
                result.domains.extend(st_result.domains)
                result.subdomains.extend(st_result.subdomains)
                result.ip_addresses.extend(st_result.ip_addresses)
        except Exception as e:
            logger.warning(f"SecurityTrails enrichment failed: {e}")

    result.items_discovered = len(result.ip_addresses) + len(result.subdomains)
    return result


async def _combined_intel_module(session, config, orchestrator):
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="intel")

    for name, coro_factory in [
        ("shodan_internetdb", lambda: __import__("attacktrace.modules.intel.shodan_internetdb", fromlist=["run"]).run),
        ("wayback", lambda: __import__("attacktrace.modules.intel.wayback", fromlist=["run"]).run),
        ("alienvault_otx", lambda: __import__("attacktrace.modules.intel.alienvault_otx", fromlist=["run"]).run),
        ("greynoise", lambda: __import__("attacktrace.modules.intel.greynoise", fromlist=["run"]).run),
        ("builtwith", lambda: __import__("attacktrace.modules.intel.builtwith", fromlist=["run"]).run),
    ]:
        try:
            run_fn = coro_factory()
            r = await run_fn(session, config, orchestrator)
            if r:
                result.findings.extend(r.findings)
                result.items_discovered += r.items_discovered
        except Exception as e:
            logger.debug(f"Intel module {name} skipped: {e}")

    if config.api_keys.urlscan:
        try:
            from attacktrace.modules.intel.urlscan import run as urlscan_run
            r = await urlscan_run(session, config, orchestrator)
            if r:
                result.findings.extend(r.findings)
                result.items_discovered += r.items_discovered
        except Exception as e:
            logger.debug(f"urlscan skipped: {e}")

    if config.api_keys.ipinfo:
        try:
            from attacktrace.modules.intel.ipinfo import run as ipinfo_run
            r = await ipinfo_run(session, config, orchestrator)
            if r:
                result.findings.extend(r.findings)
                result.items_discovered += r.items_discovered
        except Exception as e:
            logger.debug(f"ipinfo skipped: {e}")

    if config.api_keys.chaos:
        try:
            from attacktrace.modules.intel.chaos_projectdiscovery import run as chaos_run
            r = await chaos_run(session, config, orchestrator)
            if r:
                result.subdomains.extend(r.subdomains)
                result.findings.extend(r.findings)
                result.items_discovered += r.items_discovered
        except Exception as e:
            logger.debug(f"chaos skipped: {e}")

    if config.api_keys.passivetotal:
        try:
            from attacktrace.modules.intel.passivetotal import run as pt_run
            r = await pt_run(session, config, orchestrator)
            if r:
                result.subdomains.extend(r.subdomains)
                result.findings.extend(r.findings)
                result.items_discovered += r.items_discovered
        except Exception as e:
            logger.debug(f"passivetotal skipped: {e}")

    if config.api_keys.hibp or config.api_keys.dehashed or config.api_keys.leakcheck:
        try:
            from attacktrace.modules.intel.breach_check import run as breach_run
            r = await breach_run(session, config, orchestrator)
            if r:
                result.findings.extend(r.findings)
                result.items_discovered += r.items_discovered
        except Exception as e:
            logger.debug(f"breach_check skipped: {e}")

    return result


async def _combined_osint_module(session, config, orchestrator):
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="osint")

    for name, mod_path in [
        ("github_recon", "attacktrace.modules.osint.github_recon"),
        ("employee_discovery", "attacktrace.modules.osint.employee_discovery"),
    ]:
        try:
            mod = __import__(mod_path, fromlist=["run"])
            r = await mod.run(session, config, orchestrator)
            if r:
                result.findings.extend(r.findings)
                result.items_discovered += r.items_discovered
        except Exception as e:
            logger.debug(f"OSINT module {name} skipped: {e}")

    return result


async def _combined_web_module(session, config, orchestrator):
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="web")

    try:
        from attacktrace.modules.web.http_prober import run as http_probe_run
        http_result = await http_probe_run(session, config, orchestrator)
        if http_result:
            result.web_applications.extend(http_result.web_applications)
            result.certificates.extend(http_result.certificates)
            result.findings.extend(http_result.findings)
    except Exception as e:
        logger.warning(f"HTTP probing failed: {e}")

    # Capture screenshots for live web apps using a proxy session so we don't
    # dirty the orchestrator's session.web_applications (which causes duplicates
    # when the orchestrator later merges result.web_applications into the session).
    if result.web_applications:
        try:
            from attacktrace.modules.web.screenshot import run as screenshot_run

            class _WebAppProxy:
                """Lightweight proxy that exposes web_applications for the screenshot module.
                Must carry session.id because screenshot.run() calls config.get_screenshots_dir(session.id).
                """
                def __init__(self, webapps, session_id):
                    self.web_applications = webapps
                    self.id = session_id

            proxy = _WebAppProxy(result.web_applications, session.id)
            await screenshot_run(proxy, config, orchestrator)
            captured = sum(1 for w in result.web_applications if getattr(w, "screenshot_path", ""))
            logger.info(f"Screenshots captured: {captured}/{len(result.web_applications)} web apps")
        except Exception as e:
            logger.warning(f"Screenshot capture failed: {e}")

    result.items_discovered = len(result.web_applications)
    result.success = True
    return result


# --- Asset/Finding persistence ---

def _compute_dedup_hash(org_id: UUID, title: str, affected_asset: str) -> str:
    """Compute a stable dedup hash for a finding (org + title + asset)."""
    key = f"{str(org_id)}|{title}|{affected_asset}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def _load_suppression_rules(db_session, org_id: UUID) -> list:
    """Load all active (non-expired) suppression rules for the org."""
    from app.models.db.suppression_rule import ScanSuppressionRule
    from sqlalchemy import select as sync_select, or_
    now = datetime.now(timezone.utc)
    try:
        rules = db_session.execute(
            sync_select(ScanSuppressionRule).where(
                ScanSuppressionRule.org_id == org_id,
                or_(
                    ScanSuppressionRule.expires_at == None,
                    ScanSuppressionRule.expires_at > now,
                ),
            )
        ).scalars().all()
        return list(rules)
    except Exception as e:
        logger.warning(f"Failed to load suppression rules: {e}")
        return []


def _matches_suppression_rule(finding_title: str, affected_asset: str, rules: list):
    """Return the first matching rule or None."""
    for rule in rules:
        if rule.finding_title == finding_title and rule.affected_asset_pattern == affected_asset:
            return rule
    return None


def _enrich_kev_epss(db_session, scan_job_id_str: str) -> None:
    """
    Enrich all findings for this scan that have CVEs with KEV/EPSS data.
    Runs synchronously using httpx. Called after _persist_session_results.
    """
    from app.models.db.finding import Finding as DBFinding
    from app.services.kev_epss_sync import load_kev, get_epss_sync, compute_priority_score
    from sqlalchemy import select as sync_select

    try:
        scan_uuid = UUID(scan_job_id_str)
    except ValueError:
        return

    try:
        kev_set = load_kev()

        findings_with_cves = db_session.execute(
            sync_select(DBFinding).where(
                DBFinding.scan_job_id == scan_uuid,
                DBFinding.cve != None,
            )
        ).scalars().all()

        enriched = 0
        for finding in findings_with_cves:
            cve_list = finding.cve or []
            if not cve_list:
                continue
            kev_status = any(cve in kev_set for cve in cve_list)
            epss_score = get_epss_sync(cve_list[0])
            priority = compute_priority_score(finding.cvss_score, epss_score, kev_status)
            finding.kev_status = kev_status
            finding.epss_score = epss_score
            finding.priority_score = priority
            db_session.add(finding)
            enriched += 1

        if enriched:
            db_session.flush()
            logger.info(f"KEV/EPSS enriched {enriched} findings for scan {scan_job_id_str}")
    except Exception as e:
        logger.warning(f"KEV/EPSS enrichment failed for scan {scan_job_id_str}: {e}")


def _persist_module_results_partial(
    db_session, scan_job_id_str: str, org_id: UUID, module_name: str, module_result
) -> None:
    """
    Persist results from a single module immediately after it completes.
    Idempotent: skips findings/assets that already exist for this scan+dedup_hash.
    """
    from app.models.db.asset import Asset, AssetType
    from app.models.db.finding import Finding as DBFinding, FindingSeverity, FindingStatus
    from app.models.db.suppression_rule import ScanSuppressionRule
    from sqlalchemy import select as sync_select

    try:
        scan_job_uuid = UUID(scan_job_id_str)
    except ValueError:
        return

    suppression_rules = _load_suppression_rules(db_session, org_id)

    try:
        # Persist domains
        for domain in getattr(module_result, "domains", []):
            try:
                db_session.add(Asset(
                    org_id=org_id,
                    scan_job_id=scan_job_uuid,
                    asset_type=AssetType.DOMAIN,
                    value=domain.fqdn,
                    metadata_={
                        "registrar": getattr(domain, "registrar", ""),
                        "source": getattr(domain, "source", module_name),
                        "module": module_name,
                    },
                ))
            except Exception as e:
                logger.debug(f"Partial persist domain skipped [{module_name}]: {e}")

        # Persist findings (with dedup check)
        for f in getattr(module_result, "findings", []):
            sev_value = f.severity.value if hasattr(f.severity, "value") else f.severity
            dedup_hash = _compute_dedup_hash(org_id, f.title, f.affected_asset)

            # Check for existing finding with same dedup hash
            existing = db_session.execute(
                sync_select(DBFinding).where(
                    DBFinding.org_id == org_id,
                    DBFinding.dedup_hash == dedup_hash,
                )
            ).scalar_one_or_none()

            if existing:
                logger.debug(f"Dedup skip (partial) [{module_name}]: {f.title} / {f.affected_asset}")
                continue

            # Check suppression rules
            matched_rule = _matches_suppression_rule(f.title, f.affected_asset, suppression_rules)

            try:
                new_finding = DBFinding(
                    org_id=org_id,
                    scan_job_id=scan_job_uuid,
                    title=(f.title or "")[:1000],
                    description=f.description,
                    severity=FindingSeverity(sev_value),
                    category=f.category,
                    affected_asset=(f.affected_asset or "")[:2000],
                    evidence={"raw": f.evidence} if isinstance(f.evidence, str) else (f.evidence or {}),
                    remediation=f.remediation,
                    references=getattr(f, "references", []) or [],
                    cve=f.cve or [],
                    cvss_score=f.cvss_score,
                    false_positive=f.false_positive,
                    status=FindingStatus.OPEN,
                    confidence=getattr(f, "confidence", "firm"),
                    dedup_hash=dedup_hash,
                )
                if matched_rule:
                    new_finding.suppressed = True
                    new_finding.suppressed_reason = f"Auto-suppressed by rule: {matched_rule.action}"
                    if matched_rule.action == "false_positive":
                        new_finding.status = FindingStatus.FALSE_POSITIVE
                        new_finding.false_positive = True
                    elif matched_rule.action == "accepted_risk":
                        new_finding.status = FindingStatus.ACCEPTED_RISK
                db_session.add(new_finding)
            except Exception as e:
                logger.warning(f"Partial persist finding failed [{module_name}]: {e}")

        db_session.flush()
        logger.debug(
            f"Partial persist: {module_name} → "
            f"{len(getattr(module_result, 'findings', []))} findings"
        )
    except Exception as e:
        logger.warning(f"Partial persist failed for module {module_name}: {e}")


def _persist_session_results(db_session, scan_job, attacktrace_session, org_id: UUID) -> tuple:
    from app.models.db.asset import Asset, AssetType
    from app.models.db.finding import Finding as DBFinding, FindingSeverity, FindingStatus
    from sqlalchemy import select as sync_select

    assets_created = 0
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Load suppression rules once for the whole session
    suppression_rules = _load_suppression_rules(db_session, org_id)

    for domain in attacktrace_session.domains:
        db_session.add(Asset(
            org_id=org_id,
            scan_job_id=scan_job.id,
            asset_type=AssetType.DOMAIN,
            value=domain.fqdn,
            metadata_={
                "registrar": domain.registrar,
                "registrant_org": domain.registrant_org,
                "name_servers": domain.name_servers,
                "tags": domain.tags,
                "source": domain.source,
            },
        ))
        assets_created += 1

    for subdomain in attacktrace_session.subdomains:
        db_session.add(Asset(
            org_id=org_id,
            scan_job_id=scan_job.id,
            asset_type=AssetType.SUBDOMAIN,
            value=subdomain.fqdn,
            metadata_={
                "parent_domain": subdomain.parent_domain,
                "resolved_ips": subdomain.resolved_ips,
                "is_alive": subdomain.is_alive,
                "http_status": subdomain.http_status,
                "source": subdomain.source,
            },
        ))
        assets_created += 1

    for ip in attacktrace_session.ip_addresses:
        db_session.add(Asset(
            org_id=org_id,
            scan_job_id=scan_job.id,
            asset_type=AssetType.IP,
            value=ip.address,
            metadata_={
                "asn": ip.asn,
                "asn_org": ip.asn_org,
                "cloud_provider": ip.cloud_provider.value if ip.cloud_provider else None,
                "geolocation": ip.geolocation.model_dump() if ip.geolocation else {},
                "reverse_dns": ip.reverse_dns,
                "source": ip.source,
            },
        ))
        assets_created += 1

    _workspace = Path(settings.ATTACKTRACE_WORKSPACE_DIR)
    for webapp in attacktrace_session.web_applications:
        screenshot_url = None
        if getattr(webapp, "screenshot_path", None):
            try:
                rel = Path(webapp.screenshot_path).relative_to(_workspace)
                screenshot_url = f"/static/screenshots/{rel}"
            except ValueError:
                pass
        db_session.add(Asset(
            org_id=org_id,
            scan_job_id=scan_job.id,
            asset_type=AssetType.WEBAPP,
            value=webapp.url,
            screenshot_url=screenshot_url,
            metadata_={
                "title": webapp.title,
                "status_code": webapp.status_code,
                "is_alive": webapp.is_alive,
                "source": webapp.source,
            },
        ))
        assets_created += 1

    for cloud in attacktrace_session.cloud_assets:
        db_session.add(Asset(
            org_id=org_id,
            scan_job_id=scan_job.id,
            asset_type=AssetType.CLOUD,
            value=cloud.url or cloud.name,
            metadata_={
                "provider": cloud.provider.value if cloud.provider else None,
                "asset_type": cloud.asset_type.value if cloud.asset_type else None,
                "name": cloud.name,
                "is_public": cloud.is_public,
                "source": cloud.source,
            },
        ))
        assets_created += 1

    for f in attacktrace_session.findings:
        sev_value = f.severity.value
        dedup_hash = _compute_dedup_hash(org_id, f.title, f.affected_asset)

        # Idempotent: skip if already persisted (e.g., by partial persist callback)
        existing = db_session.execute(
            sync_select(DBFinding).where(
                DBFinding.org_id == org_id,
                DBFinding.dedup_hash == dedup_hash,
                DBFinding.scan_job_id == scan_job.id,
            )
        ).scalar_one_or_none()

        if existing:
            # Still count it in findings_count
            findings_count[sev_value] = findings_count.get(sev_value, 0) + 1
            continue

        findings_count[sev_value] = findings_count.get(sev_value, 0) + 1

        # Check suppression rules
        matched_rule = _matches_suppression_rule(f.title, f.affected_asset, suppression_rules)

        try:
            new_finding = DBFinding(
                org_id=org_id,
                scan_job_id=scan_job.id,
                title=(f.title or "")[:1000],
                description=f.description,
                severity=FindingSeverity(sev_value),
                category=f.category,
                affected_asset=(f.affected_asset or "")[:2000],
                evidence={"raw": f.evidence} if isinstance(f.evidence, str) else (f.evidence or {}),
                remediation=f.remediation,
                references=getattr(f, "references", []) or [],
                cve=f.cve or [],
                cvss_score=f.cvss_score,
                false_positive=f.false_positive,
                status=FindingStatus.OPEN,
                confidence=getattr(f, "confidence", "firm"),
                dedup_hash=dedup_hash,
            )
            if matched_rule:
                new_finding.suppressed = True
                new_finding.suppressed_reason = f"Auto-suppressed by rule: {matched_rule.action}"
                if matched_rule.action == "false_positive":
                    new_finding.status = FindingStatus.FALSE_POSITIVE
                    new_finding.false_positive = True
                elif matched_rule.action == "accepted_risk":
                    new_finding.status = FindingStatus.ACCEPTED_RISK
            db_session.add(new_finding)
        except Exception as e:
            logger.error(f"Failed to persist finding '{f.title}': {e}")

    db_session.flush()

    attacktrace_session.update_statistics()
    results_summary = {
        "total_domains": attacktrace_session.total_domains,
        "total_subdomains": attacktrace_session.total_subdomains,
        "total_ips": attacktrace_session.total_ips,
        "total_web_apps": attacktrace_session.total_web_apps,
        "total_cloud_assets": attacktrace_session.total_cloud_assets,
        "total_assets": assets_created,
        "total_findings": sum(findings_count.values()),
    }
    return results_summary, findings_count


# --- AttackTrace config builder ---

def _build_attacktrace_config(job, creds=None):
    from attacktrace.config import AttackTraceConfig, APIKeys
    from app.core.security import decrypt_credential

    api_keys = APIKeys()

    if creds:
        _decrypt_pairs = [
            (creds.shodan_key_enc, "shodan", "shodan"),
            (creds.censys_id_enc, "censys_id", "censys_id"),
            (creds.censys_secret_enc, "censys_secret", "censys_secret"),
            (creds.securitytrails_key_enc, "securitytrails", "securitytrails"),
            (creds.github_token_enc, "github", "github"),
            (creds.alienvault_key_enc, "alienvault", "alienvault"),
            (creds.passivetotal_user_enc, "passivetotal_user", "passivetotal_user"),
            (creds.passivetotal_key_enc, "passivetotal", "passivetotal"),
        ]
        for enc_value, attr_name, label in _decrypt_pairs:
            if enc_value:
                try:
                    setattr(api_keys, attr_name, decrypt_credential(enc_value))
                except Exception as e:
                    logger.warning(f"Failed to decrypt credential '{label}': {e}")

    config = AttackTraceConfig(api_keys=api_keys)

    # Set output directory per org/job
    output_base = Path(settings.ATTACKTRACE_WORKSPACE_DIR) / str(job.org_id) / str(job.id)
    output_base.mkdir(parents=True, exist_ok=True)
    config.output.directory = str(output_base)
    config.output.screenshots_dir = str(output_base / "screenshots")

    return config


# --- Main Celery task ---

@celery_app.task(bind=True, max_retries=3, name="app.workers.scan_worker.run_scan")
def run_scan(self: Task, scan_job_id: str) -> dict:
    """Main Celery task: runs an AttackTrace scan and persists results."""
    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)
    r = _get_sync_redis()

    with SessionFactory() as db:
        from app.models.db.scan import ScanJob, ScanStatus as DBScanStatus
        from app.models.db.org import OrgCredentials
        from sqlalchemy import select as sync_select

        try:
            _scan_uuid = UUID(scan_job_id)
        except ValueError:
            logger.error(f"Invalid scan_job_id format: {scan_job_id!r}")
            return {"error": "invalid_scan_job_id"}

        job = db.get(ScanJob, _scan_uuid)
        if job is None:
            logger.error(f"ScanJob {scan_job_id} not found")
            return {"error": "scan_job_not_found"}

        if job.status in (DBScanStatus.CANCELLED, DBScanStatus.COMPLETED, DBScanStatus.FAILED):
            return {"status": job.status.value}

        job.status = DBScanStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        _publish_event(r, scan_job_id, "status_change", {"status": "running"})

        orchestrator = None
        try:
            # Load org credentials
            creds = db.execute(
                sync_select(OrgCredentials).where(OrgCredentials.org_id == job.org_id)
            ).scalar_one_or_none()

            # Build AttackTrace config
            attacktrace_config = _build_attacktrace_config(job, creds)

            # Create orchestrator
            from attacktrace.core.orchestrator import Orchestrator

            db_path = (
                Path(settings.ATTACKTRACE_WORKSPACE_DIR) / str(job.org_id) / f"{job.id}.db"
            )
            db_path.parent.mkdir(parents=True, exist_ok=True)

            orchestrator = Orchestrator(config=attacktrace_config, db_path=db_path)

            # Register all modules
            _register_modules(orchestrator)

            # Create session
            intensity = job.intensity.value
            passive_only = intensity == "passive"
            modules_to_skip = set(job.modules_to_skip or [])
            modules_to_run = [m for m in orchestrator.MODULE_ORDER if m not in modules_to_skip]

            attacktrace_session = orchestrator.create_session(
                company=job.company_name or "",
                domains=job.target_domains,
                passive_only=passive_only,
                intensity=intensity,
                modules=modules_to_run,
            )

            job.session_id = attacktrace_session.id
            db.commit()

            # Wire SSE callbacks
            def on_module_start(module_name: str) -> None:
                _publish_event(r, scan_job_id, "module_start", {"module": module_name})

            def on_module_complete(module_name: str, result) -> None:
                # Partial persist: write this module's results immediately
                try:
                    _persist_module_results_partial(
                        db, scan_job_id, job.org_id, module_name, result
                    )
                    db.commit()
                except Exception as _partial_err:
                    logger.warning(f"Partial persist commit failed [{module_name}]: {_partial_err}")
                    try:
                        db.rollback()
                    except Exception:
                        pass

                _publish_event(r, scan_job_id, "module_complete", {
                    "module": module_name,
                    "success": result.success,
                    "items_discovered": result.items_discovered,
                    "error": result.error_message if not result.success else None,
                })

            def on_finding(finding) -> None:
                _publish_event(r, scan_job_id, "finding", {
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "affected_asset": finding.affected_asset,
                })

            orchestrator.on_module_start(on_module_start)
            orchestrator.on_module_complete(on_module_complete)
            orchestrator.on_finding(on_finding)

            # Run the pipeline
            completed_session = asyncio.run(orchestrator.run())

            # Persist results (final pass — idempotent, skips already-persisted)
            results_summary, findings_count = _persist_session_results(
                db, job, completed_session, job.org_id
            )

            # KEV/EPSS enrichment for findings with CVEs
            try:
                _enrich_kev_epss(db, scan_job_id)
            except Exception as _kev_err:
                logger.warning(f"KEV/EPSS enrichment skipped: {_kev_err}")

            job.status = DBScanStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.results_summary = results_summary
            job.findings_count = findings_count
            db.commit()

            _publish_event(r, scan_job_id, "status_change", {
                "status": "completed",
                "findings_count": findings_count,
                "results_summary": results_summary,
            })
            _publish_event(r, scan_job_id, "complete", {"status": "completed"})

            # Trigger AI triage
            triage_scan_findings.delay(scan_job_id)

            # Notifications
            try:
                asyncio.run(_async_notify_completion(
                    str(job.org_id), scan_job_id, job.target_domains, findings_count
                ))
            except Exception as e:
                logger.warning(f"Notification failed: {e}")

            logger.info(f"Scan {scan_job_id} completed. {sum(findings_count.values())} findings.")
            return {"status": "completed", "findings_count": findings_count}

        except SoftTimeLimitExceeded:
            logger.warning(f"Scan {scan_job_id} hit soft time limit")
            job.status = DBScanStatus.FAILED
            job.error_message = "Scan exceeded time limit"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
            _publish_event(r, scan_job_id, "error", {"message": "Scan exceeded time limit"})
            _publish_event(r, scan_job_id, "status_change", {"status": "failed"})
            raise

        except Exception as exc:
            logger.exception(f"Scan {scan_job_id} failed: {exc}")
            job.status = DBScanStatus.FAILED
            job.error_message = str(exc)[:2000]
            job.completed_at = datetime.now(timezone.utc)
            db.commit()

            _publish_event(r, scan_job_id, "error", {"message": str(exc)[:500]})
            _publish_event(r, scan_job_id, "status_change", {"status": "failed"})

            if self.request.retries < self.max_retries:
                countdown = 60 * (2 ** self.request.retries)
                raise self.retry(exc=exc, countdown=countdown)

            return {"status": "failed", "error": str(exc)[:500]}

        finally:
            if orchestrator:
                try:
                    orchestrator.cleanup()
                except Exception:
                    pass


# --- AI triage task ---

@celery_app.task(name="app.workers.scan_worker.triage_scan_findings")
def triage_scan_findings(scan_job_id: str) -> dict:
    """Background task: AI triage on findings from a completed scan."""
    if not settings.ANTHROPIC_API_KEY:
        return {"status": "skipped", "reason": "no_api_key"}

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    with SessionFactory() as db:
        from app.models.db.finding import Finding as DBFinding, FindingSeverity
        from app.models.db.asset import Asset
        from app.models.db.scan import ScanJob
        from app.models.db.org import Organization
        from sqlalchemy import select as sync_select

        try:
            _triage_uuid = UUID(scan_job_id)
        except ValueError:
            logger.error(f"Invalid scan_job_id for triage: {scan_job_id!r}")
            return {"error": "invalid_scan_job_id"}

        job = db.get(ScanJob, _triage_uuid)
        if not job:
            return {"error": "scan_not_found"}

        org = db.get(Organization, job.org_id)
        org_context = {
            "plan": org.plan.value if org else "unknown",
            "org_id": str(job.org_id),
        }

        findings = db.execute(
            sync_select(DBFinding).where(
                DBFinding.scan_job_id == _triage_uuid,
                DBFinding.ai_triaged_at == None,
            )
        ).scalars().all()

        if not findings:
            return {"status": "no_findings_to_triage"}

        triaged = 0
        errors = 0

        for finding in findings:
            try:
                asset_ctx = {}
                if finding.asset_id:
                    asset = db.get(Asset, finding.asset_id)
                    if asset:
                        asset_ctx = {
                            "type": asset.asset_type.value,
                            "value": asset.value,
                            "risk_score": asset.risk_score,
                        }

                triage_result = asyncio.run(_import_and_triage(finding, asset_ctx, org_context))

                ai_sev = triage_result.get("severity", finding.severity.value)
                try:
                    finding.ai_severity = FindingSeverity(ai_sev)
                except ValueError:
                    finding.ai_severity = finding.severity

                finding.ai_reasoning = triage_result.get("reasoning", "")
                finding.ai_confidence = float(triage_result.get("confidence", 0.0))
                finding.ai_triaged_at = datetime.now(timezone.utc)

                if triage_result.get("is_false_positive"):
                    finding.false_positive = True

                db.add(finding)
                triaged += 1

                if triaged % 10 == 0:
                    db.commit()

            except Exception as e:
                logger.error(f"AI triage failed for finding {finding.id}: {e}")
                errors += 1

        db.commit()
        return {"status": "completed", "triaged": triaged, "errors": errors}


async def _import_and_triage(finding, asset_ctx: dict, org_context: dict) -> dict:
    from app.services.ai_service import triage_finding
    return await triage_finding(finding, asset_ctx, org_context)


async def _async_notify_completion(org_id, scan_job_id, target_domains, findings_count):
    try:
        from app.services.notification_service import notify_scan_completed
        await notify_scan_completed(
            org_id=org_id,
            scan_id=scan_job_id,
            target_domains=target_domains,
            findings_count=findings_count,
        )
    except Exception as e:
        logger.warning(f"notify_scan_completed failed: {e}")


# --- Stuck scan watchdog ---

@celery_app.task(name="app.workers.scan_worker.recover_stuck_scans")
def recover_stuck_scans() -> dict:
    """
    Periodic watchdog: finds scans stuck in PENDING or RUNNING and recovers them.

    PENDING > 5 min  → requeue (task was likely lost when a worker restarted)
    RUNNING > 3 hours → mark FAILED (worker died mid-scan)

    Safe to run concurrently — uses DB-level compare-and-set to avoid double-recovery.
    """
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import select, update
    from app.models.db.scan import ScanJob, ScanStatus as DBScanStatus

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)
    r = _get_sync_redis()

    now = datetime.now(timezone.utc)
    pending_cutoff = now - timedelta(minutes=5)
    running_cutoff = now - timedelta(hours=3)

    requeued = 0
    failed = 0

    with SessionFactory() as db:
        # --- Recover PENDING scans (task was lost) ---
        stuck_pending = db.execute(
            select(ScanJob).where(
                ScanJob.status == DBScanStatus.PENDING,
                ScanJob.created_at < pending_cutoff,
            )
        ).scalars().all()

        for job in stuck_pending:
            # Atomically flip PENDING → PENDING with new celery task; skip if already changed
            try:
                result = run_scan.apply_async(args=[str(job.id)], queue="scans")
                job.celery_task_id = result.id
                db.commit()
                _publish_event(r, str(job.id), "status_change", {
                    "status": "pending",
                    "message": "Task requeued after worker restart",
                })
                logger.info(f"Requeued stuck PENDING scan {job.id} → task {result.id}")
                requeued += 1
            except Exception as exc:
                logger.warning(f"Failed to requeue scan {job.id}: {exc}")
                db.rollback()

        # --- Recover RUNNING scans (worker died mid-scan) ---
        stuck_running = db.execute(
            select(ScanJob).where(
                ScanJob.status == DBScanStatus.RUNNING,
                ScanJob.started_at < running_cutoff,
            )
        ).scalars().all()

        for job in stuck_running:
            try:
                job.status = DBScanStatus.FAILED
                job.completed_at = now
                db.commit()
                _publish_event(r, str(job.id), "error", {
                    "message": "Scan timed out — the worker processing this scan appears to have crashed. Please re-run the scan.",
                })
                _publish_event(r, str(job.id), "status_change", {"status": "failed"})
                logger.warning(f"Marked timed-out RUNNING scan {job.id} as FAILED")
                failed += 1
            except Exception as exc:
                logger.warning(f"Failed to fail scan {job.id}: {exc}")
                db.rollback()

    return {"requeued": requeued, "failed": failed}
