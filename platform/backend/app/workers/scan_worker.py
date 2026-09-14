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

# Only retry scans on transient infrastructure errors.
# Logic errors (invalid target, bad config, auth failure) are permanent — retrying wastes time.
_TRANSIENT_SCAN_EXCEPTIONS = (
    ConnectionError,
    TimeoutError,
    OSError,
    ConnectionResetError,
    BrokenPipeError,
)


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

_sync_engine = None


def _get_sync_engine():
    global _sync_engine
    if _sync_engine is None:
        db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
        from sqlalchemy import create_engine
        _sync_engine = create_engine(
            db_url,
            pool_pre_ping=True,
            # Size for concurrent scan workers: 1 conn per worker + headroom
            pool_size=int(os.getenv("CELERYD_CONCURRENCY", "4")) + 2,
            max_overflow=4,
            pool_recycle=1800,     # recycle connections every 30 min
            pool_timeout=30,       # raise after 30s waiting for a connection
            connect_args={
                "connect_timeout": 10,                  # fail fast if DB unreachable
                "options": f"-c statement_timeout={settings.DATABASE_STATEMENT_TIMEOUT_MS}",
            },
        )
    return _sync_engine


def _get_session_factory(engine):
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(bind=engine, expire_on_commit=False)


# --- Redis publisher ---

def _get_sync_redis():
    import redis
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


def _publish_event(r, scan_id: str, event_type: str, data: dict) -> None:
    _TTL = 86_400  # 24 h
    try:
        # Monotonic sequence number per scan — used by SSE clients for Last-Event-ID replay
        seq_key = f"scan:{scan_id}:seq"
        event_id = r.incr(seq_key)
        r.expire(seq_key, _TTL)

        payload = json.dumps({
            "event_type": event_type,
            "event_id": event_id,
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })

        r.publish(f"scan:{scan_id}", payload)

        if event_type == "finding":
            # Store last 100 findings for reconnect replay (capped list)
            findings_key = f"scan:{scan_id}:findings"
            r.rpush(findings_key, payload)
            r.ltrim(findings_key, -100, -1)
            r.expire(findings_key, _TTL)
        else:
            # Structural events replayed in full for state reconstruction
            replay_key = f"scan:{scan_id}:events"
            r.rpush(replay_key, payload)
            r.expire(replay_key, _TTL)
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


async def _scan_web_assets_for_secrets(session, r, scan_job_id: str) -> None:
    """Scan live web assets for exposed secrets/config files.
    Best-effort — publishes secret_found events via Redis pub/sub.
    """
    from app.services.secret_scanner_service import scan_url_for_secrets

    web_applications = getattr(session, "web_applications", [])
    scanned = 0
    for webapp in web_applications:
        url = getattr(webapp, "url", None)
        status = getattr(webapp, "status_code", None)
        is_alive = getattr(webapp, "is_alive", False)
        if not url or not is_alive or status not in (200, 301, 302):
            continue
        try:
            secret_findings = await scan_url_for_secrets(url)
            for sf in secret_findings:
                _publish_event(r, scan_job_id, "secret_found", {
                    "title": sf["title"],
                    "severity": sf["severity"],
                    "affected_asset": sf["affected_asset"],
                    "description": sf["description"],
                })
                logger.info(f"Secret scanner: {sf['title']} at {sf['affected_asset']}")
            scanned += 1
            if scanned >= 20:  # Limit total web assets scanned
                break
        except Exception as e:
            logger.debug(f"Secret scan failed for {url}: {e}")


async def _run_url_discovery_for_session(session, r, scan_job_id: str) -> None:
    """Run historical URL discovery for domains in the session.
    Best-effort — publishes url_discovery events via Redis pub/sub.
    """
    from app.services.url_discovery_service import run_url_discovery

    target_domains = getattr(session, "domains", [])
    domain_values = []
    for d in target_domains:
        fqdn = getattr(d, "fqdn", None) or (d if isinstance(d, str) else None)
        if fqdn:
            domain_values.append(fqdn)

    for domain in domain_values[:3]:  # Limit to first 3 domains
        try:
            discovered_urls = await run_url_discovery(domain)
            if discovered_urls:
                param_urls = [u for u in discovered_urls if u["params"]]
                _publish_event(r, scan_job_id, "url_discovery", {
                    "domain": domain,
                    "count": len(discovered_urls),
                    "urls": [u["url"] for u in discovered_urls[:10]],  # Preview
                    "param_url_count": len(param_urls),
                })
                logger.info(
                    f"URL discovery: {len(discovered_urls)} historical URLs, "
                    f"{len(param_urls)} with params for {domain}"
                )
        except Exception as e:
            logger.debug(f"URL discovery skipped for {domain}: {e}")


# --- Asset/Finding persistence ---

from app.core.dedup import compute_dedup_hash as _compute_dedup_hash  # noqa: E402


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
    Runs synchronously. Uses a single batch EPSS API call instead of per-CVE requests.
    Called after _persist_session_results.
    """
    import requests as _requests
    from app.models.db.finding import Finding as DBFinding
    from app.services.kev_epss_sync import load_kev, compute_priority_score
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

        # Collect all unique CVEs across findings for a single batch API call
        all_cves = []
        for finding in findings_with_cves:
            all_cves.extend(finding.cve or [])
        all_cves = list(set(all_cves))

        epss_data: dict = {}
        if all_cves:
            cve_param = ",".join(all_cves[:100])  # API limit
            try:
                resp = _requests.get(
                    f"https://api.first.org/data/v1/epss?cve={cve_param}",
                    timeout=10,
                )
                if resp.status_code == 200:
                    for item in resp.json().get("data", []):
                        epss_data[item["cve"].upper()] = float(item.get("epss", 0))
            except Exception as _epss_err:
                logger.warning(f"Batch EPSS fetch failed: {_epss_err}")

        from app.services.risk_scoring_service import compute_risk_score

        enriched = 0
        for finding in findings_with_cves:
            cve_list = finding.cve or []
            if not cve_list:
                continue
            kev_status = any(cve in kev_set for cve in cve_list)
            # Look up EPSS score from batch result; use first CVE as representative
            epss_score = epss_data.get(cve_list[0].upper(), None)
            priority = compute_priority_score(finding.cvss_score, epss_score, kev_status)
            finding.kev_status = kev_status
            finding.epss_score = epss_score
            finding.priority_score = priority

            # Compute AI risk score
            sev_val = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
            risk_score, risk_explanation = compute_risk_score(
                sev_val, finding.cvss_score, epss_score, kev_status, priority
            )
            finding.risk_score = risk_score
            finding.risk_explanation = risk_explanation

            db_session.add(finding)
            enriched += 1

        if enriched:
            db_session.flush()
            logger.info(f"KEV/EPSS enriched {enriched} findings for scan {scan_job_id_str}")
    except Exception as e:
        logger.warning(f"KEV/EPSS enrichment failed for scan {scan_job_id_str}: {e}")


def _persist_module_results_partial(
    db_session, scan_job_id_str: str, org_id: UUID, module_name: str, module_result,
    org_sla_config: Optional[dict] = None,
) -> None:
    """
    Persist results from a single module immediately after it completes.
    Idempotent: skips findings/assets that already exist for this scan+dedup_hash.
    """
    from app.models.db.asset import Asset, AssetType
    from app.models.db.finding import Finding as DBFinding, FindingSeverity, FindingStatus
    from app.models.db.suppression_rule import ScanSuppressionRule
    from app.services.sla_service import compute_sla_deadline, apply_compliance_tags
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
                _upsert_asset(db_session,
                    org_id=org_id, scan_job_id=scan_job_uuid,
                    asset_type=AssetType.DOMAIN, value=domain.fqdn,
                    metadata_={"registrar": getattr(domain, "registrar", ""),
                               "source": getattr(domain, "source", module_name), "module": module_name},
                )
            except Exception as e:
                logger.debug(f"Partial persist domain skipped [{module_name}]: {e}")

        # Persist findings (with dedup check)
        from sqlalchemy.exc import IntegrityError as _IntegrityError
        for f in getattr(module_result, "findings", []):
            sev_value = f.severity.value if hasattr(f.severity, "value") else f.severity
            dedup_hash = _compute_dedup_hash(org_id, f.title, f.affected_asset, getattr(f, "cve", None))

            # no_autoflush prevents pending adds from flushing mid-SELECT and
            # hitting the unique constraint before we've had a chance to check.
            with db_session.no_autoflush:
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
                    asset_id=_resolve_asset_id_sync(db_session, org_id, f.affected_asset or ""),
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
                    confidence=getattr(f, "confidence", "medium"),
                    dedup_hash=dedup_hash,
                )
                # SLA deadline and compliance tags
                new_finding.sla_deadline = compute_sla_deadline(sev_value, org_sla_config)
                new_finding.compliance_tags = apply_compliance_tags(
                    f.title or "", f.category or "", getattr(f, "description", "") or ""
                )
                if matched_rule:
                    new_finding.suppressed = True
                    new_finding.suppressed_reason = f"Auto-suppressed by rule: {matched_rule.action}"
                    if matched_rule.action == "false_positive":
                        new_finding.status = FindingStatus.FALSE_POSITIVE
                        new_finding.false_positive = True
                    elif matched_rule.action == "accepted_risk":
                        new_finding.status = FindingStatus.ACCEPTED_RISK
            except Exception as e:
                logger.warning(f"Partial persist finding failed [{module_name}]: {e}")
                continue

            # Add + flush this ONE finding inside its own SAVEPOINT. This must be
            # per-finding, not a single batch flush at the end of the loop: calling
            # db_session.begin_nested() while OTHER finding objects from earlier in
            # this same loop are still pending (added but not yet flushed) makes
            # SQLAlchemy pre-flush that pending state as part of establishing the
            # SAVEPOINT itself — i.e. BEFORE the SAVEPOINT actually exists — so a
            # collision there would still require a full session rollback and
            # reintroduce the exact bug this is meant to fix. Flushing immediately
            # after each add keeps every SAVEPOINT scoped to exactly one insert.
            try:
                with db_session.begin_nested():
                    db_session.add(new_finding)
                    db_session.flush()
            except _IntegrityError:
                # A concurrent partial-persist or retry already wrote this exact
                # finding. Roll back only this SAVEPOINT (this one finding-insert
                # attempt), not the whole transaction — otherwise this would also
                # discard the asset upserts already flushed earlier in the same
                # db_session/transaction (new ports, resolved IPs, etc.), which a
                # plain db_session.rollback() here used to silently wipe out.
                logger.warning(f"Partial persist [{module_name}]: dedup conflict on flush for '{f.title}', skipping")
        logger.debug(
            f"Partial persist: {module_name} → "
            f"{len(getattr(module_result, 'findings', []))} findings"
        )
    except Exception as e:
        logger.warning(f"Partial persist failed for module {module_name}: {e}")
        try:
            db_session.rollback()
        except Exception:
            pass


def _upsert_asset(db_session, **kwargs):
    """Insert an asset, or refresh it if (org_id, value, asset_type) already exists.

    Previously this was ON CONFLICT DO NOTHING, so a rescanned asset's metadata
    (open ports, resolved IPs, etc.) and scan_job_id stayed pinned to whichever
    scan first discovered it — silently going stale forever. Refreshing on
    conflict is required for the EASM diff task to have anything new to detect.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy import func as sa_func
    from app.models.db.asset import Asset
    stmt = pg_insert(Asset).values(**kwargs)
    # stmt.excluded is keyed by actual DB column names, not ORM attribute aliases
    # (Asset.metadata_ maps to the "metadata" column) — translate accordingly.
    _col_for_kwarg = {"scan_job_id": "scan_job_id", "metadata_": "metadata"}
    update_cols = {
        _col_for_kwarg[k]: stmt.excluded[_col_for_kwarg[k]] for k in _col_for_kwarg if k in kwargs
    }
    update_cols["last_seen"] = sa_func.now()
    stmt = stmt.on_conflict_do_update(
        index_elements=["org_id", "value", "asset_type"],
        set_=update_cols,
    )
    db_session.execute(stmt)


def _extract_hostname_sync(affected_asset: str) -> Optional[str]:
    """Sync-context twin of app.services.asset_upsert._extract_hostname —
    duplicated rather than imported since this file's persist functions run
    on a sync SQLAlchemy session (Celery context) and that helper's sibling
    resolve_asset_id is async. Kept in sync (heh) manually; it's a tiny pure
    function so the duplication is low-risk."""
    if not affected_asset:
        return None
    value = affected_asset.strip()
    if "://" in value:
        from urllib.parse import urlparse
        try:
            host = urlparse(value).hostname
        except ValueError:
            host = None
        return host.lower() if host else None
    candidate = value.split("/")[0].split(":")[0].strip().lower()
    if not candidate or " " in candidate or "." not in candidate:
        return None
    return candidate


def _resolve_asset_id_sync(db_session, org_id: UUID, affected_asset: str) -> Optional[UUID]:
    """Sync-context best-effort Finding.affected_asset -> Asset.id lookup —
    see app.services.asset_upsert.resolve_asset_id for the full rationale
    (no scanner links findings to Asset rows today, which silently breaks
    the Asset detail page's finding list and the correlation engine's
    asset-grouping). Read-only, never creates an Asset."""
    # Asset.value is only unique per (org_id, value, asset_type) — the same
    # string can legitimately exist as more than one asset_type row, so this
    # must tolerate multiple matches (`.limit(1)`) rather than assume at
    # most one.
    from sqlalchemy import select as _select
    from app.models.db.asset import Asset
    if not affected_asset:
        return None
    exact = db_session.execute(
        _select(Asset.id).where(Asset.org_id == org_id, Asset.value == affected_asset.strip()).limit(1)
    ).scalar_one_or_none()
    if exact:
        return exact
    host = _extract_hostname_sync(affected_asset)
    if not host:
        return None
    return db_session.execute(
        _select(Asset.id).where(Asset.org_id == org_id, Asset.value == host).limit(1)
    ).scalar_one_or_none()


def _persist_session_results(db_session, scan_job, attacktrace_session, org_id: UUID, org_sla_config: Optional[dict] = None) -> tuple:
    from app.models.db.asset import Asset, AssetType
    from app.models.db.finding import Finding as DBFinding, FindingSeverity, FindingStatus
    from app.services.sla_service import compute_sla_deadline, apply_compliance_tags
    from sqlalchemy import select as sync_select

    assets_created = 0
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Load suppression rules once for the whole session
    suppression_rules = _load_suppression_rules(db_session, org_id)

    for domain in attacktrace_session.domains:
        _upsert_asset(db_session,
            org_id=org_id, scan_job_id=scan_job.id,
            asset_type=AssetType.DOMAIN, value=domain.fqdn,
            metadata_={"registrar": domain.registrar, "registrant_org": domain.registrant_org,
                       "name_servers": domain.name_servers, "tags": domain.tags, "source": domain.source},
        )
        assets_created += 1

    for subdomain in attacktrace_session.subdomains:
        _upsert_asset(db_session,
            org_id=org_id, scan_job_id=scan_job.id,
            asset_type=AssetType.SUBDOMAIN, value=subdomain.fqdn,
            metadata_={"parent_domain": subdomain.parent_domain, "resolved_ips": subdomain.resolved_ips,
                       "is_alive": subdomain.is_alive, "http_status": subdomain.http_status, "source": subdomain.source},
        )
        assets_created += 1

    for ip in attacktrace_session.ip_addresses:
        _upsert_asset(db_session,
            org_id=org_id, scan_job_id=scan_job.id,
            asset_type=AssetType.IP, value=ip.address,
            metadata_={"asn": ip.asn, "asn_org": ip.asn_org,
                       "cloud_provider": ip.cloud_provider.value if ip.cloud_provider else None,
                       "geolocation": ip.geolocation.model_dump() if ip.geolocation else {},
                       "reverse_dns": ip.reverse_dns, "source": ip.source},
        )
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
        _upsert_asset(db_session,
            org_id=org_id, scan_job_id=scan_job.id,
            asset_type=AssetType.WEBAPP, value=webapp.url,
            screenshot_url=screenshot_url,
            metadata_={"title": webapp.title, "status_code": webapp.status_code,
                       "is_alive": webapp.is_alive, "source": webapp.source},
        )
        assets_created += 1

    for cloud in attacktrace_session.cloud_assets:
        _upsert_asset(db_session,
            org_id=org_id, scan_job_id=scan_job.id,
            asset_type=AssetType.CLOUD, value=cloud.url or cloud.name,
            metadata_={"provider": cloud.provider.value if cloud.provider else None,
                       "asset_type": cloud.asset_type.value if cloud.asset_type else None,
                       "name": cloud.name, "is_public": cloud.is_public, "source": cloud.source},
        )
        assets_created += 1

    from sqlalchemy.exc import IntegrityError as _IntegrityError
    for f in attacktrace_session.findings:
        sev_value = f.severity.value
        dedup_hash = _compute_dedup_hash(org_id, f.title, f.affected_asset, getattr(f, "cve", None))

        # Idempotent: skip if already persisted (e.g., by partial persist callback).
        # no_autoflush prevents pending adds from flushing mid-SELECT and hitting
        # the unique constraint before the check completes.
        with db_session.no_autoflush:
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
                asset_id=_resolve_asset_id_sync(db_session, org_id, f.affected_asset or ""),
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
                confidence=getattr(f, "confidence", "medium"),
                dedup_hash=dedup_hash,
            )
            # SLA deadline and compliance tags
            new_finding.sla_deadline = compute_sla_deadline(sev_value, org_sla_config)
            new_finding.compliance_tags = apply_compliance_tags(
                f.title or "", f.category or "", getattr(f, "description", "") or ""
            )
            if matched_rule:
                new_finding.suppressed = True
                new_finding.suppressed_reason = f"Auto-suppressed by rule: {matched_rule.action}"
                if matched_rule.action == "false_positive":
                    new_finding.status = FindingStatus.FALSE_POSITIVE
                    new_finding.false_positive = True
                elif matched_rule.action == "accepted_risk":
                    new_finding.status = FindingStatus.ACCEPTED_RISK
        except Exception as e:
            logger.error(f"Failed to persist finding '{f.title}': {e}")
            continue

        # Add + flush this ONE finding inside its own SAVEPOINT — see the matching
        # comment in _persist_module_results_partial for why this must be done
        # per-finding rather than batched into a single flush at the end of the
        # loop (db_session.begin_nested() pre-flushes any OTHER pending objects
        # before the SAVEPOINT exists, so a batched flush would still let a
        # collision force a full-transaction rollback).
        try:
            with db_session.begin_nested():
                db_session.add(new_finding)
                db_session.flush()
        except _IntegrityError:
            # SAVEPOINT rollback only — a plain db_session.rollback() here would
            # roll back the whole outer transaction, discarding the asset
            # upserts (_upsert_asset calls above, and any from partial-persist
            # earlier in this same db_session) that already flushed successfully.
            logger.warning(f"Final persist: dedup conflict on flush for '{f.title}' — skipped")

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


# --- Asset change detection diff ---

def _compute_and_store_diff(db_session, scan_job_id_str: str, org_id: UUID, target_domains: list) -> None:
    """
    Compute asset and finding diffs between the current scan and the most recent
    prior completed scan for the same org + overlapping targets.  Store a ScanDiff record.
    """
    from app.models.db.asset import Asset
    from app.models.db.finding import Finding as DBFinding, FindingStatus
    from app.models.db.scan import ScanJob, ScanStatus as DBScanStatus, ScanDiff
    from sqlalchemy import select as sync_select

    try:
        scan_uuid = UUID(scan_job_id_str)
    except ValueError:
        return

    # Find most recent prior completed scan for same org
    prior_scan = db_session.execute(
        sync_select(ScanJob)
        .where(
            ScanJob.org_id == org_id,
            ScanJob.status == DBScanStatus.COMPLETED,
            ScanJob.id != scan_uuid,
        )
        .order_by(ScanJob.completed_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    # Fetch current scan assets and findings
    current_assets = db_session.execute(
        sync_select(Asset).where(Asset.scan_job_id == scan_uuid)
    ).scalars().all()

    current_findings = db_session.execute(
        sync_select(DBFinding).where(DBFinding.scan_job_id == scan_uuid)
    ).scalars().all()

    current_asset_values = {a.value for a in current_assets}
    current_finding_hashes = {f.dedup_hash for f in current_findings if f.dedup_hash}

    new_assets_list = []
    removed_assets_list = []
    new_findings_list = []
    resolved_findings_list = []

    if prior_scan:
        prior_assets = db_session.execute(
            sync_select(Asset).where(Asset.scan_job_id == prior_scan.id)
        ).scalars().all()

        prior_findings = db_session.execute(
            sync_select(DBFinding).where(DBFinding.scan_job_id == prior_scan.id)
        ).scalars().all()

        prior_asset_values = {a.value for a in prior_assets}
        prior_finding_hashes = {f.dedup_hash for f in prior_findings if f.dedup_hash}

        # New: in current but not in prior
        new_asset_vals = current_asset_values - prior_asset_values
        new_assets_list = [
            {"type": a.asset_type.value, "value": a.value}
            for a in current_assets if a.value in new_asset_vals
        ]

        # Removed: in prior but not in current
        removed_asset_vals = prior_asset_values - current_asset_values
        removed_assets_list = [
            {"type": a.asset_type.value, "value": a.value}
            for a in prior_assets if a.value in removed_asset_vals
        ]

        # New findings: in current hashes but not prior
        new_hash_set = current_finding_hashes - prior_finding_hashes
        new_findings_list = [
            {"title": f.title, "severity": f.severity.value, "asset": f.affected_asset, "dedup_hash": f.dedup_hash}
            for f in current_findings if f.dedup_hash in new_hash_set
        ]

        # Resolved: open findings in prior that are not in current
        resolved_hash_set = prior_finding_hashes - current_finding_hashes
        resolved_findings_list = [
            {"title": f.title, "severity": f.severity.value, "asset": f.affected_asset, "dedup_hash": f.dedup_hash}
            for f in prior_findings
            if f.dedup_hash in resolved_hash_set and f.status == FindingStatus.OPEN
        ]

    diff_summary = {
        "new_assets_count": len(new_assets_list),
        "removed_assets_count": len(removed_assets_list),
        "new_findings_count": len(new_findings_list),
        "resolved_findings_count": len(resolved_findings_list),
        "total_assets": len(current_assets),
        "total_findings": len(current_findings),
    }

    scan_diff = ScanDiff(
        org_id=org_id,
        scan_id=scan_uuid,
        previous_scan_id=prior_scan.id if prior_scan else None,
        new_assets=new_assets_list,
        removed_assets=removed_assets_list,
        new_findings=new_findings_list,
        resolved_findings=resolved_findings_list,
        diff_summary=diff_summary,
    )
    db_session.add(scan_diff)
    db_session.flush()
    logger.info(
        f"Scan diff stored for {scan_job_id_str}: "
        f"+{len(new_assets_list)} assets, -{len(removed_assets_list)} assets, "
        f"+{len(new_findings_list)} findings, {len(resolved_findings_list)} resolved"
    )


# --- Main Celery task ---

@celery_app.task(bind=True, max_retries=3, name="app.workers.scan_worker.run_scan")
def run_scan(self: Task, scan_job_id: str) -> dict:
    """Main Celery task: runs an AttackTrace scan and persists results."""
    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)
    r = _get_sync_redis()

    with SessionFactory() as db:
        from app.models.db.scan import ScanJob, ScanStatus as DBScanStatus, ScanIntensity as DBScanIntensity
        from app.models.db.org import OrgCredentials
        from sqlalchemy import select as sync_select

        try:
            _scan_uuid = UUID(scan_job_id)
        except ValueError:
            logger.error(f"Invalid scan_job_id format: {scan_job_id!r}")
            return {"error": "invalid_scan_job_id"}

        job = db.get(ScanJob, _scan_uuid)
        if job is None:
            # The API commits the record before dispatching, but under very high load
            # the worker may start before the commit propagates. Retry once after a brief wait.
            import time as _time
            _time.sleep(2)
            db.expire_all()
            job = db.get(ScanJob, _scan_uuid)
        if job is None:
            logger.error(f"ScanJob {scan_job_id} not found")
            return {"error": "scan_job_not_found"}

        if job.status in (DBScanStatus.CANCELLED, DBScanStatus.COMPLETED, DBScanStatus.FAILED, DBScanStatus.RUNNING):
            logger.info(f"Scan {scan_job_id} already in status {job.status.value} — skipping duplicate")
            return {"status": job.status.value}

        # --- Atomic scan claiming via PostgreSQL advisory lock ---
        # pg_try_advisory_xact_lock acquires a transaction-level lock:
        # - Only one worker can hold it at a time (no race between duplicate tasks)
        # - Released automatically when the transaction ends (no cleanup needed)
        # - Uses a stable int64 derived from the scan UUID
        import hashlib as _hashlib
        from sqlalchemy import text as _text
        _lock_key = int(_hashlib.md5(scan_job_id.encode()).hexdigest()[:16], 16) % (2**63)
        lock_acquired = db.execute(
            _text("SELECT pg_try_advisory_xact_lock(:key)"),
            {"key": _lock_key}
        ).scalar()

        if not lock_acquired:
            logger.info(f"Scan {scan_job_id} already claimed by another worker — skipping")
            return {"status": "skipped", "reason": "advisory_lock_held"}

        # Re-fetch status inside the lock to catch races
        db.refresh(job)
        if job.status in (DBScanStatus.CANCELLED, DBScanStatus.COMPLETED, DBScanStatus.FAILED, DBScanStatus.RUNNING):
            logger.info(f"Scan {scan_job_id} already in status {job.status.value} — skipping duplicate")
            return {"status": job.status.value}

        # Per-org concurrency limit: max 3 running scans per org at a time.
        # Checked inside the advisory lock so the count+update is atomic.
        _MAX_CONCURRENT_SCANS_PER_ORG = 3
        running_count = db.execute(
            sync_select(ScanJob).where(
                ScanJob.org_id == job.org_id,
                ScanJob.status == DBScanStatus.RUNNING,
                ScanJob.id != job.id,
            )
        ).scalars().all()

        if len(running_count) >= _MAX_CONCURRENT_SCANS_PER_ORG:
            logger.info(
                f"Org {job.org_id} already has {len(running_count)} running scans; "
                f"rescheduling scan {scan_job_id} in 120s"
            )
            raise self.retry(countdown=120, exc=Exception("org_concurrency_limit"))

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

            # Load org SLA config for deadline computation
            from app.models.db.org import Organization as _Organization
            _org = db.get(_Organization, job.org_id)
            _org_sla_config = _org.sla_config if _org else None

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
            passive_only = intensity in ("passive", "passive_due_diligence")

            # Due diligence mode: only run passive OSINT modules
            if intensity == "passive_due_diligence":
                modules_to_run = [m for m in ["seed", "domain", "intel"] if m in orchestrator.MODULE_ORDER]
            else:
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
                        db, scan_job_id, job.org_id, module_name, result,
                        org_sla_config=_org_sla_config,
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

            # Historical URL discovery (best-effort, non-blocking)
            try:
                asyncio.run(_run_url_discovery_for_session(completed_session, r, scan_job_id))
            except Exception as _url_disc_err:
                logger.debug(f"URL discovery post-run skipped: {_url_disc_err}")

            # Secret scanning for live web assets (best-effort, non-blocking)
            try:
                asyncio.run(_scan_web_assets_for_secrets(completed_session, r, scan_job_id))
            except Exception as _secret_err:
                logger.debug(f"Secret scanning post-run skipped: {_secret_err}")

            # Persist results (final pass — idempotent, skips already-persisted)
            results_summary, findings_count = _persist_session_results(
                db, job, completed_session, job.org_id, org_sla_config=_org_sla_config
            )

            # KEV/EPSS enrichment for findings with CVEs
            try:
                _enrich_kev_epss(db, scan_job_id)
            except Exception as _kev_err:
                logger.warning(f"KEV/EPSS enrichment skipped: {_kev_err}")

            # Asset change detection diff
            try:
                _compute_and_store_diff(db, scan_job_id, job.org_id, job.target_domains)
            except Exception as _diff_err:
                logger.warning(f"Scan diff computation skipped: {_diff_err}")

            job.status = DBScanStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.results_summary = results_summary
            job.findings_count = findings_count
            db.commit()

            # Invalidate dashboard cache so newly-discovered findings/assets
            # show up immediately instead of waiting out the 5-15min TTL —
            # this is the single most common cache-staleness trigger (every
            # completed scan changes dashboard counts), previously only
            # invalidated on scan *deletion*.
            try:
                r.delete(f"dashboard:stats:{job.org_id}", f"dashboard:executive:{job.org_id}")
            except Exception as _cache_err:
                logger.warning(f"Dashboard cache invalidation skipped: {_cache_err}")

            # Refresh scan metrics materialized view (best-effort, non-blocking)
            try:
                from sqlalchemy import text as sa_text
                db.execute(sa_text("REFRESH MATERIALIZED VIEW CONCURRENTLY scan_metrics_mv"))
                db.commit()
            except Exception as _mv_err:
                logger.warning(f"scan_metrics_mv refresh skipped: {_mv_err}")

            _publish_event(r, scan_job_id, "status_change", {
                "status": "completed",
                "findings_count": findings_count,
                "results_summary": results_summary,
            })
            _publish_event(r, scan_job_id, "complete", {"status": "completed"})

            # Trigger AI triage (passive classification of what the scanners found)
            triage_scan_findings.delay(scan_job_id)

            # Trigger active AI testing/validation (Attack Suite AI Agent) against
            # this scan's targets — the follow-up step after passive triage.
            run_ai_agent_after_scan.delay(scan_job_id)

            # Trigger cross-scanner correlation — looks for compound risk
            # patterns (e.g. takeover + exposed service on the same asset)
            # across this org's findings, not just this one scan's batch.
            try:
                from app.workers.correlation_worker import correlate_after_scan
                correlate_after_scan.delay(scan_job_id)
            except Exception as e:
                logger.warning(f"Failed to dispatch correlate_after_scan: {e}")

            # AGGRESSIVE scans additionally auto-chain a curated set of
            # standalone scanner tools (nuclei, secrets, js_scanner,
            # takeover) against the discovered domains/subdomains — so
            # "aggressive" means everything runs, not just a deeper core
            # pipeline pass. NORMAL/PASSIVE scans don't get this (cost/time).
            if job.intensity == DBScanIntensity.AGGRESSIVE:
                try:
                    from app.workers.standalone_scan_worker import run_standalone_scanners_after_scan
                    run_standalone_scanners_after_scan.delay(scan_job_id)
                except Exception as e:
                    logger.warning(f"Failed to dispatch run_standalone_scanners_after_scan: {e}")

            # Notifications: scan.completed channels (Slack, Jira, Teams, webhooks)
            try:
                asyncio.run(_async_notify_completion(
                    str(job.org_id), scan_job_id, job.target_domains, findings_count
                ))
            except Exception as e:
                logger.warning(f"Notification failed: {e}")

            # Notifications: finding.critical channels for each critical/high finding
            try:
                asyncio.run(_async_notify_critical_findings(
                    str(job.org_id), scan_job_id, findings_count
                ))
            except Exception as e:
                logger.warning(f"Critical finding notification failed: {e}")

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
            try:
                db.rollback()
            except Exception:
                pass
            job.status = DBScanStatus.FAILED
            job.error_message = str(exc)[:2000]
            job.completed_at = datetime.now(timezone.utc)
            db.commit()

            _publish_event(r, scan_job_id, "error", {"message": str(exc)[:500]})
            _publish_event(r, scan_job_id, "status_change", {"status": "failed"})

            # Only auto-retry transient infrastructure errors.
            # Logic errors (bad config, invalid target) are permanent — don't retry.
            if self.request.retries < self.max_retries and isinstance(exc, _TRANSIENT_SCAN_EXCEPTIONS):
                countdown = 60 * (2 ** self.request.retries)
                logger.warning(
                    f"Scan {scan_job_id} transient failure (attempt {self.request.retries + 1}/"
                    f"{self.max_retries}), retrying in {countdown}s: {exc}"
                )
                raise self.retry(exc=exc, countdown=countdown)

            return {"status": "failed", "error": str(exc)[:500]}

        finally:
            try:
                r.close()
            except Exception:
                pass
            if orchestrator:
                try:
                    orchestrator.cleanup()
                except Exception:
                    pass


# --- AI triage task ---

@celery_app.task(
    name="app.workers.scan_worker.triage_scan_findings",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def triage_scan_findings(self, scan_job_id: str) -> dict:
    """Background task: AI triage on findings from a completed scan."""
    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    with SessionFactory() as db:
        from app.models.db.finding import Finding as DBFinding, FindingSeverity
        from app.models.db.asset import Asset
        from app.models.db.scan import ScanJob
        from app.models.db.org import Organization, OrgCredentials
        from app.core.security import decrypt_credential
        from sqlalchemy import select as sync_select

        try:
            _triage_uuid = UUID(scan_job_id)
        except ValueError:
            logger.error(f"Invalid scan_job_id for triage: {scan_job_id!r}")
            return {"error": "invalid_scan_job_id"}

        job = db.get(ScanJob, _triage_uuid)
        if not job:
            return {"error": "scan_not_found"}

        # Resolve org-specific AI credentials (fall back to system env vars).
        # This duplicates get_org_ai_config()'s logic rather than calling it
        # directly because this task runs in a sync Celery worker context
        # with its own sync SQLAlchemy session — kept provider-aware in step
        # with that function so a Qwen-configured org isn't silently skipped
        # here just because it has no Anthropic key (it doesn't need one).
        provider = "anthropic"
        ai_api_key = settings.ANTHROPIC_API_KEY
        ai_base_url = settings.AI_BASE_URL
        ai_model = settings.AI_MODEL
        try:
            creds_row = db.execute(
                sync_select(OrgCredentials).where(OrgCredentials.org_id == job.org_id)
            ).scalar_one_or_none()
            if creds_row:
                if creds_row.ai_provider == "qwen":
                    provider = "qwen"
                    ai_api_key = decrypt_credential(creds_row.qwen_api_key_enc) if creds_row.qwen_api_key_enc else None
                    ai_base_url = decrypt_credential(creds_row.qwen_base_url_enc) if creds_row.qwen_base_url_enc else None
                    ai_model = decrypt_credential(creds_row.qwen_model_enc) if creds_row.qwen_model_enc else None
                else:
                    if creds_row.anthropic_key_enc:
                        ai_api_key = decrypt_credential(creds_row.anthropic_key_enc)
                    if creds_row.ai_base_url_enc:
                        ai_base_url = decrypt_credential(creds_row.ai_base_url_enc)
                    if creds_row.ai_model_override_enc:
                        ai_model = decrypt_credential(creds_row.ai_model_override_enc)
        except Exception as e:
            logger.warning(f"Could not load org AI credentials: {e}")

        ai_ready = bool(ai_api_key) or (provider == "qwen" and bool(ai_base_url))
        if not ai_ready:
            return {"status": "skipped", "reason": "no_api_key"}

        ai_config = {"provider": provider, "api_key": ai_api_key, "base_url": ai_base_url, "model": ai_model}

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

        # Build asset context map (one DB query per finding was the old approach — avoid N+1)
        asset_ids = list({f.asset_id for f in findings if f.asset_id})
        asset_rows = db.execute(
            sync_select(Asset).where(Asset.id.in_(asset_ids))
        ).scalars().all() if asset_ids else []
        asset_map = {
            str(a.id): {"type": a.asset_type.value, "value": a.value, "risk_score": a.risk_score}
            for a in asset_rows
        }

        # Batch triage with concurrency semaphore — single asyncio.run() for the entire
        # batch replaces N separate asyncio.run() calls (one event loop per finding was wrong).
        async def _batch_triage() -> list[tuple]:
            sem = asyncio.Semaphore(5)  # max 5 concurrent AI calls

            async def _one(finding):
                async with sem:
                    try:
                        ctx = asset_map.get(str(finding.asset_id), {}) if finding.asset_id else {}
                        result = await _import_and_triage(finding, ctx, org_context, ai_config)
                        return finding, result, None
                    except Exception as e:
                        return finding, None, e

            return await asyncio.gather(*[_one(f) for f in findings])

        triage_results = asyncio.run(_batch_triage())

        triaged = 0
        errors = 0

        for finding, result, err in triage_results:
            if err is not None:
                logger.error(f"AI triage failed for finding {finding.id}: {err}")
                errors += 1
                continue

            ai_sev = result.get("severity", finding.severity.value)
            try:
                finding.ai_severity = FindingSeverity(ai_sev)
            except ValueError:
                finding.ai_severity = finding.severity

            finding.ai_reasoning = result.get("reasoning", "")
            finding.ai_confidence = float(result.get("confidence", 0.0))
            finding.ai_business_impact = result.get("business_impact", "")
            finding.ai_triaged_at = datetime.now(timezone.utc)

            if result.get("is_false_positive"):
                finding.false_positive = True

            db.add(finding)
            triaged += 1

        db.commit()
        return {"status": "completed", "triaged": triaged, "errors": errors}


# --- Automatic post-scan active testing (Attack Suite AI Agent) ---

# Bounded, provider-aware budget for the *unattended* agent run fired after
# every scan — deliberately smaller than the interactive ceiling in
# attack_suite.py's _AGENT_BUDGET_CEILING, since this task may run the agent
# against several targets back-to-back in one Celery task and must finish
# comfortably inside CELERY_TASK_SOFT_TIME_LIMIT (2h) with no human watching.
_AUTO_AGENT_BUDGET = {
    "anthropic": {"turns": 20, "seconds": 480},
    "qwen": {"turns": 100, "seconds": 3600},
}
# Cap how many of a scan's target_domains get an automatic agent run — a scan
# covering dozens of domains would otherwise serialize into a multi-hour task.
_AUTO_AGENT_MAX_TARGETS = 5


@celery_app.task(
    name="app.workers.scan_worker.run_ai_agent_after_scan",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
)
def run_ai_agent_after_scan(self, scan_job_id: str) -> dict:
    """Background task: automatically launch the bounded Attack Suite AI
    Agent (active testing/validation) against each in-scope target surfaced
    by a completed scan. This is the "second half" of the pipeline —
    triage_scan_findings does passive AI classification of what the scanners
    already found; this does active, tool-use follow-up testing against the
    same assets, exactly like a manually-started agent run, just system-
    triggered. Runs fully autonomously per the existing agent safety model
    (scope enforcement, fixed tool envelope, bounded budget, full AuditLog
    trail) — no additional gate is introduced here.
    """
    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    with SessionFactory() as db:
        from app.models.db.scan import ScanJob
        from app.models.db.org import OrgCredentials
        from app.core.security import decrypt_credential
        from sqlalchemy import select as sync_select

        try:
            _uuid = UUID(scan_job_id)
        except ValueError:
            logger.error(f"Invalid scan_job_id for auto-agent: {scan_job_id!r}")
            return {"error": "invalid_scan_job_id"}

        job = db.get(ScanJob, _uuid)
        if not job:
            return {"error": "scan_not_found"}

        # Same provider-aware credential resolution as triage_scan_findings —
        # a Qwen-configured org must not be skipped just because it has no
        # Anthropic key (it doesn't need one).
        provider = "anthropic"
        ai_api_key = settings.ANTHROPIC_API_KEY
        ai_base_url = settings.AI_BASE_URL
        ai_model = settings.AI_MODEL
        try:
            creds_row = db.execute(
                sync_select(OrgCredentials).where(OrgCredentials.org_id == job.org_id)
            ).scalar_one_or_none()
            if creds_row:
                if creds_row.ai_provider == "qwen":
                    provider = "qwen"
                    ai_api_key = decrypt_credential(creds_row.qwen_api_key_enc) if creds_row.qwen_api_key_enc else None
                    ai_base_url = decrypt_credential(creds_row.qwen_base_url_enc) if creds_row.qwen_base_url_enc else None
                    ai_model = decrypt_credential(creds_row.qwen_model_enc) if creds_row.qwen_model_enc else None
                else:
                    if creds_row.anthropic_key_enc:
                        ai_api_key = decrypt_credential(creds_row.anthropic_key_enc)
                    if creds_row.ai_base_url_enc:
                        ai_base_url = decrypt_credential(creds_row.ai_base_url_enc)
                    if creds_row.ai_model_override_enc:
                        ai_model = decrypt_credential(creds_row.ai_model_override_enc)
        except Exception as e:
            logger.warning(f"Could not load org AI credentials for auto-agent: {e}")

        ai_ready = bool(ai_api_key) or (provider == "qwen" and bool(ai_base_url))
        if not ai_ready:
            return {"status": "skipped", "reason": "no_api_key"}

        ai_config = {"provider": provider, "api_key": ai_api_key, "base_url": ai_base_url, "model": ai_model}
        budget = _AUTO_AGENT_BUDGET.get(provider, _AUTO_AGENT_BUDGET["anthropic"])

        targets = list(dict.fromkeys(job.target_domains or []))[:_AUTO_AGENT_MAX_TARGETS]
        if not targets:
            return {"status": "skipped", "reason": "no_targets"}

        results = []
        for target in targets:
            try:
                summary = asyncio.run(
                    _run_agent_once(job.org_id, job.created_by, target, ai_config, budget)
                )
                results.append({"target": target, **summary})
            except Exception as e:
                logger.exception(f"Auto AI agent run failed for target {target} (scan {scan_job_id}): {e}")
                results.append({"target": target, "status": "error", "error": str(e)[:500]})

        logger.info(f"Auto AI agent runs for scan {scan_job_id}: {results}")
        return {"status": "completed", "results": results}


async def _run_agent_once(org_id, user_id, target: str, ai_config: dict, budget: dict) -> dict:
    """Drive one attack_agent.run_agent() call to completion on its own
    short-lived async engine — mirrors the pattern already used by
    _async_notify_critical_findings() in this file for bridging a sync
    Celery task into async DB/agent code without sharing the main app's
    event-loop-bound connection pool."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession as _AsyncSession
    from sqlalchemy.orm import sessionmaker as _sessionmaker
    from app.services.attack_agent import run_agent

    async_db_url = settings.DATABASE_URL
    if not async_db_url.startswith("postgresql+asyncpg"):
        async_db_url = async_db_url.replace("postgresql://", "postgresql+asyncpg://").replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )
    _engine = create_async_engine(async_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
    _AsyncSessionFactory = _sessionmaker(_engine, class_=_AsyncSession, expire_on_commit=False)

    status = "unknown"
    turns = 0
    findings_recorded = 0
    try:
        async with _AsyncSessionFactory() as db:
            async for event in run_agent(
                db, org_id, user_id, target,
                objective="Automated post-scan active testing and validation of newly-scanned assets.",
                ai_config=ai_config,
                max_turns=budget["turns"], max_seconds=budget["seconds"],
            ):
                data = event.get("data") or {}
                if event["event"] == "tool_call" and data.get("tool") == "record_finding" and (data.get("result") or {}).get("recorded"):
                    findings_recorded += 1
                if isinstance(data.get("turns"), int):
                    turns = data["turns"]
                if isinstance(data.get("turn"), int):
                    turns = data["turn"]
                if event["event"] in ("done", "budget_exhausted", "stopped", "error"):
                    status = event["event"]
    finally:
        await _engine.dispose()

    return {"status": status, "turns": turns, "findings_recorded": findings_recorded}


async def _import_and_triage(finding, asset_ctx: dict, org_context: dict, ai_config: dict | None = None) -> dict:
    from app.services.ai_service import triage_finding
    return await triage_finding(finding, asset_ctx, org_context, ai_config=ai_config)


async def _async_notify_critical_findings(org_id: str, scan_job_id: str, findings_count: dict) -> None:
    """
    Fire finding.critical dispatch_notifications for critical/high findings in this scan.
    Runs once after the scan completes — queries the DB for the newly persisted findings
    so we have real finding IDs to include in the payload.
    """
    critical = findings_count.get("critical", 0)
    high = findings_count.get("high", 0)
    if critical == 0 and high == 0:
        return

    try:
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker as _sessionmaker
        from sqlalchemy import select as _async_select
        from app.models.db.finding import Finding as _DBFinding, FindingSeverity as _FindingSeverity
        from app.services.notification_service import dispatch_notifications

        async_db_url = settings.DATABASE_URL
        if not async_db_url.startswith("postgresql+asyncpg"):
            async_db_url = async_db_url.replace("postgresql://", "postgresql+asyncpg://").replace(
                "postgresql+psycopg2://", "postgresql+asyncpg://"
            )

        _engine = create_async_engine(
            async_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0
        )
        _AsyncSessionFactory = _sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )

        try:
            from uuid import UUID as _UUID
            _scan_uuid = _UUID(scan_job_id)
            _org_uuid = _UUID(org_id)

            async with _AsyncSessionFactory() as _db:
                _result = await _db.execute(
                    _async_select(_DBFinding).where(
                        _DBFinding.scan_job_id == _scan_uuid,
                        _DBFinding.org_id == _org_uuid,
                        _DBFinding.severity.in_([
                            _FindingSeverity.CRITICAL, _FindingSeverity.HIGH
                        ]),
                    ).limit(50)
                )
                crit_findings = _result.scalars().all()

                for f in crit_findings:
                    try:
                        await dispatch_notifications(
                            org_id=org_id,
                            event_type="finding.critical",
                            payload={
                                "finding_id": str(f.id),
                                "scan_id": scan_job_id,
                                "org_id": org_id,
                                "title": f.title,
                                "severity": f.severity.value,
                                "affected_asset": f.affected_asset or "",
                            },
                            db_session=_db,
                        )
                    except Exception as _fe:
                        logger.warning(f"dispatch_notifications finding.critical failed for {f.id}: {_fe}")
        finally:
            await _engine.dispose()
    except Exception as exc:
        logger.warning(f"_async_notify_critical_findings failed: {exc}")


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

    # Dispatch to configured notification channels (Slack, Jira, Teams, webhooks)
    try:
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker as _sessionmaker

        async_db_url = settings.DATABASE_URL
        if not async_db_url.startswith("postgresql+asyncpg"):
            async_db_url = async_db_url.replace("postgresql://", "postgresql+asyncpg://").replace(
                "postgresql+psycopg2://", "postgresql+asyncpg://"
            )

        _engine = create_async_engine(
            async_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0
        )
        _AsyncSessionFactory = _sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )

        from app.services.notification_service import dispatch_notifications

        async with _AsyncSessionFactory() as db:
            await dispatch_notifications(
                org_id=org_id,
                event_type="scan.completed",
                payload={
                    "scan_id": scan_job_id,
                    "org_id": org_id,
                    "target_domains": target_domains,
                    "findings_count": findings_count,
                },
                db_session=db,
            )
        await _engine.dispose()
    except Exception as exc:
        logger.warning(f"dispatch_notifications (scan.completed) failed: {exc}")


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

    try:
        r.close()
    except Exception:
        pass

    return {"requeued": requeued, "failed": failed}
