"""
Main v1 API router — combines all sub-routers.
"""

import logging

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.orgs import router as orgs_router, org_router
from app.api.v1.scans import router as scans_router
from app.api.v1.assets import router as assets_router
from app.api.v1.findings import router as findings_router
from app.api.v1.reports import router as reports_router
from app.api.v1.ai import router as ai_router
from app.api.v1.activity import router as activity_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.nmap import router as nmap_router
from app.api.v1.nuclei import router as nuclei_router
from app.api.v1.ffuf import router as ffuf_router
from app.api.v1.attack_suite import router as attack_suite_router
from app.api.v1.takeover import router as takeover_router
from app.api.v1.suppression_rules import router as suppression_rules_router
from app.api.v1.testgen import router as testgen_router
from app.api.v1.mobile import router as mobile_router
from app.api.v1.firewall import router as firewall_router
from app.api.v1.network_graph import router as network_graph_router
from app.api.v1.schedules import router as schedules_router
from app.api.v1.notifications import router as notifications_router
from app.api.v1.cloud import router as cloud_router
# Note: burp_analyzer.py is imported directly (functions only) by attack_suite.py —
# its own router is intentionally not mounted here; it declares an APIRouter but
# has zero @router-decorated routes (dead refactor artifact).

_log = logging.getLogger(__name__)

# Optional modules — added recently; wrapped so server starts even on stale installs
try:
    from app.api.v1.attackmapper import router as attackmapper_router
except ImportError:
    _log.warning("attackmapper module not found — Attack Path Mapper disabled")
    attackmapper_router = None

try:
    from app.api.v1.cicd import router as cicd_router
except ImportError:
    _log.warning("cicd module not found — CI/CD integration disabled")
    cicd_router = None

try:
    from app.api.v1.attack_mapper import router as attack_mapper_router
except ImportError:
    _log.warning("attack_mapper module not found — MITRE ATT&CK mapper disabled")
    attack_mapper_router = None

try:
    from app.api.v1.compliance import router as compliance_router
except ImportError:
    _log.warning("compliance module not found — Compliance evidence export disabled")
    compliance_router = None

try:
    from app.api.v1.webhooks import router as webhooks_router
except ImportError:
    _log.warning("webhooks module not found — Webhooks disabled")
    webhooks_router = None

try:
    from app.api.v1.ai_scanner import router as ai_scanner_router
except ImportError:
    _log.warning("ai_scanner module not found — AI/LLM Scanner disabled")
    ai_scanner_router = None

try:
    from app.api.v1.mcp_scanner import router as mcp_scanner_router
except ImportError:
    _log.warning("mcp_scanner module not found — MCP Scanner disabled")
    mcp_scanner_router = None

try:
    from app.api.v1.js_scanner import router as js_scanner_router
except ImportError:
    _log.warning("js_scanner module not found — JS Scanner disabled")
    js_scanner_router = None

try:
    from app.api.v1.secrets import router as secrets_router
except ImportError:
    _log.warning("secrets module not found — Secret Scanner disabled")
    secrets_router = None

try:
    from app.api.v1.cspm import router as cspm_router
except ImportError:
    _log.warning("cspm module not found — CSPM Scanner disabled")
    cspm_router = None

try:
    from app.api.v1.exposure_scanner import router as exposure_router
except ImportError:
    _log.warning("exposure_scanner module not found — Exposure Scanner disabled")
    exposure_router = None

try:
    from app.api.v1.email_security import router as email_security_router
except ImportError:
    _log.warning("email_security module not found — Email Security Scanner disabled")
    email_security_router = None

try:
    from app.api.v1.iac_scanner import router as iac_router
except ImportError:
    _log.warning("iac_scanner module not found — IaC Scanner disabled")
    iac_router = None

try:
    from app.api.v1.supply_chain import router as supply_chain_router
except ImportError:
    _log.warning("supply_chain module not found — Supply Chain Scanner disabled")
    supply_chain_router = None

try:
    from app.api.v1.container_scanner import router as container_router
except ImportError:
    _log.warning("container_scanner module not found — Container Scanner disabled")
    container_router = None

try:
    from app.api.v1.api_scanner import router as api_scanner_router
except ImportError:
    _log.warning("api_scanner module not found — API Security Scanner disabled")
    api_scanner_router = None

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(orgs_router)
api_router.include_router(org_router)
api_router.include_router(scans_router)
api_router.include_router(assets_router)
api_router.include_router(findings_router)
api_router.include_router(reports_router)
api_router.include_router(ai_router)
api_router.include_router(activity_router)
api_router.include_router(dashboard_router)
api_router.include_router(nmap_router)
api_router.include_router(nuclei_router)
api_router.include_router(ffuf_router)
api_router.include_router(attack_suite_router)
api_router.include_router(takeover_router)
api_router.include_router(suppression_rules_router)
api_router.include_router(testgen_router)
api_router.include_router(mobile_router)
api_router.include_router(firewall_router)
api_router.include_router(network_graph_router)
api_router.include_router(schedules_router)
api_router.include_router(notifications_router)
api_router.include_router(cloud_router)

if attackmapper_router:
    api_router.include_router(attackmapper_router)
if cicd_router:
    api_router.include_router(cicd_router)
if attack_mapper_router:
    api_router.include_router(attack_mapper_router)
if compliance_router:
    api_router.include_router(compliance_router)
if webhooks_router:
    api_router.include_router(webhooks_router)
if ai_scanner_router:
    api_router.include_router(ai_scanner_router)
if mcp_scanner_router:
    api_router.include_router(mcp_scanner_router)
if js_scanner_router:
    api_router.include_router(js_scanner_router)
if secrets_router:
    api_router.include_router(secrets_router)
if cspm_router:
    api_router.include_router(cspm_router)
if exposure_router:
    api_router.include_router(exposure_router)
if email_security_router:
    api_router.include_router(email_security_router)
if iac_router:
    api_router.include_router(iac_router)
if supply_chain_router:
    api_router.include_router(supply_chain_router)
if container_router:
    api_router.include_router(container_router)
if api_scanner_router:
    api_router.include_router(api_scanner_router)
