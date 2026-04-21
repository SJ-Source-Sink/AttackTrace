"""
Main v1 API router — combines all sub-routers.
"""

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.orgs import router as orgs_router, org_router
from app.api.v1.scans import router as scans_router
from app.api.v1.assets import router as assets_router
from app.api.v1.findings import router as findings_router
from app.api.v1.reports import router as reports_router
from app.api.v1.ai import router as ai_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.nmap import router as nmap_router
from app.api.v1.nuclei import router as nuclei_router
from app.api.v1.ffuf import router as ffuf_router
from app.api.v1.attack_suite import router as attack_suite_router
from app.api.v1.ai_attack_suite import router as ai_attack_suite_router
from app.api.v1.takeover import router as takeover_router
from app.api.v1.suppression_rules import router as suppression_rules_router
from app.api.v1.attackmapper import router as attackmapper_router
from app.api.v1.testgen import router as testgen_router
from app.api.v1.mobile import router as mobile_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(orgs_router)
api_router.include_router(org_router)
api_router.include_router(scans_router)
api_router.include_router(assets_router)
api_router.include_router(findings_router)
api_router.include_router(reports_router)
api_router.include_router(ai_router)
api_router.include_router(dashboard_router)
api_router.include_router(nmap_router)
api_router.include_router(nuclei_router)
api_router.include_router(ffuf_router)
api_router.include_router(attack_suite_router)
api_router.include_router(ai_attack_suite_router)
api_router.include_router(takeover_router)
api_router.include_router(suppression_rules_router)
api_router.include_router(attackmapper_router)
api_router.include_router(testgen_router)
api_router.include_router(mobile_router)
