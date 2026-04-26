"""
MITRE ATT&CK Technique Mapper
Maps CVE → CWE → ATT&CK Technique → APT Groups
"""

from __future__ import annotations

from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.finding import Finding
from app.models.db.user import User

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])

# CWE → ATT&CK Technique mapping (curated subset)
CWE_TO_ATTACK: dict[str, dict] = {
    "CWE-89": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "SQL Injection enables attackers to exploit public-facing web applications",
        "mitigations": ["M1048 - Application Isolation", "M1026 - Privileged Account Management"],
    },
    "CWE-79": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "XSS can be used for drive-by compromise via malicious scripts",
        "mitigations": ["M1021 - Restrict Web-Based Content", "M1051 - Update Software"],
    },
    "CWE-22": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Path traversal enables unauthorized file system access",
        "mitigations": ["M1022 - Restrict File and Directory Permissions"],
    },
    "CWE-287": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence",
        "description": "Authentication bypass allows use of valid account credentials",
        "mitigations": ["M1032 - Multi-factor Authentication", "M1017 - User Training"],
    },
    "CWE-200": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Information exposure can leak credentials and sensitive data",
        "mitigations": ["M1041 - Encrypt Sensitive Information"],
    },
    "CWE-798": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Hardcoded credentials are trivially exploitable for credential access",
        "mitigations": ["M1041 - Encrypt Sensitive Information", "M1027 - Password Policies"],
    },
    "CWE-502": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Deserialization vulnerabilities enable arbitrary code execution",
        "mitigations": ["M1049 - Antivirus/Antimalware", "M1038 - Execution Prevention"],
    },
    "CWE-611": {
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": "XXE enables reading of local files and internal network scanning",
        "mitigations": ["M1042 - Disable or Remove Feature or Program"],
    },
    "CWE-918": {
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "tactic": "Command and Control",
        "description": "SSRF enables proxying requests through the server to internal resources",
        "mitigations": ["M1031 - Network Intrusion Prevention"],
    },
    "CWE-352": {
        "technique_id": "T1185",
        "technique_name": "Browser Session Hijacking",
        "tactic": "Collection",
        "description": "CSRF can hijack authenticated user sessions",
        "mitigations": ["M1054 - Software Configuration"],
    },
    "CWE-416": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Use-after-free can cause application crashes / denial of service",
        "mitigations": ["M1050 - Exploit Protection"],
    },
    "CWE-732": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Incorrect permissions allow unauthorized access to sensitive files",
        "mitigations": ["M1022 - Restrict File and Directory Permissions"],
    },
}

# CVE prefix → CWE (common mappings for well-known CVE families)
CVE_PATTERN_TO_CWE: dict[str, str] = {
    "sql": "CWE-89",
    "injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "auth bypass": "CWE-287",
    "authentication bypass": "CWE-287",
    "information disclosure": "CWE-200",
    "hardcoded": "CWE-798",
    "deserialization": "CWE-502",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "csrf": "CWE-352",
    "use after free": "CWE-416",
    "permission": "CWE-732",
}

# ATT&CK Technique → Known APT Groups
ATTACK_TO_APT: dict[str, list[dict]] = {
    "T1190": [
        {"id": "G0016", "name": "APT29 (Cozy Bear)", "country": "Russia", "also_known_as": ["The Dukes", "YTTRIUM"]},
        {"id": "G0050", "name": "APT32 (OceanLotus)", "country": "Vietnam", "also_known_as": ["SeaLotus"]},
        {"id": "G0007", "name": "APT28 (Fancy Bear)", "country": "Russia", "also_known_as": ["Sofacy", "STRONTIUM"]},
    ],
    "T1189": [
        {"id": "G0037", "name": "APT38", "country": "North Korea", "also_known_as": ["Lazarus Group"]},
        {"id": "G0059", "name": "Magic Hound", "country": "Iran", "also_known_as": ["APT35", "Charming Kitten"]},
    ],
    "T1078": [
        {"id": "G0016", "name": "APT29 (Cozy Bear)", "country": "Russia", "also_known_as": ["The Dukes"]},
        {"id": "G0096", "name": "APT41", "country": "China", "also_known_as": ["Double Dragon", "Winnti"]},
    ],
    "T1552": [
        {"id": "G0007", "name": "APT28 (Fancy Bear)", "country": "Russia", "also_known_as": ["Sofacy"]},
        {"id": "G0096", "name": "APT41", "country": "China", "also_known_as": ["Double Dragon"]},
    ],
    "T1059": [
        {"id": "G0037", "name": "Lazarus Group", "country": "North Korea", "also_known_as": ["APT38", "Hidden Cobra"]},
        {"id": "G0096", "name": "APT41", "country": "China", "also_known_as": ["Double Dragon"]},
    ],
    "T1090": [
        {"id": "G0007", "name": "APT28 (Fancy Bear)", "country": "Russia", "also_known_as": ["Sofacy"]},
        {"id": "G0050", "name": "APT32 (OceanLotus)", "country": "Vietnam", "also_known_as": ["SeaLotus"]},
    ],
    "T1083": [
        {"id": "G0096", "name": "APT41", "country": "China", "also_known_as": ["Double Dragon"]},
        {"id": "G0050", "name": "APT32 (OceanLotus)", "country": "Vietnam", "also_known_as": []},
    ],
    "T1213": [
        {"id": "G0016", "name": "APT29 (Cozy Bear)", "country": "Russia", "also_known_as": ["The Dukes"]},
    ],
    "T1185": [
        {"id": "G0059", "name": "APT35", "country": "Iran", "also_known_as": ["Charming Kitten"]},
    ],
    "T1499": [
        {"id": "G0037", "name": "Lazarus Group", "country": "North Korea", "also_known_as": []},
    ],
}


def _infer_cwe_from_title(title: str) -> Optional[str]:
    """Heuristically infer CWE from finding title."""
    title_lower = title.lower()
    for pattern, cwe in CVE_PATTERN_TO_CWE.items():
        if pattern in title_lower:
            return cwe
    return None


def _map_finding_to_attack(finding: Finding) -> Optional[dict]:
    """Map a finding to ATT&CK technique."""
    # Try explicit CWE field first
    cwe = None
    if finding.cve:
        # Look for CWE references in cve list
        for cve in finding.cve:
            if str(cve).startswith("CWE-"):
                cwe = str(cve)
                break

    # Fall back to heuristic title matching
    if not cwe:
        cwe = _infer_cwe_from_title(finding.title)

    if not cwe or cwe not in CWE_TO_ATTACK:
        return None

    attack = CWE_TO_ATTACK[cwe]
    technique_id = attack["technique_id"]
    apts = ATTACK_TO_APT.get(technique_id, [])

    return {
        "finding_id": str(finding.id),
        "finding_title": finding.title,
        "severity": finding.severity.value,
        "affected_asset": finding.affected_asset,
        "cwe": cwe,
        "attack_technique": {
            "id": technique_id,
            "name": attack["technique_name"],
            "tactic": attack["tactic"],
            "description": attack["description"],
            "url": f"https://attack.mitre.org/techniques/{technique_id}/",
            "mitigations": attack["mitigations"],
        },
        "apt_groups": apts,
        "risk_context": (
            f"This finding ({finding.severity.value.upper()}) maps to ATT&CK technique "
            f"{technique_id} ({attack['technique_name']}) under the {attack['tactic']} tactic. "
            f"{len(apts)} known APT groups use this technique."
        ),
    }


@router.get(
    "/map",
    summary="Map org findings to MITRE ATT&CK techniques and APT groups",
)
async def map_findings_to_attack(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    scan_job_id: Optional[str] = None,
    severity: Optional[str] = None,
) -> dict:
    query = select(Finding).where(Finding.org_id == org_id)
    if scan_job_id:
        query = query.where(Finding.scan_job_id == UUID(scan_job_id))
    if severity:
        query = query.where(Finding.severity == severity)

    result = await db.execute(query)
    findings = result.scalars().all()

    mappings = []
    unmapped = []
    tactic_summary: dict[str, int] = {}
    apt_summary: dict[str, int] = {}

    for f in findings:
        mapping = _map_finding_to_attack(f)
        if mapping:
            mappings.append(mapping)
            tactic = mapping["attack_technique"]["tactic"]
            tactic_summary[tactic] = tactic_summary.get(tactic, 0) + 1
            for apt in mapping["apt_groups"]:
                apt_summary[apt["name"]] = apt_summary.get(apt["name"], 0) + 1
        else:
            unmapped.append({"finding_id": str(f.id), "title": f.title, "severity": f.severity.value})

    return {
        "total_findings": len(findings),
        "mapped_count": len(mappings),
        "unmapped_count": len(unmapped),
        "mappings": mappings,
        "unmapped": unmapped,
        "tactic_summary": dict(sorted(tactic_summary.items(), key=lambda x: x[1], reverse=True)),
        "apt_exposure": dict(sorted(apt_summary.items(), key=lambda x: x[1], reverse=True)),
    }


@router.get(
    "/techniques",
    summary="List all ATT&CK techniques in the mapping database",
)
async def list_techniques(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    techniques = {}
    for cwe, attack in CWE_TO_ATTACK.items():
        tid = attack["technique_id"]
        if tid not in techniques:
            techniques[tid] = {
                **attack,
                "cwe_ids": [],
                "apt_groups": ATTACK_TO_APT.get(tid, []),
            }
        techniques[tid]["cwe_ids"].append(cwe)
    return {"items": list(techniques.values()), "total": len(techniques)}
