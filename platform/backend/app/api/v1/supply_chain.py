"""
Supply Chain Security Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parses dependency manifests and checks for:
  1. Known vulnerabilities via OSV.dev batch API
  2. Dependency confusion attack surface
  3. Abandoned / deprecated packages
  4. License risk (GPL/AGPL in commercial context)

Supported manifests:
  package.json, requirements.txt, Pipfile.lock, poetry.lock,
  go.mod, go.sum, pom.xml, Gemfile, Gemfile.lock, composer.json
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid as _uuid_mod
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.services.enrichment_service import batch_enrich_cves
from app.services.finding_ingest import ingest_findings
from app.models.db.user import User

# ── SBOM (CycloneDX) generation ───────────────────────────────────────────────

_PURL_ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "golang",
    "Maven": "maven",
    "RubyGems": "gem",
    "Packagist": "composer",
}


def _build_cyclonedx_sbom(deps: list[dict], findings: list[dict]) -> dict:
    """Build a CycloneDX 1.5 SBOM document from parsed dependencies and OSV findings."""
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model.vulnerability import (
        Vulnerability, VulnerabilityRating, VulnerabilitySeverity, BomTarget,
    )
    from cyclonedx.output.json import JsonV1Dot5
    from packageurl import PackageURL

    bom = Bom()
    seen: set[tuple[str, str, str]] = set()
    components_by_key: dict[tuple[str, str], Component] = {}

    for d in deps:
        name = d.get("name", "")
        version = d.get("version", "") or "0.0.0"
        ecosystem = d.get("ecosystem", "")
        key = (ecosystem, name, version)
        if not name or key in seen:
            continue
        seen.add(key)

        purl_type = _PURL_ECOSYSTEM_MAP.get(ecosystem)
        purl = None
        if purl_type:
            try:
                if purl_type == "maven" and ":" in name:
                    namespace, artifact = name.split(":", 1)
                    purl = PackageURL(type=purl_type, namespace=namespace, name=artifact, version=version)
                else:
                    purl = PackageURL(type=purl_type, name=name, version=version)
            except Exception:
                purl = None

        try:
            component = Component(
                name=name, version=version, type=ComponentType.LIBRARY,
                purl=purl, bom_ref=f"{ecosystem}:{name}@{version}",
            )
            bom.components.add(component)
            components_by_key[(ecosystem, name)] = component
        except Exception:
            continue

    severity_map = {
        "critical": VulnerabilitySeverity.CRITICAL,
        "high": VulnerabilitySeverity.HIGH,
        "medium": VulnerabilitySeverity.MEDIUM,
        "low": VulnerabilitySeverity.LOW,
        "info": VulnerabilitySeverity.INFO,
    }
    for f in findings:
        if f.get("type") not in (None, "vulnerability") or not f.get("vuln_id"):
            continue
        pkg = f.get("package", "")
        ecosystem = f.get("ecosystem", "")
        component = components_by_key.get((ecosystem, pkg))
        try:
            vuln = Vulnerability(
                id=f.get("vuln_id"),
                description=f.get("description", ""),
                ratings=[VulnerabilityRating(severity=severity_map.get(f.get("severity", "medium"), VulnerabilitySeverity.MEDIUM))],
            )
            if component is not None:
                vuln.affects.add(BomTarget(ref=component.bom_ref))
            bom.vulnerabilities.add(vuln)
        except Exception:
            continue

    output = JsonV1Dot5(bom)
    return json.loads(output.output_as_string())

router = APIRouter(prefix="/supply-chain", tags=["Supply Chain Scanner"])

# ── History helpers ────────────────────────────────────────────────────────────

def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "supply_chain_scanner" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


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
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return None


def _delete_scan(org_id: str, scan_id: str) -> bool:
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            path.unlink()
            return True
    except Exception:
        pass
    return False


# ── Manifest parsers ───────────────────────────────────────────────────────────

def _parse_package_json(content: str) -> list[dict]:
    """Parse npm package.json — dependencies + devDependencies."""
    deps = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, ver in (data.get(section) or {}).items():
                # Normalise version: strip ^~>=<
                clean_ver = re.sub(r"^[\^~>=<\s]+", "", str(ver)).strip() or "latest"
                deps.append({"name": name, "version": clean_ver, "ecosystem": "npm"})
    except Exception:
        pass
    return deps


def _parse_requirements_txt(content: str) -> list[dict]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=)\s*([^\s;#]+)", line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                deps.append({"name": m2.group(1), "version": "latest", "ecosystem": "PyPI"})
    return deps


def _parse_pipfile_lock(content: str) -> list[dict]:
    deps = []
    try:
        data = json.loads(content)
        for section in ("default", "develop"):
            for name, meta in (data.get(section) or {}).items():
                ver = str(meta.get("version", "")).lstrip("=") or "latest"
                deps.append({"name": name, "version": ver, "ecosystem": "PyPI"})
    except Exception:
        pass
    return deps


def _parse_poetry_lock(content: str) -> list[dict]:
    deps = []
    blocks = re.split(r'\[\[package\]\]', content)
    for block in blocks[1:]:
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            deps.append({"name": name_m.group(1), "version": ver_m.group(1), "ecosystem": "PyPI"})
    return deps


def _parse_go_mod(content: str) -> list[dict]:
    deps = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            part = stripped.replace("require ", "").strip()
            parts = part.split()
            if len(parts) >= 2:
                deps.append({"name": parts[0], "version": parts[1], "ecosystem": "Go"})
    return deps


def _parse_go_sum(content: str) -> list[dict]:
    seen: set[str] = set()
    deps = []
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            mod = parts[0]
            ver = parts[1].split("/")[0]
            if mod not in seen:
                seen.add(mod)
                deps.append({"name": mod, "version": ver, "ecosystem": "Go"})
    return deps[:200]  # cap


def _parse_pom_xml(content: str) -> list[dict]:
    deps = []
    try:
        root = ET.fromstring(content)
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        for dep in root.iter():
            tag = dep.tag.split("}")[-1] if "}" in dep.tag else dep.tag
            if tag == "dependency":
                g = dep.find("groupId") or dep.find("{http://maven.apache.org/POM/4.0.0}groupId")
                a = dep.find("artifactId") or dep.find("{http://maven.apache.org/POM/4.0.0}artifactId")
                v = dep.find("version") or dep.find("{http://maven.apache.org/POM/4.0.0}version")
                if g is not None and a is not None:
                    name = f"{g.text}:{a.text}"
                    ver = v.text if v is not None else "latest"
                    deps.append({"name": name, "version": str(ver), "ecosystem": "Maven"})
    except Exception:
        pass
    return deps


def _parse_gemfile(content: str) -> list[dict]:
    deps = []
    for line in content.splitlines():
        m = re.match(r"^\s*gem\s+'([^']+)'(?:\s*,\s*'([^']+)')?", line)
        if not m:
            m = re.match(r'^\s*gem\s+"([^"]+)"(?:\s*,\s*"([^"]+)")?', line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2) or "latest", "ecosystem": "RubyGems"})
    return deps


def _parse_gemfile_lock(content: str) -> list[dict]:
    deps = []
    in_gems = False
    for line in content.splitlines():
        if line.strip() == "GEM":
            in_gems = True
            continue
        if in_gems and line and not line.startswith(" "):
            break
        if in_gems:
            m = re.match(r"^\s{4}([a-z][a-z0-9_\-]+)\s+\(([^)]+)\)", line)
            if m:
                deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "RubyGems"})
    return deps


def _parse_composer_json(content: str) -> list[dict]:
    deps = []
    try:
        data = json.loads(content)
        for section in ("require", "require-dev"):
            for name, ver in (data.get(section) or {}).items():
                if name == "php":
                    continue
                clean_ver = re.sub(r"^[\^~>=<\s]+", "", str(ver)).strip() or "latest"
                deps.append({"name": name, "version": clean_ver, "ecosystem": "Packagist"})
    except Exception:
        pass
    return deps


def _detect_and_parse(filename: str, content: str) -> tuple[str, list[dict]]:
    """Returns (manifest_type, dependencies)."""
    base = Path(filename).name.lower()

    if base == "package.json":
        return "npm", _parse_package_json(content)
    if base == "requirements.txt":
        return "pip", _parse_requirements_txt(content)
    if base == "pipfile.lock":
        return "pipenv", _parse_pipfile_lock(content)
    if base == "poetry.lock":
        return "poetry", _parse_poetry_lock(content)
    if base == "go.mod":
        return "go_mod", _parse_go_mod(content)
    if base == "go.sum":
        return "go_sum", _parse_go_sum(content)
    if base == "pom.xml":
        return "maven", _parse_pom_xml(content)
    if base in ("gemfile",):
        return "bundler", _parse_gemfile(content)
    if base == "gemfile.lock":
        return "bundler_lock", _parse_gemfile_lock(content)
    if base == "composer.json":
        return "composer", _parse_composer_json(content)

    # Fallback: try requirements.txt format
    if filename.endswith(".txt"):
        deps = _parse_requirements_txt(content)
        if deps:
            return "pip", deps

    return "unknown", []


# ── OSV.dev vulnerability lookup ───────────────────────────────────────────────

OSV_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pip": "PyPI",
    "pipenv": "PyPI",
    "poetry": "PyPI",
    "go_mod": "Go",
    "go_sum": "Go",
    "maven": "Maven",
    "bundler": "RubyGems",
    "bundler_lock": "RubyGems",
    "composer": "Packagist",
}

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 100  # OSV limit per request


async def _osv_lookup(deps: list[dict], client: httpx.AsyncClient) -> list[dict]:
    """Query OSV.dev for vulnerabilities. Returns list of finding dicts."""
    findings = []
    # Process in batches
    for i in range(0, len(deps), BATCH_SIZE):
        batch = deps[i:i + BATCH_SIZE]
        queries = []
        for dep in batch:
            eco = dep.get("ecosystem") or dep.get("manifest_type", "")
            queries.append({
                "package": {"name": dep["name"], "ecosystem": eco},
                "version": dep["version"],
            })
        try:
            resp = await client.post(
                OSV_BATCH_URL,
                json={"queries": queries},
                timeout=30,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            results = data.get("results", [])
            for dep, result in zip(batch, results):
                for vuln in (result.get("vulns") or []):
                    vuln_id = vuln.get("id", "")
                    aliases = vuln.get("aliases") or []
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                    summary = vuln.get("summary", "No summary available")

                    # Determine severity
                    severity = "medium"
                    sev_list = vuln.get("severity") or []
                    for s in sev_list:
                        score_str = s.get("score", "")
                        if score_str:
                            try:
                                score = float(score_str)
                                if score >= 9.0:
                                    severity = "critical"
                                elif score >= 7.0:
                                    severity = "high"
                                elif score >= 4.0:
                                    severity = "medium"
                                else:
                                    severity = "low"
                            except ValueError:
                                pass
                        # CVSS type severity
                        type_sev = s.get("type", "")
                        if "CRITICAL" in type_sev.upper():
                            severity = "critical"
                        elif "HIGH" in type_sev.upper():
                            severity = "high"

                    # Extract fixed version
                    fixed_in = None
                    for affected in (vuln.get("affected") or []):
                        for rng in (affected.get("ranges") or []):
                            for evt in (rng.get("events") or []):
                                if "fixed" in evt:
                                    fixed_in = evt["fixed"]
                                    break

                    findings.append({
                        "type": "vulnerability",
                        "package": dep["name"],
                        "version": dep["version"],
                        "ecosystem": dep.get("ecosystem", ""),
                        "vuln_id": vuln_id,
                        "cve_id": cve_id,
                        "severity": severity,
                        "summary": summary,
                        "fixed_in": fixed_in,
                        "osv_url": f"https://osv.dev/vulnerability/{vuln_id}",
                    })
        except Exception:
            continue
    return findings


# ── Dependency confusion check ─────────────────────────────────────────────────

_PRIVATE_NAME_PATTERNS = [
    re.compile(r"^@[a-z][a-z0-9_\-]+/"),  # scoped npm packages @company/pkg
    re.compile(r"^(internal|private|corp|company|org|enterprise|self|local)\-", re.IGNORECASE),
    re.compile(r"\-(internal|private|corp|oss|lib)$", re.IGNORECASE),
]


def _looks_private(name: str) -> bool:
    for p in _PRIVATE_NAME_PATTERNS:
        if p.search(name):
            return True
    return False


async def _check_npm_exists(name: str, client: httpx.AsyncClient) -> bool:
    try:
        url = f"https://registry.npmjs.org/{name.replace('/', '%2F')}"
        r = await client.head(url, timeout=8)
        return r.status_code == 200
    except Exception:
        return False


async def _check_pypi_exists(name: str, client: httpx.AsyncClient) -> bool:
    try:
        r = await client.head(f"https://pypi.org/pypi/{name}/json", timeout=8)
        return r.status_code == 200
    except Exception:
        return False


async def _dependency_confusion_check(
    deps: list[dict], manifest_type: str, client: httpx.AsyncClient
) -> list[dict]:
    findings = []
    # Only do this for npm and PyPI; cap at 20 checks to avoid rate limiting
    candidates = [d for d in deps if _looks_private(d["name"])][:20]

    for dep in candidates:
        eco = dep.get("ecosystem", "")
        name = dep["name"]

        if eco == "npm":
            exists = await _check_npm_exists(name, client)
            if not exists:
                findings.append({
                    "type": "dependency_confusion",
                    "package": name,
                    "version": dep["version"],
                    "ecosystem": eco,
                    "severity": "high",
                    "summary": f"Dependency confusion attack possible — '{name}' is not published on the public npm registry",
                    "remediation": "Use npm scoped packages with registry configuration, or add an .npmrc that pins to private registry",
                })
            else:
                findings.append({
                    "type": "dependency_confusion",
                    "package": name,
                    "version": dep["version"],
                    "ecosystem": eco,
                    "severity": "critical",
                    "summary": f"Potential dependency confusion — '{name}' found on public npm registry with possibly unknown maintainer",
                    "remediation": "Verify npm package ownership. An attacker may have squatted this name on the public registry.",
                })
        elif eco == "PyPI":
            exists = await _check_pypi_exists(name, client)
            if not exists:
                findings.append({
                    "type": "dependency_confusion",
                    "package": name,
                    "version": dep["version"],
                    "ecosystem": eco,
                    "severity": "high",
                    "summary": f"Dependency confusion possible — '{name}' is not published on PyPI",
                    "remediation": "Configure pip to use your private index with --index-url or PIP_INDEX_URL",
                })

        await asyncio.sleep(0.05)  # light rate limiting

    return findings


# ── Abandoned/deprecated check (npm only) ─────────────────────────────────────

async def _abandoned_check(deps: list[dict], client: httpx.AsyncClient) -> list[dict]:
    findings = []
    npm_deps = [d for d in deps if d.get("ecosystem") == "npm"][:30]

    for dep in npm_deps:
        try:
            r = await client.get(
                f"https://registry.npmjs.org/{dep['name'].replace('/', '%2F')}",
                timeout=8,
            )
            if r.status_code != 200:
                continue
            data = r.json()

            # Check deprecated field
            latest_ver = data.get("dist-tags", {}).get("latest", "")
            latest_meta = data.get("versions", {}).get(latest_ver, {})
            deprecated = latest_meta.get("deprecated")
            if deprecated:
                findings.append({
                    "type": "abandoned",
                    "package": dep["name"],
                    "version": dep["version"],
                    "ecosystem": "npm",
                    "severity": "medium",
                    "summary": f"Package '{dep['name']}' is deprecated: {deprecated}",
                    "remediation": f"Replace '{dep['name']}' with an actively maintained alternative",
                })
                continue

            # Check last publish date
            times = data.get("time", {})
            modified = times.get("modified") or times.get("created")
            if modified:
                modified_dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - modified_dt).days
                if age_days > 730:  # > 2 years
                    years = age_days // 365
                    findings.append({
                        "type": "abandoned",
                        "package": dep["name"],
                        "version": dep["version"],
                        "ecosystem": "npm",
                        "severity": "medium",
                        "summary": f"Package '{dep['name']}' is unmaintained — last published {years} year(s) ago",
                        "remediation": f"Consider replacing '{dep['name']}' with an actively maintained alternative",
                    })
        except Exception:
            pass
        await asyncio.sleep(0.05)

    return findings


# ── License risk check ─────────────────────────────────────────────────────────

_GPL_LICENSES = {"GPL-3.0", "GPL-2.0", "AGPL-3.0", "AGPL-1.0", "GPL-3.0-only", "GPL-3.0-or-later",
                 "AGPL-3.0-only", "AGPL-3.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later"}


async def _license_check(deps: list[dict], client: httpx.AsyncClient) -> list[dict]:
    findings = []
    npm_deps = [d for d in deps if d.get("ecosystem") == "npm"][:30]

    for dep in npm_deps:
        try:
            r = await client.get(
                f"https://registry.npmjs.org/{dep['name'].replace('/', '%2F')}",
                timeout=8,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            license_field = data.get("license") or ""
            if isinstance(license_field, dict):
                license_field = license_field.get("type", "")
            if license_field and license_field in _GPL_LICENSES:
                findings.append({
                    "type": "license_risk",
                    "package": dep["name"],
                    "version": dep["version"],
                    "ecosystem": "npm",
                    "severity": "info",
                    "summary": f"Package '{dep['name']}' uses {license_field} license — may restrict commercial use",
                    "remediation": "Review license compatibility with your commercial product. GPL/AGPL may require open-sourcing your code.",
                })
        except Exception:
            pass
        await asyncio.sleep(0.05)

    return findings


# ── SSE helper ─────────────────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


# ── Finding-quality adapter ────────────────────────────────────────────────────

_TYPE_CONFIDENCE = {
    "vulnerability": "high",          # OSV.dev matched exact name+version against a public advisory
    "dependency_confusion": "medium", # heuristic: name pattern + registry existence check
    "abandoned": "high",              # registry-confirmed fact (deprecated flag / last-publish date)
    "license_risk": "high",           # registry-confirmed license field
}


async def _adapt_supply_chain_findings(findings: list[dict]) -> list[dict]:
    """Normalize supply_chain.py findings for finding_ingest.ingest_findings,
    enriching OSV vulnerability findings with CVSS v4/EPSS/KEV where the
    advisory has a mapped CVE (many OSV/GHSA entries don't — enrichment is a
    no-op for those rather than a failure)."""
    # OSV vuln_id is often a GHSA id; use cve_id specifically, not vuln_id, for enrichment
    cve_ids = list({f["cve_id"] for f in findings if f.get("type") == "vulnerability" and f.get("cve_id")})
    enrichment = await batch_enrich_cves(cve_ids) if cve_ids else {}

    adapted = []
    for f in findings:
        ftype = f.get("type", "")
        pkg = f.get("package", "")
        version = f.get("version", "")
        title = f"{f.get('vuln_id', ftype)} — {pkg}" if ftype == "vulnerability" else f"{ftype.replace('_', ' ').title()} — {pkg}"
        enrich = enrichment.get((f.get("cve_id") or "").upper(), {}) if ftype == "vulnerability" else {}
        remediation = f.get("remediation", "")
        if not remediation and ftype == "vulnerability":
            remediation = (
                f"Upgrade {pkg} to {f['fixed_in']} or later." if f.get("fixed_in")
                else f"No fixed version is published yet for this advisory — track {f.get('osv_url', 'the OSV advisory')} for updates."
            )
        adapted.append({
            "title": title,
            "description": f.get("summary", ""),
            "severity": f.get("severity", "medium"),
            "category": f"supply-chain-{ftype}",
            "affected_asset": f"{pkg}@{version}" if version else pkg,
            "evidence": {"ecosystem": f.get("ecosystem"), "fixed_in": f.get("fixed_in"), "osv_url": f.get("osv_url")},
            "remediation": remediation,
            "cve": [f["cve_id"]] if f.get("cve_id") else ([f["vuln_id"]] if f.get("vuln_id") else []),
            "confidence": _TYPE_CONFIDENCE.get(ftype, "medium"),
            "cvss_score": enrich.get("cvss_v4_score"),
            "epss_score": enrich.get("epss_score"),
            "kev_status": enrich.get("is_kev", False),
        })
    return adapted


# ── Scan generator ─────────────────────────────────────────────────────────────

async def _scan_generator(
    files: list[UploadFile],
    org_id: str,
    scan_id: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()
    all_findings: list[dict] = []
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_packages = 0
    vulnerable_packages: set[str] = set()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        all_deps: list[dict] = []
        manifest_summaries: list[dict] = []

        # Phase 1 — Parse manifests
        yield _sse("phase", {"phase": "parsing", "message": "Parsing dependency manifests..."})
        for upload in files:
            filename = upload.filename or "manifest"
            try:
                raw = await upload.read()
                content = raw.decode("utf-8", errors="replace")
            except Exception:
                continue

            manifest_type, deps = _detect_and_parse(filename, content)
            # Attach ecosystem to each dep
            ecosystem_name = OSV_ECOSYSTEM_MAP.get(manifest_type, manifest_type)
            for d in deps:
                if not d.get("ecosystem"):
                    d["ecosystem"] = ecosystem_name

            yield _sse("manifest_parsed", {
                "filename": filename,
                "manifest_type": manifest_type,
                "package_count": len(deps),
            })
            all_deps.extend(deps)
            total_packages += len(deps)
            manifest_summaries.append({"filename": filename, "manifest_type": manifest_type, "count": len(deps)})
            await asyncio.sleep(0)

        yield _sse("parse_complete", {"total_packages": total_packages})
        await asyncio.sleep(0)

        # Phase 2 — OSV vulnerability lookup
        if all_deps:
            yield _sse("phase", {"phase": "osv", "message": f"Querying OSV.dev for {total_packages} packages..."})
            await asyncio.sleep(0)
            try:
                vuln_findings = await _osv_lookup(all_deps, client)
                for f in vuln_findings:
                    sev = f.get("severity", "medium")
                    by_severity[sev] = by_severity.get(sev, 0) + 1
                    vulnerable_packages.add(f["package"])
                    all_findings.append(f)
                    yield _sse("finding", f)
                    await asyncio.sleep(0)
            except Exception as e:
                yield _sse("phase_error", {"phase": "osv", "message": f"OSV lookup failed: {e}"})

        # Phase 3 — Dependency confusion
        yield _sse("phase", {"phase": "confusion", "message": "Checking for dependency confusion risks..."})
        await asyncio.sleep(0)
        try:
            confusion_findings = await _dependency_confusion_check(all_deps, "", client)
            for f in confusion_findings:
                sev = f.get("severity", "high")
                by_severity[sev] = by_severity.get(sev, 0) + 1
                all_findings.append(f)
                yield _sse("finding", f)
                await asyncio.sleep(0)
        except Exception as e:
            yield _sse("phase_error", {"phase": "confusion", "message": str(e)})

        # Phase 4 — Abandoned/deprecated check
        yield _sse("phase", {"phase": "abandoned", "message": "Checking for abandoned/deprecated packages..."})
        await asyncio.sleep(0)
        try:
            abandoned_findings = await _abandoned_check(all_deps, client)
            for f in abandoned_findings:
                sev = f.get("severity", "medium")
                by_severity[sev] = by_severity.get(sev, 0) + 1
                all_findings.append(f)
                yield _sse("finding", f)
                await asyncio.sleep(0)
        except Exception as e:
            yield _sse("phase_error", {"phase": "abandoned", "message": str(e)})

        # Phase 5 — License risk
        yield _sse("phase", {"phase": "license", "message": "Checking for license risks..."})
        await asyncio.sleep(0)
        try:
            license_findings = await _license_check(all_deps, client)
            for f in license_findings:
                sev = f.get("severity", "info")
                by_severity[sev] = by_severity.get(sev, 0) + 1
                all_findings.append(f)
                yield _sse("finding", f)
                await asyncio.sleep(0)
        except Exception as e:
            yield _sse("phase_error", {"phase": "license", "message": str(e)})

    completed_at = datetime.now(timezone.utc).isoformat()
    summary = {
        "id": scan_id,
        "total_packages": total_packages,
        "vulnerable_packages": len(vulnerable_packages),
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "manifests": manifest_summaries,
    }
    yield _sse("complete", summary)

    record = {
        "id": scan_id,
        "started_at": started_at,
        "completed_at": completed_at,
        "total_packages": total_packages,
        "vulnerable_packages": len(vulnerable_packages),
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "manifests": manifest_summaries,
        "findings": all_findings,
        "dependencies": all_deps,
    }
    _save_scan_result(org_id, record)

    try:
        adapted = await _adapt_supply_chain_findings(all_findings)
        await ingest_findings(db, org_id, source="supply_chain", source_scan_id=scan_id, findings=adapted)
        await db.commit()
    except Exception:
        await db.rollback()


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/history")
async def get_history(
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
):
    return _load_history(str(org_id))


@router.get("/history/{scan_id}")
async def get_scan(
    scan_id: str,
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
):
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}")
async def delete_scan(
    scan_id: str,
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
):
    if not _delete_scan(str(org_id), scan_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return {"deleted": True}


@router.get("/history/{scan_id}/sbom", summary="Export a CycloneDX SBOM for a past scan")
async def get_scan_sbom(
    scan_id: str,
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
):
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    deps = record.get("dependencies") or []
    if not deps:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This scan has no stored dependency list to build an SBOM from")
    try:
        sbom = _build_cyclonedx_sbom(deps, record.get("findings") or [])
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to build SBOM: {exc}")
    return sbom


@router.post("/scan")
async def scan_supply_chain(
    files: list[UploadFile],
    org_id: Annotated[str, Depends(get_current_org_id)] = None,
    current_user: Annotated[User, Depends(get_current_user)] = None,
    db: AsyncSession = Depends(get_db),
):
    if not files:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No files provided")

    scan_id = str(_uuid_mod.uuid4())
    return StreamingResponse(
        _scan_generator(files, str(org_id), scan_id, db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
