"""
Network Graph API — builds interactive graph data from assets and findings.

Endpoints:
  GET /network/graph         — full graph for a scan or org-wide
  GET /network/graph/timeline — per-scan snapshots ordered by completion time
  GET /network/graph/stats   — quick aggregated stats without building the graph
"""

from collections import defaultdict
from typing import Annotated
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.asset import Asset, AssetType
from app.models.db.finding import Finding, FindingStatus
from app.models.db.scan import ScanJob, ScanStatus
from app.models.db.user import User

router = APIRouter(prefix="/network", tags=["Network Graph"])

# ---------------------------------------------------------------------------
# Severity ordering (higher index = worse)
# ---------------------------------------------------------------------------
_SEV_ORDER: dict[str, int] = {
    "none": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

_ACTIVE_FINDING_STATUSES = [
    FindingStatus.OPEN,
    FindingStatus.IN_PROGRESS,
]


def _worse_severity(a: str, b: str) -> str:
    """Return whichever severity string is more severe (case-insensitive)."""
    a_lower, b_lower = a.lower(), b.lower()
    return a_lower if _SEV_ORDER.get(a_lower, 0) >= _SEV_ORDER.get(b_lower, 0) else b_lower


def _extract_hostname(url: str) -> str:
    """Parse hostname from a URL string; fallback to the raw value."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.hostname or url
    except Exception:
        return url


def _root_domain(hostname: str) -> str:
    """Return the last two dot-separated parts of a hostname (e.g. example.com)."""
    parts = hostname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _fetch_assets(
    db: AsyncSession,
    org_id: UUID,
    scan_id: UUID | None,
) -> list[Asset]:
    """Fetch only the columns needed for graph construction (not full ORM objects)."""
    cols = [Asset.id, Asset.asset_type, Asset.value, Asset.metadata_,
            Asset.risk_score, Asset.scan_job_id, Asset.org_id, Asset.is_active]
    if scan_id is not None:
        stmt = select(*cols).where(
            and_(Asset.org_id == org_id, Asset.scan_job_id == scan_id)
        )
    else:
        stmt = select(*cols).where(
            and_(Asset.org_id == org_id, Asset.is_active == True)  # noqa: E712
        ).limit(5000)  # safety cap — graph becomes unreadable beyond 5k nodes
    result = await db.execute(stmt)
    # Return as lightweight row objects that have the same attribute access as ORM objects
    return list(result.mappings().all())  # type: ignore[return-value]


async def _fetch_findings_for_assets(
    db: AsyncSession,
    org_id: UUID,
    asset_ids: list[UUID],
    assets: list,
) -> list:
    """Fetch findings and return records keyed to asset IDs.

    Two strategies used together:
    1. Direct asset_id FK match (populated for newer scans).
    2. affected_asset text match against asset.value (covers older scans
       where asset_id was not backfilled on findings).
    """
    if not asset_ids:
        return []

    # Build value → id map for fuzzy matching
    value_to_asset_id: dict[str, UUID] = {
        a.value.lower().rstrip("/"): a.id for a in assets
    }

    stmt = select(
        Finding.id, Finding.asset_id, Finding.affected_asset,
        Finding.severity, Finding.status,
    ).where(
        and_(
            Finding.org_id == org_id,
            Finding.status.in_(_ACTIVE_FINDING_STATUSES),
        )
    ).where(
        # Either directly linked OR same scan scope
        Finding.asset_id.in_(asset_ids) | Finding.scan_job_id.in_(
            select(Asset.scan_job_id).where(Asset.id.in_(asset_ids)).distinct()
        )
    )
    result = await db.execute(stmt)
    rows = list(result.mappings().all())

    # Enrich rows that lack asset_id by matching affected_asset → asset.value
    enriched = []
    for row in rows:
        r = dict(row)
        if r.get("asset_id") is None and r.get("affected_asset"):
            key = (r["affected_asset"] or "").lower().rstrip("/")
            matched_id = value_to_asset_id.get(key)
            if matched_id is None:
                # Try stripping scheme for webapp matching
                for suffix in [key.removeprefix("https://"), key.removeprefix("http://")]:
                    matched_id = value_to_asset_id.get(suffix)
                    if matched_id:
                        break
            if matched_id:
                r["asset_id"] = matched_id
        enriched.append(r)
    return enriched


def _build_finding_index(
    findings: list,
) -> dict[UUID, dict]:
    """
    Returns a dict keyed by asset_id → {count, worst_severity}.
    Handles both UUID asset_id values and None (skips unresolved findings).
    """
    index: dict[UUID, dict] = defaultdict(lambda: {"count": 0, "worst_severity": "none"})
    for f in findings:
        aid = f.get("asset_id") if hasattr(f, "get") else getattr(f, "asset_id", None)
        if aid is None:
            continue
        entry = index[aid]
        entry["count"] += 1
        sev = f.get("severity") if hasattr(f, "get") else getattr(f, "severity", None)
        sev_val = sev.value if hasattr(sev, "value") else str(sev)
        entry["worst_severity"] = _worse_severity(entry["worst_severity"], sev_val.lower())
    return dict(index)


def _build_nodes(
    assets: list[Asset],
    finding_index: dict[UUID, dict],
) -> list[dict]:
    nodes = []
    for asset in assets:
        meta = asset.metadata_ or {}
        finfo = finding_index.get(asset.id, {"count": 0, "worst_severity": "none"})
        node = {
            "id": f"asset:{asset.id}",
            "type": asset.asset_type.value,
            "label": asset.value[:60],
            "severity": finfo["worst_severity"],
            "finding_count": finfo["count"],
            "risk_score": asset.risk_score,
            "scan_id": str(asset.scan_job_id) if asset.scan_job_id else None,
            "metadata": {
                "ip": meta.get("ip"),
                "ips": meta.get("ips", []),
                "ports": meta.get("ports", []),
                "tech": meta.get("tech", []),
                "cdn": meta.get("cdn"),
                "asn": meta.get("asn"),
                "country": meta.get("country"),
                "status_code": meta.get("status_code"),
                "title": meta.get("title"),
                "cloud_provider": meta.get("cloud_provider"),
            },
        }
        nodes.append(node)
    return nodes


def _build_edges(assets: list[Asset]) -> list[dict]:
    """
    Derive edges from asset relationships:
      - resolves_to : subdomain/domain → ip (via metadata_.ip / metadata_.ips)
      - hosted_on   : webapp → subdomain/domain/ip (via parsed hostname)
      - parent_domain: domain → subdomain (root domain match)
    """
    # Build lookup maps
    value_to_node_id: dict[str, str] = {}
    for asset in assets:
        value_to_node_id[asset.value.lower()] = f"asset:{asset.id}"

    edges_set: set[tuple[str, str, str]] = set()
    edges: list[dict] = []

    def _add_edge(source: str, target: str, etype: str, label: str) -> None:
        key = (source, target, etype)
        if key not in edges_set and source != target:
            edges_set.add(key)
            edges.append({"source": source, "target": target, "type": etype, "label": label})

    for asset in assets:
        node_id = f"asset:{asset.id}"
        meta = asset.metadata_ or {}

        # resolves_to: subdomain / domain → IP asset
        if asset.asset_type in (AssetType.SUBDOMAIN, AssetType.DOMAIN):
            candidate_ips: list[str] = []
            single_ip = meta.get("ip")
            if single_ip:
                candidate_ips.append(str(single_ip).lower())
            for ip in meta.get("ips", []):
                candidate_ips.append(str(ip).lower())
            for ip_val in candidate_ips:
                target_node = value_to_node_id.get(ip_val)
                if target_node:
                    _add_edge(node_id, target_node, "resolves_to", "resolves to")

        # hosted_on: webapp → subdomain / domain / ip
        if asset.asset_type == AssetType.WEBAPP:
            hostname = _extract_hostname(asset.value).lower()
            # Try exact hostname match, then root domain match
            target_node = value_to_node_id.get(hostname)
            if target_node:
                _add_edge(node_id, target_node, "hosted_on", "hosted on")
            else:
                root = _root_domain(hostname)
                target_node = value_to_node_id.get(root)
                if target_node:
                    _add_edge(node_id, target_node, "hosted_on", "hosted on")

        # parent_domain: domain → its subdomains
        if asset.asset_type == AssetType.DOMAIN:
            domain_val = asset.value.lower().lstrip("*.")
            for other in assets:
                if other.id == asset.id:
                    continue
                if other.asset_type != AssetType.SUBDOMAIN:
                    continue
                sub_val = other.value.lower()
                if sub_val.endswith(f".{domain_val}") or sub_val == domain_val:
                    sub_node = f"asset:{other.id}"
                    _add_edge(node_id, sub_node, "parent_domain", "parent domain")

    return edges


def _build_attack_path_edges(
    edges: list[dict],
    finding_index: dict,
    assets: list,
) -> list[dict]:
    """
    Derive attack_path edges: connect nodes with critical/high findings
    that are already linked via any existing edge. This surfaces the most
    dangerous traversal paths through the graph.

    Strategy:
    1. Collect all node IDs that have critical or high severity findings.
    2. For each existing edge where BOTH endpoints are high-risk, add an
       attack_path edge in the same direction.
    3. Also add attack_path edges from any critical node to nodes it
       connects to (even if the target is medium severity) — a critical
       entry point can pivot anywhere it reaches.
    """
    # Build asset id → node id map
    asset_node_map: dict = {f"asset:{a.id}": a.id for a in assets}

    critical_nodes: set[str] = set()
    high_nodes: set[str] = set()
    medium_nodes: set[str] = set()
    for node_id, asset_id in asset_node_map.items():
        sev = finding_index.get(asset_id, {}).get("worst_severity", "none")
        if sev == "critical":
            critical_nodes.add(node_id)
        elif sev == "high":
            high_nodes.add(node_id)
        elif sev == "medium":
            medium_nodes.add(node_id)

    # Use the highest available tier; fall back to medium if no critical/high exist
    if critical_nodes or high_nodes:
        primary_nodes = critical_nodes | high_nodes
        pivot_nodes = critical_nodes          # critical can reach anything
    elif medium_nodes:
        primary_nodes = medium_nodes
        pivot_nodes = medium_nodes
    else:
        return []

    attack_edges_set: set[tuple] = set()
    attack_edges: list[dict] = []

    def _add(src: str, tgt: str) -> None:
        key = (src, tgt)
        if key not in attack_edges_set and src != tgt:
            attack_edges_set.add(key)
            attack_edges.append({
                "source": src,
                "target": tgt,
                "type": "attack_path",
                "label": "attack path",
            })

    for edge in edges:
        src, tgt = edge["source"], edge["target"]
        # Both endpoints are risk nodes → definite attack path
        if src in primary_nodes and tgt in primary_nodes:
            _add(src, tgt)
        # Pivot nodes (critical/high) can reach any connected node
        elif src in pivot_nodes:
            _add(src, tgt)

    return attack_edges


def _compute_stats(
    assets: list[Asset],
    edges: list[dict],
    finding_index: dict[UUID, dict],
) -> dict:
    asset_type_counts: dict[str, int] = defaultdict(int)
    critical_nodes = 0
    high_nodes = 0
    for asset in assets:
        asset_type_counts[asset.asset_type.value] += 1
        finfo = finding_index.get(asset.id, {"worst_severity": "none"})
        sev = finfo["worst_severity"]
        if sev == "critical":
            critical_nodes += 1
        elif sev == "high":
            high_nodes += 1

    return {
        "total_nodes": len(assets),
        "total_edges": len(edges),
        "critical_nodes": critical_nodes,
        "high_nodes": high_nodes,
        "asset_types": dict(asset_type_counts),
    }


# ---------------------------------------------------------------------------
# Endpoint 1: Full graph
# ---------------------------------------------------------------------------

@router.get("/graph", summary="Build network graph for a scan or org-wide")
async def get_network_graph(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    scan_id: UUID | None = Query(default=None, description="Scope graph to a specific scan; omit for org-wide"),
) -> dict:
    # 1. Assets
    assets = await _fetch_assets(db, org_id, scan_id)

    # 2. Findings grouped by asset
    asset_ids = [a.id for a in assets]
    findings = await _fetch_findings_for_assets(db, org_id, asset_ids, assets)
    finding_index = _build_finding_index(findings)

    # 3. Nodes
    nodes = _build_nodes(assets, finding_index)

    # 4. Edges
    edges = _build_edges(assets)
    attack_path_edges = _build_attack_path_edges(edges, finding_index, assets)
    edges = edges + attack_path_edges

    # 5. Stats
    stats = _compute_stats(assets, edges, finding_index)

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": stats,
        "scan_id": str(scan_id) if scan_id else None,
    }


# ---------------------------------------------------------------------------
# Endpoint 2: Timeline — one snapshot per completed scan
# ---------------------------------------------------------------------------

@router.get("/graph/timeline", summary="Graph snapshots per completed scan")
async def get_graph_timeline(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # Fetch last 20 completed scans
    scans_result = await db.execute(
        select(ScanJob)
        .where(and_(ScanJob.org_id == org_id, ScanJob.status == ScanStatus.COMPLETED))
        .order_by(ScanJob.completed_at.asc())
        .limit(20)
    )
    scans: list[ScanJob] = list(scans_result.scalars().all())

    if not scans:
        return {"snapshots": []}

    scan_ids = [s.id for s in scans]

    # Asset counts per scan
    asset_count_rows = await db.execute(
        select(Asset.scan_job_id, func.count().label("cnt"))
        .where(Asset.scan_job_id.in_(scan_ids))
        .group_by(Asset.scan_job_id)
    )
    asset_counts: dict[UUID, int] = {row[0]: row[1] for row in asset_count_rows.all()}

    # Finding counts by severity per scan
    finding_rows = await db.execute(
        select(Finding.scan_job_id, Finding.severity, func.count().label("cnt"))
        .where(
            and_(
                Finding.scan_job_id.in_(scan_ids),
                Finding.status.in_(_ACTIVE_FINDING_STATUSES),
            )
        )
        .group_by(Finding.scan_job_id, Finding.severity)
    )
    finding_by_scan: dict[UUID, dict[str, int]] = defaultdict(
        lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    for row in finding_rows.all():
        scan_fid, severity, cnt = row[0], row[1], row[2]
        finding_by_scan[scan_fid][severity.value] = cnt

    snapshots = []
    for scan in scans:
        fc = finding_by_scan.get(scan.id, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        snapshots.append({
            "scan_id": str(scan.id),
            "scan_name": scan.company_name or (
                ", ".join(scan.target_domains[:2]) if scan.target_domains else str(scan.id)
            ),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "asset_count": asset_counts.get(scan.id, 0),
            "finding_counts": {
                "critical": fc.get("critical", 0),
                "high": fc.get("high", 0),
                "medium": fc.get("medium", 0),
                "low": fc.get("low", 0),
                "info": fc.get("info", 0),
            },
        })

    return {"snapshots": snapshots}


# ---------------------------------------------------------------------------
# Endpoint 3: Quick stats
# ---------------------------------------------------------------------------

@router.get("/graph/stats", summary="Quick org-wide network graph stats")
async def get_graph_stats(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # Assets by type
    asset_type_rows = await db.execute(
        select(Asset.asset_type, func.count().label("cnt"))
        .where(and_(Asset.org_id == org_id, Asset.is_active == True))  # noqa: E712
        .group_by(Asset.asset_type)
    )
    assets_by_type: dict[str, int] = {
        row[0].value: row[1] for row in asset_type_rows.all()
    }
    total_assets = sum(assets_by_type.values())

    # Active findings by severity
    finding_sev_rows = await db.execute(
        select(Finding.severity, func.count().label("cnt"))
        .where(
            and_(
                Finding.org_id == org_id,
                Finding.status.in_(_ACTIVE_FINDING_STATUSES),
            )
        )
        .group_by(Finding.severity)
    )
    findings_by_severity: dict[str, int] = {
        row[0].value: row[1] for row in finding_sev_rows.all()
    }
    total_findings = sum(findings_by_severity.values())

    # Most connected assets: top 10 assets by active finding count
    top_assets_rows = await db.execute(
        select(
            Finding.asset_id,
            func.count().label("finding_cnt"),
        )
        .where(
            and_(
                Finding.org_id == org_id,
                Finding.asset_id.isnot(None),
                Finding.status.in_(_ACTIVE_FINDING_STATUSES),
            )
        )
        .group_by(Finding.asset_id)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_asset_tuples = top_assets_rows.all()

    # Fetch asset details for the top assets
    top_asset_ids = [row[0] for row in top_asset_tuples]
    top_asset_count_map: dict[UUID, int] = {row[0]: row[1] for row in top_asset_tuples}

    most_connected: list[dict] = []
    if top_asset_ids:
        asset_detail_rows = await db.execute(
            select(Asset).where(Asset.id.in_(top_asset_ids))
        )
        asset_details: list[Asset] = list(asset_detail_rows.scalars().all())
        # Preserve ordering by finding count descending
        asset_details.sort(
            key=lambda a: top_asset_count_map.get(a.id, 0), reverse=True
        )
        for asset in asset_details:
            most_connected.append({
                "asset_id": str(asset.id),
                "node_id": f"asset:{asset.id}",
                "value": asset.value[:80],
                "type": asset.asset_type.value,
                "finding_count": top_asset_count_map.get(asset.id, 0),
                "risk_score": asset.risk_score,
            })

    return {
        "total_assets": total_assets,
        "assets_by_type": assets_by_type,
        "total_active_findings": total_findings,
        "findings_by_severity": {
            "critical": findings_by_severity.get("critical", 0),
            "high": findings_by_severity.get("high", 0),
            "medium": findings_by_severity.get("medium", 0),
            "low": findings_by_severity.get("low", 0),
            "info": findings_by_severity.get("info", 0),
        },
        "most_connected_assets": most_connected,
    }
