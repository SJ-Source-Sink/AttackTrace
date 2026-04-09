"""
Database layer for AttackTrace.

Provides persistence for scan sessions and discovered assets using TinyDB
for simplicity and portability.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

from attacktrace.core.models import (
    ScanSession,
    Domain,
    Subdomain,
    IPAddress,
    WebApplication,
    CloudAsset,
    Finding,
    Certificate,
    ModuleResult,
    ScanStatus,
)


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class Database:
    """Database interface for AttackTrace."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the database.

        Args:
            db_path: Path to the database file. If None, uses in-memory storage.
        """
        if db_path:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.db = TinyDB(
                db_path,
                storage=CachingMiddleware(JSONStorage),
            )
        else:
            self.db = TinyDB(storage=CachingMiddleware(JSONStorage))
            self.db.storage.memory = {}

        # Tables
        self.sessions = self.db.table("sessions")
        self.domains = self.db.table("domains")
        self.subdomains = self.db.table("subdomains")
        self.ip_addresses = self.db.table("ip_addresses")
        self.web_applications = self.db.table("web_applications")
        self.cloud_assets = self.db.table("cloud_assets")
        self.findings = self.db.table("findings")
        self.certificates = self.db.table("certificates")

    def close(self) -> None:
        """Close the database connection."""
        self.db.close()

    # Session operations
    def create_session(self, session: ScanSession) -> str:
        """Create a new scan session."""
        data = json.loads(session.model_dump_json())
        self.sessions.insert(data)
        return session.id

    def get_session(self, session_id: str) -> Optional[ScanSession]:
        """Get a scan session by ID."""
        Session = Query()
        result = self.sessions.search(Session.id == session_id)
        if result:
            return ScanSession(**result[0])
        return None

    def update_session(self, session: ScanSession) -> None:
        """Update an existing scan session."""
        Session = Query()
        session.updated_at = datetime.utcnow()
        data = json.loads(session.model_dump_json())
        self.sessions.update(data, Session.id == session.id)

    def delete_session(self, session_id: str) -> bool:
        """Delete a scan session."""
        Session = Query()
        removed = self.sessions.remove(Session.id == session_id)
        return len(removed) > 0

    def list_sessions(
        self,
        status: Optional[ScanStatus] = None,
        limit: int = 50
    ) -> list[ScanSession]:
        """List scan sessions, optionally filtered by status."""
        if status:
            Session = Query()
            results = self.sessions.search(Session.status == status.value)
        else:
            results = self.sessions.all()

        # Sort by created_at descending
        results = sorted(results, key=lambda x: x.get("created_at", ""), reverse=True)

        return [ScanSession(**r) for r in results[:limit]]

    # Domain operations
    def add_domain(self, session_id: str, domain: Domain) -> None:
        """Add a domain to a session."""
        data = json.loads(domain.model_dump_json())
        data["session_id"] = session_id
        self.domains.insert(data)

    def get_domains(self, session_id: str) -> list[Domain]:
        """Get all domains for a session."""
        DomainQuery = Query()
        results = self.domains.search(DomainQuery.session_id == session_id)
        return [Domain(**{k: v for k, v in r.items() if k != "session_id"}) for r in results]

    def update_domain(self, session_id: str, domain: Domain) -> None:
        """Update a domain."""
        DomainQuery = Query()
        data = json.loads(domain.model_dump_json())
        data["session_id"] = session_id
        self.domains.update(
            data,
            (DomainQuery.session_id == session_id) & (DomainQuery.fqdn == domain.fqdn)
        )

    # Subdomain operations
    def add_subdomain(self, session_id: str, subdomain: Subdomain) -> None:
        """Add a subdomain to a session."""
        data = json.loads(subdomain.model_dump_json())
        data["session_id"] = session_id
        self.subdomains.insert(data)

    def add_subdomains_bulk(self, session_id: str, subdomains: list[Subdomain]) -> int:
        """Add multiple subdomains in bulk."""
        data_list = []
        for subdomain in subdomains:
            data = json.loads(subdomain.model_dump_json())
            data["session_id"] = session_id
            data_list.append(data)
        self.subdomains.insert_multiple(data_list)
        return len(data_list)

    def get_subdomains(self, session_id: str) -> list[Subdomain]:
        """Get all subdomains for a session."""
        SubdomainQuery = Query()
        results = self.subdomains.search(SubdomainQuery.session_id == session_id)
        return [Subdomain(**{k: v for k, v in r.items() if k != "session_id"}) for r in results]

    def subdomain_exists(self, session_id: str, fqdn: str) -> bool:
        """Check if a subdomain already exists."""
        SubdomainQuery = Query()
        result = self.subdomains.search(
            (SubdomainQuery.session_id == session_id) & (SubdomainQuery.fqdn == fqdn)
        )
        return len(result) > 0

    def update_subdomain(self, session_id: str, subdomain: "Subdomain") -> None:
        """Update an existing subdomain with new data (e.g., resolved IPs)."""
        SubdomainQuery = Query()
        data = json.loads(subdomain.model_dump_json())
        data["session_id"] = session_id
        self.subdomains.update(
            data,
            (SubdomainQuery.session_id == session_id) & (SubdomainQuery.fqdn == subdomain.fqdn)
        )

    # IP Address operations
    def add_ip_address(self, session_id: str, ip: IPAddress) -> None:
        """Add an IP address to a session."""
        data = json.loads(ip.model_dump_json())
        data["session_id"] = session_id
        self.ip_addresses.insert(data)

    def add_ip_addresses_bulk(self, session_id: str, ips: list[IPAddress]) -> int:
        """Add multiple IP addresses in bulk."""
        data_list = []
        for ip in ips:
            data = json.loads(ip.model_dump_json())
            data["session_id"] = session_id
            data_list.append(data)
        self.ip_addresses.insert_multiple(data_list)
        return len(data_list)

    def get_ip_addresses(self, session_id: str) -> list[IPAddress]:
        """Get all IP addresses for a session."""
        IPQuery = Query()
        results = self.ip_addresses.search(IPQuery.session_id == session_id)
        return [IPAddress(**{k: v for k, v in r.items() if k != "session_id"}) for r in results]

    def update_ip_address(self, session_id: str, ip: IPAddress) -> None:
        """Update an IP address."""
        IPQuery = Query()
        data = json.loads(ip.model_dump_json())
        data["session_id"] = session_id
        self.ip_addresses.update(
            data,
            (IPQuery.session_id == session_id) & (IPQuery.address == ip.address)
        )

    def ip_exists(self, session_id: str, address: str) -> bool:
        """Check if an IP address already exists."""
        IPQuery = Query()
        result = self.ip_addresses.search(
            (IPQuery.session_id == session_id) & (IPQuery.address == address)
        )
        return len(result) > 0

    # Web Application operations
    def add_web_application(self, session_id: str, webapp: WebApplication) -> None:
        """Add a web application to a session."""
        data = json.loads(webapp.model_dump_json())
        data["session_id"] = session_id
        self.web_applications.insert(data)

    def add_web_applications_bulk(self, session_id: str, webapps: list[WebApplication]) -> int:
        """Add multiple web applications in bulk."""
        data_list = []
        for webapp in webapps:
            data = json.loads(webapp.model_dump_json())
            data["session_id"] = session_id
            data_list.append(data)
        self.web_applications.insert_multiple(data_list)
        return len(data_list)

    def get_web_applications(self, session_id: str) -> list[WebApplication]:
        """Get all web applications for a session."""
        WebAppQuery = Query()
        results = self.web_applications.search(WebAppQuery.session_id == session_id)
        return [
            WebApplication(**{k: v for k, v in r.items() if k != "session_id"})
            for r in results
        ]

    def update_web_application(self, session_id: str, webapp: WebApplication) -> None:
        """Update a web application (e.g., with screenshot path)."""
        WebAppQuery = Query()
        data = json.loads(webapp.model_dump_json())
        data["session_id"] = session_id
        self.web_applications.update(
            data,
            (WebAppQuery.session_id == session_id) & (WebAppQuery.url == webapp.url)
        )

    # Cloud Asset operations
    def add_cloud_asset(self, session_id: str, asset: CloudAsset) -> None:
        """Add a cloud asset to a session."""
        data = json.loads(asset.model_dump_json())
        data["session_id"] = session_id
        self.cloud_assets.insert(data)

    def get_cloud_assets(self, session_id: str) -> list[CloudAsset]:
        """Get all cloud assets for a session."""
        AssetQuery = Query()
        results = self.cloud_assets.search(AssetQuery.session_id == session_id)
        return [CloudAsset(**{k: v for k, v in r.items() if k != "session_id"}) for r in results]

    # Finding operations
    def add_finding(self, session_id: str, finding: Finding) -> None:
        """Add a finding to a session."""
        data = json.loads(finding.model_dump_json())
        data["session_id"] = session_id
        self.findings.insert(data)

    def add_findings_bulk(self, session_id: str, findings: list[Finding]) -> int:
        """Add multiple findings in bulk."""
        data_list = []
        for finding in findings:
            data = json.loads(finding.model_dump_json())
            data["session_id"] = session_id
            data_list.append(data)
        self.findings.insert_multiple(data_list)
        return len(data_list)

    def get_findings(self, session_id: str) -> list[Finding]:
        """Get all findings for a session."""
        FindingQuery = Query()
        results = self.findings.search(FindingQuery.session_id == session_id)
        return [Finding(**{k: v for k, v in r.items() if k != "session_id"}) for r in results]

    # Certificate operations
    def add_certificate(self, session_id: str, cert: Certificate) -> None:
        """Add a certificate to a session."""
        data = json.loads(cert.model_dump_json())
        data["session_id"] = session_id
        self.certificates.insert(data)

    def get_certificates(self, session_id: str) -> list[Certificate]:
        """Get all certificates for a session."""
        CertQuery = Query()
        results = self.certificates.search(CertQuery.session_id == session_id)
        return [Certificate(**{k: v for k, v in r.items() if k != "session_id"}) for r in results]

    # Utility methods
    def get_all_unique_ips(self, session_id: str) -> set[str]:
        """Get all unique IP addresses discovered in a session."""
        ips = set()

        # From IP addresses table
        for ip in self.get_ip_addresses(session_id):
            ips.add(ip.address)

        # From subdomain resolutions
        for subdomain in self.get_subdomains(session_id):
            ips.update(subdomain.resolved_ips)

        return ips

    def get_all_unique_domains(self, session_id: str) -> set[str]:
        """Get all unique domains and subdomains."""
        domains = set()

        for domain in self.get_domains(session_id):
            domains.add(domain.fqdn)

        for subdomain in self.get_subdomains(session_id):
            domains.add(subdomain.fqdn)

        return domains

    def get_session_summary(self, session_id: str) -> dict:
        """Get a summary of session findings."""
        session = self.get_session(session_id)
        if not session:
            return {}

        findings = self.get_findings(session_id)

        return {
            "session_id": session_id,
            "status": session.status.value,
            "target": session.target_company or ", ".join(session.target_domains),
            "domains": len(self.get_domains(session_id)),
            "subdomains": len(self.get_subdomains(session_id)),
            "ip_addresses": len(self.get_ip_addresses(session_id)),
            "web_applications": len(self.get_web_applications(session_id)),
            "cloud_assets": len(self.get_cloud_assets(session_id)),
            "findings": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity.value == "critical"),
                "high": sum(1 for f in findings if f.severity.value == "high"),
                "medium": sum(1 for f in findings if f.severity.value == "medium"),
                "low": sum(1 for f in findings if f.severity.value == "low"),
            },
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "updated_at": session.updated_at.isoformat() if session.updated_at else None,
        }

    def export_session(self, session_id: str) -> dict:
        """Export all session data as a dictionary."""
        session = self.get_session(session_id)
        if not session:
            return {}

        return {
            "session": json.loads(session.model_dump_json()),
            "domains": [json.loads(d.model_dump_json()) for d in self.get_domains(session_id)],
            "subdomains": [
                json.loads(s.model_dump_json()) for s in self.get_subdomains(session_id)
            ],
            "ip_addresses": [
                json.loads(ip.model_dump_json()) for ip in self.get_ip_addresses(session_id)
            ],
            "web_applications": [
                json.loads(w.model_dump_json()) for w in self.get_web_applications(session_id)
            ],
            "cloud_assets": [
                json.loads(c.model_dump_json()) for c in self.get_cloud_assets(session_id)
            ],
            "findings": [
                json.loads(f.model_dump_json()) for f in self.get_findings(session_id)
            ],
            "certificates": [
                json.loads(c.model_dump_json()) for c in self.get_certificates(session_id)
            ],
        }
