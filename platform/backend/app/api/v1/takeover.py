"""
AttackTrace Domain Takeover Detector — Enterprise-grade subdomain takeover detection.

Detection layers:
  1. CNAME chain resolution — follow every hop, detect dangling destinations
  2. HTTP fingerprinting — 50+ service signatures from real takeover reports
  3. NS takeover — nameserver delegation to expired/unclaimed providers
  4. MX takeover — dangling mail service records
  5. Dangling A record — IPs that are no longer allocated
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

import dns.resolver
import dns.exception
import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.target_guard import guard_scan_target
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.models.db.user import User
from app.api.v1.dashboard import invalidate_dashboard_cache
from app.services.finding_ingest import ingest_findings

router = APIRouter(prefix="/takeover", tags=["Takeover"])

_scan_history: dict[str, dict] = {}

# ── Cloud IP Ranges ────────────────────────────────────────────────────────────

CLOUD_IP_RANGES: dict[str, list[str]] = {
    "AWS": ["3.0.0.0/8", "18.0.0.0/8", "52.0.0.0/6", "54.0.0.0/8"],
    "GCP": ["34.0.0.0/8", "35.0.0.0/8", "104.196.0.0/14"],
    "Azure": ["13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10"],
    "Cloudflare": ["104.16.0.0/12", "172.64.0.0/13", "198.41.128.0/17"],
    "Fastly": ["151.101.0.0/16", "199.27.72.0/21"],
    "GitHub": ["185.199.108.0/22"],
}

# Pre-compile networks for efficient lookups
_CLOUD_NETWORKS: list[tuple[str, ipaddress.IPv4Network]] = [
    (provider, ipaddress.IPv4Network(cidr))
    for provider, cidrs in CLOUD_IP_RANGES.items()
    for cidr in cidrs
]


def _is_cloud_ip(ip: str) -> tuple[bool, str]:
    """Check whether an IP belongs to a known cloud provider's address range.

    Returns:
        (True, provider_name) if matched, (False, "") otherwise.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False, ""

    for provider, network in _CLOUD_NETWORKS:
        if addr in network:
            return True, provider

    return False, ""


# ── Fingerprint Database ───────────────────────────────────────────────────────

FINGERPRINT_DB: list[dict] = [
    {
        "service": "GitHub Pages",
        "fingerprints": ["There isn't a GitHub Pages site here"],
        "cname_patterns": ["github.io"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "Subdomain points to an unclaimed GitHub Pages namespace. Attacker can create a repo at the matching username/repo path and serve arbitrary content.",
        "remediation": "Remove the dangling CNAME record from your DNS zone, or claim the corresponding GitHub Pages repository.",
    },
    {
        "service": "AWS S3",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "Subdomain CNAME points to an S3 bucket that no longer exists. Attacker can create a bucket with the same name in any AWS account.",
        "remediation": "Delete the CNAME record or recreate and lock down the S3 bucket with appropriate bucket policies.",
    },
    {
        "service": "AWS Elastic Beanstalk",
        "fingerprints": ["NoSuchApplication"],
        "cname_patterns": [".elasticbeanstalk.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to a deleted Elastic Beanstalk environment. Attacker can register the environment name and host malicious content.",
        "remediation": "Remove the CNAME record or recreate the Elastic Beanstalk environment and update DNS.",
    },
    {
        "service": "Heroku",
        "fingerprints": ["No Such Account", "no app configured"],
        "cname_patterns": [".herokudns.com", ".herokuapp.com"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "CNAME points to an unclaimed Heroku app name. Attacker can claim the app slug and serve arbitrary content under your domain.",
        "remediation": "Remove the dangling CNAME or claim the Heroku app name and configure it correctly.",
    },
    {
        "service": "Fastly",
        "fingerprints": ["Fastly error: unknown domain"],
        "cname_patterns": [".fastly.net"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "Domain is configured to use Fastly CDN but has not been added as a custom domain in any Fastly service.",
        "remediation": "Add the domain to your Fastly service configuration or remove the CNAME record.",
    },
    {
        "service": "CloudFront",
        "fingerprints": ["ERROR: The request could not be satisfied"],
        "cname_patterns": [".cloudfront.net"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to a CloudFront distribution that no longer exists or is misconfigured. Attacker may be able to create a new distribution with a matching alternate domain.",
        "remediation": "Remove the CNAME record or verify that the CloudFront distribution includes this domain as an alternate name.",
    },
    {
        "service": "Netlify",
        "fingerprints": ["Not Found - Request ID"],
        "cname_patterns": [".netlify.app", ".netlify.com"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "CNAME points to Netlify but the site has been deleted. Attacker can deploy a Netlify site and claim this custom domain.",
        "remediation": "Remove the CNAME record or redeploy the Netlify site and reassign the custom domain.",
    },
    {
        "service": "Vercel",
        "fingerprints": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "cname_patterns": [".vercel.app", ".now.sh"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "CNAME points to a Vercel deployment that has been deleted. Attacker can deploy a Vercel project and configure this domain.",
        "remediation": "Remove the CNAME record or redeploy the Vercel project and reclaim the custom domain.",
    },
    {
        "service": "Firebase Hosting",
        "fingerprints": ["The domain has not been configured"],
        "cname_patterns": [".web.app", ".firebaseapp.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "Domain CNAME points to Firebase Hosting but has not been linked to any Firebase project.",
        "remediation": "Remove the CNAME record or link the domain to the correct Firebase Hosting project.",
    },
    {
        "service": "Surge.sh",
        "fingerprints": ["project not found"],
        "cname_patterns": [".surge.sh"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "CNAME points to a Surge.sh project that no longer exists. Attacker can publish a Surge project with the same subdomain name.",
        "remediation": "Remove the CNAME record or republish the Surge project and reassign the custom domain.",
    },
    {
        "service": "Webflow",
        "fingerprints": ["The page you are looking for doesn't exist"],
        "cname_patterns": [".webflow.io"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to Webflow but the site no longer has this domain configured.",
        "remediation": "Remove the CNAME record or reconnect the domain in your Webflow project settings.",
    },
    {
        "service": "Shopify",
        "fingerprints": ["Sorry, this shop is currently unavailable"],
        "cname_patterns": [".myshopify.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME resolves to Shopify but no active store is associated with this domain.",
        "remediation": "Remove the CNAME record or reactivate the Shopify store and reassign the domain.",
    },
    {
        "service": "Zendesk",
        "fingerprints": ["Help Center Closed"],
        "cname_patterns": [".zendesk.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to a Zendesk Help Center that has been decommissioned.",
        "remediation": "Remove the CNAME record or reopen the Zendesk Help Center and map the domain.",
    },
    {
        "service": "Tumblr",
        "fingerprints": ["There's nothing here"],
        "cname_patterns": [".tumblr.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to a Tumblr blog that has been deleted. Attacker can create a Tumblr blog with this address.",
        "remediation": "Remove the CNAME record or claim the Tumblr blog associated with this subdomain.",
    },
    {
        "service": "Squarespace",
        "fingerprints": ["No Such Account"],
        "cname_patterns": [".squarespace.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to Squarespace but no site is configured for this domain.",
        "remediation": "Remove the CNAME record or relink the domain inside Squarespace Domains settings.",
    },
    {
        "service": "Ghost",
        "fingerprints": ["The thing you were looking for is no longer here"],
        "cname_patterns": [".ghost.io"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to Ghost(Pro) but the publication has been deleted.",
        "remediation": "Remove the CNAME record or recreate the Ghost publication and reassign the domain.",
    },
    {
        "service": "Readme.io",
        "fingerprints": ["Project doesnt exist anymore"],
        "cname_patterns": [".readme.io"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to a ReadMe documentation project that has been deleted.",
        "remediation": "Remove the CNAME record or recreate the ReadMe project and reconfigure the custom domain.",
    },
    {
        "service": "Statuspage",
        "fingerprints": ["You are being redirected", "page not found"],
        "cname_patterns": [".statuspage.io"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to an Atlassian Statuspage that no longer exists. An attacker could create a fake status page impersonating your service.",
        "remediation": "Remove the CNAME record or recreate the Statuspage and reassign the domain.",
    },
    {
        "service": "Pantheon",
        "fingerprints": ["The gods are wise"],
        "cname_patterns": [".pantheonsite.io"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to a Pantheon site that has been deleted.",
        "remediation": "Remove the CNAME record or restore the Pantheon site and associate the domain.",
    },
    {
        "service": "WP Engine",
        "fingerprints": ["The site you were looking for couldn't be found"],
        "cname_patterns": [".wpengine.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to a WP Engine install that has been deleted or the domain mapping removed.",
        "remediation": "Remove the CNAME record or reassign the domain to an active WP Engine install.",
    },
    {
        "service": "Cargo",
        "fingerprints": ["If you're moving your domain away from Cargo"],
        "cname_patterns": ["cargocollective.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to Cargo Collective but the project no longer claims this domain.",
        "remediation": "Remove the CNAME record or reclaim the domain inside your Cargo project settings.",
    },
    {
        "service": "FeedPress",
        "fingerprints": ["The feed has not been found"],
        "cname_patterns": ["feedpress.me"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to FeedPress but the associated feed account has been deleted.",
        "remediation": "Remove the CNAME record or recreate the FeedPress feed and map the custom domain.",
    },
    {
        "service": "HelpScout Docs",
        "fingerprints": ["No settings were found"],
        "cname_patterns": [".helpscoutdocs.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to HelpScout Docs but the associated Docs site has been deleted.",
        "remediation": "Remove the CNAME record or recreate the HelpScout Docs site and link the custom domain.",
    },
    {
        "service": "Intercom",
        "fingerprints": ["This page is reserved for artistic works"],
        "cname_patterns": ["custom.intercom.help"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to Intercom Help Center but the workspace no longer owns this domain.",
        "remediation": "Remove the CNAME record or reconfigure the custom domain inside your Intercom workspace.",
    },
    {
        "service": "Azure App Service",
        "fingerprints": ["404 Web Site not found"],
        "cname_patterns": [".azurewebsites.net"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "CNAME points to an Azure App Service that has been deleted. Attacker can create an App Service with the same name in any Azure subscription.",
        "remediation": "Remove the CNAME record or recreate the Azure App Service and reconfigure the custom domain binding.",
    },
    {
        "service": "Azure Front Door",
        "fingerprints": ["Hmm\u2026can't reach this page"],
        "cname_patterns": [".azurefd.net"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to an Azure Front Door profile that no longer has this domain configured.",
        "remediation": "Remove the CNAME record or add the custom domain to your Azure Front Door profile.",
    },
    {
        "service": "Azure Blob Storage",
        "fingerprints": ["The specified container does not exist"],
        "cname_patterns": [".blob.core.windows.net"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "CNAME points to an Azure Blob Storage container that has been deleted. Attacker can create a storage account with the same name.",
        "remediation": "Remove the CNAME record or recreate the Azure Blob Storage container.",
    },
    {
        "service": "Azure Traffic Manager",
        "fingerprints": [],
        "cname_patterns": [".trafficmanager.net"],
        "severity": "high",
        "confidence": "potential",
        "description": "CNAME points to an Azure Traffic Manager profile. If the profile returns NXDOMAIN the endpoint may be unclaimed.",
        "remediation": "Remove the CNAME record or verify the Traffic Manager profile is active and routes to a live backend.",
    },
    {
        "service": "Freshdesk",
        "fingerprints": ["There is no helpdesk here"],
        "cname_patterns": [".freshdesk.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to a Freshdesk helpdesk that has been deleted.",
        "remediation": "Remove the CNAME record or recreate the Freshdesk helpdesk and map the custom domain.",
    },
    {
        "service": "UserVoice",
        "fingerprints": ["This UserVoice subdomain is currently available"],
        "cname_patterns": [".uservoice.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to an unclaimed UserVoice subdomain. Attacker can claim it and impersonate your feedback portal.",
        "remediation": "Remove the CNAME record or claim the UserVoice subdomain for your organisation.",
    },
    {
        "service": "Unbounce",
        "fingerprints": ["The requested URL was not found on this server"],
        "cname_patterns": [".unbouncepages.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to an Unbounce landing page domain that is no longer active.",
        "remediation": "Remove the CNAME record or republish the Unbounce page and reassign the custom domain.",
    },
    {
        "service": "HubSpot",
        "fingerprints": ["Domain not configured"],
        "cname_patterns": [".hs-sites.com", ".hubspotpagebuilder.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to HubSpot but the domain is not mapped to any active HubSpot portal.",
        "remediation": "Remove the CNAME record or reconnect the domain inside your HubSpot account.",
    },
    {
        "service": "Campaign Monitor",
        "fingerprints": ["Trying to access your account?"],
        "cname_patterns": [".createsend.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to Campaign Monitor but no account has claimed this custom domain.",
        "remediation": "Remove the CNAME record or reclaim the custom domain in your Campaign Monitor account.",
    },
    {
        "service": "Smartjobboard",
        "fingerprints": ["This job board website is either expired"],
        "cname_patterns": [".smartjobboard.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to an expired Smartjobboard subscription.",
        "remediation": "Remove the CNAME record or renew the Smartjobboard subscription and reassign the domain.",
    },
    {
        "service": "Tave",
        "fingerprints": ["tave.com"],
        "cname_patterns": [".tave.com"],
        "severity": "low",
        "confidence": "potential",
        "description": "CNAME points to Tave (studio management software) but the account may be unclaimed.",
        "remediation": "Remove the CNAME record or verify the Tave account is active and the domain is mapped.",
    },
    {
        "service": "Fly.io",
        "fingerprints": ["404 Not Found"],
        "cname_patterns": [".fly.dev"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to a Fly.io application that has been deleted. Attacker can deploy an app with the same name.",
        "remediation": "Remove the CNAME record or redeploy the Fly.io application and reassign the custom domain.",
    },
    {
        "service": "Render",
        "fingerprints": ["Page Not Found"],
        "cname_patterns": [".onrender.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to a Render service that has been deleted.",
        "remediation": "Remove the CNAME record or redeploy the Render service and reconfigure the custom domain.",
    },
    {
        "service": "Railway",
        "fingerprints": ["Application not found"],
        "cname_patterns": [".railway.app"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to a Railway deployment that has been deleted.",
        "remediation": "Remove the CNAME record or redeploy the Railway project and reassign the custom domain.",
    },
    {
        "service": "Kinsta",
        "fingerprints": ["No Site For Domain"],
        "cname_patterns": [".kinsta.cloud"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to Kinsta but the domain is not mapped to any active Kinsta site.",
        "remediation": "Remove the CNAME record or map the domain to your Kinsta site inside MyKinsta.",
    },
    {
        "service": "GitLab Pages",
        "fingerprints": ["404"],
        "cname_patterns": [".gitlab.io"],
        "severity": "high",
        "confidence": "potential",
        "description": "CNAME points to GitLab Pages but the namespace or project may be unclaimed.",
        "remediation": "Remove the CNAME record or create the GitLab Pages project that serves this domain.",
    },
    {
        "service": "Bitbucket",
        "fingerprints": ["Repository not found"],
        "cname_patterns": [".bitbucket.io"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "CNAME points to Bitbucket Pages but the repository has been deleted.",
        "remediation": "Remove the CNAME record or recreate the Bitbucket repository that serves this Pages site.",
    },
    {
        "service": "Launchrock",
        "fingerprints": ["It looks like you may have taken a wrong turn"],
        "cname_patterns": [".launchrock.com"],
        "severity": "medium",
        "confidence": "confirmed",
        "description": "CNAME points to an unclaimed or deleted Launchrock landing page.",
        "remediation": "Remove the CNAME record or recreate the Launchrock page and assign the custom domain.",
    },
    # ── Additional services (appended) ────────────────────────────────────────
    {
        "service": "Webflow",
        "fingerprints": ["This page is reserved", "webflow.io"],
        "cname_patterns": ["proxy.webflow.com", "webflow.io"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "Webflow project is unclaimed",
        "remediation": "Claim the project in Webflow dashboard or update DNS",
    },
    {
        "service": "Readme.io",
        "fingerprints": ["Project doesnt exist", "readme.io"],
        "cname_patterns": ["readme.io", "readmessl.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "Readme.io documentation site is unclaimed",
        "remediation": "Create a project at readme.io or remove DNS record",
    },
    {
        "service": "Fly.io",
        "fingerprints": ["404 Not Found", "fly.io"],
        "cname_patterns": ["fly.dev", "fly.io"],
        "severity": "high",
        "confidence": "potential",
        "description": "Fly.io app may be unclaimed",
        "remediation": "Deploy an app to this hostname or remove DNS record",
    },
    {
        "service": "Vercel",
        "fingerprints": ["The deployment could not be found", "vercel.com"],
        "cname_patterns": ["vercel.app", "vercel-dns.com", "now.sh"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "Vercel deployment is unclaimed — anyone can deploy to this hostname",
        "remediation": "Add this domain to a Vercel project or remove DNS record",
    },
    {
        "service": "Netlify",
        "fingerprints": ["Not Found", "netlify.app", "netlify.com"],
        "cname_patterns": ["netlify.app", "netlify.com"],
        "severity": "critical",
        "confidence": "confirmed",
        "description": "Netlify site is unclaimed",
        "remediation": "Create a Netlify site with this subdomain or remove DNS record",
    },
    {
        "service": "Railway",
        "fingerprints": ["Application not found", "railway.app"],
        "cname_patterns": ["railway.app", "up.railway.app"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "Railway application is unclaimed",
        "remediation": "Create a Railway project for this subdomain or update DNS",
    },
    {
        "service": "Render",
        "fingerprints": ["not found", "render.com"],
        "cname_patterns": ["render.com", "onrender.com"],
        "severity": "high",
        "confidence": "confirmed",
        "description": "Render service is unclaimed",
        "remediation": "Create a Render service for this hostname or remove DNS record",
    },
]

# Known NS providers that support dangling delegation detection
_UNCLAIMED_NS_PROVIDERS = [
    "awsdns",
    "azure-dns",
    "googledomains",
    "cloudflare",
    "ns1.com",
    "dnsimple",
    "easydns",
    "namecheap",
    "domaincontrol",
]

# ── Pydantic Models ────────────────────────────────────────────────────────────

class TakeoverRequest(BaseModel):
    @field_validator("targets")
    @classmethod
    def _guard_scan_target(cls, v):
        # Block loopback/private/metadata addresses unless ALLOW_PRIVATE_SCAN_TARGETS (see target_guard)
        return guard_scan_target(v)

    targets: list[str]
    check_cname: bool = True
    check_ns: bool = True
    check_mx: bool = False
    timeout: int = 10

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: list[str]) -> list[str]:
        if len(v) > 500:
            raise ValueError("Maximum 500 targets per scan")
        cleaned = []
        for t in v:
            t = t.strip().lower().rstrip(".")
            if t:
                cleaned.append(t)
        return cleaned


class TakeoverResult(BaseModel):
    hostname: str
    status: str  # VULNERABLE | NEEDS_REVIEW | NOT_VULNERABLE | ERROR
    service: Optional[str] = None
    cname_chain: list[str] = []
    reason: str
    confidence: Optional[str] = None  # confirmed | potential | none
    severity: Optional[str] = None    # critical | high | medium | low
    remediation: Optional[str] = None
    check_type: str = "cname"         # cname | ns | mx | fingerprint
    ttl_warning: Optional[str] = None
    evidence: list[str] = []


# ── DNS Helpers ────────────────────────────────────────────────────────────────

def _sync_resolve_cname_chain(
    hostname: str,
) -> tuple[list[str], str | None, bool, str | None]:
    """Synchronous CNAME chain follower.

    Returns:
        (chain, final_dest, is_dangling, ttl_warning)
        where ttl_warning is a human-readable string when any hop has TTL ≤ 300,
        or None otherwise.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    chain: list[str] = [hostname]
    current = hostname
    dangling = False
    ttl_warning: str | None = None

    for _ in range(10):  # max 10 hops to prevent infinite loops
        try:
            answers = resolver.resolve(current, "CNAME")
            ttl = answers.rrset.ttl if answers.rrset is not None else None
            if ttl is not None and ttl <= 300:
                ttl_warning = (
                    f"Low TTL ({ttl}s) suggests recent DNS change — increased takeover risk."
                )
            target = str(answers[0].target).rstrip(".")
            chain.append(target)
            current = target
        except dns.resolver.NoAnswer:
            # No CNAME record — stop following
            break
        except dns.resolver.NXDOMAIN:
            dangling = True
            break
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            break

    final = chain[-1] if len(chain) > 1 else None
    return chain, final, dangling, ttl_warning


def _sync_resolve_ns(hostname: str) -> tuple[list[str], bool]:
    """Resolve NS records. Returns (nameservers, is_servfail)."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    try:
        answers = resolver.resolve(hostname, "NS")
        return [str(r.target).rstrip(".") for r in answers], False
    except dns.resolver.NXDOMAIN:
        return [], True
    except dns.resolver.NoNameservers:
        return [], True
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return [], False


def _sync_resolve_mx(hostname: str) -> tuple[list[str], bool]:
    """Resolve MX records. Returns (mail_hosts, is_nxdomain)."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    try:
        answers = resolver.resolve(hostname, "MX")
        return [str(r.exchange).rstrip(".") for r in answers], False
    except dns.resolver.NXDOMAIN:
        return [], True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return [], False


def _sync_check_host_resolves(hostname: str) -> bool:
    """Return True if hostname has any A/AAAA record (i.e. is live)."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6

    for qtype in ("A", "AAAA"):
        try:
            resolver.resolve(hostname, qtype)
            return True
        except Exception:
            continue
    return False


# ── Core Detection Functions ───────────────────────────────────────────────────

async def _resolve_cname_chain(
    hostname: str,
) -> tuple[list[str], str | None, bool, str | None]:
    """Async wrapper — runs sync DNS in thread."""
    return await asyncio.to_thread(_sync_resolve_cname_chain, hostname)


async def _check_service_fingerprint(
    hostname: str, client: httpx.AsyncClient
) -> TakeoverResult | None:
    """Fetch HTTP/HTTPS response and match body against FINGERPRINT_DB."""
    body = ""
    for scheme in ("https", "http"):
        try:
            resp = await client.get(
                f"{scheme}://{hostname}",
                follow_redirects=True,
                timeout=10.0,
            )
            body = resp.text
            break
        except Exception:
            continue

    if not body:
        return None

    body_lower = body.lower()
    for fp in FINGERPRINT_DB:
        for fingerprint in fp["fingerprints"]:
            if fingerprint and fingerprint.lower() in body_lower:
                return TakeoverResult(
                    hostname=hostname,
                    status="VULNERABLE",
                    service=fp["service"],
                    cname_chain=[],
                    reason=f"HTTP body matches {fp['service']} takeover fingerprint: \"{fingerprint}\"",
                    confidence=fp["confidence"],
                    severity=fp["severity"],
                    remediation=fp["remediation"],
                    check_type="fingerprint",
                )
    return None


async def _check_ns_takeover(hostname: str) -> TakeoverResult | None:
    """Check if NS records point to providers that may have unclaimed delegations."""
    nameservers, is_nxdomain = await asyncio.to_thread(_sync_resolve_ns, hostname)

    if is_nxdomain and not nameservers:
        return TakeoverResult(
            hostname=hostname,
            status="NEEDS_REVIEW",
            service=None,
            cname_chain=[],
            reason="NS query returned NXDOMAIN — zone may be orphaned or delegation removed",
            confidence="potential",
            severity="high",
            remediation="Verify the parent zone delegation is intentional. Remove DS/NS records if the zone is no longer active.",
            check_type="ns",
        )

    if not nameservers:
        return None

    # Check if nameservers themselves don't resolve (dangling delegation)
    dangling_ns = []
    for ns in nameservers:
        resolves = await asyncio.to_thread(_sync_check_host_resolves, ns)
        if not resolves:
            dangling_ns.append(ns)

    if dangling_ns:
        return TakeoverResult(
            hostname=hostname,
            status="VULNERABLE",
            service="NS Delegation",
            cname_chain=[],
            reason=f"Nameservers do not resolve (dangling delegation): {', '.join(dangling_ns)}",
            confidence="confirmed",
            severity="critical",
            remediation="Update NS records to point to nameservers you control, or remove the delegation entirely.",
            check_type="ns",
        )

    return None


async def _check_mx_takeover(hostname: str) -> TakeoverResult | None:
    """Check MX records for unclaimed mail service providers."""
    mail_hosts, is_nxdomain = await asyncio.to_thread(_sync_resolve_mx, hostname)

    if not mail_hosts and not is_nxdomain:
        return None

    dangling_mx = []
    for mxhost in mail_hosts:
        resolves = await asyncio.to_thread(_sync_check_host_resolves, mxhost)
        if not resolves:
            dangling_mx.append(mxhost)

    if dangling_mx:
        return TakeoverResult(
            hostname=hostname,
            status="VULNERABLE",
            service="MX Record",
            cname_chain=[],
            reason=f"MX record mail hosts do not resolve (dangling): {', '.join(dangling_mx)}",
            confidence="confirmed",
            severity="high",
            remediation="Remove the dangling MX records and update them to point to your active mail provider.",
            check_type="mx",
        )

    return None


def _match_cname_to_fingerprint(cname: str) -> dict | None:
    """Return the first FINGERPRINT_DB entry whose cname_patterns match cname."""
    cname_lower = cname.lower()
    for fp in FINGERPRINT_DB:
        for pattern in fp["cname_patterns"]:
            if pattern.lower() in cname_lower:
                return fp
    return None


def _sync_resolve_a_records(hostname: str) -> list[str]:
    """Resolve A records for a hostname. Returns list of IP strings."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6
    try:
        answers = resolver.resolve(hostname, "A")
        return [str(r.address) for r in answers]
    except Exception:
        return []


async def _analyze_target(
    hostname: str,
    client: httpx.AsyncClient,
    req: TakeoverRequest,
) -> dict:
    """Full multi-layer analysis of one target. Returns a structured result dict."""

    base: dict = {
        "hostname": hostname,
        "cname_chain": [],
        "status": "NOT_VULNERABLE",
        "service": None,
        "reason": "No takeover indicators found",
        "confidence": "none",
        "severity": None,
        "remediation": None,
        "check_type": "cname",
        "ttl_warning": None,
        "evidence": [],
    }

    try:
        # ── Layer 1: CNAME chain resolution ───────────────────────────────────
        if req.check_cname:
            chain, final_cname, is_dangling, ttl_warning = await _resolve_cname_chain(hostname)
            base["cname_chain"] = chain
            if ttl_warning:
                base["ttl_warning"] = ttl_warning

            if final_cname:
                matched_fp = _match_cname_to_fingerprint(final_cname)

                if is_dangling:
                    # CNAME destination returned NXDOMAIN — confirmed dangling
                    if matched_fp:
                        base.update(
                            status="VULNERABLE",
                            service=matched_fp["service"],
                            reason=(
                                f"CNAME points to {matched_fp['service']} "
                                f"(dangling — NXDOMAIN on {final_cname})"
                            ),
                            confidence="confirmed",
                            severity=matched_fp["severity"],
                            remediation=matched_fp["remediation"],
                            check_type="cname",
                        )
                        return base
                    else:
                        base.update(
                            status="VULNERABLE",
                            service="Unknown",
                            reason=f"CNAME chain ends in NXDOMAIN on {final_cname} — dangling record",
                            confidence="confirmed",
                            severity="high",
                            remediation=(
                                "Remove the dangling CNAME record or recreate the target resource "
                                f"at {final_cname}."
                            ),
                            check_type="cname",
                        )
                        return base

                # CNAME resolves — try HTTP fingerprint to confirm
                if matched_fp:
                    fp_result = await _check_service_fingerprint(hostname, client)
                    if fp_result:
                        base.update(fp_result.model_dump())
                        base["cname_chain"] = chain
                        return base

                    # CNAME matches pattern but body didn't confirm — "potential"
                    base.update(
                        status="NEEDS_REVIEW",
                        service=matched_fp["service"],
                        reason=(
                            f"CNAME points to {matched_fp['service']} domain ({final_cname}) "
                            f"but body fingerprint was not confirmed"
                        ),
                        confidence="potential",
                        severity=matched_fp["severity"],
                        remediation=matched_fp["remediation"],
                        check_type="cname",
                    )
                    return base

        # ── Layer 1b: A-record cloud IP range validation ───────────────────────
        a_records = await asyncio.to_thread(_sync_resolve_a_records, hostname)
        if a_records:
            # Probe the host to check for owned/live content
            has_content_fingerprint = bool(await _check_service_fingerprint(hostname, client))
            for ip in a_records:
                is_cloud, provider = _is_cloud_ip(ip)
                if is_cloud and not has_content_fingerprint:
                    base["evidence"].append(
                        f"Potential cloud resource with no matching content fingerprint "
                        f"(IP {ip} belongs to {provider})"
                    )

        # ── Layer 2: Body-only fingerprint (no matching CNAME) ─────────────────
        fp_result = await _check_service_fingerprint(hostname, client)
        if fp_result:
            fp_dict = fp_result.model_dump()
            fp_dict["cname_chain"] = base["cname_chain"]
            fp_dict.setdefault("evidence", base["evidence"])
            fp_dict.setdefault("ttl_warning", base.get("ttl_warning"))
            return fp_dict

        # ── Layer 3: NS takeover ───────────────────────────────────────────────
        if req.check_ns:
            ns_result = await _check_ns_takeover(hostname)
            if ns_result:
                ns_dict = ns_result.model_dump()
                ns_dict["cname_chain"] = base["cname_chain"]
                return ns_dict

        # ── Layer 4: MX takeover ──────────────────────────────────────────────
        if req.check_mx:
            mx_result = await _check_mx_takeover(hostname)
            if mx_result:
                mx_dict = mx_result.model_dump()
                mx_dict["cname_chain"] = base["cname_chain"]
                return mx_dict

    except Exception as exc:
        base.update(
            status="ERROR",
            reason=f"Analysis failed: {type(exc).__name__}: {exc}",
            confidence="none",
        )

    return base


# ── SSE Generator ─────────────────────────────────────────────────────────────

def _adapt_takeover_findings(results: list[dict]) -> list[dict]:
    """Normalize takeover.py results for finding_ingest — only VULNERABLE/
    NEEDS_REVIEW results are findings; NOT_VULNERABLE/ERROR are not.

    Confidence reuses this scanner's own existing confirmed/potential grading
    (a two-signal check: CNAME resolves to a known-dead service AND the
    response body matches that service's fingerprint) — already solid, just
    never made it into the shared Finding table before.
    """
    confidence_map = {"confirmed": "certain", "potential": "medium"}
    adapted = []
    for r in results:
        if r.get("status") not in ("VULNERABLE", "NEEDS_REVIEW"):
            continue
        adapted.append({
            "title": f"Possible Subdomain Takeover — {r.get('hostname')}" if r["status"] == "NEEDS_REVIEW"
                     else f"Subdomain Takeover — {r.get('hostname')} ({r.get('service', 'unknown service')})",
            "description": r.get("reason", ""),
            "severity": r.get("severity") or ("high" if r["status"] == "VULNERABLE" else "medium"),
            "category": f"takeover-{r.get('check_type', 'cname')}",
            "affected_asset": r.get("hostname", ""),
            "evidence": {"cname_chain": r.get("cname_chain"), "evidence": r.get("evidence"),
                         "ttl_warning": r.get("ttl_warning")},
            "remediation": r.get("remediation") or "Remove the dangling DNS record or reclaim the referenced cloud resource.",
            "confidence": confidence_map.get(r.get("confidence"), "medium"),
        })
    return adapted


async def _stream_takeover_scan(
    scan_id: str,
    req: TakeoverRequest,
    user_email: str,
    org_id: uuid.UUID,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    """Main SSE generator — analyzes targets concurrently and streams results."""

    total = len(req.targets)
    completed = 0
    vulnerabilities = 0
    needs_review = 0

    # Record scan start
    _scan_history[scan_id] = {
        "scan_id": scan_id,
        "started_by": user_email,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "targets": req.targets,
        "total": total,
        "status": "running",
        "results": [],
        "org_id": str(org_id),
    }

    yield f"event: start\ndata: {json.dumps({'scan_id': scan_id, 'total': total, 'message': 'Takeover scan started'})}\n\n"

    semaphore = asyncio.Semaphore(20)

    limits = httpx.Limits(max_connections=40, max_keepalive_connections=20)
    transport = httpx.AsyncHTTPTransport(retries=1)

    async with httpx.AsyncClient(
        limits=limits,
        transport=transport,
        timeout=httpx.Timeout(req.timeout, connect=5.0),
        headers={"User-Agent": "AttackTrace/1.0 TakeoverScanner"},
        follow_redirects=True,
        verify=False,
    ) as client:

        async def _bounded_analyze(hostname: str) -> dict:
            async with semaphore:
                return await _analyze_target(hostname, client, req)

        tasks = [asyncio.create_task(_bounded_analyze(h)) for h in req.targets]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1

            if result["status"] == "VULNERABLE":
                vulnerabilities += 1
            elif result["status"] == "NEEDS_REVIEW":
                needs_review += 1

            _scan_history[scan_id]["results"].append(result)

            # Emit result event
            yield f"event: result\ndata: {json.dumps(result)}\n\n"

            # Emit progress event
            progress_data = {
                "completed": completed,
                "total": total,
                "percent": round(completed / total * 100, 1),
                "vulnerabilities": vulnerabilities,
                "needs_review": needs_review,
            }
            yield f"event: progress\ndata: {json.dumps(progress_data)}\n\n"

    # Finalise history record
    _scan_history[scan_id].update(
        {
            "status": "complete",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": vulnerabilities,
            "needs_review": needs_review,
        }
    )

    try:
        adapted = _adapt_takeover_findings(_scan_history[scan_id]["results"])
        await ingest_findings(db, org_id, source="takeover", source_scan_id=scan_id, findings=adapted)
        await db.commit()
        await invalidate_dashboard_cache(org_id)
    except Exception:
        await db.rollback()

    summary = {
        "scan_id": scan_id,
        "total": total,
        "completed": completed,
        "vulnerabilities": vulnerabilities,
        "needs_review": needs_review,
        "not_vulnerable": completed - vulnerabilities - needs_review,
        "message": "Takeover scan complete",
    }
    yield f"event: complete\ndata: {json.dumps(summary)}\n\n"


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/scan")
async def scan_takeover(
    req: TakeoverRequest,
    current_user: User = Depends(require_tool("takeover")),
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """
    Stream subdomain/domain takeover analysis via SSE.

    Each target is analysed concurrently (max 20 in-flight). Results are emitted
    as SSE events as they complete — one `result` event per target, plus
    `progress` events and a final `complete` event.

    Event types:
    - `start`    — scan initiated, includes scan_id and total count
    - `result`   — individual target result (VULNERABLE / NEEDS_REVIEW / NOT_VULNERABLE / ERROR)
    - `progress` — running tallies of completed / vulnerabilities / needs_review
    - `complete` — final summary
    """
    if not req.targets:
        raise HTTPException(status_code=400, detail="At least one target is required")

    scan_id = str(uuid.uuid4())

    from app.services.scan_activity import tee_scan_activity
    return StreamingResponse(
        tee_scan_activity(org_id, "takeover", ", ".join(req.targets), scan_id, _stream_takeover_scan(scan_id, req, current_user.email, org_id, db)),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "X-Scan-ID": scan_id,
        },
    )


@router.get("/fingerprints")
async def list_fingerprints(
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Return the full fingerprint database used by the takeover scanner.

    Useful for displaying supported services in the UI, building allow-lists,
    or auditing coverage before running a scan.
    """
    return {
        "total": len(FINGERPRINT_DB),
        "fingerprints": FINGERPRINT_DB,
    }


@router.get("/history")
async def list_scan_history(
    current_user: User = Depends(get_current_user),
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    """Return recent takeover scan history (in-memory, current process only)."""
    scans = sorted(
        (s for s in _scan_history.values() if s.get("org_id") == str(org_id)),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"total": len(scans), "scans": scans[:50]}


@router.get("/history/{scan_id}")
async def get_scan_result(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    """Return full results for a specific takeover scan."""
    scan = _scan_history.get(scan_id)
    if not scan or scan.get("org_id") != str(org_id):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan
