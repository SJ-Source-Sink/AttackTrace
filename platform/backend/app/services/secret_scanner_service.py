"""
Secret scanning service.

Checks common sensitive file paths on web targets for exposed credentials,
configuration files, and secrets. Also supports trufflehog-based git scanning.
"""

import asyncio
import json
import shutil

COMMON_SECRET_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/config.yaml",
    "/.git/config",
    "/wp-config.php",
    "/database.yml",
    "/secrets.yaml",
    "/credentials.json",
    "/service-account.json",
]


async def scan_url_for_secrets(base_url: str) -> list[dict]:
    """Check common secret file paths on a web target."""
    import httpx
    secrets = []
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
            for path in COMMON_SECRET_PATHS:
                try:
                    resp = await client.get(base_url.rstrip("/") + path)
                    if resp.status_code == 200 and len(resp.text) > 20:
                        # Check if it looks like actual config content
                        content = resp.text[:500]
                        if any(kw in content.lower() for kw in ["password", "secret", "key", "token", "database"]):
                            secrets.append({
                                "title": f"Exposed Configuration File: {path}",
                                "severity": "critical",
                                "category": "exposed_secret",
                                "affected_asset": base_url.rstrip("/") + path,
                                "description": f"Configuration file accessible at {path}. May contain sensitive credentials.",
                                "evidence": [{"title": "Response Preview", "content": content[:200] + "..."}],
                                "remediation": (
                                    f"Immediately restrict access to {path}. "
                                    "Remove from web root or add to .htaccess/nginx deny rules."
                                ),
                            })
                except Exception:
                    pass
    except Exception:
        pass
    return secrets


async def run_trufflehog_scan(git_url: str) -> list[dict]:
    """Run trufflehog against a git URL if available."""
    trufflehog = shutil.which("trufflehog")
    if not trufflehog:
        return []
    secrets = []
    try:
        proc = await asyncio.create_subprocess_exec(
            trufflehog, "git", git_url, "--json", "--no-update",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        for line in stdout.decode().splitlines():
            try:
                finding = json.loads(line)
                detector = finding.get("DetectorName", "Unknown")
                raw = finding.get("Raw", "")[:50] + "..." if finding.get("Raw") else "REDACTED"
                source = finding.get("SourceMetadata", {}).get("Data", {})
                file_path = source.get("Git", {}).get("file", "")
                secrets.append({
                    "title": f"Exposed {detector} Secret in Git Repository",
                    "severity": "critical",
                    "category": "exposed_secret",
                    "affected_asset": git_url,
                    "description": f"A {detector} secret was found in the Git history. File: {file_path}",
                    "evidence": [{"title": "Secret Preview (Redacted)", "content": raw}],
                    "remediation": (
                        "Rotate the exposed credential immediately. "
                        "Use git-filter-repo to remove from history. "
                        "Add secret scanning to CI/CD."
                    ),
                })
            except Exception:
                pass
    except Exception:
        pass
    return secrets
