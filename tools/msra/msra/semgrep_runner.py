"""
Optional Semgrep integration for MSRA.
Runs semgrep on decompiled Java/Kotlin sources and converts results to Finding objects.
Falls back silently if semgrep is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import List

from .utils import Evidence, Finding

# Default ruleset — can be overridden via MSRA_SEMGREP_RULES env var
import os
SEMGREP_RULES = os.environ.get("MSRA_SEMGREP_RULES", "p/java")

_SEVERITY_MAP = {
    "ERROR":   "High",
    "WARNING": "Medium",
    "INFO":    "Low",
}


def is_available() -> bool:
    return shutil.which("semgrep") is not None


def run(sources_root: str, timeout: int = 180) -> List[Finding]:
    """
    Run semgrep on sources_root and return Finding objects.
    Returns an empty list if semgrep is not installed, times out, or fails.
    """
    if not is_available():
        return []

    try:
        result = subprocess.run(
            [
                "semgrep", "--json",
                "--config", SEMGREP_RULES,
                "--no-git-ignore",
                "--quiet",
                sources_root,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return _parse(result.stdout)
    except subprocess.TimeoutExpired:
        print("[!] Semgrep timed out — skipping")
        return []
    except Exception as e:
        print(f"[!] Semgrep error: {e}")
        return []


def _parse(json_text: str) -> List[Finding]:
    try:
        data = json.loads(json_text)
    except Exception:
        return []

    findings: List[Finding] = []
    for r in data.get("results", []):
        extra_meta = r.get("extra", {})
        meta       = extra_meta.get("metadata", {})
        severity   = _SEVERITY_MAP.get(extra_meta.get("severity", "WARNING"), "Medium")
        check_id   = r.get("check_id", "unknown")
        path       = r.get("path", "")
        line       = r.get("start", {}).get("line", 0)
        snippet    = extra_meta.get("lines", "")

        evidence = Evidence(
            file_path=path,
            line_number=line,
            snippet=snippet,
            matched_text=snippet,
        )

        # Build a readable title from the check ID
        rule_short = check_id.split(".")[-1].replace("-", " ").replace("_", " ").title()
        title = f"[Semgrep] {rule_short}"

        refs = meta.get("references", [])
        if isinstance(refs, str):
            refs = [refs]

        findings.append(Finding(
            fid=f"semgrep:{check_id}:{path}:{line}",
            title=title,
            severity=severity,
            description=extra_meta.get("message", ""),
            attack_path="",
            adb_commands=[],
            evidence=evidence,
            references=refs or None,
            extra={
                "source":     "semgrep",
                "rule_id":    check_id,
                "category":   meta.get("category", "Other"),
                "cwe":        meta.get("cwe", []),
                "confidence": "medium",
            },
        ))

    return findings
