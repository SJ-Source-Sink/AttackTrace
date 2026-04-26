"""
AI Risk Score computation for findings.
"""

from typing import Optional


def compute_risk_score(
    severity: str,
    cvss: Optional[float],
    epss: Optional[float],
    kev_status: bool,
    priority_score: Optional[float],
) -> tuple[float, str]:
    """Return (score 0-100, explanation string)"""
    severity_base = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
    base = cvss * 10 if cvss else severity_base.get(severity.lower(), 40)
    epss_boost = (epss or 0) * 25
    kev_boost = 15 if kev_status else 0
    score = min(100.0, round(base + epss_boost + kev_boost, 1))

    parts = []
    if kev_status:
        parts.append("actively exploited (CISA KEV)")
    if epss and epss > 0.1:
        parts.append(f"high exploit probability ({epss:.0%} EPSS)")
    if cvss and cvss >= 9.0:
        parts.append(f"critical CVSS {cvss:.1f}")
    elif cvss and cvss >= 7.0:
        parts.append(f"high CVSS {cvss:.1f}")

    if score >= 85:
        urgency = "Immediate action required"
    elif score >= 60:
        urgency = "High priority remediation needed"
    elif score >= 35:
        urgency = "Should be addressed in next sprint"
    else:
        urgency = "Low priority, schedule for maintenance window"

    explanation = (
        f"Risk score {score:.0f}/100. "
        + (f"Factors: {', '.join(parts)}. " if parts else "")
        + urgency
        + "."
    )
    return score, explanation
