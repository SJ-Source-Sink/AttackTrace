"""
AI Risk Score computation for findings.

Returns a (score, explanation, factors) tuple where:
  score       — 0–100 float
  explanation — human-readable string for display
  factors     — structured list for programmatic drilling-down in the UI
"""

from typing import Optional


def compute_risk_score(
    severity: str,
    cvss: Optional[float],
    epss: Optional[float],
    kev_status: bool,
    priority_score: Optional[float],
) -> tuple[float, str]:
    """Return (score 0-100, explanation string).

    Scoring model:
      base  = CVSS×10 if available, else severity default
      boost = EPSS×25  (up to +25 for certainty of exploitation)
      boost += 15      if in CISA KEV (actively exploited)
    Score is capped at 100.
    """
    severity_base = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
    base = cvss * 10 if cvss else severity_base.get(severity.lower(), 40)
    epss_boost = (epss or 0) * 25
    kev_boost = 15 if kev_status else 0
    score = min(100.0, round(base + epss_boost + kev_boost, 1))

    # Build structured factors list (used by UI for drill-down tooltips)
    factors = []
    if kev_status:
        factors.append({
            "name": "CISA KEV",
            "description": "Actively exploited in the wild",
            "contribution": kev_boost,
            "icon": "flame",
        })
    if epss is not None and epss > 0:
        factors.append({
            "name": "EPSS",
            "description": f"{epss:.1%} probability of exploitation in next 30 days",
            "contribution": round(epss_boost, 1),
            "icon": "trending-up",
        })
    if cvss:
        factors.append({
            "name": "CVSS",
            "description": f"CVSS score {cvss:.1f}/10",
            "contribution": round(base, 1),
            "icon": "shield",
        })
    else:
        factors.append({
            "name": "Severity",
            "description": f"Severity-based default ({severity})",
            "contribution": round(base, 1),
            "icon": "alert-triangle",
        })

    # Plain-text parts for the explanation string
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
