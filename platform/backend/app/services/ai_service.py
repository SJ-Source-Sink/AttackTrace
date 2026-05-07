"""
AI service using Anthropic Claude for security finding triage,
natural-language search translation, executive summary generation,
and Jira ticket generation.
"""

import asyncio
import json
import logging
import time
from typing import Optional

import anthropic

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_AI_TIMEOUT = 60  # seconds per request
_AI_MAX_RETRIES = 3

# --- Redis-backed AI circuit breaker ---
# Trips after 5 consecutive failures; auto-resets after 60s (half-open probe).
# Prevents cascading timeouts when the Anthropic API is degraded.
_CB_FAILURE_THRESHOLD = 5
_CB_OPEN_TIMEOUT = 60  # seconds before attempting half-open probe
_CB_KEY = "ai:circuit_breaker"


def _cb_is_open() -> bool:
    """Return True if the circuit is open and AI calls should be skipped."""
    try:
        import redis as _redis_sync
        r = _redis_sync.from_url(settings.REDIS_URL, socket_connect_timeout=1, decode_responses=True)
        state = r.get(f"{_CB_KEY}:state")
        if state == "open":
            last_fail = float(r.get(f"{_CB_KEY}:last_fail") or 0)
            if time.time() - last_fail > _CB_OPEN_TIMEOUT:
                r.set(f"{_CB_KEY}:state", "half_open")
                r.close()
                return False  # allow one probe request
            r.close()
            return True
        r.close()
    except Exception:
        pass  # Redis unavailable → treat as closed (fail open)
    return False


def _cb_record_success() -> None:
    try:
        import redis as _redis_sync
        r = _redis_sync.from_url(settings.REDIS_URL, socket_connect_timeout=1, decode_responses=True)
        r.delete(f"{_CB_KEY}:failures", f"{_CB_KEY}:state", f"{_CB_KEY}:last_fail")
        r.close()
    except Exception:
        pass


def _cb_record_failure() -> None:
    try:
        import redis as _redis_sync
        r = _redis_sync.from_url(settings.REDIS_URL, socket_connect_timeout=1, decode_responses=True)
        failures = int(r.incr(f"{_CB_KEY}:failures") or 0)
        r.set(f"{_CB_KEY}:last_fail", time.time())
        r.expire(f"{_CB_KEY}:failures", 300)  # reset counter after 5 min inactivity
        if failures >= _CB_FAILURE_THRESHOLD:
            r.set(f"{_CB_KEY}:state", "open")
            logger.warning(f"AI circuit breaker OPENED after {failures} consecutive failures")
        r.close()
    except Exception:
        pass


def _get_client() -> anthropic.Anthropic:
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not configured")
    return anthropic.Anthropic(
        api_key=settings.ANTHROPIC_API_KEY,
        timeout=_AI_TIMEOUT,
        max_retries=0,  # We handle retries ourselves for better control
    )


async def _call_with_retry(client: anthropic.Anthropic, **kwargs) -> anthropic.types.Message:
    """Call Claude with exponential backoff on transient errors and circuit breaker protection."""
    if _cb_is_open():
        raise RuntimeError("AI circuit breaker is open — Anthropic API is currently degraded")

    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(_AI_MAX_RETRIES):
        try:
            result = client.messages.create(**kwargs)
            _cb_record_success()
            return result
        except anthropic.RateLimitError as exc:
            wait = 2 ** attempt
            logger.warning(f"AI rate limited, retrying in {wait}s (attempt {attempt + 1})")
            _cb_record_failure()
            await asyncio.sleep(wait)
            last_exc = exc
        except (anthropic.APITimeoutError, anthropic.APIConnectionError) as exc:
            wait = 2 ** attempt
            logger.warning(f"AI transient error: {exc}, retrying in {wait}s (attempt {attempt + 1})")
            _cb_record_failure()
            await asyncio.sleep(wait)
            last_exc = exc
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500:
                wait = 2 ** attempt
                logger.warning(f"AI server error {exc.status_code}, retrying in {wait}s")
                _cb_record_failure()
                await asyncio.sleep(wait)
                last_exc = exc
            else:
                raise
    raise last_exc


async def triage_finding(
    finding,
    asset_context: dict,
    org_context: dict,
) -> dict:
    """
    Use Claude to classify severity, detect false positives,
    and generate reasoning for a security finding.

    Returns a dict with keys: severity, is_false_positive, reasoning, confidence.
    """
    client = _get_client()

    evidence_str = json.dumps(finding.evidence or {}, indent=2)
    system_prompt = (
        "You are an expert security analyst performing triage on security findings "
        "discovered during an external attack surface scan. "
        "Analyze the finding carefully and provide a structured assessment. "
        "Be conservative: prefer not to downgrade severity unless clearly justified. "
        "Respond ONLY with valid JSON matching the specified schema."
    )

    user_message = f"""Analyze this security finding and provide your assessment:

FINDING DETAILS:
- Title: {finding.title}
- Description: {finding.description}
- Current Severity: {finding.severity.value}
- Category: {finding.category}
- Affected Asset: {finding.affected_asset}
- CVEs: {', '.join(finding.cve) if finding.cve else 'None'}
- CVSS Score: {finding.cvss_score if finding.cvss_score else 'Not available'}
- Evidence: {evidence_str}
- Remediation: {finding.remediation}

ASSET CONTEXT:
{json.dumps(asset_context, indent=2)}

ORGANIZATION CONTEXT:
- Plan: {org_context.get('plan', 'unknown')}
- Industry context available: {bool(org_context)}

Respond with this exact JSON structure:
{{
  "severity": "<critical|high|medium|low|info>",
  "is_false_positive": <true|false>,
  "confidence": <0.0-1.0>,
  "reasoning": "<2-3 sentence explanation of your assessment>",
  "priority_score": <1-10>,
  "recommended_action": "<immediate|within_week|within_month|monitor|dismiss>"
}}"""

    try:
        response = await _call_with_retry(
            client,
            model=settings.AI_MODEL,
            max_tokens=settings.AI_MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        text = response.content[0].text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)
        return result
    except json.JSONDecodeError as e:
        logger.error(f"AI triage returned invalid JSON: {e}")
        return {
            "severity": finding.severity.value,
            "is_false_positive": False,
            "confidence": 0.0,
            "reasoning": "AI triage failed to return valid JSON",
            "priority_score": 5,
            "recommended_action": "monitor",
        }
    except Exception as e:
        logger.error(f"AI triage failed: {e}")
        return {
            "severity": finding.severity.value,
            "is_false_positive": False,
            "confidence": 0.0,
            "reasoning": f"AI triage unavailable: {str(e)}",
            "priority_score": 5,
            "recommended_action": "monitor",
        }


async def nl_to_filter(query: str, schema: dict) -> dict:
    """
    Translate a natural language query into a structured asset/finding filter JSON.

    Args:
        query: Human-readable search string e.g. "show me critical findings with CVEs in login pages"
        schema: Dict describing available filter fields and their types

    Returns:
        Structured filter dict matching AssetFilter or FindingFilter schema.
    """
    client = _get_client()

    system_prompt = (
        "You are a query parser for a security platform. "
        "Translate natural language search queries into structured filter objects. "
        "Only use filter fields defined in the schema. "
        "Respond ONLY with valid JSON. No explanations."
    )

    user_message = f"""Convert this search query to a filter object.

QUERY: "{query}"

AVAILABLE FILTER SCHEMA:
{json.dumps(schema, indent=2)}

Rules:
- Only include fields that are mentioned or clearly implied in the query
- For severity, use: critical, high, medium, low, info
- For status, use: open, in_progress, remediated, accepted_risk, false_positive
- For asset_type, use: domain, subdomain, ip, webapp, cloud
- Return an empty dict {{}} if the query is too ambiguous

Respond with ONLY a JSON object."""

    try:
        response = await _call_with_retry(
            client,
            model=settings.AI_MODEL,
            max_tokens=512,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        text = response.content[0].text.strip()
        # Strip markdown fences if Claude wrapped the response
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except RuntimeError:
        # API key not configured — re-raise so the endpoint returns 503
        raise
    except json.JSONDecodeError:
        # Claude returned non-JSON or ambiguous query — return empty filter
        logger.warning(f"NL filter returned non-JSON for query: {query!r}")
        return {}
    except Exception as e:
        logger.error(f"NL to filter failed: {e}")
        return {}


async def generate_exec_summary(scan_job, diff: Optional[dict] = None) -> str:
    """
    Generate a 3-bullet executive summary for a completed scan.

    Args:
        scan_job: ScanJob ORM instance
        diff: Optional change detection diff from a previous scan

    Returns:
        Markdown-formatted executive summary string.
    """
    client = _get_client()

    fc = scan_job.findings_count or {}
    rs = scan_job.results_summary or {}

    system_prompt = (
        "You are a security expert writing an executive summary for a non-technical audience. "
        "Be concise, factual, and actionable. Use clear language without security jargon. "
        "Respond in exactly 3 bullet points in Markdown."
    )

    diff_section = ""
    if diff:
        diff_section = f"""
CHANGES FROM PREVIOUS SCAN:
- New assets appeared: {diff.get('appeared_count', 0)}
- Assets disappeared: {diff.get('disappeared_count', 0)}
- Risk upgrades: {diff.get('risk_upgraded_count', 0)}
- Notable changes: {json.dumps(diff.get('notable_changes', []), indent=2)}
"""

    user_message = f"""Write an executive summary for this attack surface scan:

SCAN TARGET: {', '.join(scan_job.target_domains)}
COMPANY: {scan_job.company_name or 'Unknown'}
SCAN DATE: {scan_job.completed_at.isoformat() if scan_job.completed_at else 'In progress'}
INTENSITY: {scan_job.intensity.value}

FINDINGS:
- Critical: {fc.get('critical', 0)}
- High: {fc.get('high', 0)}
- Medium: {fc.get('medium', 0)}
- Low: {fc.get('low', 0)}
- Info: {fc.get('info', 0)}

ASSETS DISCOVERED:
- Domains: {rs.get('total_domains', 0)}
- Subdomains: {rs.get('total_subdomains', 0)}
- IP Addresses: {rs.get('total_ips', 0)}
- Web Applications: {rs.get('total_web_apps', 0)}
- Cloud Assets: {rs.get('total_cloud_assets', 0)}
- Open Ports: {rs.get('total_ports', 0)}
{diff_section}

Write exactly 3 bullet points covering:
1. Overall risk posture
2. Most critical findings requiring immediate action
3. Recommended next steps

Format each bullet as: - **[Topic]**: [2-3 sentences]"""

    try:
        response = await _call_with_retry(
            client,
            model=settings.AI_MODEL,
            max_tokens=settings.AI_MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text.strip()
    except Exception as e:
        logger.error(f"Executive summary generation failed: {e}")
        total_critical = fc.get("critical", 0)
        total_high = fc.get("high", 0)
        return (
            f"- **Risk Posture**: Scan completed with {total_critical} critical and {total_high} high severity findings.\n"
            f"- **Immediate Actions**: Review critical findings in the findings dashboard.\n"
            f"- **Next Steps**: Assign findings to team members and track remediation progress."
        )


async def generate_remediation_ticket(finding, technologies: list[str]) -> dict:
    """
    Generate a Jira-ready remediation ticket for a finding.

    Returns:
        Dict with keys: summary, description, priority, labels, acceptance_criteria.
    """
    client = _get_client()

    system_prompt = (
        "You are a senior security engineer creating remediation tickets for developers. "
        "Write clear, actionable tickets with specific steps. "
        "Respond ONLY with valid JSON."
    )

    tech_str = ", ".join(technologies) if technologies else "Unknown"
    severity_to_priority = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }

    user_message = f"""Create a Jira remediation ticket for this security finding:

FINDING:
- Title: {finding.title}
- Severity: {finding.severity.value}
- Category: {finding.category}
- Affected Asset: {finding.affected_asset}
- CVEs: {', '.join(finding.cve) if finding.cve else 'None'}
- CVSS Score: {finding.cvss_score or 'N/A'}
- Description: {finding.description}
- Remediation Guidance: {finding.remediation}
- Technologies: {tech_str}

Respond with this JSON structure:
{{
  "summary": "<Jira ticket title, max 80 chars>",
  "description": "<Detailed description with context, impact, and steps to reproduce>",
  "priority": "{severity_to_priority.get(finding.severity.value, 'Medium')}",
  "labels": ["security", "<category>", "<severity>"],
  "acceptance_criteria": [
    "<specific verifiable condition 1>",
    "<specific verifiable condition 2>",
    "<specific verifiable condition 3>"
  ],
  "estimated_effort": "<hours>",
  "components": ["<relevant component>"]
}}"""

    try:
        response = await _call_with_retry(
            client,
            model=settings.AI_MODEL,
            max_tokens=settings.AI_MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        text = response.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as e:
        logger.error(f"Ticket generation failed: {e}")
        return {
            "summary": f"[Security] {finding.title[:70]}",
            "description": f"Severity: {finding.severity.value}\n\nAffected Asset: {finding.affected_asset}\n\n{finding.description}\n\nRemediation: {finding.remediation}",
            "priority": severity_to_priority.get(finding.severity.value, "Medium"),
            "labels": ["security", finding.category, finding.severity.value],
            "acceptance_criteria": [
                "The vulnerability has been patched or mitigated",
                "Verification scan confirms the finding is no longer present",
                "Affected system has been retested by the security team",
            ],
            "estimated_effort": "4",
            "components": [],
        }


async def bulk_triage_findings(findings: list, asset_map: dict, org_context: dict) -> list[dict]:
    """
    Triage multiple findings in batch, returning results in order.
    Skips AI on findings already triaged.
    """
    results = []
    for finding in findings:
        if finding.ai_triaged_at is not None:
            # Already triaged, use cached result
            results.append({
                "finding_id": str(finding.id),
                "severity": finding.ai_severity.value if finding.ai_severity else finding.severity.value,
                "is_false_positive": finding.false_positive,
                "confidence": finding.ai_confidence or 0.0,
                "reasoning": finding.ai_reasoning or "Previously triaged",
                "priority_score": 5,
                "recommended_action": "monitor",
            })
            continue

        asset_ctx = asset_map.get(str(finding.asset_id), {}) if finding.asset_id else {}
        triage_result = await triage_finding(finding, asset_ctx, org_context)
        triage_result["finding_id"] = str(finding.id)
        results.append(triage_result)

    return results
