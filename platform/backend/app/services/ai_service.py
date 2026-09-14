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

_AI_MAX_RETRIES = 3

# --- Redis-backed AI circuit breaker ---
# Trips after 5 consecutive failures; auto-resets after 60s (half-open probe).
# Prevents cascading timeouts when the Anthropic API is degraded.
# All Redis I/O is async (aioredis) so it never blocks the event loop.
_CB_FAILURE_THRESHOLD = 5
_CB_OPEN_TIMEOUT = 60  # seconds before attempting half-open probe
_CB_KEY = "ai:circuit_breaker"


def _get_async_redis():
    """Return the shared async Redis pool (avoids spawning new connections per call)."""
    try:
        from app.services.scan_service import _get_redis as _sr
        return _sr()
    except Exception:
        return None


async def _cb_is_open() -> bool:
    """Return True if the circuit is open and AI calls should be skipped."""
    r = _get_async_redis()
    if r is None:
        return False  # Redis unavailable → fail open (allow requests)
    try:
        state = await r.get(f"{_CB_KEY}:state")
        if state == "open":
            last_fail = float(await r.get(f"{_CB_KEY}:last_fail") or 0)
            if time.time() - last_fail > _CB_OPEN_TIMEOUT:
                await r.set(f"{_CB_KEY}:state", "half_open")
                return False  # allow one probe request through
            return True
    except Exception:
        pass  # Redis error → fail open
    return False


async def _cb_record_success() -> None:
    r = _get_async_redis()
    if r is None:
        return
    try:
        await r.delete(f"{_CB_KEY}:failures", f"{_CB_KEY}:state", f"{_CB_KEY}:last_fail")
    except Exception:
        pass


async def _cb_record_failure() -> None:
    r = _get_async_redis()
    if r is None:
        return
    try:
        failures = int(await r.incr(f"{_CB_KEY}:failures") or 0)
        await r.set(f"{_CB_KEY}:last_fail", time.time())
        await r.expire(f"{_CB_KEY}:failures", 300)  # reset counter after 5 min inactivity
        if failures >= _CB_FAILURE_THRESHOLD:
            await r.set(f"{_CB_KEY}:state", "open")
            logger.warning(f"AI circuit breaker OPENED after {failures} consecutive failures")
    except Exception:
        pass


async def get_org_ai_config(org_id, db) -> dict:
    """
    Resolve the effective AI configuration for an org.

    Priority: org DB credential > system env var / config default. When the
    org has selected "qwen" as its provider, api_key/base_url/model resolve
    from the qwen_* fields instead — there is no global-settings fallback
    for Qwen (there's no equivalent of ANTHROPIC_API_KEY for a self-hosted
    server), so an incomplete Qwen config surfaces as a clear error at call
    time rather than silently falling back to Claude.

    Returns dict with keys: provider ("anthropic" | "qwen"), api_key,
    base_url, model.
    """
    from app.core.security import decrypt_credential
    from app.models.db.org import OrgCredentials
    from sqlalchemy import select

    provider = "anthropic"
    api_key: str | None = settings.ANTHROPIC_API_KEY
    base_url: str | None = settings.AI_BASE_URL
    model: str = settings.AI_MODEL

    if org_id and db:
        try:
            result = await db.execute(
                select(OrgCredentials).where(OrgCredentials.org_id == org_id)
            )
            creds = result.scalar_one_or_none()
            if creds:
                if creds.ai_provider == "qwen":
                    provider = "qwen"
                    api_key = decrypt_credential(creds.qwen_api_key_enc) if creds.qwen_api_key_enc else None
                    base_url = decrypt_credential(creds.qwen_base_url_enc) if creds.qwen_base_url_enc else None
                    model = decrypt_credential(creds.qwen_model_enc) if creds.qwen_model_enc else None
                else:
                    if creds.anthropic_key_enc:
                        api_key = decrypt_credential(creds.anthropic_key_enc)
                    if creds.ai_base_url_enc:
                        base_url = decrypt_credential(creds.ai_base_url_enc)
                    if creds.ai_model_override_enc:
                        model = decrypt_credential(creds.ai_model_override_enc)
        except Exception as exc:
            logger.warning(f"Could not fetch org AI config for {org_id}: {exc}")

    return {
        "provider": provider, "api_key": api_key, "base_url": base_url, "model": model,
        "org_id": str(org_id) if org_id else None,
    }


async def _call_llm_with_retry(ai_config: dict, system: str | None, messages: list[dict], max_tokens: int, label: str = "unknown") -> str:
    """Call the configured provider (Claude or Qwen, via llm_client.complete)
    with exponential backoff on transient errors and circuit breaker
    protection. Provider-agnostic: both SDKs expose the same exception
    names (RateLimitError, APITimeoutError, APIConnectionError,
    APIStatusError with .status_code), so one retry policy covers both."""
    import openai
    from app.services import llm_client

    if await _cb_is_open():
        raise RuntimeError("AI circuit breaker is open — Anthropic API is currently degraded")

    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(_AI_MAX_RETRIES):
        try:
            result = await llm_client.complete(ai_config, system, messages, max_tokens, label=label)
            await _cb_record_success()
            return result
        except (anthropic.RateLimitError, openai.RateLimitError) as exc:
            wait = 2 ** attempt
            logger.warning(f"AI rate limited, retrying in {wait}s (attempt {attempt + 1})")
            await _cb_record_failure()
            await asyncio.sleep(wait)
            last_exc = exc
        except (anthropic.APITimeoutError, anthropic.APIConnectionError, openai.APITimeoutError, openai.APIConnectionError) as exc:
            wait = 2 ** attempt
            logger.warning(f"AI transient error: {exc}, retrying in {wait}s (attempt {attempt + 1})")
            await _cb_record_failure()
            await asyncio.sleep(wait)
            last_exc = exc
        except (anthropic.APIStatusError, openai.APIStatusError) as exc:
            if exc.status_code >= 500:
                wait = 2 ** attempt
                logger.warning(f"AI server error {exc.status_code}, retrying in {wait}s")
                await _cb_record_failure()
                await asyncio.sleep(wait)
                last_exc = exc
            else:
                raise
    raise last_exc


async def triage_finding(
    finding,
    asset_context: dict,
    org_context: dict,
    ai_config: dict | None = None,
) -> dict:
    """
    Use Claude to classify severity, detect false positives,
    and generate reasoning for a security finding.

    Returns a dict with keys: severity, is_false_positive, reasoning, confidence.
    ai_config: optional dict with keys api_key, base_url, model (from get_org_ai_config).
    """
    cfg = ai_config or {}

    evidence_str = json.dumps(finding.evidence or {}, indent=2)

    system_prompt = (
        "You are a senior security analyst triaging findings from an external attack surface scan. "
        "Your job: validate severity, detect false positives, and prioritise remediation.\n\n"
        "Severity calibration:\n"
        "- critical: RCE, SQLi with data access, auth bypass, exposed secrets/credentials\n"
        "- high: XSS with session theft, SSRF, IDOR with sensitive data, missing auth on sensitive endpoints\n"
        "- medium: Reflected XSS, CORS misconfiguration, info disclosure (stack traces, version banners)\n"
        "- low: Missing security headers, verbose errors, low-impact misconfigs\n"
        "- info: Informational, no direct exploitability\n\n"
        "False positive indicators: scanner artefact, unreachable asset, test/dev environment, "
        "known benign behaviour, evidence contradicts the finding title.\n\n"
        "Respond ONLY with valid JSON — no markdown, no explanation."
    )

    user_message = f"""Triage this security finding:

FINDING:
  Title: {finding.title}
  Severity (scanner-assigned): {finding.severity.value}
  Category: {finding.category}
  Affected asset: {finding.affected_asset}
  CVEs: {', '.join(finding.cve) if finding.cve else 'none'}
  CVSS: {finding.cvss_score if finding.cvss_score else 'n/a'}
  Description: {finding.description}
  Evidence: {evidence_str}
  Remediation hint: {finding.remediation}

ASSET CONTEXT:
{json.dumps(asset_context, indent=2)}

Respond with this exact JSON (no other text):
{{
  "severity": "critical|high|medium|low|info",
  "is_false_positive": true|false,
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentences: what you validated, why severity is correct/wrong, false-positive rationale if applicable",
  "priority_score": 1-10,
  "recommended_action": "immediate|within_week|within_month|monitor|dismiss"
}}"""

    try:
        text = await _call_llm_with_retry(
            cfg, system_prompt, [{"role": "user", "content": user_message}], settings.AI_MAX_TOKENS,
            label="triage_finding",
        )
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


async def nl_to_filter(query: str, schema: dict, ai_config: dict | None = None) -> dict:
    """
    Translate a natural language query into a structured asset/finding filter JSON.

    Args:
        query: Human-readable search string e.g. "show me critical findings with CVEs in login pages"
        schema: Dict describing available filter fields and their types
        ai_config: optional dict with keys api_key, base_url, model

    Returns:
        Structured filter dict matching AssetFilter or FindingFilter schema.
    """
    cfg = ai_config or {}

    system_prompt = (
        "You are a search query parser for a security platform. "
        "Convert natural language into a JSON filter object. "
        "Only output fields that are explicitly mentioned or clearly implied. "
        "Never invent fields not in the schema. "
        "Respond with ONLY a JSON object — no markdown, no explanation."
    )

    user_message = f"""Convert this search query into a filter object using the schema below.

QUERY: "{query}"

SCHEMA:
{json.dumps(schema, indent=2)}

FIELD VALUES:
- severity: critical, high, medium, low, info
- status: open, in_progress, remediated, accepted_risk, false_positive
- asset_type: domain, subdomain, ip, webapp, cloud

EXAMPLES:
  "show critical open findings"          → {{"severity": "critical", "status": "open"}}
  "unpatched CVEs"                       → {{"has_cve": true, "status": "open"}}
  "subdomains found in last scan"        → {{"asset_type": "subdomain"}}
  "high risk web apps"                   → {{"asset_type": "webapp", "min_risk_score": 70}}
  "false positives"                      → {{"is_false_positive": true}}
  "medium findings in progress"          → {{"severity": "medium", "status": "in_progress"}}
  "everything"                           → {{}}

Return {{}} if the query is too vague or matches no schema fields.
Respond with ONLY the JSON object."""

    try:
        text = await _call_llm_with_retry(cfg, system_prompt, [{"role": "user", "content": user_message}], 512, label="nl_to_filter")
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
    Template-based — no API key required.

    Args:
        scan_job: ScanJob ORM instance
        diff: Optional change detection diff from a previous scan

    Returns:
        Markdown-formatted executive summary string.
    """
    fc = scan_job.findings_count or {}
    rs = scan_job.results_summary or {}

    critical = fc.get("critical", 0)
    high     = fc.get("high", 0)
    medium   = fc.get("medium", 0)
    low      = fc.get("low", 0)
    total    = critical + high + medium + low + fc.get("info", 0)

    total_assets = (
        rs.get("total_domains", 0) + rs.get("total_subdomains", 0) +
        rs.get("total_ips", 0) + rs.get("total_web_apps", 0) +
        rs.get("total_cloud_assets", 0)
    )

    targets = ", ".join(scan_job.target_domains[:3])
    if len(scan_job.target_domains) > 3:
        targets += f" (+{len(scan_job.target_domains) - 3} more)"

    # Bullet 1 — Risk posture
    if critical > 0:
        risk_level  = "critical risk"
        risk_detail = f"{critical} critical finding{'s' if critical != 1 else ''} require immediate attention"
    elif high > 0:
        risk_level  = "high risk"
        risk_detail = f"{high} high severity finding{'s' if high != 1 else ''} require prompt remediation"
    elif medium > 0:
        risk_level  = "medium risk"
        risk_detail = f"{medium} medium severity finding{'s' if medium != 1 else ''} should be addressed"
    else:
        risk_level  = "low risk"
        risk_detail = "no critical or high severity findings detected"

    b1 = (
        f"- **Risk Posture**: Scan of {targets} identified {total} finding{'s' if total != 1 else ''} "
        f"across {total_assets} discovered assets — **{risk_level}**. {risk_detail.capitalize()}."
    )

    # Bullet 2 — Immediate actions / current status
    urgent = critical + high
    if urgent > 0:
        b2 = (
            f"- **Immediate Actions Required**: {urgent} finding{'s' if urgent != 1 else ''} "
            f"({critical} critical, {high} high) need urgent remediation. "
            f"Assign owners in the findings dashboard and set SLA deadlines to prevent exploitation."
        )
    else:
        b2 = (
            f"- **Current Status**: No critical or high severity findings detected. "
            f"{medium} medium and {low} low severity finding{'s' if (medium + low) != 1 else ''} "
            f"should be reviewed and addressed within your standard patch cycle."
        )

    # Bullet 3 — Changes or next steps
    if diff:
        appeared   = diff.get("appeared_count", 0)
        disappeared = diff.get("disappeared_count", 0)
        upgraded   = diff.get("risk_upgraded_count", 0)
        b3 = (
            f"- **Changes Since Last Scan**: {appeared} new asset{'s' if appeared != 1 else ''} appeared, "
            f"{disappeared} disappeared, and {upgraded} finding{'s' if upgraded != 1 else ''} increased in severity. "
            f"Prioritise reviewing new assets and any risk upgrades before addressing unchanged findings."
        )
    else:
        ports = rs.get("total_ports", 0)
        cloud = rs.get("total_cloud_assets", 0)
        extras = []
        if ports:
            extras.append(f"review {ports} open port{'s' if ports != 1 else ''} for unnecessary exposure")
        if cloud:
            extras.append(f"audit {cloud} cloud asset{'s' if cloud != 1 else ''} for misconfigurations")
        extras_str = (", ".join(extras) + ", and ") if extras else ""
        b3 = (
            f"- **Recommended Next Steps**: {extras_str.capitalize()}"
            f"schedule a re-scan after remediation to verify all fixes are effective."
        )

    return f"{b1}\n{b2}\n{b3}"


async def generate_remediation_ticket(finding, technologies: list[str]) -> dict:
    """
    Generate a Jira-ready remediation ticket for a finding.
    Template-based — no API key required.

    Returns:
        Dict with keys: summary, description, priority, labels, acceptance_criteria.
    """
    severity_to_priority = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }
    severity_to_effort = {
        "critical": "8",
        "high": "4",
        "medium": "2",
        "low": "1",
        "info": "1",
    }

    sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    priority = severity_to_priority.get(sev, "Medium")
    effort   = severity_to_effort.get(sev, "4")

    tech_str   = ", ".join(technologies) if technologies else "N/A"
    cve_str    = ", ".join(finding.cve) if getattr(finding, "cve", None) else "None"
    cvss_str   = str(finding.cvss_score) if getattr(finding, "cvss_score", None) else "N/A"
    asset_str  = getattr(finding, "affected_asset", getattr(finding, "asset_value", "Unknown"))
    category   = str(getattr(finding, "category", "vulnerability"))
    remediation = str(getattr(finding, "remediation", "") or "See security team for remediation steps.")

    # Build a structured Jira description
    lines = [
        f"h2. Security Finding: {finding.title}",
        "",
        f"*Severity:* {sev.upper()}  |  *Priority:* {priority}  |  *Category:* {category}",
        f"*Affected Asset:* {asset_str}",
        f"*CVE(s):* {cve_str}  |  *CVSS Score:* {cvss_str}",
    ]
    if technologies:
        lines.append(f"*Technologies:* {tech_str}")
    lines += [
        "",
        "h3. Description",
        str(finding.description or ""),
        "",
        "h3. Remediation Steps",
    ]
    if hasattr(finding, "remediation_steps") and finding.remediation_steps:
        for i, step in enumerate(finding.remediation_steps, 1):
            lines.append(f"{i}. {step}")
    else:
        lines.append(remediation)

    lines += [
        "",
        "h3. References",
        "* OWASP Testing Guide",
        "* AttackTrace finding ID: to be linked by reporter",
    ]

    description = "\n".join(lines)

    # Acceptance criteria vary by category
    category_lower = category.lower()
    if "xss" in category_lower or "injection" in category_lower:
        criteria = [
            f"The {category} vector on {asset_str} is no longer exploitable with known payloads",
            "Input validation / output encoding is verified by the security team",
            "Re-scan shows finding is resolved (status: remediated)",
        ]
    elif "header" in category_lower or "misconfigur" in category_lower:
        criteria = [
            f"The misconfiguration on {asset_str} has been corrected per security standards",
            "HTTP response headers / config verified via automated check",
            "Re-scan shows finding is resolved",
        ]
    elif "credential" in category_lower or "secret" in category_lower or "exposure" in category_lower:
        criteria = [
            "Exposed credential/secret has been rotated and the old value invalidated",
            "Root cause (e.g. committed .env, exposed endpoint) has been fixed",
            "Scanning tools confirm the secret is no longer accessible publicly",
        ]
    else:
        criteria = [
            f"The vulnerability identified in {finding.title} has been patched or mitigated",
            "Verification scan confirms the finding is no longer present",
            "Affected system has been retested and signed off by the security team",
        ]

    return {
        "summary": f"[Security/{sev.upper()}] {finding.title[:72]}",
        "description": description,
        "priority": priority,
        "labels": ["security", category.replace(" ", "-").lower(), sev],
        "acceptance_criteria": criteria,
        "estimated_effort": effort,
        "components": [],
    }


async def bulk_triage_findings(
    findings: list,
    asset_map: dict,
    org_context: dict,
    ai_config: dict | None = None,
) -> list[dict]:
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
        triage_result = await triage_finding(finding, asset_ctx, org_context, ai_config=ai_config)
        triage_result["finding_id"] = str(finding.id)
        results.append(triage_result)

    return results
