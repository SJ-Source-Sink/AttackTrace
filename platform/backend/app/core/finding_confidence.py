"""
Shared confidence grading — implements the false-positive-gate doctrine already
written as prose in app.api.v1.attack_suite's _HUNT_SKILL_CONTEXT (oracle
reliability tiers) as actual code every scanner's finding-adapter can call,
instead of leaving `Finding.confidence` null.

Confidence values match app.models.db.finding.Finding.confidence (free-form
String(16)): "certain", "high", "medium", "low".
"""

# Oracle type -> confidence. An oracle is *how* a finding was confirmed, not
# what class of vulnerability it is.
_ORACLE_CONFIDENCE: dict[str, str] = {
    # Strong: accept on a single clean fire
    "dom-exec": "certain",
    "extracted-value": "certain",
    "oob-dns": "certain",
    "oob-http": "certain",
    "api-confirmed": "certain",   # e.g. a cloud provider API directly returning the misconfigured state
    "two-signal": "high",         # e.g. takeover.py's CNAME-dead + fingerprint-match combo
    # Medium: needs a control/differential to be sure
    "differential": "medium",
    "status-flip": "medium",
    "redirect-location": "medium",
    "pattern-entropy": "medium",  # regex match that also passed an entropy/fake-value filter
    # Weak: the #1 false-positive source, or no corroboration at all
    "timing": "low",
    "timing-x3": "medium",        # timing repeated 3x against a clean baseline
    "error-string": "low",
    "reflected": "low",
    "bare-signal": "low",         # a single unconfirmed check (missing header, open port, pass/fail probe)
}

DEFAULT_CONFIDENCE = "low"


def grade_confidence(oracle: str) -> str:
    """Map an oracle type to a Finding.confidence value. Unknown oracles grade
    as low — silence is not evidence."""
    return _ORACLE_CONFIDENCE.get(oracle, DEFAULT_CONFIDENCE)


# Full, user-facing explanation of each oracle — surfaced on the finding
# detail page ("how was this found?") so a confidence label isn't just an
# unexplained word. Written for someone reading a single finding, not for a
# developer reading this file — explains the actual verification mechanism.
_ORACLE_EXPLANATIONS: dict[str, str] = {
    "dom-exec": "Confirmed by actually executing in the browser DOM — e.g. a payload's JavaScript ran and was observed firing (not just reflected in a response body).",
    "extracted-value": "Confirmed by directly reading back a real, sensitive value from the target (e.g. a file's contents, a config value, a database row) — not inferred from a side effect.",
    "oob-dns": "Confirmed via an out-of-band DNS callback: the target made a real DNS lookup to an attacker-controlled domain during testing, proving it processed the injected input server-side.",
    "oob-http": "Confirmed via an out-of-band HTTP callback: the target made a real outbound HTTP request to an attacker-controlled listener during testing, proving server-side request execution.",
    "api-confirmed": "Confirmed directly by the cloud/platform provider's own API returning the misconfigured or exposed state — not inferred, the provider itself reports it.",
    "two-signal": "Confirmed by two independent corroborating signals agreeing (e.g. a DNS record pointing at an unclaimed service AND a fingerprint match on the response) — stronger than either signal alone, but not a live-executed proof.",
    "differential": "Confirmed by comparing behavior against a control/baseline request and observing a meaningful difference only the vulnerable condition would produce.",
    "status-flip": "Confirmed by an HTTP status code changing in a way that only makes sense if the tested condition is real (e.g. 403 → 200 after a bypass technique).",
    "redirect-location": "Confirmed by an HTTP redirect's Location header pointing somewhere that proves the tested condition (e.g. an open-redirect payload actually redirecting).",
    "pattern-entropy": "Detected by a regex/pattern match that also passed an entropy and known-placeholder filter (to rule out fake/example values like \"YOUR_API_KEY_HERE\") — not manually verified against a live system, so treat as needing confirmation before acting.",
    "timing": "Detected by a single response-time anomaly versus what was expected. Timing-based signals are the single most common source of false positives in automated scanning (network jitter, server load, and caching all produce the same signal) — treat as a lead to investigate, not a confirmed finding.",
    "timing-x3": "Detected by a response-time anomaly that repeated consistently across 3 separate attempts against a clean baseline — meaningfully more reliable than a single timing observation, but still not a definitive proof the way a callback or extracted value is.",
    "error-string": "Detected by an error message or stack trace appearing in the response that's characteristic of the tested vulnerability class — reasonably reliable but can occasionally false-positive on generic error pages.",
    "reflected": "Detected by the injected payload being echoed back in the response body — proves reflection, not execution; without DOM/oob confirmation this doesn't yet prove exploitability.",
    "bare-signal": "Detected by a single unconfirmed check with no corroboration (e.g. a missing security header, a port simply being open, a pass/fail probe) — the weakest tier; this describes a condition that MAY be a problem depending on context, not a proven exploit.",
}


def explain_oracle(oracle: str | None) -> str | None:
    """Human-readable explanation of how a finding with this oracle was
    actually verified, for display on the finding detail page. None if no
    oracle is recorded (most scanner-adapter findings don't set one — this
    is currently populated by the Attack Suite AI Agent and any scanner that
    calls grade_confidence directly)."""
    if not oracle:
        return None
    return _ORACLE_EXPLANATIONS.get(oracle)
