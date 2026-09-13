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
