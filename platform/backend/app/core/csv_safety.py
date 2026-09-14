"""
Shared CSV formula-injection guard (CWE-1236).

Any value written into a CSV cell that begins with =, +, -, @, or a tab can
be interpreted by Excel/Sheets/LibreOffice as a formula when the file is
opened — e.g. a finding titled '=HYPERLINK("http://evil/x","click")' becomes
a live, clickable formula for whoever opens the export. Finding fields
(title, affected_asset, ai_reasoning, ticket_ref, ...) are attacker-
influenceable, since scan targets can control what text a scanner records
(e.g. a hostname, a git commit message, an HTTP response header) — so every
field written into a CSV export must be run through csv_safe() first.

Originally implemented ad hoc in app/api/v1/compliance.py as `_csv_safe`;
extracted here so app/api/v1/findings.py's /findings/export CSV branch (and
any future CSV export) shares one implementation instead of re-deriving it.
"""


def csv_safe(value) -> str:
    """Neutralize CSV formula injection: prefix a value with a leading
    single-quote if its first character would be interpreted by a
    spreadsheet application as a formula/macro trigger."""
    s = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
    if s and s[0] in ("=", "+", "-", "@", "\t"):
        return "'" + s
    return s
