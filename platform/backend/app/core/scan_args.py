"""
Validation for user-supplied values that end up on a scanner's command line.

None of our subprocess calls use a shell, so shell metacharacters aren't the risk; the risk is
a value being parsed by the tool as an *option* (``-iL /etc/passwd``, ``-oN /tmp/x``,
``--script /tmp/evil.nse``) which turns a scan into an arbitrary file read/write.
"""

import re

# nmap flags that take no value
_NMAP_BARE = frozenset({
    "-sS", "-sT", "-sU", "-sV", "-sC", "-sn", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM", "-sY", "-sZ",
    "-Pn", "-PE", "-PP", "-PM", "-n", "-R", "-O", "-A", "-F", "-r", "-6",
    "-v", "-vv", "-vvv", "-d", "-dd",
    "--open", "--reason", "--traceroute", "--osscan-guess", "--osscan-limit", "--version-light",
    "--version-all", "--version-trace", "--system-dns", "--send-eth", "--send-ip", "--privileged",
    "--unprivileged", "--no-stylesheet", "--defeat-rst-ratelimit",
})
# flags with an attached/following value, and the value shape they accept
_NMAP_VALUED = {
    "-p": r"[\d,\-TUS:]+",
    "--top-ports": r"\d{1,5}",
    "--max-retries": r"\d{1,2}",
    "--min-rate": r"\d{1,6}",
    "--max-rate": r"\d{1,6}",
    "--host-timeout": r"\d{1,6}(ms|s|m|h)?",
    "--version-intensity": r"[0-9]",
    "--script-timeout": r"\d{1,6}(ms|s|m|h)?",
    # named NSE scripts/categories only: no path separators, no file args
    "--script": r"[A-Za-z0-9_,\-+*]+",
}
_NMAP_ATTACHED = re.compile(r"^-(P[SAUY])[\d,\-]*$")  # -PS22,80 style probes
_TIMING = re.compile(r"^-T[0-5]$")


def validate_nmap_flags(raw: str) -> list[str]:
    """Return ``raw`` split into tokens if every token is on the allowlist, else raise ValueError."""
    tokens = raw.split()
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _NMAP_BARE or _TIMING.match(tok) or _NMAP_ATTACHED.match(tok):
            out.append(tok)
            i += 1
            continue
        flag, eq, attached = tok.partition("=")
        if flag in _NMAP_VALUED:
            if eq:
                value, step = attached, 1
            elif i + 1 < len(tokens):
                value, step = tokens[i + 1], 2
            else:
                raise ValueError(f"Flag {flag} needs a value")
            if not re.fullmatch(_NMAP_VALUED[flag], value):
                raise ValueError(f"Invalid value for {flag}")
            out.extend([tok] if eq else [tok, value])
            i += step
            continue
        raise ValueError(f"Flag not allowed: {tok[:30]}")
    return out


def reject_option_like(value: str, label: str = "Target") -> str:
    """Reject a value a CLI tool would parse as an option (leading '-')."""
    v = value.strip()
    if v.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    return v
