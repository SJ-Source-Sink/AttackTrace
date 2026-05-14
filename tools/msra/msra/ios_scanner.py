"""
iOS IPA static analysis scanner for MSRA.
Analyzes IPA files for OWASP MASVS violations without any dynamic execution.
"""

import json
import os
import plistlib
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_DEFAULT_PATTERNS_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "data",
    "builtin",
    "ios_patterns.json",
)


class IOSScanner:
    """Static analysis scanner for iOS IPA files."""

    def __init__(self, patterns_path: Optional[str] = None):
        if patterns_path is None:
            patterns_path = os.path.normpath(_DEFAULT_PATTERNS_PATH)
        with open(patterns_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.patterns: List[Dict[str, Any]] = [
            p for p in data.get("patterns", []) if p.get("enabled", True)
        ]

    # ── Public API ──────────────────────────────────────────────────────────

    def scan(self, ipa_path: str) -> List[Dict[str, Any]]:
        """Main entry point. Returns a list of findings dicts."""
        findings: List[Dict[str, Any]] = []
        fid_counter = 1

        with tempfile.TemporaryDirectory() as tmpdir:
            self._extract_ipa(ipa_path, tmpdir)
            app_dir = self._find_app_dir(tmpdir)

            info_plist = self._parse_info_plist(app_dir) if app_dir else {}
            entitlements = self._extract_entitlements(app_dir) if app_dir else {}
            binary_path = self._find_main_binary(app_dir, info_plist) if app_dir else None
            binary_strings = self._extract_strings(binary_path) if binary_path else []
            binary_flags = self._check_binary_flags(binary_path) if binary_path else {
                "pie": None,
                "stack_canary": None,
                "arc": None,
                "encrypted": None,
            }

            for pattern in self.patterns:
                detection = pattern.get("detection", {})
                det_type = detection.get("type", "")

                new_findings: List[Dict[str, Any]] = []

                if det_type == "plist_key":
                    new_findings = self._check_plist_pattern(pattern, info_plist, fid_counter)
                elif det_type == "entitlement":
                    new_findings = self._check_entitlement_pattern(pattern, entitlements, fid_counter)
                elif det_type == "binary_string":
                    new_findings = self._check_binary_strings_pattern(pattern, binary_strings, fid_counter)
                elif det_type == "binary_flag":
                    new_findings = self._check_binary_flag_pattern(pattern, binary_flags, fid_counter)

                for f in new_findings:
                    f["id"] = fid_counter
                    f["fid"] = fid_counter
                    fid_counter += 1
                findings.extend(new_findings)

        return findings

    # ── Internal helpers ────────────────────────────────────────────────────

    def _extract_ipa(self, ipa_path: str, tmpdir: str) -> None:
        """Unzip IPA into tmpdir."""
        with zipfile.ZipFile(ipa_path, "r") as zf:
            zf.extractall(tmpdir)

    def _find_app_dir(self, base_path: str) -> Optional[str]:
        """Find Payload/*.app directory."""
        payload = os.path.join(base_path, "Payload")
        if not os.path.isdir(payload):
            return None
        for entry in os.listdir(payload):
            if entry.endswith(".app"):
                candidate = os.path.join(payload, entry)
                if os.path.isdir(candidate):
                    return candidate
        return None

    def _parse_info_plist(self, app_dir: str) -> Dict[str, Any]:
        """Parse Info.plist from the app bundle. Returns {} on error."""
        plist_path = os.path.join(app_dir, "Info.plist")
        if not os.path.isfile(plist_path):
            return {}
        try:
            with open(plist_path, "rb") as fh:
                return plistlib.load(fh)
        except Exception:
            return {}

    def _extract_entitlements(self, app_dir: str) -> Dict[str, Any]:
        """
        Try `codesign -d --entitlements - <binary>` to get entitlements.
        Parse the XML plist from stdout/stderr. Returns {} on failure.
        """
        binary_path = self._find_main_binary(app_dir, self._parse_info_plist(app_dir))
        if not binary_path or not os.path.isfile(binary_path):
            return {}
        try:
            result = subprocess.run(
                ["codesign", "-d", "--entitlements", "-", binary_path],
                capture_output=True,
                timeout=15,
            )
            # codesign writes plist to stdout; sometimes mixed into stderr
            output = result.stdout + result.stderr
            # Find the plist XML blob
            start = output.find(b"<?xml")
            if start == -1:
                start = output.find(b"<plist")
            if start == -1:
                return {}
            plist_data = output[start:]
            return plistlib.loads(plist_data)
        except Exception:
            return {}

    def _find_main_binary(self, app_dir: str, info_plist: Dict[str, Any]) -> Optional[str]:
        """
        Return path to main binary.
        Uses CFBundleExecutable from Info.plist; falls back to largest file
        without extension inside app_dir.
        """
        if not app_dir or not os.path.isdir(app_dir):
            return None
        bundle_exec = info_plist.get("CFBundleExecutable")
        if bundle_exec:
            candidate = os.path.join(app_dir, bundle_exec)
            if os.path.isfile(candidate):
                return candidate

        # Fallback: largest file without extension
        best: Optional[Tuple[int, str]] = None
        for entry in os.listdir(app_dir):
            full = os.path.join(app_dir, entry)
            if os.path.isfile(full) and "." not in entry:
                size = os.path.getsize(full)
                if best is None or size > best[0]:
                    best = (size, full)
        return best[1] if best else None

    def _extract_strings(self, binary_path: str) -> List[str]:
        """
        Extract printable strings from binary.
        Tries `strings -n 6`; falls back to pure-Python regex on raw bytes.
        """
        if not binary_path or not os.path.isfile(binary_path):
            return []
        try:
            result = subprocess.run(
                ["strings", "-n", "6", binary_path],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.decode("utf-8", errors="replace").splitlines()
        except Exception:
            pass
        # Pure-Python fallback
        try:
            with open(binary_path, "rb") as fh:
                data = fh.read()
            return re.findall(r"[\x20-\x7E]{6,}", data.decode("latin-1", errors="replace"))
        except Exception:
            return []

    def _check_binary_flags(self, binary_path: str) -> Dict[str, Optional[bool]]:
        """
        Check Mach-O binary security flags via otool.
        Returns dict with keys: pie, stack_canary, arc, encrypted.
        All None if otool is unavailable.
        """
        flags: Dict[str, Optional[bool]] = {
            "pie": None,
            "stack_canary": None,
            "arc": None,
            "encrypted": None,
        }
        if not binary_path or not os.path.isfile(binary_path):
            return flags

        try:
            # PIE — look for PIE flag in otool -hv output
            r = subprocess.run(
                ["otool", "-hv", binary_path],
                capture_output=True, timeout=15,
            )
            if r.returncode == 0:
                output = r.stdout.decode("utf-8", errors="replace")
                flags["pie"] = "PIE" in output

            # Stack canary and ARC — scan imported symbols
            r = subprocess.run(
                ["otool", "-Iv", binary_path],
                capture_output=True, timeout=30,
            )
            if r.returncode == 0:
                symbols = r.stdout.decode("utf-8", errors="replace")
                flags["stack_canary"] = "___stack_chk_fail" in symbols
                flags["arc"] = "_objc_release" in symbols

            # Encryption — check cryptid in LC_ENCRYPTION_INFO
            r = subprocess.run(
                ["otool", "-lv", binary_path],
                capture_output=True, timeout=30,
            )
            if r.returncode == 0:
                load_cmds = r.stdout.decode("utf-8", errors="replace")
                # cryptid 0 means not encrypted; non-zero means encrypted
                cryptid_matches = re.findall(r"cryptid\s+(\d+)", load_cmds)
                if cryptid_matches:
                    flags["encrypted"] = any(int(c) != 0 for c in cryptid_matches)
                else:
                    flags["encrypted"] = False
        except FileNotFoundError:
            # otool not available (non-macOS or not installed)
            pass
        except Exception:
            pass

        return flags

    # ── Pattern check methods ───────────────────────────────────────────────

    def _resolve_plist_key(
        self, key_path: str, plist: Dict[str, Any]
    ) -> Tuple[bool, Any]:
        """
        Navigate dot-separated key_path in a plist dict.
        Returns (found: bool, value).
        """
        parts = key_path.split(".")
        current: Any = plist
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                return False, None
            current = current[part]
        return True, current

    def _check_plist_pattern(
        self,
        pattern: Dict[str, Any],
        plist: Dict[str, Any],
        finding_id: int,
    ) -> List[Dict[str, Any]]:
        """Check a plist_key pattern against the parsed Info.plist."""
        detection = pattern.get("detection", {})
        key_path: str = detection.get("key_path", "")
        check: str = detection.get("check", "exists")

        found, value = self._resolve_plist_key(key_path, plist)

        triggered = False
        snippet = ""

        if check == "exists":
            triggered = found
            snippet = repr(value) if found else ""
        elif check == "missing":
            triggered = not found
            snippet = f"Key '{key_path}' not present in Info.plist"
        elif check == "true":
            triggered = found and value is True
            snippet = repr(value) if triggered else ""
        elif check == "false":
            triggered = found and value is False
            snippet = repr(value) if triggered else ""
        elif check == "equals":
            expected = detection.get("value")
            triggered = found and value == expected
            snippet = repr(value) if triggered else ""
        elif check == "not_equals":
            expected = detection.get("value")
            triggered = found and value != expected
            snippet = repr(value) if triggered else ""
        elif check == "not_empty":
            triggered = found and bool(value)
            if triggered:
                if isinstance(value, (list, dict)):
                    snippet = f"{len(value)} entries"
                else:
                    snippet = repr(value)

        if not triggered:
            return []

        return [
            self._make_finding(
                fid=finding_id,
                pattern=pattern,
                file_path="Info.plist",
                line=0,
                snippet=snippet,
            )
        ]

    def _check_entitlement_pattern(
        self,
        pattern: Dict[str, Any],
        entitlements: Dict[str, Any],
        finding_id: int,
    ) -> List[Dict[str, Any]]:
        """Check an entitlement pattern against parsed entitlements."""
        detection = pattern.get("detection", {})
        key: str = detection.get("key", "")
        check: str = detection.get("check", "exists")

        present = key in entitlements
        value = entitlements.get(key)

        triggered = False
        snippet = ""

        if check == "exists":
            triggered = present
            snippet = repr(value) if present else ""
        elif check == "missing":
            triggered = not present
            snippet = f"Entitlement '{key}' not present"
        elif check == "true":
            triggered = present and value is True
            snippet = repr(value) if triggered else ""
        elif check == "false":
            triggered = present and value is False
            snippet = repr(value) if triggered else ""

        if not triggered:
            return []

        return [
            self._make_finding(
                fid=finding_id,
                pattern=pattern,
                file_path="entitlements",
                line=0,
                snippet=snippet,
            )
        ]

    def _check_binary_strings_pattern(
        self,
        pattern: Dict[str, Any],
        strings_list: List[str],
        finding_id: int,
    ) -> List[Dict[str, Any]]:
        """Regex match against extracted binary strings. Collect up to 3 matches."""
        detection = pattern.get("detection", {})
        regex_pattern: str = detection.get("pattern", "")
        if not regex_pattern:
            return []

        try:
            rx = re.compile(regex_pattern)
        except re.error:
            return []

        matches: List[str] = []
        for s in strings_list:
            if rx.search(s):
                matches.append(s)
                if len(matches) >= 3:
                    break

        if not matches:
            return []

        snippet = " | ".join(matches[:3])
        return [
            self._make_finding(
                fid=finding_id,
                pattern=pattern,
                file_path="binary",
                line=0,
                snippet=snippet,
            )
        ]

    def _check_binary_flag_pattern(
        self,
        pattern: Dict[str, Any],
        flags: Dict[str, Optional[bool]],
        finding_id: int,
    ) -> List[Dict[str, Any]]:
        """Check a binary flag value against expected."""
        detection = pattern.get("detection", {})
        flag_name: str = detection.get("flag", "")
        expected_value = detection.get("value")  # bool

        flag_value = flags.get(flag_name)
        if flag_value is None:
            # Cannot determine — skip
            return []

        if flag_value != expected_value:
            return []

        snippet = f"{flag_name} = {flag_value}"
        return [
            self._make_finding(
                fid=finding_id,
                pattern=pattern,
                file_path="binary (Mach-O headers)",
                line=0,
                snippet=snippet,
            )
        ]

    # ── Finding factory ─────────────────────────────────────────────────────

    def _make_finding(
        self,
        fid: int,
        pattern: Dict[str, Any],
        file_path: str,
        line: int,
        snippet: str,
    ) -> Dict[str, Any]:
        """Return a finding dict in MSRA standard format."""
        return {
            "id": fid,
            "fid": fid,
            "title": pattern.get("title", ""),
            "severity": pattern.get("severity", "Info"),
            "category": pattern.get("category", ""),
            "description": pattern.get("description", ""),
            "evidence": {
                "file": file_path,
                "file_path": file_path,
                "line_number": line,
                "snippet": snippet,
            },
            "adb_commands": [],
            "remediation": pattern.get("remediation", ""),
            "attack_path": pattern.get("attack_path", ""),
            "cwe": pattern.get("cwe", []),
            "references": pattern.get("references", []),
            "platform": "ios",
        }


# ── Module-level convenience function ───────────────────────────────────────


def scan_ipa(ipa_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Scan an IPA and return (findings, metadata).

    metadata keys:
        bundle_id       — CFBundleIdentifier
        app_name        — CFBundleName
        version         — CFBundleShortVersionString
        build           — CFBundleVersion
        platform        — 'ios'
    """
    scanner = IOSScanner()

    # Extract metadata from Info.plist without a full scan pass
    metadata: Dict[str, Any] = {
        "bundle_id": None,
        "app_name": None,
        "version": None,
        "build": None,
        "platform": "ios",
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        scanner._extract_ipa(ipa_path, tmpdir)
        app_dir = scanner._find_app_dir(tmpdir)
        if app_dir:
            info_plist = scanner._parse_info_plist(app_dir)
            metadata["bundle_id"] = info_plist.get("CFBundleIdentifier")
            metadata["app_name"] = info_plist.get("CFBundleName")
            metadata["version"] = info_plist.get("CFBundleShortVersionString")
            metadata["build"] = info_plist.get("CFBundleVersion")

    findings = scanner.scan(ipa_path)
    return findings, metadata
