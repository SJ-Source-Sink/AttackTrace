"""
JAR file static analysis scanner for MSRA.
Analyses Java Archive files for OWASP/CVE-based vulnerabilities without execution.
"""

from __future__ import annotations

import json
import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_DEFAULT_PATTERNS_PATH = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "data", "builtin", "jar_patterns.json"
))

# Minimum printable string length to extract from .class files
_MIN_STR_LEN = 6


class JARScanner:
    """Static analysis scanner for Java JAR files."""

    def __init__(self, patterns_path: Optional[str] = None):
        if patterns_path is None:
            patterns_path = _DEFAULT_PATTERNS_PATH
        with open(patterns_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.patterns: List[Dict[str, Any]] = [
            p for p in data.get("patterns", []) if p.get("enabled", True)
        ]

    # ── Public API ──────────────────────────────────────────────────────────

    def scan(self, jar_path: str) -> List[Dict[str, Any]]:
        """Main entry point. Returns a list of finding dicts."""
        findings: List[Dict[str, Any]] = []
        fid = 1

        try:
            with zipfile.ZipFile(jar_path, "r") as zf:
                manifest      = self._parse_manifest(zf)
                entry_names   = zf.namelist()
                class_strings = self._extract_class_strings(zf)
                services      = self._list_services(entry_names)
                dup_entries   = self._find_duplicate_entries(zf)
                lib_names     = self._collect_lib_names(entry_names)
        except zipfile.BadZipFile as exc:
            return [self._error_finding(fid, str(exc))]
        except Exception as exc:
            return [self._error_finding(fid, str(exc))]

        context = {
            "manifest":      manifest,
            "entry_names":   entry_names,
            "class_strings": class_strings,
            "services":      services,
            "dup_entries":   dup_entries,
            "lib_names":     lib_names,
        }

        for pattern in self.patterns:
            det  = pattern.get("detection", {})
            dtype = det.get("type", "")

            new: List[Dict[str, Any]] = []

            if dtype == "manifest_attr":
                new = self._check_manifest_attr(pattern, context, fid)
            elif dtype == "class_exists":
                new = self._check_class_exists(pattern, context, fid)
            elif dtype == "string_pattern":
                new = self._check_string_pattern(pattern, context, fid)
            elif dtype == "entry_pattern":
                new = self._check_entry_pattern(pattern, context, fid)
            elif dtype == "library_version":
                new = self._check_library_version(pattern, context, fid)
            elif dtype == "duplicate_entries":
                new = self._check_duplicate_entries(pattern, context, fid)
            elif dtype == "services_entry":
                new = self._check_services_entry(pattern, context, fid)

            for f in new:
                f["id"]  = fid
                f["fid"] = fid
                fid += 1
            findings.extend(new)

        return findings

    # ── JAR parsing helpers ──────────────────────────────────────────────────

    def _parse_manifest(self, zf: zipfile.ZipFile) -> Dict[str, str]:
        """Parse META-INF/MANIFEST.MF into a flat key→value dict (lowercase keys)."""
        for name in ("META-INF/MANIFEST.MF", "META-INF/manifest.mf"):
            try:
                raw = zf.read(name).decode("utf-8", errors="replace")
                result: Dict[str, str] = {}
                for line in raw.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        result[k.strip().lower()] = v.strip()
                return result
            except KeyError:
                continue
        return {}

    def _extract_class_strings(self, zf: zipfile.ZipFile) -> List[str]:
        """
        Extract printable ASCII strings from all .class files in the JAR.
        Uses a lightweight approach: scan raw bytes for printable sequences
        >= _MIN_STR_LEN chars. This captures string constants, class/method names.
        Caps total strings to avoid OOM on huge JARs.
        """
        strings: List[str] = []
        limit   = 200_000  # max strings to collect

        for name in zf.namelist():
            if not name.endswith(".class"):
                continue
            try:
                data = zf.read(name)
            except Exception:
                continue
            # Decode as latin-1 so no bytes are lost
            text = data.decode("latin-1", errors="replace")
            for m in re.finditer(r"[\x20-\x7E]{" + str(_MIN_STR_LEN) + r",}", text):
                strings.append(m.group())
                if len(strings) >= limit:
                    return strings

        return strings

    def _list_services(self, entry_names: List[str]) -> List[str]:
        """Return META-INF/services/* interface names."""
        prefix = "META-INF/services/"
        return [
            n[len(prefix):]
            for n in entry_names
            if n.startswith(prefix) and n != prefix
        ]

    def _find_duplicate_entries(self, zf: zipfile.ZipFile) -> List[str]:
        """Return list of entry names that appear more than once in the ZIP central directory."""
        seen: Dict[str, int] = {}
        for info in zf.infolist():
            seen[info.filename] = seen.get(info.filename, 0) + 1
        return [name for name, count in seen.items() if count > 1]

    def _collect_lib_names(self, entry_names: List[str]) -> List[str]:
        """
        Collect JAR file names bundled inside this JAR (fat-jar / uber-jar),
        plus the top-level filename itself.
        """
        libs = [
            os.path.basename(n)
            for n in entry_names
            if n.endswith(".jar") or (n.startswith("META-INF/") and n.endswith(".jar"))
        ]
        return libs

    # ── Pattern check methods ────────────────────────────────────────────────

    def _check_manifest_attr(
        self, pattern: Dict, ctx: Dict, fid: int
    ) -> List[Dict]:
        det       = pattern["detection"]
        attr      = det.get("attribute", "").lower()
        check     = det.get("check", "exists")
        expected  = str(det.get("value", "")).lower()

        present = attr in ctx["manifest"]
        val     = ctx["manifest"].get(attr, "")

        triggered = False
        snippet   = ""

        if check == "exists":
            triggered = present
            snippet   = f"{attr}: {val}" if present else ""
        elif check == "missing":
            triggered = not present
            snippet   = f"'{attr}' not present in MANIFEST.MF"
        elif check == "equals":
            triggered = present and val.lower() == expected
            snippet   = f"{attr}: {val}" if triggered else ""
        elif check == "contains":
            triggered = present and expected in val.lower()
            snippet   = f"{attr}: {val}" if triggered else ""
        elif check == "not_empty":
            triggered = present and bool(val.strip())
            snippet   = f"{attr}: {val}" if triggered else ""
        elif check == "regex":
            try:
                triggered = present and bool(re.search(expected, val, re.I))
                snippet   = f"{attr}: {val}" if triggered else ""
            except re.error:
                pass

        if not triggered:
            return []
        return [self._make_finding(fid, pattern, "META-INF/MANIFEST.MF", snippet)]

    def _check_class_exists(
        self, pattern: Dict, ctx: Dict, fid: int
    ) -> List[Dict]:
        det        = pattern["detection"]
        class_name = det.get("class_name", "")
        if not class_name:
            return []

        # Normalise slashes
        class_name_norm = class_name.replace(".", "/")
        if not class_name_norm.endswith(".class"):
            class_name_norm += ".class"

        found = any(
            e == class_name_norm or e.endswith("/" + class_name_norm)
            for e in ctx["entry_names"]
        )
        if not found:
            return []
        return [self._make_finding(fid, pattern, class_name_norm,
                                   f"Class present: {class_name_norm}")]

    def _check_string_pattern(
        self, pattern: Dict, ctx: Dict, fid: int
    ) -> List[Dict]:
        det       = pattern["detection"]
        rx_str    = det.get("pattern", "")
        if not rx_str:
            return []

        try:
            rx = re.compile(rx_str, re.I)
        except re.error:
            return []

        matches: List[str] = []
        for s in ctx["class_strings"]:
            if rx.search(s):
                matches.append(s.strip()[:120])
                if len(matches) >= 3:
                    break

        if not matches:
            return []

        snippet = " | ".join(matches)
        return [self._make_finding(fid, pattern, "class files (string constants)", snippet)]

    def _check_entry_pattern(
        self, pattern: Dict, ctx: Dict, fid: int
    ) -> List[Dict]:
        det    = pattern["detection"]
        rx_str = det.get("pattern", "")
        if not rx_str:
            return []

        try:
            rx = re.compile(rx_str, re.I)
        except re.error:
            return []

        matched = [e for e in ctx["entry_names"] if rx.search(e)]
        if not matched:
            return []

        snippet = ", ".join(matched[:5])
        return [self._make_finding(fid, pattern, "JAR entries", snippet)]

    def _check_library_version(
        self, pattern: Dict, ctx: Dict, fid: int
    ) -> List[Dict]:
        """
        Match known-vulnerable library versions from:
        - Nested .jar file names inside the fat-jar
        - MANIFEST.MF Implementation-Title + Implementation-Version
        - MANIFEST.MF Built-By or Class-Path
        """
        det        = pattern["detection"]
        name_rx    = det.get("name_pattern", "")
        if not name_rx:
            return []

        try:
            rx = re.compile(name_rx, re.I)
        except re.error:
            return []

        # 1) nested jar names
        for lib in ctx["lib_names"]:
            if rx.search(lib):
                return [self._make_finding(fid, pattern, "bundled dependency", lib)]

        # 2) MANIFEST Implementation-Title + Version
        impl_title = ctx["manifest"].get("implementation-title", "")
        impl_ver   = ctx["manifest"].get("implementation-version", "")
        combined   = f"{impl_title}-{impl_ver}"
        if rx.search(combined):
            return [self._make_finding(fid, pattern, "META-INF/MANIFEST.MF",
                                       f"Implementation: {combined}")]

        # 3) Class-Path header
        cp = ctx["manifest"].get("class-path", "")
        if cp:
            for token in cp.split():
                if rx.search(os.path.basename(token)):
                    return [self._make_finding(fid, pattern, "META-INF/MANIFEST.MF",
                                               f"Class-Path: {token}")]

        # 4) Check all entry names (in case lib is expanded inside the JAR)
        for name in ctx["entry_names"]:
            basename = os.path.basename(name)
            if rx.search(basename):
                return [self._make_finding(fid, pattern, name, basename)]

        return []

    def _check_duplicate_entries(
        self, pattern: Dict, ctx: Dict, fid: int
    ) -> List[Dict]:
        dups = ctx["dup_entries"]
        if not dups:
            return []
        snippet = ", ".join(dups[:5]) + ("…" if len(dups) > 5 else "")
        return [self._make_finding(fid, pattern, "ZIP structure", snippet)]

    def _check_services_entry(
        self, pattern: Dict, ctx: Dict, fid: int
    ) -> List[Dict]:
        det       = pattern["detection"]
        interface = det.get("interface", "")
        if not interface:
            # match any suspicious SPI service
            dangerous = [
                "java.security.Provider",
                "javax.net.ssl",
                "java.util.spi",
                "sun.misc.Unsafe",
            ]
            found = [s for s in ctx["services"]
                     if any(d.lower() in s.lower() for d in dangerous)]
            if not found:
                return []
            snippet = ", ".join(found[:5])
        else:
            found = [s for s in ctx["services"] if interface.lower() in s.lower()]
            if not found:
                return []
            snippet = ", ".join(found[:5])

        return [self._make_finding(fid, pattern, "META-INF/services/", snippet)]

    # ── Finding factory ──────────────────────────────────────────────────────

    def _make_finding(
        self, fid: int, pattern: Dict, file_path: str, snippet: str
    ) -> Dict[str, Any]:
        return {
            "id":          fid,
            "fid":         fid,
            "title":       pattern.get("title", ""),
            "severity":    pattern.get("severity", "Info"),
            "category":    pattern.get("category", ""),
            "description": pattern.get("description", ""),
            "evidence": {
                "file":        file_path,
                "file_path":   file_path,
                "line_number": 0,
                "snippet":     snippet,
            },
            "adb_commands": [],
            "remediation":  pattern.get("remediation", ""),
            "attack_path":  pattern.get("attack_path", ""),
            "cwe":          pattern.get("cwe", []),
            "references":   pattern.get("references", []),
            "platform":     "jar",
        }

    def _error_finding(self, fid: int, msg: str) -> Dict[str, Any]:
        return {
            "id": fid, "fid": fid,
            "title": "JAR Parse Error",
            "severity": "Info",
            "category": "Scanner",
            "description": f"Could not parse JAR: {msg}",
            "evidence": {"file": "", "file_path": "", "line_number": 0, "snippet": msg},
            "adb_commands": [], "remediation": "", "attack_path": "",
            "cwe": [], "references": [], "platform": "jar",
        }


# ── Module-level convenience function ───────────────────────────────────────


def scan_jar(jar_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Scan a JAR and return (findings, metadata).

    metadata keys:
        main_class      — Main-Class from MANIFEST.MF
        implementation  — Implementation-Title / Implementation-Version
        vendor          — Implementation-Vendor
        platform        — 'jar'
    """
    scanner  = JARScanner()
    metadata: Dict[str, Any] = {
        "main_class":     None,
        "implementation": None,
        "vendor":         None,
        "platform":       "jar",
    }

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            manifest = scanner._parse_manifest(zf)
        metadata["main_class"]     = manifest.get("main-class")
        metadata["implementation"] = (
            (manifest.get("implementation-title") or "") + " " +
            (manifest.get("implementation-version") or "")
        ).strip() or None
        metadata["vendor"] = manifest.get("implementation-vendor")
    except Exception:
        pass

    findings = scanner.scan(jar_path)
    return findings, metadata
