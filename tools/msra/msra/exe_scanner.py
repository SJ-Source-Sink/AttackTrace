"""
Windows PE/EXE static analysis scanner for MSRA.
Analyses executable files for security misconfigurations, dangerous API usage,
malware indicators, and missing exploit mitigations.

Requires `pefile` for full analysis: pip install pefile
Falls back to string-only analysis if pefile is not installed.
"""

from __future__ import annotations

import collections
import json
import math
import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


_DEFAULT_PATTERNS_PATH = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "data", "builtin", "exe_patterns.json"
))

# PE DLL Characteristics flags
_DLLCHARS = {
    "HIGH_ENTROPY_ASLR": 0x0020,
    "ASLR":              0x0040,
    "FORCE_INTEGRITY":   0x0080,
    "DEP_NX":            0x0100,
    "NO_SEH":            0x0400,
    "CFG":               0x4000,
}

# Section permission flags
_SCN_EXECUTE = 0x20000000
_SCN_READ    = 0x40000000
_SCN_WRITE   = 0x80000000

# Machines
_MACHINE_AMD64 = 0x8664
_MACHINE_I386  = 0x014C
_MACHINE_ARM64 = 0xAA64

# Entropy thresholds
_ENTROPY_HIGH   = 7.0
_ENTROPY_MEDIUM = 6.5

# Known packer section names
_PACKER_SECTIONS: Set[str] = {
    "upx0", "upx1", "upx2", ".aspack", ".adata",
    ".pec1", ".pec2", ".mpress1", ".mpress2", ".themida", ".winlicense",
}

# Min string length for extraction
_MIN_STR_LEN = 6


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    ctr = collections.Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in ctr.values())


def _extract_strings(data: bytes, min_len: int = _MIN_STR_LEN) -> List[str]:
    """Extract ASCII and UTF-16LE strings from raw bytes."""
    results: List[str] = []
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data):
        results.append(m.group().decode("ascii", errors="replace"))
    # UTF-16LE wide strings
    for m in re.finditer(
        rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}", data
    ):
        results.append(m.group().decode("utf-16-le", errors="replace"))
    return results


class EXEScanner:
    """Static analysis scanner for Windows PE/EXE files."""

    def __init__(self, patterns_path: Optional[str] = None):
        if patterns_path is None:
            patterns_path = _DEFAULT_PATTERNS_PATH
        with open(patterns_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.patterns: List[Dict[str, Any]] = [
            p for p in data.get("patterns", []) if p.get("enabled", True)
        ]

    # ── Public API ──────────────────────────────────────────────────────────

    def scan(self, exe_path: str) -> List[Dict[str, Any]]:
        """Main entry point. Returns a list of finding dicts."""
        raw = Path(exe_path).read_bytes()
        ctx = self._build_context(raw)
        findings: List[Dict[str, Any]] = []
        fid = 1

        for pattern in self.patterns:
            det   = pattern.get("detection", {})
            dtype = det.get("type", "")

            # Skip PE-specific checks if pefile is unavailable
            if dtype in ("pe_characteristic", "pe_imports", "pe_imports_combo",
                         "pe_section", "pe_manifest") and not ctx["has_pefile"]:
                continue

            new: List[Dict[str, Any]] = []

            if dtype == "pe_characteristic":
                new = self._check_characteristic(pattern, ctx, fid)
            elif dtype == "pe_imports":
                new = self._check_imports(pattern, ctx, fid)
            elif dtype == "pe_imports_combo":
                new = self._check_imports_combo(pattern, ctx, fid)
            elif dtype == "pe_section":
                new = self._check_section(pattern, ctx, fid)
            elif dtype == "pe_manifest":
                new = self._check_manifest(pattern, ctx, fid)
            elif dtype == "string_pattern":
                new = self._check_string_pattern(pattern, ctx, fid)

            for f in new:
                f["id"]  = fid
                f["fid"] = fid
                fid += 1
            findings.extend(new)

        return findings

    # ── Context builder ──────────────────────────────────────────────────────

    def _build_context(self, raw: bytes) -> Dict[str, Any]:
        """Parse PE file and build analysis context. Gracefully handles missing pefile."""
        ctx: Dict[str, Any] = {
            "has_pefile":      False,
            "strings":         _extract_strings(raw),
            "raw":             raw,
            # PE-specific (populated below if pefile available)
            "dll_chars":       {},
            "is_64bit":        False,
            "imports":         {},   # {api_name_lower: dll_name}
            "import_flat":     set(),  # all API names (lowercase)
            "sections":        [],
            "has_authenticode": False,
            "stack_cookie":    False,
            "safe_seh":        False,
            "cfg_lc":          False,
            "manifest_level":  None,
            "manifest_uiaccess": False,
            "version_info":    {},
            "file_type":       "PE",
        }

        try:
            import pefile as _pef
            pe = _pef.PE(data=raw)
            ctx["has_pefile"] = True
        except ImportError:
            return ctx
        except Exception:
            return ctx

        # DLL Characteristics
        dllchars = pe.OPTIONAL_HEADER.DllCharacteristics
        machine  = pe.FILE_HEADER.Machine
        ctx["is_64bit"] = (machine == _MACHINE_AMD64 or machine == _MACHINE_ARM64)
        ctx["dll_chars"] = {name: bool(dllchars & val) for name, val in _DLLCHARS.items()}

        # LoadConfig — stack cookie, SafeSEH, CFG detail
        if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
            lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            if hasattr(lc, "SecurityCookie"):
                ctx["stack_cookie"] = (lc.SecurityCookie != 0)
            if hasattr(lc, "SEHandlerCount"):
                ctx["safe_seh"] = (lc.SEHandlerCount > 0)
            if hasattr(lc, "GuardCFCheckFunctionPointer"):
                ctx["cfg_lc"] = (lc.GuardCFCheckFunctionPointer != 0)

        # GS fallback via import names
        if not ctx["stack_cookie"] and hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            gs_syms = {
                "__security_cookie", "__security_check_cookie",
                "__security_init_cookie", "__gshandlercheck",
            }
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode("utf-8", errors="replace").lower() in gs_syms:
                        ctx["stack_cookie"] = True
                        break

        # Imports — flat set and per-API lookup
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace").lower()
                for imp in entry.imports:
                    if imp.name:
                        api = imp.name.decode("utf-8", errors="replace")
                        ctx["imports"][api] = dll
                        ctx["import_flat"].add(api.lower())

        # Sections
        for section in pe.sections:
            name  = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            chars = section.Characteristics
            data  = section.get_data()
            ctx["sections"].append({
                "name":     name,
                "entropy":  round(_calculate_entropy(data), 4),
                "chars":    chars,
                "is_exec":  bool(chars & _SCN_EXECUTE),
                "is_write": bool(chars & _SCN_WRITE),
                "is_read":  bool(chars & _SCN_READ),
                "is_rwx":   bool((chars & _SCN_EXECUTE) and (chars & _SCN_WRITE)),
                "raw_size": section.SizeOfRawData,
            })

        # Authenticode — presence via Security Directory
        ctx["has_authenticode"] = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and \
                                   len(pe.DIRECTORY_ENTRY_SECURITY) > 0

        # Manifest — requestedExecutionLevel, uiAccess
        ctx["manifest_level"], ctx["manifest_uiaccess"] = self._parse_manifest(pe)

        # Version info
        ctx["version_info"] = self._parse_version_info(pe)

        return ctx

    def _parse_manifest(self, pe: Any) -> Tuple[Optional[str], bool]:
        """Extract requestedExecutionLevel and uiAccess from RT_MANIFEST resource."""
        RT_MANIFEST = 24
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None, False
        try:
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if res_type.id == RT_MANIFEST:
                    for res_id in res_type.directory.entries:
                        for res_lang in res_id.directory.entries:
                            data_rva = res_lang.data.struct.OffsetToData
                            size     = res_lang.data.struct.Size
                            xml_data = pe.get_data(data_rva, size)
                            xml_str  = xml_data.decode("utf-8", errors="replace")
                            level, uiaccess = self._parse_execution_level(xml_str)
                            return level, uiaccess
        except Exception:
            pass
        return None, False

    def _parse_execution_level(self, xml_str: str) -> Tuple[Optional[str], bool]:
        """Parse requestedExecutionLevel from manifest XML string."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_str)
            for elem in root.iter():
                if "requestedExecutionLevel" in elem.tag:
                    level     = elem.attrib.get("level", "asInvoker")
                    uiaccess  = elem.attrib.get("uiAccess", "false").lower() == "true"
                    return level, uiaccess
        except Exception:
            # Fallback regex
            m = re.search(r'level=["\'](\w+)["\']', xml_str, re.I)
            level = m.group(1) if m else None
            uiaccess = bool(re.search(r'uiAccess=["\']true["\']', xml_str, re.I))
            return level, uiaccess
        return None, False

    def _parse_version_info(self, pe: Any) -> Dict[str, str]:
        """Extract StringFileInfo version fields."""
        result: Dict[str, str] = {}
        if not hasattr(pe, "FileInfo"):
            return result
        try:
            for file_info in pe.FileInfo:
                for info in file_info:
                    if hasattr(info, "StringTable"):
                        for st in info.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode("utf-8", errors="replace")
                                val = v.decode("utf-8", errors="replace").strip("\x00")
                                result[key] = val
        except Exception:
            pass
        return result

    # ── Pattern check methods ────────────────────────────────────────────────

    def _check_characteristic(self, pattern: Dict, ctx: Dict, fid: int) -> List[Dict]:
        """Check a PE security characteristic (DLL flag, stack cookie, etc.)."""
        det   = pattern["detection"]
        flag  = det.get("flag", "")
        check = det.get("check", "missing")  # missing | present

        # Special pseudo-flags handled separately
        if flag == "STACK_COOKIE":
            present = ctx["stack_cookie"]
        elif flag == "AUTHENTICODE":
            present = ctx["has_authenticode"]
        elif flag == "SAFE_SEH":
            present = ctx["safe_seh"]
        elif flag == "HIGH_ENTROPY_ASLR":
            # Only meaningful on 64-bit
            if not ctx["is_64bit"]:
                return []
            present = ctx["dll_chars"].get("HIGH_ENTROPY_ASLR", False)
        else:
            present = ctx["dll_chars"].get(flag, False)

        triggered = (check == "missing" and not present) or \
                    (check == "present" and present)
        if not triggered:
            return []

        snippet = f"{flag}: {'present' if present else 'missing'}"
        return [self._make_finding(fid, pattern, "PE Optional Header", snippet)]

    def _check_imports(self, pattern: Dict, ctx: Dict, fid: int) -> List[Dict]:
        """Check if any of the listed APIs are imported."""
        det       = pattern["detection"]
        apis      = [a.lower() for a in det.get("apis", [])]
        match_all = det.get("match", "any") == "all"

        if not apis:
            return []

        found = [a for a in apis if a in ctx["import_flat"]]

        if match_all:
            if len(found) < len(apis):
                return []
        else:
            if not found:
                return []

        # Find original-case names for the snippet
        original = [
            a for a in ctx["imports"] if a.lower() in {f.lower() for f in found}
        ]
        snippet = ", ".join(original[:5]) + ("…" if len(original) > 5 else "")
        dll_info = ", ".join({ctx["imports"][a] for a in original[:3]})
        return [self._make_finding(fid, pattern, f"Import Table ({dll_info})", snippet)]

    def _check_imports_combo(self, pattern: Dict, ctx: Dict, fid: int) -> List[Dict]:
        """
        Trigger if at least min_matches out of the API list are imported.
        Used for high-confidence combos (e.g. injection triad, ransomware APIs).
        """
        det          = pattern["detection"]
        apis         = [a.lower() for a in det.get("apis", [])]
        min_matches  = int(det.get("min_matches", 2))

        found = [a for a in apis if a in ctx["import_flat"]]
        if len(found) < min_matches:
            return []

        original = [a for a in ctx["imports"] if a.lower() in set(found)]
        snippet  = f"{len(found)}/{len(apis)} APIs present: {', '.join(original[:6])}"
        return [self._make_finding(fid, pattern, "Import Table (API combo)", snippet)]

    def _check_section(self, pattern: Dict, ctx: Dict, fid: int) -> List[Dict]:
        """Check section security properties (RWX, entropy, packer names)."""
        det   = pattern["detection"]
        check = det.get("check", "")

        matches: List[Dict[str, str]] = []

        for sec in ctx["sections"]:
            name    = sec["name"]
            hit     = False
            snippet = ""

            if check == "rwx" and sec["is_rwx"]:
                hit     = True
                snippet = f"Section '{name}' is Read+Write+Execute"

            elif check == "high_entropy" and sec["entropy"] > _ENTROPY_HIGH:
                hit     = True
                snippet = f"Section '{name}' entropy={sec['entropy']:.2f} (>7.0, likely packed/encrypted)"

            elif check == "packer_name" and name.lower() in _PACKER_SECTIONS:
                hit     = True
                snippet = f"Known packer section: '{name}'"

            elif check == "exec_write" and sec["is_exec"] and sec["is_write"]:
                hit     = True
                snippet = f"Section '{name}' is both executable and writable"

            if hit:
                matches.append({"sec": name, "snippet": snippet})

        results: List[Dict[str, Any]] = []
        for i, m in enumerate(matches):
            f = self._make_finding(fid + i, pattern, f"Section '{m['sec']}'", m["snippet"])
            results.append(f)

        return results

    def _check_manifest(self, pattern: Dict, ctx: Dict, fid: int) -> List[Dict]:
        """Check manifest requestedExecutionLevel or uiAccess."""
        det   = pattern["detection"]
        check = det.get("check", "")

        if check == "admin":
            if ctx["manifest_level"] and "administrator" in ctx["manifest_level"].lower():
                return [self._make_finding(fid, pattern, "Application Manifest",
                                           f"requestedExecutionLevel={ctx['manifest_level']}")]
        elif check == "uiaccess":
            if ctx["manifest_uiaccess"]:
                return [self._make_finding(fid, pattern, "Application Manifest",
                                           "uiAccess=true — can drive higher-privilege UI")]
        return []

    def _check_string_pattern(self, pattern: Dict, ctx: Dict, fid: int) -> List[Dict]:
        """Regex match against all extracted strings."""
        det    = pattern["detection"]
        rx_str = det.get("pattern", "")
        if not rx_str:
            return []

        try:
            rx = re.compile(rx_str, re.IGNORECASE)
        except re.error:
            return []

        matches: List[str] = []
        for s in ctx["strings"]:
            if rx.search(s):
                matches.append(s.strip()[:120])
                if len(matches) >= 3:
                    break

        if not matches:
            return []

        snippet = " | ".join(matches)
        return [self._make_finding(fid, pattern, "String constants", snippet)]

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
            "platform":     "exe",
        }


# ── Module-level convenience function ───────────────────────────────────────


def scan_exe(exe_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Scan a PE/EXE file and return (findings, metadata).

    metadata keys:
        original_filename   — from version info OriginalFilename
        product_name        — from version info ProductName
        file_version        — from version info FileVersion
        company             — from version info CompanyName
        architecture        — x86 / x64 / ARM64
        has_pefile          — True if pefile library was available
        platform            — 'exe'
    """
    scanner  = EXEScanner()
    metadata: Dict[str, Any] = {
        "original_filename": None,
        "product_name":      None,
        "file_version":      None,
        "company":           None,
        "architecture":      None,
        "has_pefile":        False,
        "platform":          "exe",
    }

    try:
        raw = Path(exe_path).read_bytes()
        ctx = scanner._build_context(raw)
        metadata["has_pefile"] = ctx["has_pefile"]

        vi = ctx.get("version_info", {})
        metadata["original_filename"] = vi.get("OriginalFilename") or vi.get("InternalName")
        metadata["product_name"]      = vi.get("ProductName")
        metadata["file_version"]      = vi.get("FileVersion")
        metadata["company"]           = vi.get("CompanyName")

        if ctx["has_pefile"]:
            if ctx["is_64bit"]:
                metadata["architecture"] = "x64"
            else:
                metadata["architecture"] = "x86"
    except Exception:
        pass

    findings = scanner.scan(exe_path)
    return findings, metadata
