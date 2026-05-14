"""
Rules management API for the web dashboard.
Provides JSON-serializable rule data and CRUD for custom rules.
Custom rules are persisted to data/custom/user_rules.json.
Enable/disable overrides are persisted to data/custom/overrides.json.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR     = Path(__file__).parent.parent / "data"
CUSTOM_DIR   = DATA_DIR / "custom"
USER_RULES_F = CUSTOM_DIR / "user_rules.json"
OVERRIDES_F  = CUSTOM_DIR / "overrides.json"

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# ── In-memory rules cache ────────────────────────────────────────────────────
_rules_cache: Optional[List[dict]] = None
_rules_cache_ts: float = 0.0
_CACHE_TTL: float = 60.0  # seconds


def _invalidate_cache() -> None:
    global _rules_cache
    _rules_cache = None


def _ensure_dirs():
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)


# ── Overrides (enable/disable state) ───────────────────────────────────────

def _load_overrides() -> Dict[str, List[str]]:
    if OVERRIDES_F.exists():
        try:
            return json.loads(OVERRIDES_F.read_text())
        except Exception:
            pass
    return {"disabled": [], "enabled": []}


def _save_overrides(data: Dict[str, List[str]]):
    _ensure_dirs()
    OVERRIDES_F.write_text(json.dumps(data, indent=2))


# ── Custom rules ────────────────────────────────────────────────────────────

def _load_user_rules() -> List[dict]:
    if USER_RULES_F.exists():
        try:
            data = json.loads(USER_RULES_F.read_text())
            return data.get("patterns", [])
        except Exception:
            pass
    return []


def _save_user_rules(rules: List[dict]):
    _ensure_dirs()
    USER_RULES_F.write_text(json.dumps({
        "schema_version": "1.0.0",
        "name": "User Custom Rules",
        "patterns": rules,
    }, indent=2))


# ── Serialization ───────────────────────────────────────────────────────────

def _pattern_to_dict(raw: dict, source: str, overrides: Dict[str, List[str]],
                     platform: str = "android") -> dict:
    pid             = raw.get("id", "")
    default_enabled = raw.get("enabled", True)

    if pid in overrides.get("disabled", []):
        enabled = False
    elif pid in overrides.get("enabled", []):
        enabled = True
    else:
        enabled = default_enabled

    meta      = raw.get("metadata", {}) or {}
    detection = raw.get("detection", {}) or {}
    det_type  = detection.get("type", "regex")

    patterns_list = []
    if det_type in ("regex", "regex-multiline", "combined", "ast", "binary_string"):
        for p in detection.get("patterns", []):
            patterns_list.append({
                "pattern":    p.get("pattern", ""),
                "flags":      p.get("flags", "i"),
                "file_types": p.get("file_types", []),
            })

    manifest_checks = []
    if det_type in ("manifest", "combined"):
        for mc in detection.get("manifest_checks", []):
            manifest_checks.append({
                "xpath":     mc.get("xpath", ""),
                "condition": mc.get("condition", "exists"),
                "attribute": mc.get("attribute", ""),
                "value":     mc.get("value", ""),
            })

    # iOS-specific detection fields
    ios_detection: dict = {}
    if det_type in ("plist_key", "entitlement", "binary_flag"):
        ios_detection = {k: v for k, v in detection.items() if k != "type"}

    # JAR-specific detection fields
    jar_detection: dict = {}
    if det_type in ("manifest_attr", "class_exists", "string_pattern",
                    "entry_pattern", "library_version", "duplicate_entries",
                    "services_entry"):
        jar_detection = {k: v for k, v in detection.items() if k != "type"}

    # EXE/PE-specific detection fields
    exe_detection: dict = {}
    if det_type in ("pe_characteristic", "pe_imports", "pe_imports_combo",
                    "pe_section", "pe_manifest"):
        exe_detection = {k: v for k, v in detection.items() if k != "type"}

    return {
        "id":             pid,
        "title":          raw.get("title", ""),
        "severity":       raw.get("severity", "Medium"),
        "category":       raw.get("category", "Other"),
        "description":    raw.get("description", ""),
        "attack_path":    raw.get("attack_path", ""),
        "remediation":    raw.get("remediation", ""),
        "detection_type": det_type,
        "patterns":       patterns_list,
        "manifest_checks":manifest_checks,
        "ios_detection":  ios_detection,
        "jar_detection":  jar_detection,
        "exe_detection":  exe_detection,
        "cwe":            raw.get("cwe", []) or meta.get("cwe", []),
        "cve":            meta.get("cve", []),
        "references":     raw.get("references", []) or meta.get("references", []),
        "confidence":     meta.get("confidence", "medium"),
        "false_positive_rate": meta.get("false_positive_rate", ""),
        "tags":           raw.get("tags", []),
        "adb_category":   raw.get("adb_category", "general"),
        "enabled":        enabled,
        "source":         source,
        "platform":       raw.get("platform", platform),
        "test_cases":     raw.get("test_cases", []),
        "created_at":     raw.get("created_at"),
    }


# ── Public API ──────────────────────────────────────────────────────────────

def _compute_all_rules() -> List[dict]:
    """Build the full rules list from disk (uncached)."""
    overrides = _load_overrides()
    rules     = []
    seen      = set()

    def add_from_file(path: Path, source: str, platform: str = "android"):
        try:
            data = json.loads(path.read_text())
            plat = data.get("platform", platform)
            for p in data.get("patterns", []):
                pid = p.get("id", "")
                if pid and pid not in seen:
                    seen.add(pid)
                    rules.append(_pattern_to_dict(p, source, overrides, plat))
        except Exception:
            pass

    # Built-in Android
    builtin = DATA_DIR / "builtin" / "patterns.json"
    if builtin.exists():
        add_from_file(builtin, "builtin", "android")

    # Built-in iOS
    ios_builtin = DATA_DIR / "builtin" / "ios_patterns.json"
    if ios_builtin.exists():
        add_from_file(ios_builtin, "builtin", "ios")

    # Built-in JAR
    jar_builtin = DATA_DIR / "builtin" / "jar_patterns.json"
    if jar_builtin.exists():
        add_from_file(jar_builtin, "builtin", "jar")

    # Built-in EXE/PE
    exe_builtin = DATA_DIR / "builtin" / "exe_patterns.json"
    if exe_builtin.exists():
        add_from_file(exe_builtin, "builtin", "exe")

    # Community
    community_dir = DATA_DIR / "community"
    if community_dir.exists():
        for f in sorted(community_dir.glob("*.json")):
            add_from_file(f, "community")

    # Custom user rules
    for p in _load_user_rules():
        pid = p.get("id", "")
        if pid and pid not in seen:
            seen.add(pid)
            rules.append(_pattern_to_dict(p, "custom", overrides))

    rules.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 99), r["title"]))
    return rules


def get_all_rules() -> List[dict]:
    """Return all rules as JSON-serializable dicts, sorted by severity (cached)."""
    global _rules_cache, _rules_cache_ts
    now = time.time()
    if _rules_cache is not None and (now - _rules_cache_ts) < _CACHE_TTL:
        return _rules_cache
    _rules_cache = _compute_all_rules()
    _rules_cache_ts = now
    return _rules_cache


def get_rule_by_id(rule_id: str) -> Optional[dict]:
    return next((r for r in get_all_rules() if r["id"] == rule_id), None)


def _validate_patterns(data: dict) -> None:
    """Raise ValueError if any regex pattern in data fails to compile."""
    det_type = data.get("detection_type", "regex")
    if det_type not in ("regex", "regex-multiline", "combined"):
        return
    for p in data.get("patterns", []):
        pat = p.get("pattern", "")
        if not pat:
            continue
        try:
            re.compile(pat)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern '{pat}': {exc}") from exc


def toggle_rule(rule_id: str) -> dict:
    """Toggle a rule's enabled state. Returns {"id": ..., "enabled": ...}."""
    overrides = _load_overrides()

    # Determine default enabled state from any builtin pattern file
    original_enabled = True
    for builtin_name in ("patterns.json", "ios_patterns.json", "jar_patterns.json", "exe_patterns.json"):
        builtin = DATA_DIR / "builtin" / builtin_name
        if not builtin.exists():
            continue
        try:
            data = json.loads(builtin.read_text())
            match = next((p for p in data.get("patterns", []) if p.get("id") == rule_id), None)
            if match is not None:
                original_enabled = match.get("enabled", True)
                break
        except Exception:
            pass

    # Determine current state
    if rule_id in overrides.get("disabled", []):
        current = False
    elif rule_id in overrides.get("enabled", []):
        current = True
    else:
        current = original_enabled

    new_state = not current

    disabled = [r for r in overrides.get("disabled", []) if r != rule_id]
    enabled  = [r for r in overrides.get("enabled",  []) if r != rule_id]

    if new_state != original_enabled:
        (enabled if new_state else disabled).append(rule_id)

    overrides["disabled"] = disabled
    overrides["enabled"]  = enabled
    _save_overrides(overrides)
    _invalidate_cache()
    return {"id": rule_id, "enabled": new_state}


def create_custom_rule(data: dict) -> dict:
    """Create a new custom rule. Raises ValueError on duplicate ID or invalid regex."""
    _validate_patterns(data)
    rules   = _load_user_rules()
    rule_id = (data.get("id") or "").strip() or ("custom-" + uuid.uuid4().hex[:8])

    if any(r.get("id") == rule_id for r in rules):
        raise ValueError(f"Rule ID '{rule_id}' already exists")

    rule = _build_rule_dict(rule_id, data)
    rules.append(rule)
    _save_user_rules(rules)
    _invalidate_cache()
    return _pattern_to_dict(rule, "custom", _load_overrides())


def update_custom_rule(rule_id: str, data: dict) -> Optional[dict]:
    """Update a custom rule. Returns None if not found. Raises ValueError on invalid regex."""
    _validate_patterns(data)
    rules = _load_user_rules()
    idx   = next((i for i, r in enumerate(rules) if r.get("id") == rule_id), None)
    if idx is None:
        return None

    rule = rules[idx]
    for f in ["title", "severity", "category", "description", "attack_path", "remediation", "tags", "adb_category"]:
        if f in data:
            rule[f] = data[f]

    det = rule.setdefault("detection", {})
    if "detection_type" in data:
        det["type"] = data["detection_type"]
    if "patterns" in data:
        det["patterns"] = data["patterns"]
    if "manifest_checks" in data:
        det["manifest_checks"] = data["manifest_checks"]

    meta = rule.setdefault("metadata", {})
    for mf in ["cwe", "cve", "references", "confidence"]:
        if mf in data:
            meta[mf] = data[mf]

    rules[idx] = rule
    _save_user_rules(rules)
    _invalidate_cache()
    return _pattern_to_dict(rule, "custom", _load_overrides())


def delete_custom_rule(rule_id: str) -> bool:
    """Delete a custom rule. Returns True if found and deleted."""
    rules     = _load_user_rules()
    new_rules = [r for r in rules if r.get("id") != rule_id]
    if len(new_rules) == len(rules):
        return False
    _save_user_rules(new_rules)
    _invalidate_cache()
    return True


def get_stats() -> dict:
    """Return aggregated statistics about all loaded rules."""
    rules        = get_all_rules()
    by_severity  = {}
    by_category  = {}
    by_source    = {}
    enabled_count = 0

    for r in rules:
        by_severity[r["severity"]]  = by_severity.get(r["severity"], 0) + 1
        by_category[r["category"]]  = by_category.get(r["category"], 0) + 1
        by_source[r["source"]]      = by_source.get(r["source"], 0) + 1
        if r["enabled"]:
            enabled_count += 1

    return {
        "total":       len(rules),
        "enabled":     enabled_count,
        "disabled":    len(rules) - enabled_count,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_source":   by_source,
    }


# ── Helpers ─────────────────────────────────────────────────────────────────

def _build_rule_dict(rule_id: str, data: dict) -> dict:
    det_type = data.get("detection_type", "regex")
    return {
        "id":          rule_id,
        "title":       data.get("title", ""),
        "severity":    data.get("severity", "High"),
        "category":    data.get("category", "Other"),
        "description": data.get("description", ""),
        "attack_path": data.get("attack_path", ""),
        "remediation": data.get("remediation", ""),
        "adb_category":data.get("adb_category", "general"),
        "enabled":     True,
        "tags":        data.get("tags", []),
        "created_at":  int(time.time()),
        "detection": {
            "type":            det_type,
            "patterns":        data.get("patterns", []),
            "manifest_checks": data.get("manifest_checks", []),
        },
        "metadata": {
            "cwe":        data.get("cwe", []),
            "cve":        data.get("cve", []),
            "references": data.get("references", []),
            "confidence": data.get("confidence", "medium"),
            "source":     {"type": "custom"},
        },
    }
