"""Data models for vulnerability patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import List, Optional, Pattern as RegexPattern


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Category(Enum):
    """Vulnerability categories based on OWASP Mobile and common Android issues."""
    OWASP_M1_CREDENTIALS = "OWASP-M1-Credentials"
    OWASP_M2_SUPPLYCHAIN = "OWASP-M2-SupplyChain"
    OWASP_M3_AUTH = "OWASP-M3-AuthN-AuthZ"
    OWASP_M4_INPUT = "OWASP-M4-InputValidation"
    OWASP_M5_COMMUNICATION = "OWASP-M5-Communication"
    OWASP_M6_PRIVACY = "OWASP-M6-Privacy"
    OWASP_M7_BINARY = "OWASP-M7-BinaryProtection"
    OWASP_M8_MISCONFIGURATION = "OWASP-M8-Misconfiguration"
    OWASP_M9_STORAGE = "OWASP-M9-DataStorage"
    OWASP_M10_CRYPTO = "OWASP-M10-Cryptography"
    INTENT_DEEPLINK = "Intent-DeepLink"
    WEBVIEW = "WebView"
    COMPONENT_EXPOSURE = "Component-Exposure"
    PERMISSION = "Permission"
    NETWORK = "Network"
    LOGGING = "Logging"
    OTHER = "Other"


class DetectionType(Enum):
    """Types of detection methods."""
    REGEX = "regex"
    REGEX_MULTILINE = "regex-multiline"
    AST = "ast"
    MANIFEST = "manifest"
    COMBINED = "combined"


class SourceType(Enum):
    """Source types for patterns."""
    BUILTIN = "builtin"
    CUSTOM = "custom"
    COMMUNITY = "community"
    HACKERONE = "hackerone"
    BLOG = "blog"
    RESEARCH = "research"


class Confidence(Enum):
    """Confidence level in pattern accuracy."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AdbCategory(Enum):
    """Categories for ADB PoC command generation."""
    WEBVIEW = "webview"
    TLS = "tls"
    LOGCAT = "logcat"
    COMPONENT = "component"
    BACKUP = "backup"
    DEBUG = "debug"
    GENERAL = "general"


@dataclass
class PatternContext:
    """Context requirements for pattern matching."""
    must_contain: List[str] = field(default_factory=list)
    must_not_contain: List[str] = field(default_factory=list)
    within_lines: int = 10


@dataclass
class RegexDetection:
    """A single regex pattern with metadata."""
    pattern: str
    flags: str = "i"
    file_types: List[str] = field(default_factory=lambda: [".java", ".kt", ".xml"])
    context: Optional[PatternContext] = None
    _compiled: Optional[RegexPattern] = field(default=None, repr=False)

    def compile(self) -> RegexPattern:
        """Compile the regex pattern with appropriate flags."""
        if self._compiled is None:
            re_flags = 0
            if "i" in self.flags:
                re_flags |= re.IGNORECASE
            if "m" in self.flags:
                re_flags |= re.MULTILINE
            if "s" in self.flags:
                re_flags |= re.DOTALL
            self._compiled = re.compile(self.pattern, re_flags)
        return self._compiled

    @property
    def compiled(self) -> RegexPattern:
        """Get compiled regex pattern."""
        return self.compile()


@dataclass
class ManifestCheck:
    """A manifest-based check."""
    xpath: str
    attribute: Optional[str] = None
    value: Optional[str] = None
    condition: str = "exists"  # equals, contains, regex, exists, not_exists


@dataclass
class Detection:
    """Detection configuration for a pattern."""
    type: DetectionType
    patterns: List[RegexDetection] = field(default_factory=list)
    manifest_checks: List[ManifestCheck] = field(default_factory=list)


@dataclass
class PatternSource:
    """Source information for a pattern."""
    type: SourceType
    url: Optional[str] = None
    author: Optional[str] = None
    report_id: Optional[str] = None


@dataclass
class PatternMetadata:
    """Rich metadata for vulnerability patterns."""
    cwe: List[str] = field(default_factory=list)
    cve: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source: Optional[PatternSource] = None
    created_at: Optional[date] = None
    updated_at: Optional[date] = None
    version: str = "1.0.0"
    confidence: Confidence = Confidence.MEDIUM
    false_positive_rate: str = "medium"


@dataclass
class TestCase:
    """Test case for pattern validation."""
    code: str
    should_match: bool
    description: str = ""


@dataclass
class VulnerabilityPattern:
    """Complete vulnerability pattern definition."""
    id: str
    title: str
    severity: Severity
    category: Category
    detection: Detection
    description: str
    attack_path: str
    metadata: PatternMetadata = field(default_factory=PatternMetadata)
    remediation: str = ""
    adb_category: str = "general"
    test_cases: List[TestCase] = field(default_factory=list)
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    @property
    def fid(self) -> str:
        """Compatibility with existing PatternRule."""
        return self.id

    def matches_file_type(self, file_path: str) -> bool:
        """Check if this pattern should be applied to a file type."""
        if self.detection.type == DetectionType.MANIFEST:
            return file_path.endswith("AndroidManifest.xml")

        for regex_det in self.detection.patterns:
            for ext in regex_det.file_types:
                if file_path.endswith(ext):
                    return True
        return False

    def get_regex_patterns(self) -> List[RegexDetection]:
        """Get all regex patterns for this vulnerability."""
        return self.detection.patterns

    def to_dict(self) -> dict:
        """Convert pattern to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "detection": {
                "type": self.detection.type.value,
                "patterns": [
                    {
                        "pattern": p.pattern,
                        "flags": p.flags,
                        "file_types": p.file_types,
                        "context": {
                            "must_contain": p.context.must_contain,
                            "must_not_contain": p.context.must_not_contain,
                            "within_lines": p.context.within_lines,
                        } if p.context else None,
                    }
                    for p in self.detection.patterns
                ],
                "manifest_checks": [
                    {
                        "xpath": m.xpath,
                        "attribute": m.attribute,
                        "value": m.value,
                        "condition": m.condition,
                    }
                    for m in self.detection.manifest_checks
                ],
            },
            "description": self.description,
            "attack_path": self.attack_path,
            "remediation": self.remediation,
            "metadata": {
                "cwe": self.metadata.cwe,
                "cve": self.metadata.cve,
                "references": self.metadata.references,
                "source": {
                    "type": self.metadata.source.type.value,
                    "url": self.metadata.source.url,
                    "author": self.metadata.source.author,
                    "report_id": self.metadata.source.report_id,
                } if self.metadata.source else None,
                "created_at": self.metadata.created_at.isoformat() if self.metadata.created_at else None,
                "updated_at": self.metadata.updated_at.isoformat() if self.metadata.updated_at else None,
                "version": self.metadata.version,
                "confidence": self.metadata.confidence.value,
                "false_positive_rate": self.metadata.false_positive_rate,
            },
            "adb_category": self.adb_category,
            "test_cases": [
                {
                    "code": t.code,
                    "should_match": t.should_match,
                    "description": t.description,
                }
                for t in self.test_cases
            ],
            "enabled": self.enabled,
            "tags": self.tags,
        }
