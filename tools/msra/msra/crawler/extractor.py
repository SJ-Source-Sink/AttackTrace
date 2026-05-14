"""Pattern extractor for security writeups."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from ..patterns.models import (
    VulnerabilityPattern,
    Detection,
    DetectionType,
    RegexDetection,
    PatternMetadata,
    PatternSource,
    SourceType,
    Severity,
    Category,
    Confidence,
)
from .hackerone import HackerOneReport
from .blogs import BlogArticle

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    """Result from pattern extraction attempt."""
    success: bool
    patterns: List[VulnerabilityPattern] = field(default_factory=list)
    requires_review: bool = True
    confidence: float = 0.0
    raw_extractions: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# Common Android vulnerability patterns for detection
ANDROID_VULN_PATTERNS = {
    "webview_js_interface": {
        "keywords": ["addJavascriptInterface", "JavascriptInterface", "WebView", "@JavascriptInterface"],
        "regex": r"addJavascriptInterface\s*\(",
        "category": Category.WEBVIEW,
        "cwe": ["CWE-749"],
        "severity": Severity.HIGH,
        "title": "WebView JavaScript Interface"
    },
    "webview_file_access": {
        "keywords": ["setAllowFileAccess", "setAllowUniversalAccessFromFileURLs", "file://", "setAllowFileAccessFromFileURLs"],
        "regex": r"setAllow(?:File|Universal)Access(?:FromFileURLs)?\s*\(\s*true",
        "category": Category.WEBVIEW,
        "cwe": ["CWE-200"],
        "severity": Severity.HIGH,
        "title": "WebView File Access"
    },
    "deeplink_validation": {
        "keywords": ["deeplink", "intent://", "scheme", "pathPrefix", "getData", "getPath"],
        "regex": r"getIntent\s*\(\s*\)\s*\.\s*getData\s*\(\s*\)",
        "category": Category.INTENT_DEEPLINK,
        "cwe": ["CWE-939"],
        "severity": Severity.HIGH,
        "title": "DeepLink Vulnerability"
    },
    "exported_component": {
        "keywords": ["exported=", "android:exported", "intent-filter", "exported component"],
        "regex": r'android:exported\s*=\s*["\']true["\']',
        "category": Category.COMPONENT_EXPOSURE,
        "cwe": ["CWE-926"],
        "severity": Severity.HIGH,
        "title": "Exported Component"
    },
    "sql_injection": {
        "keywords": ["rawQuery", "execSQL", "ContentProvider", "SQL injection", "SQLi"],
        "regex": r'rawQuery\s*\([^)]*\+',
        "category": Category.OWASP_M4_INPUT,
        "cwe": ["CWE-89"],
        "severity": Severity.CRITICAL,
        "title": "SQL Injection"
    },
    "path_traversal": {
        "keywords": ["path traversal", "../", "getCanonicalPath", "directory traversal", "LFI"],
        "regex": r'new\s+File\s*\([^)]*uri\s*\.\s*get',
        "category": Category.OWASP_M4_INPUT,
        "cwe": ["CWE-22"],
        "severity": Severity.HIGH,
        "title": "Path Traversal"
    },
    "insecure_crypto": {
        "keywords": ["DES", "MD5", "SHA1", "ECB", "weak crypto", "insecure encryption"],
        "regex": r'Cipher\s*\.\s*getInstance\s*\(\s*["\'](?:DES|AES/ECB)',
        "category": Category.OWASP_M10_CRYPTO,
        "cwe": ["CWE-327"],
        "severity": Severity.HIGH,
        "title": "Insecure Cryptography"
    },
    "hardcoded_secret": {
        "keywords": ["API_KEY", "SECRET", "PASSWORD", "hardcoded", "apikey", "secret_key"],
        "regex": r'(?:api[_-]?key|secret|password)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "category": Category.OWASP_M1_CREDENTIALS,
        "cwe": ["CWE-798"],
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Secret"
    },
    "insecure_tls": {
        "keywords": ["TrustManager", "X509TrustManager", "HostnameVerifier", "ALLOW_ALL", "SSL", "certificate"],
        "regex": r'(?:checkServerTrusted|verify)\s*\([^)]*\)\s*\{[^}]*\}',
        "category": Category.OWASP_M5_COMMUNICATION,
        "cwe": ["CWE-295"],
        "severity": Severity.CRITICAL,
        "title": "Insecure TLS Configuration"
    },
    "pending_intent": {
        "keywords": ["PendingIntent", "FLAG_MUTABLE", "FLAG_IMMUTABLE", "intent hijack"],
        "regex": r'PendingIntent\s*\.\s*get(?:Activity|Service|Broadcast)\s*\(',
        "category": Category.INTENT_DEEPLINK,
        "cwe": ["CWE-927"],
        "severity": Severity.MEDIUM,
        "title": "PendingIntent Vulnerability"
    },
    "intent_redirect": {
        "keywords": ["intent redirect", "startActivity", "getParcelableExtra", "embedded intent"],
        "regex": r'startActivity\s*\([^)]*getParcelableExtra',
        "category": Category.INTENT_DEEPLINK,
        "cwe": ["CWE-926", "CWE-940"],
        "severity": Severity.HIGH,
        "title": "Intent Redirect"
    },
    "broadcast_sensitive": {
        "keywords": ["sendBroadcast", "LocalBroadcastManager", "broadcast"],
        "regex": r'sendBroadcast\s*\(',
        "category": Category.INTENT_DEEPLINK,
        "cwe": ["CWE-927"],
        "severity": Severity.MEDIUM,
        "title": "Insecure Broadcast"
    },
}

# Regex patterns to find code blocks in writeups
CODE_BLOCK_PATTERNS = [
    re.compile(r'```(?:java|kotlin|xml|smali)?\s*(.*?)```', re.DOTALL),
    re.compile(r'<code[^>]*>(.*?)</code>', re.DOTALL),
    re.compile(r'<pre[^>]*>(.*?)</pre>', re.DOTALL),
]


class PatternExtractor:
    """
    Extracts vulnerability patterns from security writeups.
    Uses keyword matching and code analysis to identify patterns.
    """

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path.home() / ".apkanalyzer" / "data" / "crawled"

    def extract_from_hackerone(self, report: HackerOneReport) -> ExtractionResult:
        """Extract patterns from a HackerOne report."""
        result = ExtractionResult(success=False)

        # Combine all available text
        full_text = f"{report.title}\n{report.summary}\n{report.vulnerability_details}"

        # Identify vulnerability types
        identified = self._identify_vulnerability_types(full_text)
        if not identified:
            result.errors.append("Could not identify vulnerability type")
            return result

        # Extract code blocks
        code_blocks = self._extract_code_blocks(full_text)

        # Build patterns for each identified vulnerability
        for vuln_type, confidence in identified:
            config = ANDROID_VULN_PATTERNS[vuln_type]

            # Try to extract specific patterns from code
            extracted_regex = self._extract_regex_from_code(code_blocks, config)

            pattern = self._build_pattern(
                pattern_id=f"h1-{report.id}-{vuln_type}",
                title=f"{config['title']}: {report.title[:40]}",
                vuln_config=config,
                source_url=report.report_url,
                extracted_regex=extracted_regex,
                cwe=report.cwe,
                cve_ids=report.cve_ids,
                description=report.summary[:500] if report.summary else "",
            )

            result.patterns.append(pattern)
            result.raw_extractions.append({
                "vuln_type": vuln_type,
                "confidence": confidence,
                "code_blocks_found": len(code_blocks),
            })

        result.success = len(result.patterns) > 0
        result.confidence = max((conf for _, conf in identified), default=0)
        result.requires_review = True

        return result

    def extract_from_blog(self, article: BlogArticle) -> ExtractionResult:
        """Extract patterns from a blog article."""
        result = ExtractionResult(success=False)

        full_text = f"{article.title}\n{article.summary}\n{article.content}"

        # Identify all vulnerability types
        identified = self._identify_vulnerability_types(full_text)
        if not identified:
            result.errors.append("No Android vulnerability patterns identified")
            return result

        code_blocks = self._extract_code_blocks(full_text)

        for vuln_type, confidence in identified:
            config = ANDROID_VULN_PATTERNS[vuln_type]
            extracted_regex = self._extract_regex_from_code(code_blocks, config)

            pattern = self._build_pattern(
                pattern_id=f"blog-{article.id}-{vuln_type}",
                title=f"{config['title']}: {article.title[:40]}",
                vuln_config=config,
                source_url=article.url,
                extracted_regex=extracted_regex,
                description=article.summary[:500] if article.summary else "",
                author=article.author,
            )

            result.patterns.append(pattern)

        result.success = len(result.patterns) > 0
        result.confidence = max((conf for _, conf in identified), default=0)
        result.requires_review = True

        return result

    def _identify_vulnerability_types(self, text: str) -> List[Tuple[str, float]]:
        """Identify vulnerability types mentioned in text."""
        text_lower = text.lower()
        results = []

        for vuln_type, config in ANDROID_VULN_PATTERNS.items():
            score = 0
            total_keywords = len(config["keywords"])

            for keyword in config["keywords"]:
                if keyword.lower() in text_lower:
                    score += 1

            confidence = score / total_keywords if total_keywords > 0 else 0

            # Require at least 30% keyword match
            if confidence >= 0.3:
                results.append((vuln_type, confidence))

        # Sort by confidence
        return sorted(results, key=lambda x: x[1], reverse=True)

    def _extract_code_blocks(self, text: str) -> List[str]:
        """Extract code blocks from text."""
        blocks = []

        for pattern in CODE_BLOCK_PATTERNS:
            for match in pattern.finditer(text):
                code = match.group(1).strip()
                if len(code) > 10:
                    blocks.append(code)

        return blocks

    def _extract_regex_from_code(
        self,
        code_blocks: List[str],
        config: Dict[str, Any]
    ) -> Optional[str]:
        """Try to extract a more specific regex from code blocks."""
        base_regex = config.get("regex")
        if not base_regex:
            return None

        # Check if the base pattern exists in any code block
        for code in code_blocks:
            if re.search(base_regex, code, re.IGNORECASE):
                # Found matching code, could try to generalize
                # For now, return the base regex
                return base_regex

        return base_regex

    def _build_pattern(
        self,
        pattern_id: str,
        title: str,
        vuln_config: Dict[str, Any],
        source_url: str,
        extracted_regex: Optional[str] = None,
        cwe: Optional[str] = None,
        cve_ids: Optional[List[str]] = None,
        description: str = "",
        author: Optional[str] = None,
    ) -> VulnerabilityPattern:
        """Build a VulnerabilityPattern from extracted information."""

        regex_pattern = extracted_regex or vuln_config.get("regex", "")

        # Determine source type
        source_type = SourceType.HACKERONE if "hackerone" in source_url.lower() else SourceType.BLOG

        # Build CWE list
        cwe_list = list(vuln_config.get("cwe", []))
        if cwe and cwe not in cwe_list:
            cwe_list.insert(0, cwe if cwe.startswith("CWE-") else f"CWE-{cwe}")

        return VulnerabilityPattern(
            id=pattern_id,
            title=title,
            severity=vuln_config.get("severity", Severity.MEDIUM),
            category=vuln_config.get("category", Category.OTHER),
            detection=Detection(
                type=DetectionType.REGEX,
                patterns=[RegexDetection(
                    pattern=regex_pattern,
                    flags="i",
                    file_types=[".java", ".kt"]
                )] if regex_pattern else []
            ),
            description=description or f"Pattern extracted from: {source_url}",
            attack_path="See original writeup for detailed attack path.",
            metadata=PatternMetadata(
                cwe=cwe_list,
                cve=cve_ids or [],
                references=[source_url],
                source=PatternSource(
                    type=source_type,
                    url=source_url,
                    author=author,
                ),
                created_at=date.today(),
                confidence=Confidence.LOW,
                false_positive_rate="high",
            ),
            remediation="See original writeup for remediation guidance.",
            adb_category="general",
            enabled=False,  # Disabled until reviewed
            tags=["auto-extracted", "needs-review", vuln_config.get("category", Category.OTHER).value.lower()],
        )

    def save_pattern(
        self,
        pattern: VulnerabilityPattern,
        pending_review: bool = True
    ) -> Path:
        """Save extracted pattern to appropriate directory."""
        if pending_review:
            output_dir = self.output_dir / "pending_review"
        else:
            source_type = pattern.metadata.source.type.value if pattern.metadata.source else "unknown"
            output_dir = self.output_dir / source_type

        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{pattern.id}.json"

        pattern_dict = pattern.to_dict()

        with open(output_path, 'w') as f:
            json.dump(pattern_dict, f, indent=2)

        logger.info(f"Saved pattern to {output_path}")
        return output_path

    def load_pending_patterns(self) -> List[VulnerabilityPattern]:
        """Load patterns pending review."""
        pending_dir = self.output_dir / "pending_review"
        if not pending_dir.exists():
            return []

        from ..patterns.loader import PatternLoader
        loader = PatternLoader()
        return loader.load_directory(pending_dir)

    def approve_pattern(self, pattern_id: str) -> bool:
        """Move pattern from pending to approved."""
        pending_dir = self.output_dir / "pending_review"
        pending_file = pending_dir / f"{pattern_id}.json"

        if not pending_file.exists():
            logger.error(f"Pattern not found: {pattern_id}")
            return False

        # Load and enable the pattern
        with open(pending_file) as f:
            data = json.load(f)

        data["enabled"] = True

        # Determine destination based on source
        source_type = data.get("metadata", {}).get("source", {}).get("type", "unknown")
        dest_dir = self.output_dir / source_type
        dest_dir.mkdir(parents=True, exist_ok=True)

        dest_file = dest_dir / f"{pattern_id}.json"
        with open(dest_file, 'w') as f:
            json.dump(data, f, indent=2)

        # Remove from pending
        pending_file.unlink()
        logger.info(f"Approved pattern {pattern_id} -> {dest_file}")
        return True

    def reject_pattern(self, pattern_id: str) -> bool:
        """Remove pattern from pending review."""
        pending_dir = self.output_dir / "pending_review"
        pending_file = pending_dir / f"{pattern_id}.json"

        if not pending_file.exists():
            logger.error(f"Pattern not found: {pattern_id}")
            return False

        pending_file.unlink()
        logger.info(f"Rejected pattern {pattern_id}")
        return True

    def list_pending(self) -> List[Dict[str, Any]]:
        """List patterns pending review."""
        pending_dir = self.output_dir / "pending_review"
        if not pending_dir.exists():
            return []

        results = []
        for pattern_file in pending_dir.glob("*.json"):
            try:
                with open(pattern_file) as f:
                    data = json.load(f)
                results.append({
                    "id": data.get("id"),
                    "title": data.get("title"),
                    "severity": data.get("severity"),
                    "category": data.get("category"),
                    "source_url": data.get("metadata", {}).get("references", [""])[0],
                })
            except Exception as e:
                logger.warning(f"Failed to read {pattern_file}: {e}")

        return results
