"""Pattern loading from JSON files."""

from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    Category,
    Confidence,
    Detection,
    DetectionType,
    ManifestCheck,
    PatternContext,
    PatternMetadata,
    PatternSource,
    RegexDetection,
    Severity,
    SourceType,
    TestCase,
    VulnerabilityPattern,
)

logger = logging.getLogger(__name__)


class PatternLoader:
    """Loads vulnerability patterns from JSON files."""

    def load_file(self, file_path: Path) -> List[VulnerabilityPattern]:
        """Load patterns from a JSON file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self._parse_pattern_file(data, file_path)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
            raise

    def load_directory(self, directory: Path) -> List[VulnerabilityPattern]:
        """Load all pattern files from a directory."""
        patterns = []
        if not directory.exists():
            logger.warning(f"Pattern directory does not exist: {directory}")
            return patterns

        for file_path in sorted(directory.glob("*.json")):
            try:
                file_patterns = self.load_file(file_path)
                patterns.extend(file_patterns)
                logger.debug(f"Loaded {len(file_patterns)} patterns from {file_path.name}")
            except Exception as e:
                logger.warning(f"Skipping {file_path.name}: {e}")

        return patterns

    def _parse_pattern_file(self, data: Dict[str, Any], source_path: Path) -> List[VulnerabilityPattern]:
        """Parse a pattern file dictionary into VulnerabilityPattern objects."""
        patterns = []

        # Handle both single pattern and multiple patterns format
        if "patterns" in data:
            pattern_list = data["patterns"]
        elif "id" in data:
            pattern_list = [data]
        else:
            logger.warning(f"Unknown pattern file format in {source_path}")
            return patterns

        for pattern_data in pattern_list:
            try:
                pattern = self._parse_pattern(pattern_data)
                patterns.append(pattern)
            except Exception as e:
                pattern_id = pattern_data.get("id", "unknown")
                logger.warning(f"Failed to parse pattern {pattern_id}: {e}")

        return patterns

    def _parse_pattern(self, data: Dict[str, Any]) -> VulnerabilityPattern:
        """Parse a single pattern dictionary into a VulnerabilityPattern object."""
        return VulnerabilityPattern(
            id=data["id"],
            title=data["title"],
            severity=self._parse_severity(data.get("severity", "Medium")),
            category=self._parse_category(data.get("category", "Other")),
            detection=self._parse_detection(data.get("detection", {})),
            description=data.get("description", ""),
            attack_path=data.get("attack_path", ""),
            metadata=self._parse_metadata(data.get("metadata", {})),
            remediation=data.get("remediation", ""),
            adb_category=data.get("adb_category", "general"),
            test_cases=self._parse_test_cases(data.get("test_cases", [])),
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
        )

    def _parse_severity(self, value: str) -> Severity:
        """Parse severity string to Severity enum."""
        try:
            return Severity(value)
        except ValueError:
            # Try case-insensitive match
            for sev in Severity:
                if sev.value.lower() == value.lower():
                    return sev
            logger.warning(f"Unknown severity '{value}', defaulting to Medium")
            return Severity.MEDIUM

    def _parse_category(self, value: str) -> Category:
        """Parse category string to Category enum."""
        try:
            return Category(value)
        except ValueError:
            # Try case-insensitive match
            for cat in Category:
                if cat.value.lower() == value.lower():
                    return cat
            logger.warning(f"Unknown category '{value}', defaulting to Other")
            return Category.OTHER

    def _parse_detection(self, data: Dict[str, Any]) -> Detection:
        """Parse detection configuration."""
        det_type = DetectionType.REGEX
        if "type" in data:
            try:
                det_type = DetectionType(data["type"])
            except ValueError:
                logger.warning(f"Unknown detection type '{data['type']}', defaulting to regex")

        patterns = []
        for p_data in data.get("patterns", []):
            patterns.append(self._parse_regex_detection(p_data))

        manifest_checks = []
        for m_data in data.get("manifest_checks", []):
            manifest_checks.append(self._parse_manifest_check(m_data))

        return Detection(
            type=det_type,
            patterns=patterns,
            manifest_checks=manifest_checks,
        )

    def _parse_regex_detection(self, data: Dict[str, Any]) -> RegexDetection:
        """Parse regex detection configuration."""
        context = None
        if "context" in data and data["context"]:
            context = PatternContext(
                must_contain=data["context"].get("must_contain", []),
                must_not_contain=data["context"].get("must_not_contain", []),
                within_lines=data["context"].get("within_lines", 10),
            )

        return RegexDetection(
            pattern=data["pattern"],
            flags=data.get("flags", "i"),
            file_types=data.get("file_types", [".java", ".kt", ".xml"]),
            context=context,
        )

    def _parse_manifest_check(self, data: Dict[str, Any]) -> ManifestCheck:
        """Parse manifest check configuration."""
        return ManifestCheck(
            xpath=data["xpath"],
            attribute=data.get("attribute"),
            value=data.get("value"),
            condition=data.get("condition", "exists"),
        )

    def _parse_metadata(self, data: Dict[str, Any]) -> PatternMetadata:
        """Parse pattern metadata."""
        source = None
        if "source" in data and data["source"]:
            source_data = data["source"]
            source_type = SourceType.BUILTIN
            if "type" in source_data:
                try:
                    source_type = SourceType(source_data["type"])
                except ValueError:
                    pass

            source = PatternSource(
                type=source_type,
                url=source_data.get("url"),
                author=source_data.get("author"),
                report_id=source_data.get("report_id"),
            )

        created_at = None
        if "created_at" in data and data["created_at"]:
            try:
                created_at = date.fromisoformat(data["created_at"])
            except ValueError:
                pass

        updated_at = None
        if "updated_at" in data and data["updated_at"]:
            try:
                updated_at = date.fromisoformat(data["updated_at"])
            except ValueError:
                pass

        confidence = Confidence.MEDIUM
        if "confidence" in data:
            try:
                confidence = Confidence(data["confidence"])
            except ValueError:
                pass

        return PatternMetadata(
            cwe=data.get("cwe", []),
            cve=data.get("cve", []),
            references=data.get("references", []),
            source=source,
            created_at=created_at,
            updated_at=updated_at,
            version=data.get("version", "1.0.0"),
            confidence=confidence,
            false_positive_rate=data.get("false_positive_rate", "medium"),
        )

    def _parse_test_cases(self, data: List[Dict[str, Any]]) -> List[TestCase]:
        """Parse test cases."""
        test_cases = []
        for tc_data in data:
            test_cases.append(TestCase(
                code=tc_data["code"],
                should_match=tc_data["should_match"],
                description=tc_data.get("description", ""),
            ))
        return test_cases

    def pattern_to_dict(self, pattern: VulnerabilityPattern) -> Dict[str, Any]:
        """Convert a VulnerabilityPattern back to a dictionary for serialization."""
        return pattern.to_dict()

    def save_patterns(self, patterns: List[VulnerabilityPattern], output_path: Path, category: Optional[str] = None) -> None:
        """Save patterns to a JSON file."""
        output_data = {
            "schema_version": "1.0.0",
        }
        if category:
            output_data["category"] = category

        output_data["patterns"] = [self.pattern_to_dict(p) for p in patterns]

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)

        logger.info(f"Saved {len(patterns)} patterns to {output_path}")
