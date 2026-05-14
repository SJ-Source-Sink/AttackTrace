"""Pattern validation utilities."""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from .models import VulnerabilityPattern, RegexDetection, DetectionType

logger = logging.getLogger(__name__)


class PatternValidator:
    """Validates vulnerability patterns for correctness and quality."""

    # Maximum regex complexity to prevent ReDoS
    MAX_PATTERN_LENGTH = 1000
    MAX_QUANTIFIER_RANGE = 100

    def validate(
        self,
        pattern: VulnerabilityPattern,
        return_issues: bool = False
    ) -> bool | List[str]:
        """
        Validate a vulnerability pattern.

        Args:
            pattern: The pattern to validate
            return_issues: If True, return list of issues instead of bool

        Returns:
            If return_issues is False: True if valid, False otherwise
            If return_issues is True: List of validation issues (empty if valid)
        """
        issues = []

        # Validate required fields
        if not pattern.id:
            issues.append("Pattern ID is required")
        elif not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$", pattern.id):
            issues.append(f"Pattern ID '{pattern.id}' must be lowercase alphanumeric with hyphens")

        if not pattern.title:
            issues.append("Pattern title is required")

        if not pattern.description:
            issues.append("Pattern description is required")

        # Validate detection configuration
        detection_issues = self._validate_detection(pattern)
        issues.extend(detection_issues)

        # Validate test cases if present
        test_issues = self._validate_test_cases(pattern)
        issues.extend(test_issues)

        # Log issues
        if issues:
            logger.warning(f"Pattern '{pattern.id}' has validation issues: {issues}")

        if return_issues:
            return issues
        return len(issues) == 0

    def _validate_detection(self, pattern: VulnerabilityPattern) -> List[str]:
        """Validate detection configuration."""
        issues = []

        det = pattern.detection
        if det.type in (DetectionType.REGEX, DetectionType.REGEX_MULTILINE, DetectionType.COMBINED):
            if not det.patterns:
                issues.append("Regex detection type requires at least one pattern")

            for idx, regex_det in enumerate(det.patterns):
                regex_issues = self._validate_regex(regex_det, idx)
                issues.extend(regex_issues)

        if det.type in (DetectionType.MANIFEST, DetectionType.COMBINED):
            if det.type == DetectionType.MANIFEST and not det.manifest_checks:
                issues.append("Manifest detection type requires at least one manifest check")

        return issues

    def _validate_regex(self, regex_det: RegexDetection, idx: int) -> List[str]:
        """Validate a regex detection pattern."""
        issues = []
        pattern = regex_det.pattern

        # Check pattern length
        if len(pattern) > self.MAX_PATTERN_LENGTH:
            issues.append(f"Pattern #{idx} exceeds maximum length of {self.MAX_PATTERN_LENGTH}")

        # Try to compile the pattern
        try:
            re_flags = 0
            if "i" in regex_det.flags:
                re_flags |= re.IGNORECASE
            if "m" in regex_det.flags:
                re_flags |= re.MULTILINE
            if "s" in regex_det.flags:
                re_flags |= re.DOTALL
            re.compile(pattern, re_flags)
        except re.error as e:
            issues.append(f"Pattern #{idx} has invalid regex: {e}")
            return issues  # Can't do further validation

        # Check for potential ReDoS patterns
        redos_issues = self._check_redos_risk(pattern, idx)
        issues.extend(redos_issues)

        # Check file types
        if not regex_det.file_types:
            issues.append(f"Pattern #{idx} has no file types specified")

        return issues

    def _check_redos_risk(self, pattern: str, idx: int) -> List[str]:
        """Check for patterns that might be vulnerable to ReDoS."""
        issues = []

        # Check for nested quantifiers (common ReDoS pattern)
        nested_quantifier = re.search(r"(\+|\*|\{[0-9,]+\}).*\1", pattern)
        if nested_quantifier:
            issues.append(f"Pattern #{idx} may have ReDoS risk (nested quantifiers)")

        # Check for large quantifier ranges
        large_range = re.search(r"\{(\d+),(\d*)\}", pattern)
        if large_range:
            min_val = int(large_range.group(1))
            max_val = large_range.group(2)
            if max_val:
                max_val = int(max_val)
                if max_val - min_val > self.MAX_QUANTIFIER_RANGE:
                    issues.append(f"Pattern #{idx} has large quantifier range")

        return issues

    def _validate_test_cases(self, pattern: VulnerabilityPattern) -> List[str]:
        """Validate test cases against the pattern."""
        issues = []

        if not pattern.test_cases:
            return issues  # Test cases are optional

        if pattern.detection.type not in (DetectionType.REGEX, DetectionType.REGEX_MULTILINE, DetectionType.COMBINED):
            return issues  # Can only auto-validate regex patterns

        for tc_idx, test_case in enumerate(pattern.test_cases):
            for regex_det in pattern.detection.patterns:
                try:
                    compiled = regex_det.compile()
                    match = compiled.search(test_case.code)
                    matched = match is not None

                    if matched != test_case.should_match:
                        expected = "match" if test_case.should_match else "not match"
                        actual = "matched" if matched else "did not match"
                        issues.append(
                            f"Test case #{tc_idx} expected to {expected} but {actual}: "
                            f"{test_case.description or test_case.code[:50]}"
                        )
                        break  # Only need one regex to match
                except re.error:
                    pass  # Regex error already reported

        return issues

    def validate_all(self, patterns: List[VulnerabilityPattern]) -> Dict[str, List[str]]:
        """Validate all patterns and return issues by pattern ID."""
        all_issues = {}
        seen_ids = set()

        for pattern in patterns:
            # Check for duplicate IDs
            if pattern.id in seen_ids:
                if pattern.id not in all_issues:
                    all_issues[pattern.id] = []
                all_issues[pattern.id].append(f"Duplicate pattern ID: {pattern.id}")
            seen_ids.add(pattern.id)

            # Validate individual pattern
            issues = self.validate(pattern, return_issues=True)
            if issues:
                all_issues[pattern.id] = issues

        return all_issues

    def run_test_cases(self, pattern: VulnerabilityPattern) -> List[Tuple[int, bool, str]]:
        """
        Run all test cases for a pattern.

        Returns:
            List of tuples: (test_index, passed, message)
        """
        results = []

        if not pattern.test_cases:
            return results

        if pattern.detection.type not in (DetectionType.REGEX, DetectionType.REGEX_MULTILINE, DetectionType.COMBINED):
            return results

        for tc_idx, test_case in enumerate(pattern.test_cases):
            matched = False
            for regex_det in pattern.detection.patterns:
                try:
                    compiled = regex_det.compile()
                    if compiled.search(test_case.code):
                        matched = True
                        break
                except re.error:
                    pass

            passed = matched == test_case.should_match
            message = test_case.description or f"Test case #{tc_idx}"
            results.append((tc_idx, passed, message))

        return results
