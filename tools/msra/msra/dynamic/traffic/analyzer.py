"""Traffic analysis and leak detection."""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Pattern
from enum import Enum

from .proxy import HTTPFlow

logger = logging.getLogger(__name__)


class LeakSeverity(Enum):
    """Severity of data leak."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class LeakAlert:
    """Alert for detected data leak."""
    severity: LeakSeverity
    category: str  # 'credential', 'pii', 'token', 'sensitive', 'tracking'
    description: str
    pattern_matched: str
    matched_value: str  # Partially redacted
    flow: Optional[HTTPFlow] = None
    location: str = ""  # 'request_header', 'request_body', 'response_body', etc.

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "pattern": self.pattern_matched,
            "value": self.matched_value,
            "location": self.location,
            "url": self.flow.url if self.flow else None,
            "host": self.flow.host if self.flow else None,
        }


class TrafficAnalyzer:
    """Analyze captured traffic for sensitive data leaks."""

    # Default leak detection patterns
    DEFAULT_PATTERNS = {
        "password": {
            "patterns": [
                r'["\']?password["\']?\s*[:=]\s*["\']?([^"\'&\s]{4,})',
                r'["\']?passwd["\']?\s*[:=]\s*["\']?([^"\'&\s]{4,})',
                r'["\']?pwd["\']?\s*[:=]\s*["\']?([^"\'&\s]{4,})',
            ],
            "severity": LeakSeverity.CRITICAL,
            "category": "credential",
        },
        "api_key": {
            "patterns": [
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})',
                r'["\']?apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})',
                r'["\']?api_secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})',
            ],
            "severity": LeakSeverity.CRITICAL,
            "category": "credential",
        },
        "bearer_token": {
            "patterns": [
                r'[Bb]earer\s+([a-zA-Z0-9_.-]{20,})',
                r'["\']?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_.-]{20,})',
            ],
            "severity": LeakSeverity.HIGH,
            "category": "token",
        },
        "jwt": {
            "patterns": [
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            ],
            "severity": LeakSeverity.HIGH,
            "category": "token",
        },
        "session_id": {
            "patterns": [
                r'["\']?session[_-]?id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})',
                r'["\']?sessionid["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})',
                r'JSESSIONID\s*=\s*([a-zA-Z0-9]+)',
                r'PHPSESSID\s*=\s*([a-zA-Z0-9]+)',
            ],
            "severity": LeakSeverity.HIGH,
            "category": "token",
        },
        "email": {
            "patterns": [
                r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
            ],
            "severity": LeakSeverity.MEDIUM,
            "category": "pii",
        },
        "phone": {
            "patterns": [
                r'\b(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b',
            ],
            "severity": LeakSeverity.MEDIUM,
            "category": "pii",
        },
        "ssn": {
            "patterns": [
                r'\b(\d{3}-\d{2}-\d{4})\b',
            ],
            "severity": LeakSeverity.CRITICAL,
            "category": "pii",
        },
        "credit_card": {
            "patterns": [
                r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b',
            ],
            "severity": LeakSeverity.CRITICAL,
            "category": "pii",
        },
        "private_key": {
            "patterns": [
                r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
            ],
            "severity": LeakSeverity.CRITICAL,
            "category": "credential",
        },
        "aws_key": {
            "patterns": [
                r'AKIA[0-9A-Z]{16}',
                r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
            ],
            "severity": LeakSeverity.CRITICAL,
            "category": "credential",
        },
        "google_api_key": {
            "patterns": [
                r'AIza[0-9A-Za-z_-]{35}',
            ],
            "severity": LeakSeverity.HIGH,
            "category": "credential",
        },
        "device_id": {
            "patterns": [
                r'["\']?device[_-]?id["\']?\s*[:=]\s*["\']?([a-fA-F0-9-]{16,})',
                r'["\']?android[_-]?id["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{16})',
                r'["\']?imei["\']?\s*[:=]\s*["\']?(\d{15})',
            ],
            "severity": LeakSeverity.MEDIUM,
            "category": "tracking",
        },
        "location": {
            "patterns": [
                r'["\']?lat(?:itude)?["\']?\s*[:=]\s*["\']?(-?\d+\.\d+)',
                r'["\']?lon(?:gitude)?["\']?\s*[:=]\s*["\']?(-?\d+\.\d+)',
            ],
            "severity": LeakSeverity.MEDIUM,
            "category": "pii",
        },
    }

    def __init__(self, custom_patterns: Optional[Dict] = None):
        self._patterns = self.DEFAULT_PATTERNS.copy()
        if custom_patterns:
            self._patterns.update(custom_patterns)

        # Compile patterns
        self._compiled: Dict[str, List[tuple]] = {}
        for name, config in self._patterns.items():
            self._compiled[name] = [
                (re.compile(p, re.IGNORECASE), config["severity"], config["category"])
                for p in config["patterns"]
            ]

    def analyze_flow(self, flow: HTTPFlow) -> List[LeakAlert]:
        """Analyze a single flow for leaks.

        Args:
            flow: HTTPFlow to analyze.

        Returns:
            List of LeakAlert objects.
        """
        alerts = []

        # Analyze request headers
        for key, value in flow.request_headers.items():
            header_str = f"{key}: {value}"
            alerts.extend(self._scan_text(
                header_str, flow, "request_header"
            ))

        # Analyze request body
        if flow.request_body:
            try:
                body_str = flow.request_body.decode('utf-8', errors='ignore')
                alerts.extend(self._scan_text(
                    body_str, flow, "request_body"
                ))
            except Exception:
                pass

        # Analyze request URL
        alerts.extend(self._scan_text(
            flow.url, flow, "url"
        ))

        # Analyze response headers
        for key, value in flow.response_headers.items():
            header_str = f"{key}: {value}"
            alerts.extend(self._scan_text(
                header_str, flow, "response_header"
            ))

        # Analyze response body
        if flow.response_body:
            try:
                body_str = flow.response_body.decode('utf-8', errors='ignore')
                alerts.extend(self._scan_text(
                    body_str, flow, "response_body"
                ))
            except Exception:
                pass

        return alerts

    def analyze_flows(self, flows: List[HTTPFlow]) -> List[LeakAlert]:
        """Analyze multiple flows for leaks.

        Args:
            flows: List of HTTPFlow objects.

        Returns:
            List of all LeakAlert objects.
        """
        alerts = []
        for flow in flows:
            alerts.extend(self.analyze_flow(flow))
        return alerts

    def _scan_text(self, text: str, flow: HTTPFlow, location: str) -> List[LeakAlert]:
        """Scan text for leak patterns."""
        alerts = []

        for pattern_name, patterns in self._compiled.items():
            for regex, severity, category in patterns:
                matches = regex.finditer(text)
                for match in matches:
                    # Get matched value (use group 1 if available)
                    if match.lastindex and match.lastindex >= 1:
                        value = match.group(1)
                    else:
                        value = match.group(0)

                    # Redact sensitive value
                    redacted = self._redact(value)

                    alert = LeakAlert(
                        severity=severity,
                        category=category,
                        description=f"{pattern_name.replace('_', ' ').title()} detected",
                        pattern_matched=pattern_name,
                        matched_value=redacted,
                        flow=flow,
                        location=location,
                    )
                    alerts.append(alert)

        return alerts

    def _redact(self, value: str, visible_chars: int = 4) -> str:
        """Redact sensitive value, showing only first/last chars."""
        if len(value) <= visible_chars * 2:
            return '*' * len(value)

        return f"{value[:visible_chars]}{'*' * (len(value) - visible_chars * 2)}{value[-visible_chars:]}"

    def get_summary(self, alerts: List[LeakAlert]) -> Dict[str, Any]:
        """Get summary of detected leaks.

        Args:
            alerts: List of LeakAlert objects.

        Returns:
            Summary dictionary.
        """
        summary = {
            "total_alerts": len(alerts),
            "by_severity": {},
            "by_category": {},
            "by_pattern": {},
            "affected_hosts": set(),
            "critical_count": 0,
            "high_count": 0,
        }

        for alert in alerts:
            # Count by severity
            sev = alert.severity.value
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            if alert.severity == LeakSeverity.CRITICAL:
                summary["critical_count"] += 1
            elif alert.severity == LeakSeverity.HIGH:
                summary["high_count"] += 1

            # Count by category
            cat = alert.category
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

            # Count by pattern
            pat = alert.pattern_matched
            summary["by_pattern"][pat] = summary["by_pattern"].get(pat, 0) + 1

            # Track affected hosts
            if alert.flow:
                summary["affected_hosts"].add(alert.flow.host)

        summary["affected_hosts"] = list(summary["affected_hosts"])
        return summary

    def filter_alerts(self, alerts: List[LeakAlert],
                      min_severity: LeakSeverity = LeakSeverity.LOW,
                      categories: Optional[List[str]] = None,
                      hosts: Optional[List[str]] = None) -> List[LeakAlert]:
        """Filter alerts by criteria.

        Args:
            alerts: List of alerts.
            min_severity: Minimum severity to include.
            categories: Categories to include (None = all).
            hosts: Hosts to include (None = all).

        Returns:
            Filtered list of alerts.
        """
        severity_order = [
            LeakSeverity.INFO,
            LeakSeverity.LOW,
            LeakSeverity.MEDIUM,
            LeakSeverity.HIGH,
            LeakSeverity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)

        filtered = []
        for alert in alerts:
            # Check severity
            if severity_order.index(alert.severity) < min_index:
                continue

            # Check category
            if categories and alert.category not in categories:
                continue

            # Check host
            if hosts and alert.flow and alert.flow.host not in hosts:
                continue

            filtered.append(alert)

        return filtered

    def detect_unencrypted_sensitive(self, flows: List[HTTPFlow]) -> List[LeakAlert]:
        """Detect sensitive data sent over unencrypted HTTP.

        Args:
            flows: List of flows.

        Returns:
            List of alerts for unencrypted sensitive data.
        """
        alerts = []

        for flow in flows:
            if flow.is_https:
                continue

            # Analyze this HTTP flow
            flow_alerts = self.analyze_flow(flow)

            for alert in flow_alerts:
                if alert.severity in [LeakSeverity.CRITICAL, LeakSeverity.HIGH]:
                    alert.description += " (over unencrypted HTTP)"
                    alert.severity = LeakSeverity.CRITICAL
                    alerts.append(alert)

        return alerts

    def add_custom_pattern(self, name: str, patterns: List[str],
                           severity: LeakSeverity = LeakSeverity.MEDIUM,
                           category: str = "custom"):
        """Add a custom leak detection pattern.

        Args:
            name: Pattern name.
            patterns: List of regex patterns.
            severity: Alert severity.
            category: Alert category.
        """
        self._patterns[name] = {
            "patterns": patterns,
            "severity": severity,
            "category": category,
        }

        self._compiled[name] = [
            (re.compile(p, re.IGNORECASE), severity, category)
            for p in patterns
        ]
