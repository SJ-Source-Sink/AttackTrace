"""Pattern management module for APK vulnerability scanning."""

from .models import (
    VulnerabilityPattern,
    Detection,
    DetectionType,
    RegexDetection,
    ManifestCheck,
    PatternMetadata,
    PatternSource,
    Severity,
    Category,
    SourceType,
    Confidence,
    TestCase,
)
from .manager import PatternManager, PatternConfig
from .loader import PatternLoader
from .validator import PatternValidator

__all__ = [
    "VulnerabilityPattern",
    "Detection",
    "DetectionType",
    "RegexDetection",
    "ManifestCheck",
    "PatternMetadata",
    "PatternSource",
    "Severity",
    "Category",
    "SourceType",
    "Confidence",
    "TestCase",
    "PatternManager",
    "PatternConfig",
    "PatternLoader",
    "PatternValidator",
]
