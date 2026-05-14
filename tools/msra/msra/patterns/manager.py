"""Central pattern manager for vulnerability patterns."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from .models import VulnerabilityPattern, Category, Severity, SourceType
from .loader import PatternLoader
from .validator import PatternValidator

logger = logging.getLogger(__name__)


def get_default_data_dir() -> Path:
    """Get the default data directory for patterns."""
    # First check if we're in the project directory
    project_data = Path(__file__).parent.parent.parent / "data"
    if project_data.exists():
        return project_data

    # Fall back to user home directory
    return Path.home() / ".apkanalyzer" / "data"


@dataclass
class PatternConfig:
    """Configuration for pattern loading."""
    load_builtin: bool = True
    load_community: bool = True
    load_crawled: bool = True
    custom_patterns_dir: Optional[Path] = None
    data_dir: Path = field(default_factory=get_default_data_dir)

    # Filtering
    enabled_categories: Optional[List[Category]] = None
    min_severity: Optional[Severity] = None

    def __post_init__(self):
        if isinstance(self.data_dir, str):
            self.data_dir = Path(self.data_dir).expanduser()
        if isinstance(self.custom_patterns_dir, str):
            self.custom_patterns_dir = Path(self.custom_patterns_dir).expanduser()


class PatternManager:
    """
    Central manager for vulnerability patterns.
    Handles loading, merging, filtering, and caching patterns from multiple sources.
    """

    def __init__(self, config: Optional[PatternConfig] = None):
        self.config = config or PatternConfig()
        self._patterns: Dict[str, VulnerabilityPattern] = {}
        self._loader = PatternLoader()
        self._validator = PatternValidator()
        self._loaded_sources: List[str] = []
        self._loaded = False

    def load_all(self) -> None:
        """Load patterns from all configured sources in priority order."""
        if self._loaded:
            return

        # 1. Built-in patterns (lowest priority, always loaded first)
        if self.config.load_builtin:
            self._load_builtin()

        # 2. Community patterns (if enabled)
        if self.config.load_community:
            self._load_community()

        # 3. Crawled patterns (if enabled and reviewed)
        if self.config.load_crawled:
            self._load_crawled()

        # 4. Custom patterns (highest priority, can override others)
        if self.config.custom_patterns_dir:
            self._load_custom(self.config.custom_patterns_dir)

        self._loaded = True
        logger.info(f"Loaded {len(self._patterns)} patterns from {len(self._loaded_sources)} sources")

    def _load_builtin(self) -> None:
        """Load built-in patterns from package data directory."""
        builtin_dir = self.config.data_dir / "builtin"
        if builtin_dir.exists():
            self._load_from_directory(builtin_dir, "builtin")
        else:
            logger.warning(f"Built-in patterns directory not found: {builtin_dir}")

    def _load_community(self) -> None:
        """Load community patterns (downloaded from GitHub)."""
        community_dir = self.config.data_dir / "community"
        if community_dir.exists():
            self._load_from_directory(community_dir, "community")

    def _load_crawled(self) -> None:
        """Load crawled patterns that have been reviewed.

        Crawled patterns are always stored in the user's home directory
        (~/.apkanalyzer/data/crawled/) regardless of where builtin patterns
        come from. This ensures patterns extracted from threat intel updates
        are found even when running in development mode.
        """
        # Always check both locations for crawled patterns
        crawled_locations = []

        # 1. Check the configured data directory (project or fallback)
        project_crawled = self.config.data_dir / "crawled"
        if project_crawled.exists():
            crawled_locations.append(project_crawled)

        # 2. Always check user's home directory for crawled patterns
        # This is where ThreatIntelUpdater saves patterns
        user_crawled = Path.home() / ".apkanalyzer" / "data" / "crawled"
        if user_crawled.exists() and user_crawled != project_crawled:
            crawled_locations.append(user_crawled)

        # Load from all crawled locations
        for crawled_dir in crawled_locations:
            # Only load patterns NOT in pending_review
            for subdir in crawled_dir.iterdir():
                if subdir.is_dir() and subdir.name != "pending_review":
                    self._load_from_directory(subdir, f"crawled-{subdir.name}")

    def _load_custom(self, custom_dir: Path) -> None:
        """Load user's custom patterns."""
        if custom_dir.exists():
            self._load_from_directory(custom_dir, "custom")

    def _load_from_directory(self, directory: Path, source_name: str) -> None:
        """Load all pattern files from a directory."""
        patterns = self._loader.load_directory(directory)
        for pattern in patterns:
            # Later sources override earlier ones (by ID)
            self._patterns[pattern.id] = pattern

        if patterns:
            self._loaded_sources.append(f"{source_name}:{directory.name}")
            logger.debug(f"Loaded {len(patterns)} patterns from {source_name}")

    def get_patterns(
        self,
        categories: Optional[List[Category]] = None,
        severities: Optional[List[Severity]] = None,
        tags: Optional[List[str]] = None,
        enabled_only: bool = True,
    ) -> Iterator[VulnerabilityPattern]:
        """Get patterns with optional filtering."""
        if not self._loaded:
            self.load_all()

        for pattern in self._patterns.values():
            if enabled_only and not pattern.enabled:
                continue
            if categories and pattern.category not in categories:
                continue
            if severities and pattern.severity not in severities:
                continue
            if tags and not any(t in pattern.tags for t in tags):
                continue

            # Apply config-level filters
            if self.config.enabled_categories and pattern.category not in self.config.enabled_categories:
                continue
            if self.config.min_severity:
                severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                if severity_order.index(pattern.severity) < severity_order.index(self.config.min_severity):
                    continue

            yield pattern

    def get_all_patterns(self) -> List[VulnerabilityPattern]:
        """Get all loaded patterns as a list."""
        if not self._loaded:
            self.load_all()
        return list(self._patterns.values())

    def get_pattern(self, pattern_id: str) -> Optional[VulnerabilityPattern]:
        """Get a specific pattern by ID."""
        if not self._loaded:
            self.load_all()
        return self._patterns.get(pattern_id)

    def add_pattern(self, pattern: VulnerabilityPattern, persist: bool = False) -> bool:
        """
        Add or update a pattern.

        Args:
            pattern: The pattern to add
            persist: If True, save to custom patterns directory

        Returns:
            True if pattern was added successfully
        """
        issues = self._validator.validate(pattern, return_issues=True)
        if issues:
            logger.warning(f"Pattern {pattern.id} has validation issues: {issues}")
            return False

        self._patterns[pattern.id] = pattern

        if persist and self.config.custom_patterns_dir:
            self._persist_pattern(pattern)

        return True

    def _persist_pattern(self, pattern: VulnerabilityPattern) -> None:
        """Save pattern to custom directory."""
        if not self.config.custom_patterns_dir:
            return

        self.config.custom_patterns_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.config.custom_patterns_dir / f"{pattern.id}.json"
        self._loader.save_patterns([pattern], output_path)

    def remove_pattern(self, pattern_id: str) -> bool:
        """Remove a pattern by ID."""
        if pattern_id in self._patterns:
            del self._patterns[pattern_id]
            return True
        return False

    def export_patterns(
        self,
        output_path: Path,
        pattern_ids: Optional[List[str]] = None,
        category: Optional[str] = None,
    ) -> int:
        """
        Export patterns to JSON file.

        Returns:
            Number of patterns exported
        """
        if not self._loaded:
            self.load_all()

        patterns_to_export = []
        for pid, pattern in self._patterns.items():
            if pattern_ids is None or pid in pattern_ids:
                patterns_to_export.append(pattern)

        self._loader.save_patterns(patterns_to_export, output_path, category)
        return len(patterns_to_export)

    def validate_all(self) -> Dict[str, List[str]]:
        """Validate all loaded patterns and return any issues."""
        if not self._loaded:
            self.load_all()
        return self._validator.validate_all(list(self._patterns.values()))

    def reload(self) -> None:
        """Force reload all patterns."""
        self._patterns.clear()
        self._loaded_sources.clear()
        self._loaded = False
        self.load_all()

    @property
    def stats(self) -> Dict[str, any]:
        """Get statistics about loaded patterns."""
        if not self._loaded:
            self.load_all()

        stats = {
            "total": len(self._patterns),
            "enabled": sum(1 for p in self._patterns.values() if p.enabled),
            "by_severity": {},
            "by_category": {},
            "by_source": {},
            "sources_loaded": self._loaded_sources,
        }

        for pattern in self._patterns.values():
            sev = pattern.severity.value
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

            cat = pattern.category.value
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

            if pattern.metadata.source:
                src = pattern.metadata.source.type.value
                stats["by_source"][src] = stats["by_source"].get(src, 0) + 1

        return stats

    def get_categories(self) -> List[Category]:
        """Get list of categories that have patterns loaded."""
        if not self._loaded:
            self.load_all()

        categories = set()
        for pattern in self._patterns.values():
            categories.add(pattern.category)
        return sorted(categories, key=lambda c: c.value)

    def search_patterns(self, query: str) -> List[VulnerabilityPattern]:
        """Search patterns by title, description, or tags."""
        if not self._loaded:
            self.load_all()

        query_lower = query.lower()
        results = []

        for pattern in self._patterns.values():
            if (query_lower in pattern.title.lower() or
                query_lower in pattern.description.lower() or
                query_lower in pattern.id.lower() or
                any(query_lower in tag.lower() for tag in pattern.tags)):
                results.append(pattern)

        return results
