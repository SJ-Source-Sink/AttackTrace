"""Custom sources manager for threat intelligence."""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from .blogs import BlogSource, BLOG_SOURCES


@dataclass
class CustomSource:
    """User-defined threat intelligence source."""
    name: str
    url: str
    feed_url: Optional[str] = None
    source_type: str = "blog"  # blog, rss, github, other
    keywords: List[str] = field(default_factory=lambda: ["android", "mobile", "apk", "security"])
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    enabled: bool = True
    patterns_extracted: int = 0
    last_fetched: Optional[str] = None

    def to_blog_source(self) -> BlogSource:
        """Convert to BlogSource for crawler compatibility."""
        return BlogSource(
            name=self.name,
            base_url=self.url,
            feed_url=self.feed_url or f"{self.url.rstrip('/')}/feed/",
            android_keywords=self.keywords
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CustomSource':
        return cls(**data)


class SourcesManager:
    """Manages built-in and custom threat intelligence sources."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".apkanalyzer"
        self.sources_file = self.data_dir / "custom_sources.json"
        self._custom_sources: List[CustomSource] = []
        self._load_custom_sources()

    def _load_custom_sources(self) -> None:
        """Load custom sources from disk."""
        if self.sources_file.exists():
            try:
                with open(self.sources_file) as f:
                    data = json.load(f)
                self._custom_sources = [
                    CustomSource.from_dict(s) for s in data.get("sources", [])
                ]
            except Exception as e:
                print(f"[!] Failed to load custom sources: {e}")
                self._custom_sources = []

    def _save_custom_sources(self) -> None:
        """Save custom sources to disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "version": "1.0",
            "updated_at": datetime.now().isoformat(),
            "sources": [s.to_dict() for s in self._custom_sources]
        }
        with open(self.sources_file, 'w') as f:
            json.dump(data, f, indent=2)

    def add_source(
        self,
        name: str,
        url: str,
        feed_url: Optional[str] = None,
        keywords: Optional[List[str]] = None,
        source_type: str = "blog"
    ) -> CustomSource:
        """Add a new custom source."""
        # Check for duplicate
        for existing in self._custom_sources:
            if existing.url == url or existing.name.lower() == name.lower():
                raise ValueError(f"Source already exists: {existing.name}")

        source = CustomSource(
            name=name,
            url=url,
            feed_url=feed_url,
            source_type=source_type,
            keywords=keywords or ["android", "mobile", "apk", "security", "vulnerability"]
        )

        self._custom_sources.append(source)
        self._save_custom_sources()
        return source

    def remove_source(self, name: str) -> bool:
        """Remove a custom source by name."""
        for i, source in enumerate(self._custom_sources):
            if source.name.lower() == name.lower():
                self._custom_sources.pop(i)
                self._save_custom_sources()
                return True
        return False

    def get_custom_sources(self) -> List[CustomSource]:
        """Get all custom sources."""
        return self._custom_sources.copy()

    def get_all_blog_sources(self) -> List[BlogSource]:
        """Get all sources (built-in + custom) as BlogSource objects."""
        sources = list(BLOG_SOURCES)
        for custom in self._custom_sources:
            if custom.enabled:
                sources.append(custom.to_blog_source())
        return sources

    def get_source_stats(self) -> Dict[str, Any]:
        """Get statistics about sources."""
        return {
            "builtin_count": len(BLOG_SOURCES),
            "custom_count": len(self._custom_sources),
            "total_count": len(BLOG_SOURCES) + len(self._custom_sources),
            "custom_sources": [
                {
                    "name": s.name,
                    "url": s.url,
                    "enabled": s.enabled,
                    "patterns_extracted": s.patterns_extracted,
                    "last_fetched": s.last_fetched
                }
                for s in self._custom_sources
            ]
        }

    def update_source_stats(self, name: str, patterns: int) -> None:
        """Update extraction stats for a source."""
        for source in self._custom_sources:
            if source.name.lower() == name.lower():
                source.patterns_extracted += patterns
                source.last_fetched = datetime.now().isoformat()
                self._save_custom_sources()
                break


class PatternApprovalManager:
    """Manages approval workflow for extracted patterns."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".apkanalyzer" / "data" / "crawled"
        self.pending_dir = self.data_dir / "pending_review"
        self.approved_dir = self.data_dir / "approved"

    def get_pending_patterns(self) -> List[Dict[str, Any]]:
        """Get all patterns pending review."""
        if not self.pending_dir.exists():
            return []

        patterns = []
        for pattern_file in self.pending_dir.glob("*.json"):
            try:
                with open(pattern_file) as f:
                    data = json.load(f)
                data["_file"] = str(pattern_file)
                patterns.append(data)
            except Exception:
                continue

        return patterns

    def approve_pattern(self, pattern_id: str) -> bool:
        """Approve a pattern (move from pending to approved)."""
        self.approved_dir.mkdir(parents=True, exist_ok=True)

        for pattern_file in self.pending_dir.glob("*.json"):
            try:
                with open(pattern_file) as f:
                    data = json.load(f)
                if data.get("id") == pattern_id:
                    # Enable the pattern
                    data["enabled"] = True
                    # Add approval metadata
                    if "metadata" not in data:
                        data["metadata"] = {}
                    data["metadata"]["approved_at"] = datetime.now().isoformat()
                    data["tags"] = [t for t in data.get("tags", []) if t != "needs-review"]
                    data["tags"].append("approved")

                    # Save to approved directory
                    approved_path = self.approved_dir / pattern_file.name
                    with open(approved_path, 'w') as f:
                        json.dump(data, f, indent=2)

                    # Remove from pending
                    pattern_file.unlink()
                    return True
            except Exception:
                continue

        return False

    def reject_pattern(self, pattern_id: str) -> bool:
        """Reject a pattern (remove from pending)."""
        for pattern_file in self.pending_dir.glob("*.json"):
            try:
                with open(pattern_file) as f:
                    data = json.load(f)
                if data.get("id") == pattern_id:
                    pattern_file.unlink()
                    return True
            except Exception:
                continue
        return False

    def approve_all(self) -> int:
        """Approve all pending patterns."""
        count = 0
        pending = self.get_pending_patterns()
        for pattern in pending:
            if self.approve_pattern(pattern.get("id")):
                count += 1
        return count

    def get_stats(self) -> Dict[str, int]:
        """Get approval statistics."""
        pending_count = len(list(self.pending_dir.glob("*.json"))) if self.pending_dir.exists() else 0
        approved_count = len(list(self.approved_dir.glob("*.json"))) if self.approved_dir.exists() else 0

        return {
            "pending": pending_count,
            "approved": approved_count,
            "total": pending_count + approved_count
        }
