"""Threat Intelligence Updater - Automatic pattern updates from security feeds."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from .hackerone import HackerOneCrawler, HackerOneConfig
from .blogs import BlogCrawler, BLOG_SOURCES
from .extractor import PatternExtractor
from .cache import CrawlerCache
from .sources import SourcesManager

logger = logging.getLogger(__name__)


@dataclass
class UpdateConfig:
    """Configuration for threat intelligence updates."""
    # Update frequency
    min_update_interval: timedelta = field(default_factory=lambda: timedelta(hours=24))

    # Sources to fetch from
    enable_hackerone: bool = True
    enable_blogs: bool = True

    # Fetch limits
    max_hackerone_reports: int = 30
    max_blog_articles_per_source: int = 10

    # HackerOne settings (web crawling)
    hackerone_min_severity: str = "low"

    # Auto-approval
    auto_approve_threshold: float = 0.7  # Confidence threshold for auto-approval
    auto_approve_enabled: bool = False   # Disabled by default for safety

    # Paths
    data_dir: Optional[Path] = None


@dataclass
class SourceStats:
    """Statistics for a single source."""
    name: str
    articles_fetched: int = 0
    patterns_found: int = 0
    patterns_added: int = 0
    patterns_pending: int = 0
    pattern_titles: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class UpdateResult:
    """Result of a threat intelligence update."""
    success: bool
    patterns_found: int = 0
    patterns_added: int = 0
    patterns_pending: int = 0
    sources_checked: List[str] = field(default_factory=list)
    source_stats: Dict[str, SourceStats] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    skipped_reason: Optional[str] = None
    new_pattern_titles: List[str] = field(default_factory=list)


class ThreatIntelUpdater:
    """
    Coordinates threat intelligence updates from multiple sources.
    Fetches security writeups, extracts patterns, and updates the pattern database.
    """

    def __init__(self, config: Optional[UpdateConfig] = None):
        self.config = config or UpdateConfig()

        # Set up paths
        self.data_dir = self.config.data_dir or Path.home() / ".apkanalyzer"
        self.state_file = self.data_dir / "update_state.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.extractor = PatternExtractor(self.data_dir / "data" / "crawled")

        # Load state
        self._state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Load update state from disk."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
        return {"last_update": None, "update_count": 0}

    def _save_state(self) -> None:
        """Save update state to disk."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def should_update(self) -> bool:
        """Check if an update is needed based on last update time."""
        last_update = self._state.get("last_update")
        if not last_update:
            return True

        try:
            last_dt = datetime.fromisoformat(last_update)
            elapsed = datetime.now() - last_dt
            return elapsed >= self.config.min_update_interval
        except Exception:
            return True

    def update(self, force: bool = False, quiet: bool = False) -> UpdateResult:
        """
        Run a threat intelligence update.

        Args:
            force: Force update even if recently updated
            quiet: Suppress output messages

        Returns:
            UpdateResult with details of the update
        """
        start_time = datetime.now()
        result = UpdateResult(success=True)

        # Check if update is needed
        if not force and not self.should_update():
            result.success = True
            result.skipped_reason = "Recently updated"
            if not quiet:
                last = self._state.get("last_update", "never")
                print(f"[*] Threat intel is up to date (last update: {last})")
            return result

        if not quiet:
            print("[*] Updating threat intelligence feeds...")

        # Fetch from HackerOne
        if self.config.enable_hackerone:
            try:
                h1_result = self._fetch_hackerone(quiet)
                result.patterns_found += h1_result["found"]
                result.patterns_added += h1_result["added"]
                result.patterns_pending += h1_result["pending"]
                result.sources_checked.append("HackerOne")
                result.new_pattern_titles.extend(h1_result.get("pattern_titles", []))

                # Store source stats
                result.source_stats["HackerOne"] = SourceStats(
                    name="HackerOne",
                    articles_fetched=h1_result.get("articles", 0),
                    patterns_found=h1_result["found"],
                    patterns_added=h1_result["added"],
                    patterns_pending=h1_result["pending"],
                    pattern_titles=h1_result.get("pattern_titles", [])
                )
            except Exception as e:
                error_msg = f"HackerOne fetch failed: {e}"
                result.errors.append(error_msg)
                if not quiet:
                    print(f"[!] {error_msg}")

        # Fetch from security blogs
        if self.config.enable_blogs:
            try:
                blog_result = self._fetch_blogs(quiet)
                result.patterns_found += blog_result["found"]
                result.patterns_added += blog_result["added"]
                result.patterns_pending += blog_result["pending"]
                result.sources_checked.extend(blog_result["sources"])
                result.new_pattern_titles.extend(blog_result.get("pattern_titles", []))

                # Store per-source stats
                for source_name, stats in blog_result.get("source_details", {}).items():
                    result.source_stats[source_name] = SourceStats(
                        name=source_name,
                        articles_fetched=stats.get("articles", 0),
                        patterns_found=stats.get("found", 0),
                        patterns_added=stats.get("added", 0),
                        patterns_pending=stats.get("pending", 0),
                        pattern_titles=stats.get("patterns", [])
                    )
            except Exception as e:
                error_msg = f"Blog fetch failed: {e}"
                result.errors.append(error_msg)
                if not quiet:
                    print(f"[!] {error_msg}")

        # Update state
        self._state["last_update"] = datetime.now().isoformat()
        self._state["update_count"] = self._state.get("update_count", 0) + 1
        self._save_state()

        # Calculate duration
        result.duration_seconds = (datetime.now() - start_time).total_seconds()

        if not quiet:
            print()
            print("=" * 60)
            print("THREAT INTELLIGENCE UPDATE SUMMARY")
            print("=" * 60)
            print(f"  Sources checked:   {len(result.sources_checked)}")
            print(f"  Patterns found:    {result.patterns_found}")
            print(f"  Patterns added:    {result.patterns_added}")
            print(f"  Pending review:    {result.patterns_pending}")
            print(f"  Duration:          {result.duration_seconds:.1f}s")

            # Show new patterns if any
            if result.new_pattern_titles:
                print()
                print("NEW PATTERNS EXTRACTED:")
                print("-" * 40)
                for title in result.new_pattern_titles[:20]:  # Show first 20
                    print(f"  {title}")
                if len(result.new_pattern_titles) > 20:
                    print(f"  ... and {len(result.new_pattern_titles) - 20} more")

            print("=" * 60)

        return result

    def _fetch_hackerone(self, quiet: bool) -> Dict[str, Any]:
        """Fetch patterns from HackerOne by crawling the website."""
        result = {"found": 0, "added": 0, "pending": 0, "pattern_titles": [], "articles": 0}

        # Configure HackerOne crawler (web crawling, no API needed)
        h1_config = HackerOneConfig(
            min_severity=self.config.hackerone_min_severity,
        )

        crawler = HackerOneCrawler(h1_config)

        # Fetch since last update
        since = None
        if self._state.get("last_update"):
            try:
                since = datetime.fromisoformat(self._state["last_update"])
            except Exception:
                pass

        if not quiet:
            print(f"  [*] Fetching HackerOne reports (max: {self.config.max_hackerone_reports})...")

        reports = list(crawler.fetch_reports(
            since=since,
            max_reports=self.config.max_hackerone_reports,
            use_cache=True
        ))

        result["articles"] = len(reports)

        if not quiet:
            print(f"  [+] Found {len(reports)} Android-related reports")

        # Extract patterns from reports
        for report in reports:
            extraction = self.extractor.extract_from_hackerone(report)
            if extraction.success:
                result["found"] += len(extraction.patterns)

                for pattern in extraction.patterns:
                    # Check if pattern should be auto-approved
                    if (self.config.auto_approve_enabled and
                        extraction.confidence >= self.config.auto_approve_threshold):
                        self.extractor.save_pattern(pattern, pending_review=False)
                        result["added"] += 1
                        result["pattern_titles"].append(f"✓ {pattern.title}")
                    else:
                        self.extractor.save_pattern(pattern, pending_review=True)
                        result["pending"] += 1
                        result["pattern_titles"].append(f"⏳ {pattern.title}")

        return result

    def _fetch_blogs(self, quiet: bool) -> Dict[str, Any]:
        """Fetch patterns from security blogs (built-in + custom sources)."""
        result = {"found": 0, "added": 0, "pending": 0, "sources": [], "source_details": {}, "pattern_titles": []}

        # Get all sources including custom ones
        sources_manager = SourcesManager(self.data_dir)
        all_sources = sources_manager.get_all_blog_sources()

        crawler = BlogCrawler(sources=all_sources)

        if not quiet:
            builtin_count = len(BLOG_SOURCES)
            custom_count = len(all_sources) - builtin_count
            print(f"  [*] Fetching from {len(all_sources)} sources ({builtin_count} built-in, {custom_count} custom)...")
            print()

        for source in all_sources:
            source_stats = {
                "articles": 0,
                "found": 0,
                "added": 0,
                "pending": 0,
                "patterns": []
            }

            try:
                articles = list(crawler.crawl_source(
                    source.name,
                    max_articles=self.config.max_blog_articles_per_source,
                    use_cache=True
                ))

                source_stats["articles"] = len(articles)
                result["sources"].append(source.name)

                for article in articles:
                    extraction = self.extractor.extract_from_blog(article)
                    if extraction.success:
                        source_stats["found"] += len(extraction.patterns)
                        result["found"] += len(extraction.patterns)

                        for pattern in extraction.patterns:
                            if (self.config.auto_approve_enabled and
                                extraction.confidence >= self.config.auto_approve_threshold):
                                self.extractor.save_pattern(pattern, pending_review=False)
                                source_stats["added"] += 1
                                result["added"] += 1
                                source_stats["patterns"].append(f"✓ {pattern.title}")
                                result["pattern_titles"].append(f"✓ {pattern.title} (from {source.name})")
                            else:
                                self.extractor.save_pattern(pattern, pending_review=True)
                                source_stats["pending"] += 1
                                result["pending"] += 1
                                source_stats["patterns"].append(f"⏳ {pattern.title}")
                                result["pattern_titles"].append(f"⏳ {pattern.title} (from {source.name})")

                # Show per-source stats if not quiet
                if not quiet:
                    status = "✓" if source_stats["articles"] > 0 else "○"
                    patterns_info = ""
                    if source_stats["found"] > 0:
                        patterns_info = f" → {source_stats['found']} patterns"
                    print(f"    {status} {source.name}: {source_stats['articles']} articles{patterns_info}")

            except Exception as e:
                if not quiet:
                    print(f"    ✗ {source.name}: failed ({str(e)[:50]})")
                source_stats["error"] = str(e)

            result["source_details"][source.name] = source_stats

        if not quiet:
            print()
            print(f"  [+] Checked {len(result['sources'])} sources, found {result['found']} patterns")

        return result

    def get_pending_count(self) -> int:
        """Get the number of patterns pending review."""
        return len(self.extractor.list_pending())

    def get_last_update(self) -> Optional[str]:
        """Get the timestamp of the last update."""
        return self._state.get("last_update")

    def get_stats(self) -> Dict[str, Any]:
        """Get update statistics."""
        return {
            "last_update": self._state.get("last_update"),
            "update_count": self._state.get("update_count", 0),
            "pending_patterns": self.get_pending_count(),
        }
