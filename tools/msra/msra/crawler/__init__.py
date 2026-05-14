"""Security content crawler for vulnerability pattern extraction."""

from .hackerone import HackerOneCrawler, HackerOneConfig, HackerOneReport
from .blogs import BlogCrawler, BlogSource, BlogArticle, BLOG_SOURCES
from .extractor import PatternExtractor, ExtractionResult
from .cache import CrawlerCache
from .updater import ThreatIntelUpdater, UpdateConfig, UpdateResult
from .sources import SourcesManager, CustomSource, PatternApprovalManager

__all__ = [
    "HackerOneCrawler",
    "HackerOneConfig",
    "HackerOneReport",
    "BlogCrawler",
    "BlogSource",
    "BlogArticle",
    "BLOG_SOURCES",
    "PatternExtractor",
    "ExtractionResult",
    "CrawlerCache",
    "ThreatIntelUpdater",
    "UpdateConfig",
    "UpdateResult",
    "SourcesManager",
    "CustomSource",
    "PatternApprovalManager",
]
