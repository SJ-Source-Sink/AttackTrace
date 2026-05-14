"""Security blog crawler for Android vulnerability writeups."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Any

from .cache import CrawlerCache

logger = logging.getLogger(__name__)


@dataclass
class BlogSource:
    """Configuration for a security blog source."""
    name: str
    base_url: str
    feed_url: Optional[str] = None
    search_url_template: Optional[str] = None
    article_selector: Optional[str] = None
    content_selector: Optional[str] = None
    android_keywords: List[str] = field(default_factory=lambda: [
        "android", "apk", "mobile", "intent", "webview", "deeplink"
    ])


# Pre-configured blog sources
BLOG_SOURCES = [
    # Mobile Security Specialists
    BlogSource(
        name="Oversecured",
        base_url="https://blog.oversecured.com",
        feed_url="https://blog.oversecured.com/feed.xml",
        android_keywords=["android", "apk", "intent", "webview", "activity", "manifest", "mobile", "contentprovider"]
    ),
    BlogSource(
        name="NowSecure",
        base_url="https://www.nowsecure.com",
        feed_url="https://www.nowsecure.com/blog/feed/",
        android_keywords=["android", "mobile", "apk", "security"]
    ),
    BlogSource(
        name="WithSecure Labs",
        base_url="https://labs.withsecure.com",
        feed_url="https://labs.withsecure.com/rss",
        android_keywords=["android", "mobile", "apk"]
    ),

    # Major Security Research
    BlogSource(
        name="Google Project Zero",
        base_url="https://googleprojectzero.blogspot.com",
        feed_url="https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
        android_keywords=["android", "chrome", "kernel", "pixel", "samsung", "qualcomm"]
    ),
    BlogSource(
        name="PortSwigger Research",
        base_url="https://portswigger.net",
        feed_url="https://portswigger.net/research/rss",
        android_keywords=["android", "mobile", "webview", "deep link"]
    ),

    # Security Companies
    BlogSource(
        name="Checkpoint Research",
        base_url="https://research.checkpoint.com",
        feed_url="https://research.checkpoint.com/feed/",
        android_keywords=["android", "mobile", "apk", "malware", "play store"]
    ),
    BlogSource(
        name="Zimperium",
        base_url="https://www.zimperium.com",
        feed_url="https://www.zimperium.com/blog/feed/",
        android_keywords=["android", "mobile", "apk", "threat", "vulnerability"]
    ),
    BlogSource(
        name="Lookout Threat Intelligence",
        base_url="https://www.lookout.com",
        feed_url="https://www.lookout.com/blog/feed/",
        android_keywords=["android", "mobile", "surveillance", "spyware", "malware"]
    ),
    BlogSource(
        name="Promon Security",
        base_url="https://promon.co",
        feed_url="https://promon.co/feed/",
        android_keywords=["android", "mobile", "app shielding", "runtime protection"]
    ),

    # Bug Bounty & Vulnerability Research
    BlogSource(
        name="Assetnote Research",
        base_url="https://blog.assetnote.io",
        feed_url="https://blog.assetnote.io/rss/",
        android_keywords=["android", "mobile", "api", "oauth"]
    ),
    BlogSource(
        name="Synack Red Team",
        base_url="https://www.synack.com",
        feed_url="https://www.synack.com/blog/feed/",
        android_keywords=["android", "mobile", "penetration testing"]
    ),

    # Individual Researchers
    BlogSource(
        name="8ksec",
        base_url="https://8ksec.io",
        feed_url="https://8ksec.io/feed/",
        android_keywords=["android", "ios", "mobile", "reverse engineering", "frida"]
    ),

    # General Security with Android Coverage
    BlogSource(
        name="Snyk Security",
        base_url="https://snyk.io",
        feed_url="https://snyk.io/blog/feed/",
        android_keywords=["android", "gradle", "dependency", "supply chain"]
    ),
    BlogSource(
        name="OWASP",
        base_url="https://owasp.org",
        feed_url="https://owasp.org/feed.xml",
        android_keywords=["android", "mobile", "MASTG", "MASVS", "security testing"]
    ),
]


@dataclass
class BlogArticle:
    """Parsed blog article."""
    id: str
    title: str
    url: str
    source: str
    published_at: Optional[datetime]
    author: Optional[str]
    content: str
    summary: str
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "url": self.url,
            "source": self.source,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "author": self.author,
            "content": self.content,
            "summary": self.summary,
            "tags": self.tags,
        }


class HTMLTextExtractor(HTMLParser):
    """Extract text content from HTML, skipping scripts and styles."""

    def __init__(self):
        super().__init__()
        self.text_parts = []
        self._skip_tags = {'script', 'style', 'head', 'nav', 'footer', 'aside', 'noscript'}
        self._current_skip = 0
        self._in_code = False

    def handle_starttag(self, tag, attrs):
        if tag in self._skip_tags:
            self._current_skip += 1
        if tag in ('code', 'pre'):
            self._in_code = True
            self.text_parts.append('\n```\n')

    def handle_endtag(self, tag):
        if tag in self._skip_tags and self._current_skip > 0:
            self._current_skip -= 1
        if tag in ('code', 'pre'):
            self._in_code = False
            self.text_parts.append('\n```\n')

    def handle_data(self, data):
        if self._current_skip == 0:
            text = data.strip()
            if text:
                self.text_parts.append(text)

    def get_text(self) -> str:
        return ' '.join(self.text_parts)


class BlogCrawler:
    """
    Crawler for security blog articles about Android vulnerabilities.
    Supports RSS feeds and basic web scraping.
    """

    def __init__(
        self,
        sources: Optional[List[BlogSource]] = None,
        cache_dir: Optional[Path] = None,
        cache_ttl: timedelta = timedelta(days=30),
        rate_limit_seconds: float = 2.0
    ):
        self.sources = sources or BLOG_SOURCES
        cache_dir = cache_dir or Path.home() / ".apkanalyzer" / "cache" / "blogs"
        self._cache = CrawlerCache(cache_dir, cache_ttl)
        self.rate_limit_seconds = rate_limit_seconds
        self._last_request_time: float = 0

    def _rate_limit(self) -> None:
        """Enforce rate limiting."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_seconds:
            time.sleep(self.rate_limit_seconds - elapsed)
        self._last_request_time = time.time()

    def _fetch_url(self, url: str, use_cache: bool = True) -> Optional[str]:
        """Fetch URL content with caching and user agent."""
        cache_key = self._cache.url_key(url)

        if use_cache:
            cached = self._cache.get(cache_key)
            if cached:
                return cached

        self._rate_limit()

        request = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'APKAnalyzer Security Research Bot/1.0 (+https://github.com/apkanalyzer)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                if use_cache:
                    self._cache.set(cache_key, content, "blog_fetch")
                return content
        except urllib.error.HTTPError as e:
            logger.warning(f"HTTP {e.code} fetching {url}")
            return None
        except urllib.error.URLError as e:
            logger.warning(f"URL Error fetching {url}: {e.reason}")
            return None
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return None

    def crawl_all_sources(
        self,
        max_articles_per_source: int = 20,
        use_cache: bool = True
    ) -> Iterator[BlogArticle]:
        """Crawl all configured blog sources."""
        for source in self.sources:
            logger.info(f"Crawling source: {source.name}")
            try:
                articles = self._crawl_source(source, max_articles_per_source, use_cache)
                for article in articles:
                    yield article
            except Exception as e:
                logger.error(f"Failed to crawl {source.name}: {e}")

    def crawl_source(
        self,
        source_name: str,
        max_articles: int = 20,
        use_cache: bool = True
    ) -> Iterator[BlogArticle]:
        """Crawl a specific source by name."""
        source = next((s for s in self.sources if s.name.lower() == source_name.lower()), None)
        if not source:
            logger.error(f"Unknown source: {source_name}")
            return

        yield from self._crawl_source(source, max_articles, use_cache)

    def _crawl_source(
        self,
        source: BlogSource,
        max_articles: int,
        use_cache: bool
    ) -> Iterator[BlogArticle]:
        """Crawl a single blog source."""
        if source.feed_url:
            yield from self._crawl_rss_feed(source, max_articles, use_cache)
        else:
            logger.warning(f"No feed URL for {source.name}, skipping")

    def _crawl_rss_feed(
        self,
        source: BlogSource,
        max_articles: int,
        use_cache: bool
    ) -> Iterator[BlogArticle]:
        """Parse RSS/Atom feed for articles."""
        content = self._fetch_url(source.feed_url, use_cache)
        if not content:
            return

        articles = list(self._parse_feed(content, source))
        count = 0

        for article in articles:
            if count >= max_articles:
                break

            if self._is_android_related(article, source):
                # Optionally fetch full article content
                full_article = self._fetch_article_content(article, use_cache)
                if full_article:
                    yield full_article
                    count += 1
                else:
                    yield article
                    count += 1

        logger.info(f"Found {count} Android-related articles from {source.name}")

    def _parse_feed(self, content: str, source: BlogSource) -> Iterator[BlogArticle]:
        """Parse RSS/Atom feed content."""
        # Determine feed type
        is_atom = '<feed' in content[:500]

        if is_atom:
            yield from self._parse_atom_feed(content, source)
        else:
            yield from self._parse_rss_feed(content, source)

    def _parse_rss_feed(self, content: str, source: BlogSource) -> Iterator[BlogArticle]:
        """Parse RSS 2.0 feed."""
        # Simple regex-based parsing (for production, use feedparser library)
        item_pattern = re.compile(r'<item>(.*?)</item>', re.DOTALL)
        title_pattern = re.compile(r'<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>', re.DOTALL)
        link_pattern = re.compile(r'<link>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</link>')
        desc_pattern = re.compile(r'<description>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>', re.DOTALL)
        date_pattern = re.compile(r'<pubDate>(.*?)</pubDate>')
        creator_pattern = re.compile(r'<dc:creator>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</dc:creator>')
        content_pattern = re.compile(r'<content:encoded>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</content:encoded>', re.DOTALL)

        for item_match in item_pattern.finditer(content):
            item = item_match.group(1)

            title_m = title_pattern.search(item)
            link_m = link_pattern.search(item)
            desc_m = desc_pattern.search(item)
            date_m = date_pattern.search(item)
            creator_m = creator_pattern.search(item)
            content_m = content_pattern.search(item)

            if title_m and link_m:
                url = self._clean_text(link_m.group(1))
                article_id = hashlib.md5(url.encode()).hexdigest()[:12]

                # Prefer content:encoded over description
                article_content = ""
                if content_m:
                    article_content = self._clean_html(content_m.group(1))

                summary = ""
                if desc_m:
                    summary = self._clean_html(desc_m.group(1))[:500]

                yield BlogArticle(
                    id=article_id,
                    title=self._clean_html(title_m.group(1)),
                    url=url,
                    source=source.name,
                    published_at=self._parse_date(date_m.group(1) if date_m else None),
                    author=self._clean_text(creator_m.group(1)) if creator_m else None,
                    content=article_content,
                    summary=summary,
                    tags=[]
                )

    def _parse_atom_feed(self, content: str, source: BlogSource) -> Iterator[BlogArticle]:
        """Parse Atom feed."""
        entry_pattern = re.compile(r'<entry>(.*?)</entry>', re.DOTALL)
        title_pattern = re.compile(r'<title[^>]*>(.*?)</title>', re.DOTALL)
        link_pattern = re.compile(r'<link[^>]*href=["\']([^"\']+)["\'][^>]*/?>|<link[^>]*>([^<]+)</link>')
        summary_pattern = re.compile(r'<summary[^>]*>(.*?)</summary>', re.DOTALL)
        content_pattern = re.compile(r'<content[^>]*>(.*?)</content>', re.DOTALL)
        updated_pattern = re.compile(r'<(?:published|updated)>(.*?)</(?:published|updated)>')
        author_pattern = re.compile(r'<author>.*?<name>(.*?)</name>.*?</author>', re.DOTALL)

        for entry_match in entry_pattern.finditer(content):
            entry = entry_match.group(1)

            title_m = title_pattern.search(entry)
            link_m = link_pattern.search(entry)
            summary_m = summary_pattern.search(entry)
            content_m = content_pattern.search(entry)
            updated_m = updated_pattern.search(entry)
            author_m = author_pattern.search(entry)

            if title_m and link_m:
                url = link_m.group(1) or link_m.group(2)
                url = self._clean_text(url)
                article_id = hashlib.md5(url.encode()).hexdigest()[:12]

                article_content = ""
                if content_m:
                    article_content = self._clean_html(content_m.group(1))

                summary = ""
                if summary_m:
                    summary = self._clean_html(summary_m.group(1))[:500]

                yield BlogArticle(
                    id=article_id,
                    title=self._clean_html(title_m.group(1)),
                    url=url,
                    source=source.name,
                    published_at=self._parse_date(updated_m.group(1) if updated_m else None),
                    author=self._clean_text(author_m.group(1)) if author_m else None,
                    content=article_content,
                    summary=summary,
                    tags=[]
                )

    def _fetch_article_content(self, article: BlogArticle, use_cache: bool) -> Optional[BlogArticle]:
        """Fetch full article content if not already present."""
        if article.content and len(article.content) > 500:
            return article

        html = self._fetch_url(article.url, use_cache)
        if not html:
            return article

        try:
            parser = HTMLTextExtractor()
            parser.feed(html)
            content = parser.get_text()
            article.content = content[:50000]  # Limit content size
            return article
        except Exception as e:
            logger.warning(f"Failed to parse article {article.url}: {e}")
            return article

    def _is_android_related(self, article: BlogArticle, source: BlogSource) -> bool:
        """Check if article is Android-related."""
        searchable = f"{article.title} {article.summary} {article.content}".lower()
        return any(kw.lower() in searchable for kw in source.android_keywords)

    def _clean_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        # Remove CDATA markers
        text = re.sub(r'<!\[CDATA\[|\]\]>', '', text)
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        # Decode entities
        text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        text = text.replace('&quot;', '"').replace('&#39;', "'").replace('&nbsp;', ' ')
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _clean_text(self, text: str) -> str:
        """Clean text removing extra whitespace."""
        return re.sub(r'\s+', ' ', text).strip()

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse various date formats."""
        if not date_str:
            return None

        date_str = date_str.strip()

        formats = [
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        # Try ISO format with timezone handling
        try:
            if date_str.endswith('Z'):
                date_str = date_str[:-1] + '+00:00'
            return datetime.fromisoformat(date_str)
        except ValueError:
            pass

        return None

    def save_article(self, article: BlogArticle, output_dir: Path) -> Path:
        """Save article to output directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"blog_{article.id}.json"

        data = article.to_dict()
        data["fetched_at"] = datetime.utcnow().isoformat()

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        return output_path

    def add_source(self, source: BlogSource) -> None:
        """Add a new blog source."""
        self.sources.append(source)

    def list_sources(self) -> List[str]:
        """List all configured source names."""
        return [s.name for s in self.sources]
