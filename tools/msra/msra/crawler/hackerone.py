"""HackerOne web crawler for disclosed Android vulnerability reports."""

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
class HackerOneConfig:
    """Configuration for HackerOne crawler."""
    # Rate limiting
    requests_per_minute: int = 20
    # Filtering
    min_severity: str = "low"  # none, low, medium, high, critical
    # Caching
    cache_dir: Optional[Path] = None
    cache_ttl: timedelta = timedelta(days=7)


@dataclass
class HackerOneReport:
    """Parsed HackerOne disclosed report."""
    id: str
    title: str
    severity: str
    cwe: Optional[str]
    cve_ids: List[str]
    disclosed_at: Optional[datetime]
    team: str
    bounty: float
    report_url: str
    summary: str
    weakness: Optional[str]
    vulnerability_details: str = ""
    steps_to_reproduce: str = ""
    impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "cve_ids": self.cve_ids,
            "disclosed_at": self.disclosed_at.isoformat() if self.disclosed_at else None,
            "team": self.team,
            "bounty": self.bounty,
            "report_url": self.report_url,
            "summary": self.summary,
            "weakness": self.weakness,
            "vulnerability_details": self.vulnerability_details,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact,
        }


class HacktivityHTMLParser(HTMLParser):
    """Parser for HackerOne hacktivity page."""

    def __init__(self):
        super().__init__()
        self.reports = []
        self._current_report = {}
        self._in_report = False
        self._in_title = False
        self._in_team = False
        self._in_severity = False
        self._in_bounty = False
        self._capture_text = False
        self._current_text = ""

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        class_name = attrs_dict.get('class', '')

        # Detect report container
        if tag == 'a' and 'hacktivity-item' in class_name:
            self._in_report = True
            self._current_report = {
                'url': attrs_dict.get('href', ''),
            }
        elif tag == 'a' and attrs_dict.get('href', '').startswith('/reports/'):
            self._in_report = True
            self._current_report = {
                'url': attrs_dict.get('href', ''),
            }

        # Title
        if self._in_report and 'title' in class_name.lower():
            self._in_title = True
            self._capture_text = True

        # Team name
        if self._in_report and 'team' in class_name.lower():
            self._in_team = True
            self._capture_text = True

        # Severity
        if self._in_report and 'severity' in class_name.lower():
            self._in_severity = True
            self._capture_text = True

        # Bounty
        if self._in_report and 'bounty' in class_name.lower():
            self._in_bounty = True
            self._capture_text = True

    def handle_endtag(self, tag):
        if self._capture_text:
            text = self._current_text.strip()

            if self._in_title and text:
                self._current_report['title'] = text
                self._in_title = False
            elif self._in_team and text:
                self._current_report['team'] = text
                self._in_team = False
            elif self._in_severity and text:
                self._current_report['severity'] = text.lower()
                self._in_severity = False
            elif self._in_bounty and text:
                # Parse bounty amount
                amount = re.sub(r'[^\d.]', '', text)
                try:
                    self._current_report['bounty'] = float(amount) if amount else 0
                except ValueError:
                    self._current_report['bounty'] = 0
                self._in_bounty = False

            self._capture_text = False
            self._current_text = ""

        # End of report item
        if self._in_report and tag in ('a', 'div', 'article'):
            if self._current_report.get('title') and self._current_report.get('url'):
                self.reports.append(self._current_report.copy())
                self._in_report = False
                self._current_report = {}

    def handle_data(self, data):
        if self._capture_text:
            self._current_text += data


class ReportHTMLParser(HTMLParser):
    """Parser for individual HackerOne report page."""

    def __init__(self):
        super().__init__()
        self.title = ""
        self.summary = ""
        self.vulnerability_details = ""
        self.steps_to_reproduce = ""
        self.impact = ""
        self.severity = ""
        self.cwe = None
        self.cve_ids = []
        self.team = ""
        self.bounty = 0.0
        self.disclosed_at = None

        self._in_title = False
        self._in_content = False
        self._in_severity = False
        self._in_metadata = False
        self._current_section = None
        self._capture_text = False
        self._current_text = ""
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        class_name = attrs_dict.get('class', '')
        data_attr = attrs_dict.get('data-testid', '')

        # Title
        if tag == 'h1' or (tag == 'div' and 'title' in class_name.lower()):
            self._in_title = True
            self._capture_text = True

        # Content sections
        if 'vulnerability' in class_name.lower() or 'vulnerability' in data_attr.lower():
            self._current_section = 'vulnerability'
            self._capture_text = True
        elif 'steps' in class_name.lower() or 'reproduce' in class_name.lower():
            self._current_section = 'steps'
            self._capture_text = True
        elif 'impact' in class_name.lower():
            self._current_section = 'impact'
            self._capture_text = True
        elif 'summary' in class_name.lower():
            self._current_section = 'summary'
            self._capture_text = True

        # Severity badge
        if 'severity' in class_name.lower() or 'severity' in data_attr.lower():
            self._in_severity = True
            self._capture_text = True

        # Code blocks for vulnerability details
        if tag in ('pre', 'code'):
            self._capture_text = True

        self._depth += 1

    def handle_endtag(self, tag):
        self._depth -= 1

        if self._capture_text and self._current_text.strip():
            text = self._current_text.strip()

            if self._in_title:
                self.title = text
                self._in_title = False
            elif self._in_severity:
                self.severity = text.lower()
                self._in_severity = False
            elif self._current_section == 'vulnerability':
                self.vulnerability_details += text + "\n"
            elif self._current_section == 'steps':
                self.steps_to_reproduce += text + "\n"
            elif self._current_section == 'impact':
                self.impact += text + "\n"
            elif self._current_section == 'summary':
                self.summary += text + "\n"

        if tag in ('div', 'section', 'article'):
            self._current_section = None

        self._capture_text = False
        self._current_text = ""

    def handle_data(self, data):
        if self._capture_text:
            self._current_text += data

        # Look for CWE/CVE in text
        cwe_match = re.search(r'CWE-(\d+)', data)
        if cwe_match:
            self.cwe = f"CWE-{cwe_match.group(1)}"

        cve_matches = re.findall(r'CVE-\d{4}-\d+', data)
        for cve in cve_matches:
            if cve not in self.cve_ids:
                self.cve_ids.append(cve)


class HackerOneCrawler:
    """
    Web crawler for HackerOne disclosed Android vulnerability reports.
    Scrapes the hacktivity page and individual report pages.
    """

    HACKTIVITY_URL = "https://hackerone.com/hacktivity"
    SEARCH_URL = "https://hackerone.com/hacktivity?querystring=android"

    # Android-related keywords for filtering
    ANDROID_KEYWORDS = [
        "android", "apk", "aab", "dalvik", "smali",
        "activity", "intent", "deeplink", "webview",
        "contentprovider", "broadcastreceiver", "manifest",
        "exported", "mobile app", "kotlin", "java android"
    ]

    def __init__(self, config: Optional[HackerOneConfig] = None):
        self.config = config or HackerOneConfig()
        self._last_request_time: float = 0
        self._request_interval = 60.0 / self.config.requests_per_minute

        cache_dir = self.config.cache_dir or Path.home() / ".apkanalyzer" / "cache" / "hackerone"
        self._cache = CrawlerCache(cache_dir, self.config.cache_ttl)

    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._request_interval:
            sleep_time = self._request_interval - elapsed
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _fetch_url(self, url: str, use_cache: bool = True) -> Optional[str]:
        """Fetch URL content with caching."""
        cache_key = self._cache.url_key(url)

        if use_cache:
            cached = self._cache.get(cache_key)
            if cached:
                return cached

        self._rate_limit()

        request = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                if use_cache:
                    self._cache.set(cache_key, content, "hackerone_page")
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

    def fetch_reports(
        self,
        since: Optional[datetime] = None,
        max_reports: int = 100,
        use_cache: bool = True
    ) -> Iterator[HackerOneReport]:
        """
        Fetch disclosed reports by crawling HackerOne hacktivity.
        """
        cache_key = f"h1_crawl_{since.isoformat() if since else 'all'}_{max_reports}"

        if use_cache:
            cached = self._cache.get(cache_key)
            if cached:
                logger.info(f"Using cached HackerOne crawl results ({len(cached)} reports)")
                for report_data in cached:
                    yield self._dict_to_report(report_data)
                return

        logger.info("Crawling HackerOne hacktivity for Android reports...")

        all_reports = []
        fetched = 0

        # Search for Android-related reports
        search_queries = [
            "android",
            "mobile app android",
            "webview",
            "deeplink android",
            "intent android",
        ]

        seen_ids = set()

        for query in search_queries:
            if fetched >= max_reports:
                break

            url = f"https://hackerone.com/hacktivity?querystring={urllib.parse.quote(query)}"
            html = self._fetch_url(url, use_cache)

            if not html:
                continue

            # Parse the page for report links
            report_urls = self._extract_report_urls(html)
            logger.debug(f"Found {len(report_urls)} report links for query '{query}'")

            for report_url in report_urls:
                if fetched >= max_reports:
                    break

                # Extract report ID from URL
                report_id = self._extract_report_id(report_url)
                if not report_id or report_id in seen_ids:
                    continue

                seen_ids.add(report_id)

                # Fetch and parse the full report
                report = self._fetch_report(report_url, use_cache)
                if report and self._is_android_related(report):
                    if self._meets_severity_threshold(report):
                        yield report
                        all_reports.append(report.to_dict())
                        fetched += 1
                        logger.debug(f"Found report: {report.title[:50]}")

        # Cache results
        if all_reports and use_cache:
            self._cache.set(cache_key, all_reports, "hackerone_crawl")
            logger.info(f"Cached {len(all_reports)} HackerOne reports")

    def _extract_report_urls(self, html: str) -> List[str]:
        """Extract report URLs from hacktivity page."""
        urls = []

        # Pattern to match report links
        pattern = re.compile(r'href=["\'](/reports/\d+)["\']', re.IGNORECASE)
        matches = pattern.findall(html)

        for match in matches:
            full_url = f"https://hackerone.com{match}"
            if full_url not in urls:
                urls.append(full_url)

        # Also try JSON data embedded in page
        json_pattern = re.compile(r'"url":\s*"(/reports/\d+)"')
        json_matches = json_pattern.findall(html)

        for match in json_matches:
            full_url = f"https://hackerone.com{match}"
            if full_url not in urls:
                urls.append(full_url)

        return urls

    def _extract_report_id(self, url: str) -> Optional[str]:
        """Extract report ID from URL."""
        match = re.search(r'/reports/(\d+)', url)
        return match.group(1) if match else None

    def _fetch_report(self, url: str, use_cache: bool) -> Optional[HackerOneReport]:
        """Fetch and parse a single report page."""
        report_id = self._extract_report_id(url)
        if not report_id:
            return None

        html = self._fetch_url(url, use_cache)
        if not html:
            return None

        return self._parse_report_html(html, report_id, url)

    def _parse_report_html(self, html: str, report_id: str, url: str) -> Optional[HackerOneReport]:
        """Parse report page HTML."""
        try:
            # Extract title
            title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
            title = title_match.group(1).strip() if title_match else ""

            # Also try meta title
            if not title:
                meta_match = re.search(r'<title>([^<]+)</title>', html)
                if meta_match:
                    title = meta_match.group(1).split('|')[0].strip()

            # Extract severity
            severity = "medium"
            severity_patterns = [
                r'severity["\s:]+["\']?(critical|high|medium|low|none)["\']?',
                r'class="[^"]*severity[^"]*"[^>]*>([^<]+)',
                r'"severity_rating":\s*"(\w+)"',
            ]
            for pattern in severity_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    severity = match.group(1).lower()
                    break

            # Extract team name
            team = "Unknown"
            team_patterns = [
                r'"team":\s*\{[^}]*"name":\s*"([^"]+)"',
                r'class="[^"]*team[^"]*"[^>]*>([^<]+)',
                r'@(\w+)\s+disclosed',
            ]
            for pattern in team_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    team = match.group(1).strip()
                    break

            # Extract bounty
            bounty = 0.0
            bounty_match = re.search(r'\$[\d,]+(?:\.\d{2})?', html)
            if bounty_match:
                try:
                    bounty = float(bounty_match.group(0).replace('$', '').replace(',', ''))
                except ValueError:
                    pass

            # Extract CWE
            cwe = None
            cwe_match = re.search(r'CWE-(\d+)', html)
            if cwe_match:
                cwe = f"CWE-{cwe_match.group(1)}"

            # Extract CVEs
            cve_ids = list(set(re.findall(r'CVE-\d{4}-\d+', html)))

            # Extract vulnerability details (main content)
            content_patterns = [
                r'<div[^>]*class="[^"]*markdown[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*report-body[^"]*"[^>]*>(.*?)</div>',
                r'<section[^>]*class="[^"]*vulnerability[^"]*"[^>]*>(.*?)</section>',
            ]

            vulnerability_details = ""
            for pattern in content_patterns:
                matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    # Clean HTML
                    clean = re.sub(r'<[^>]+>', ' ', match)
                    clean = re.sub(r'\s+', ' ', clean).strip()
                    if len(clean) > len(vulnerability_details):
                        vulnerability_details = clean

            # Extract summary (first paragraph or description)
            summary = vulnerability_details[:500] if vulnerability_details else ""

            # Disclosed date
            disclosed_at = None
            date_patterns = [
                r'"disclosed_at":\s*"([^"]+)"',
                r'disclosed[^>]*>([^<]+\d{4})',
            ]
            for pattern in date_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    try:
                        date_str = match.group(1).strip()
                        disclosed_at = self._parse_date(date_str)
                        break
                    except Exception:
                        pass

            return HackerOneReport(
                id=report_id,
                title=title,
                severity=severity,
                cwe=cwe,
                cve_ids=cve_ids,
                disclosed_at=disclosed_at,
                team=team,
                bounty=bounty,
                report_url=url,
                summary=summary,
                weakness=cwe,
                vulnerability_details=vulnerability_details,
            )

        except Exception as e:
            logger.warning(f"Failed to parse report {url}: {e}")
            return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse various date formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
            "%B %d, %Y",
            "%b %d, %Y",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            pass

        return None

    def _dict_to_report(self, data: Dict) -> HackerOneReport:
        """Convert dictionary back to HackerOneReport."""
        disclosed_at = None
        if data.get("disclosed_at"):
            try:
                disclosed_at = datetime.fromisoformat(data["disclosed_at"])
            except ValueError:
                pass

        return HackerOneReport(
            id=data["id"],
            title=data["title"],
            severity=data["severity"],
            cwe=data.get("cwe"),
            cve_ids=data.get("cve_ids", []),
            disclosed_at=disclosed_at,
            team=data["team"],
            bounty=data["bounty"],
            report_url=data["report_url"],
            summary=data["summary"],
            weakness=data.get("weakness"),
            vulnerability_details=data.get("vulnerability_details", ""),
            steps_to_reproduce=data.get("steps_to_reproduce", ""),
            impact=data.get("impact", ""),
        )

    def _is_android_related(self, report: HackerOneReport) -> bool:
        """Check if report is Android-related based on content."""
        searchable = f"{report.title} {report.summary} {report.vulnerability_details} {report.weakness or ''}".lower()
        return any(kw.lower() in searchable for kw in self.ANDROID_KEYWORDS)

    def _meets_severity_threshold(self, report: HackerOneReport) -> bool:
        """Check if report meets minimum severity threshold."""
        severity_order = ["none", "low", "medium", "high", "critical"]
        try:
            report_idx = severity_order.index(report.severity.lower())
            threshold_idx = severity_order.index(self.config.min_severity.lower())
            return report_idx >= threshold_idx
        except ValueError:
            return True

    def save_report(self, report: HackerOneReport, output_dir: Path) -> Path:
        """Save report to cache directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"h1_{report.id}.json"

        data = report.to_dict()
        data["fetched_at"] = datetime.utcnow().isoformat()

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        return output_path

    def search_reports(self, query: str, max_results: int = 50) -> Iterator[HackerOneReport]:
        """Search for reports matching a query."""
        url = f"https://hackerone.com/hacktivity?querystring={urllib.parse.quote(query)}"
        html = self._fetch_url(url)

        if not html:
            return

        report_urls = self._extract_report_urls(html)
        count = 0

        for report_url in report_urls:
            if count >= max_results:
                break

            report = self._fetch_report(report_url, use_cache=True)
            if report:
                yield report
                count += 1
