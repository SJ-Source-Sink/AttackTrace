"""
Screenshot capture module.

Captures screenshots of web applications using multiple methods:
- gowitness (preferred, if available)
- Playwright/Chromium (fallback)
- Headless Chrome via subprocess
- HTTP-based preview (last resort)
"""

import asyncio
import shutil
import tempfile
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional
import json

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    WebApplication,
    ScanSession,
)


def check_screenshot_capabilities() -> dict:
    """Check what screenshot methods are available."""
    capabilities = {
        "gowitness": shutil.which("gowitness") is not None,
        "playwright": False,
        "chrome": False,
    }

    # Check Playwright
    try:
        import playwright
        capabilities["playwright"] = True
    except ImportError:
        pass

    # Check Chrome
    chrome_paths = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    for path in chrome_paths:
        if shutil.which(path) or Path(path).exists():
            capabilities["chrome"] = True
            break

    if not capabilities["chrome"]:
        capabilities["chrome"] = shutil.which("google-chrome") is not None or shutil.which("chromium") is not None

    return capabilities


async def capture_with_gowitness(
    urls: list[str],
    output_dir: Path,
    timeout: int = 30,
    threads: int = 4,
) -> dict[str, str]:
    """
    Capture screenshots using gowitness.

    Args:
        urls: List of URLs to screenshot
        output_dir: Directory to save screenshots
        timeout: Timeout per screenshot in seconds
        threads: Number of concurrent captures

    Returns:
        Dictionary mapping URL to screenshot path
    """
    results: dict[str, str] = {}

    if not shutil.which("gowitness"):
        return results

    output_dir.mkdir(parents=True, exist_ok=True)

    # Create URL file
    url_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for url in urls:
        url_file.write(f"{url}\n")
    url_file.close()

    try:
        # Run gowitness
        proc = await asyncio.create_subprocess_exec(
            "gowitness",
            "file",
            "-f", url_file.name,
            "-P", str(output_dir),
            "--timeout", str(timeout),
            "--threads", str(threads),
            "--disable-logging",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.wait_for(proc.wait(), timeout=timeout * len(urls) + 60)

        # Map URLs to screenshot files
        # gowitness saves as screenshot-<hash>.png
        for url in urls:
            # gowitness uses URL hash for filename
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
            possible_files = list(output_dir.glob(f"*{url_hash}*.png"))
            if not possible_files:
                # Try alternative naming
                possible_files = list(output_dir.glob("*.png"))

            for screenshot_file in possible_files:
                # Check if this file corresponds to the URL
                if screenshot_file.exists():
                    results[url] = str(screenshot_file)
                    break

    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    finally:
        Path(url_file.name).unlink(missing_ok=True)

    return results


async def capture_with_playwright(
    url: str,
    output_path: Path,
    timeout: int = 30000,
    viewport_width: int = 1920,
    viewport_height: int = 1080,
) -> bool:
    """
    Capture screenshot using Playwright.

    Args:
        url: URL to screenshot
        output_path: Path to save screenshot
        timeout: Timeout in milliseconds
        viewport_width: Browser viewport width
        viewport_height: Browser viewport height

    Returns:
        True if successful, False otherwise
    """
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": viewport_width, "height": viewport_height},
                ignore_https_errors=True,
            )
            page = await context.new_page()

            try:
                await page.goto(url, timeout=timeout, wait_until="networkidle")
                await page.screenshot(path=str(output_path), full_page=False)
                return True
            except Exception:
                # Try with less strict wait
                try:
                    await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                    await page.screenshot(path=str(output_path), full_page=False)
                    return True
                except Exception:
                    return False
            finally:
                await browser.close()

    except ImportError:
        return False
    except Exception:
        return False


async def capture_with_chrome(
    url: str,
    output_path: Path,
    timeout: int = 30,
) -> bool:
    """
    Capture screenshot using headless Chrome directly.

    Args:
        url: URL to screenshot
        output_path: Path to save screenshot
        timeout: Timeout in seconds

    Returns:
        True if successful, False otherwise
    """
    # Find Chrome executable
    chrome_paths = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ]

    chrome_path = None
    for path in chrome_paths:
        if shutil.which(path) or Path(path).exists():
            chrome_path = path
            break

    if not chrome_path:
        chrome_path = shutil.which("google-chrome") or shutil.which("chromium")

    if not chrome_path:
        return False

    try:
        proc = await asyncio.create_subprocess_exec(
            chrome_path,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--ignore-certificate-errors",
            f"--screenshot={output_path}",
            "--window-size=1920,1080",
            "--hide-scrollbars",
            url,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        await asyncio.wait_for(proc.wait(), timeout=timeout)
        return output_path.exists()

    except asyncio.TimeoutError:
        return False
    except Exception:
        return False


async def capture_with_httpx_html(
    url: str,
    output_path: Path,
    timeout: int = 30,
) -> bool:
    """
    Create a simple HTML preview when browser capture fails.
    This creates a basic HTML file that can be converted to image.

    Returns:
        True if successful, False otherwise
    """
    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            response = await client.get(url)

            # Extract title
            title = "No Title"
            import re
            title_match = re.search(r"<title[^>]*>([^<]+)</title>", response.text, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()[:100]

            # Create a placeholder image with page info
            # This is a basic SVG that will be saved as the screenshot
            status = response.status_code
            svg_content = f'''<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
                <rect width="100%" height="100%" fill="#1a1a2e"/>
                <rect x="20" y="20" width="760" height="60" rx="8" fill="#16213e"/>
                <circle cx="50" cy="50" r="8" fill="#e94560"/>
                <circle cx="75" cy="50" r="8" fill="#ffc107"/>
                <circle cx="100" cy="50" r="8" fill="#4caf50"/>
                <text x="130" y="55" fill="#94a3b8" font-family="Arial" font-size="14">{url[:80]}</text>
                <rect x="20" y="100" width="760" height="480" rx="8" fill="#0f0f23"/>
                <text x="400" y="300" fill="#6366f1" font-family="Arial" font-size="24" text-anchor="middle">{title[:50]}</text>
                <text x="400" y="340" fill="#94a3b8" font-family="Arial" font-size="16" text-anchor="middle">HTTP {status}</text>
                <text x="400" y="380" fill="#64748b" font-family="Arial" font-size="12" text-anchor="middle">Screenshot capture requires Playwright: pip install playwright && playwright install</text>
            </svg>'''

            # Convert SVG to PNG if possible, otherwise save SVG
            png_path = output_path
            try:
                import cairosvg
                cairosvg.svg2png(bytestring=svg_content.encode(), write_to=str(png_path))
                return True
            except ImportError:
                # Save as SVG instead
                svg_path = output_path.with_suffix('.svg')
                with open(svg_path, 'w') as f:
                    f.write(svg_content)
                # Create a symlink or copy as PNG for compatibility
                return False

    except Exception:
        return False


async def capture_screenshot(
    url: str,
    output_dir: Path,
    timeout: int = 30,
) -> Optional[str]:
    """
    Capture a screenshot using the best available method.

    Args:
        url: URL to screenshot
        output_dir: Directory to save screenshot
        timeout: Timeout in seconds

    Returns:
        Path to screenshot or None
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename from URL
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
    safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_").replace("=", "_").replace("&", "_").replace("%", "_").replace("#", "_")[:50]
    filename = f"{safe_name}_{url_hash}.png"
    output_path = output_dir / filename

    # Try methods in order of preference
    # 1. Try Playwright first (most reliable)
    if await capture_with_playwright(url, output_path, timeout * 1000):
        return str(output_path)

    # 2. Try headless Chrome
    if await capture_with_chrome(url, output_path, timeout):
        return str(output_path)

    # 3. Try HTML-based preview (fallback)
    if await capture_with_httpx_html(url, output_path, timeout):
        return str(output_path)

    return None


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Capture screenshots for discovered web applications.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with screenshot paths
    """
    result = ModuleResult(
        module_name="screenshot",
        started_at=datetime.utcnow(),
    )

    if not config.modules.web.screenshot:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Get URLs to screenshot
    urls = [
        webapp.final_url or webapp.url
        for webapp in session.web_applications
        if webapp.is_alive and webapp.status_code in range(200, 400)
    ]

    if not urls:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Set up output directory
    screenshots_dir = config.get_screenshots_dir(session.id)

    # Try batch capture with gowitness first
    if shutil.which("gowitness"):
        screenshot_map = await capture_with_gowitness(
            urls,
            screenshots_dir,
            config.modules.web.screenshot_timeout,
            threads=min(config.scan.threads, 8),
        )

        # Update web applications with screenshot paths
        for webapp in session.web_applications:
            url = webapp.final_url or webapp.url
            if url in screenshot_map:
                webapp.screenshot_path = screenshot_map[url]
                result.web_applications.append(webapp)

        result.items_discovered = len(screenshot_map)

    else:
        # Fall back to individual captures
        semaphore = asyncio.Semaphore(4)  # Limit concurrent browser instances
        captured = 0

        async def capture_with_semaphore(webapp: WebApplication):
            nonlocal captured
            async with semaphore:
                url = webapp.final_url or webapp.url
                screenshot_path = await capture_screenshot(
                    url,
                    screenshots_dir,
                    config.modules.web.screenshot_timeout,
                )
                if screenshot_path:
                    webapp.screenshot_path = screenshot_path
                    captured += 1
                return webapp

        tasks = [
            capture_with_semaphore(webapp)
            for webapp in session.web_applications
            if webapp.is_alive and webapp.status_code in range(200, 400)
        ]

        updated_webapps = await asyncio.gather(*tasks, return_exceptions=True)

        for webapp in updated_webapps:
            if isinstance(webapp, WebApplication) and webapp.screenshot_path:
                result.web_applications.append(webapp)

        result.items_discovered = captured

    result.success = True
    result.completed_at = datetime.utcnow()

    return result
