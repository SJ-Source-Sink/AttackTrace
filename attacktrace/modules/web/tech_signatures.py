"""
Extended technology detection signatures.

Comprehensive technology fingerprinting patterns for:
- Web servers
- Frameworks
- CMS platforms
- JavaScript libraries/frameworks
- E-commerce platforms
- Analytics tools
- Security tools
- Cloud services
- Databases
- Caching systems
"""

from dataclasses import dataclass
from typing import Optional
import re


@dataclass
class TechSignature:
    """Technology signature definition."""
    name: str
    category: str
    # Header patterns: {header_name: regex_pattern}
    headers: dict[str, str] | None = None
    # Cookie patterns: {cookie_name: regex_pattern}
    cookies: dict[str, str] | None = None
    # HTML body patterns
    body_patterns: list[str] | None = None
    # Meta tag patterns: {name: content_pattern}
    meta_patterns: dict[str, str] | None = None
    # Script src patterns
    script_patterns: list[str] | None = None
    # URL path patterns
    url_patterns: list[str] | None = None
    # Version extraction regex (applied to matched content)
    version_pattern: str | None = None
    # Confidence if matched (0-100)
    confidence: int = 80
    # Website for reference
    website: str = ""


# Comprehensive technology signatures database
TECH_SIGNATURES: list[TechSignature] = [
    # ==================== Web Servers ====================
    TechSignature(
        name="nginx",
        category="web-server",
        headers={"server": r"nginx/?(\d+\.[\d.]+)?"},
        version_pattern=r"nginx/?([\d.]+)",
        confidence=95,
    ),
    TechSignature(
        name="Apache",
        category="web-server",
        headers={"server": r"Apache/?(\d+\.[\d.]+)?"},
        version_pattern=r"Apache/?([\d.]+)",
        confidence=95,
    ),
    TechSignature(
        name="Microsoft-IIS",
        category="web-server",
        headers={"server": r"Microsoft-IIS/?(\d+\.[\d.]+)?"},
        version_pattern=r"IIS/?([\d.]+)",
        confidence=95,
    ),
    TechSignature(
        name="LiteSpeed",
        category="web-server",
        headers={"server": r"LiteSpeed"},
        confidence=90,
    ),
    TechSignature(
        name="Caddy",
        category="web-server",
        headers={"server": r"Caddy"},
        confidence=90,
    ),
    TechSignature(
        name="Kestrel",
        category="web-server",
        headers={"server": r"Kestrel"},
        confidence=90,
    ),
    TechSignature(
        name="Gunicorn",
        category="web-server",
        headers={"server": r"gunicorn"},
        confidence=90,
    ),
    TechSignature(
        name="Uvicorn",
        category="web-server",
        headers={"server": r"uvicorn"},
        confidence=90,
    ),

    # ==================== CDN/Proxy ====================
    TechSignature(
        name="Cloudflare",
        category="cdn",
        headers={"server": r"cloudflare", "cf-ray": r".+", "cf-cache-status": r".+"},
        confidence=95,
    ),
    TechSignature(
        name="AWS CloudFront",
        category="cdn",
        headers={"x-amz-cf-id": r".+", "x-amz-cf-pop": r".+"},
        confidence=95,
    ),
    TechSignature(
        name="Akamai",
        category="cdn",
        headers={"x-akamai-transformed": r".+"},
        confidence=90,
    ),
    TechSignature(
        name="Fastly",
        category="cdn",
        headers={"x-served-by": r"cache-", "x-fastly-request-id": r".+"},
        confidence=90,
    ),
    TechSignature(
        name="Varnish",
        category="caching",
        headers={"x-varnish": r"\d+", "via": r"varnish"},
        confidence=90,
    ),
    TechSignature(
        name="Vercel",
        category="cdn",
        headers={"x-vercel-id": r".+", "server": r"Vercel"},
        confidence=95,
    ),
    TechSignature(
        name="Netlify",
        category="cdn",
        headers={"x-nf-request-id": r".+", "server": r"Netlify"},
        confidence=95,
    ),

    # ==================== CMS ====================
    TechSignature(
        name="WordPress",
        category="cms",
        body_patterns=[r"/wp-content/", r"/wp-includes/", r"/wp-json/", r"wp-emoji"],
        meta_patterns={"generator": r"WordPress"},
        url_patterns=[r"/wp-admin", r"/wp-login\.php"],
        version_pattern=r"WordPress\s*([\d.]+)",
        confidence=95,
    ),
    TechSignature(
        name="Drupal",
        category="cms",
        headers={"x-drupal-cache": r".+", "x-generator": r"Drupal"},
        body_patterns=[r"Drupal\.settings", r"/sites/default/files", r"/sites/all/"],
        meta_patterns={"generator": r"Drupal"},
        confidence=90,
    ),
    TechSignature(
        name="Joomla",
        category="cms",
        body_patterns=[r"/media/jui/", r"Joomla!", r"/components/com_"],
        meta_patterns={"generator": r"Joomla"},
        confidence=90,
    ),
    TechSignature(
        name="Magento",
        category="cms",
        body_patterns=[r"/skin/frontend/", r"Mage\.Cookies", r"/js/mage/"],
        cookies={"frontend": r".+", "mage-cache-storage": r".+"},
        confidence=85,
    ),
    TechSignature(
        name="Shopify",
        category="ecommerce",
        body_patterns=[r"cdn\.shopify\.com", r"Shopify\.theme"],
        headers={"x-shopid": r"\d+", "x-shardid": r"\d+"},
        confidence=95,
    ),
    TechSignature(
        name="Wix",
        category="cms",
        body_patterns=[r"wix\.com", r"wixstatic\.com", r"X-Wix-"],
        confidence=90,
    ),
    TechSignature(
        name="Squarespace",
        category="cms",
        body_patterns=[r"squarespace\.com", r"static\.squarespace"],
        confidence=90,
    ),
    TechSignature(
        name="Ghost",
        category="cms",
        meta_patterns={"generator": r"Ghost"},
        body_patterns=[r"ghost\.io", r"/ghost/"],
        confidence=85,
    ),
    TechSignature(
        name="Hugo",
        category="static-site-generator",
        meta_patterns={"generator": r"Hugo"},
        confidence=85,
    ),
    TechSignature(
        name="Jekyll",
        category="static-site-generator",
        meta_patterns={"generator": r"Jekyll"},
        confidence=85,
    ),

    # ==================== Frameworks ====================
    TechSignature(
        name="Laravel",
        category="framework",
        cookies={"laravel_session": r".+", "XSRF-TOKEN": r".+"},
        body_patterns=[r"laravel", r"/vendor/laravel"],
        confidence=90,
    ),
    TechSignature(
        name="Django",
        category="framework",
        cookies={"csrftoken": r".+", "sessionid": r".+"},
        body_patterns=[r"__admin_media_prefix__", r"csrfmiddlewaretoken"],
        confidence=85,
    ),
    TechSignature(
        name="Ruby on Rails",
        category="framework",
        headers={"x-runtime": r"[\d.]+", "x-request-id": r"[a-f0-9-]+"},
        cookies={"_session_id": r".+"},
        meta_patterns={"csrf-token": r".+"},
        confidence=80,
    ),
    TechSignature(
        name="ASP.NET",
        category="framework",
        headers={"x-aspnet-version": r".+", "x-powered-by": r"ASP\.NET"},
        cookies={"ASP.NET_SessionId": r".+", "__RequestVerificationToken": r".+"},
        body_patterns=[r"__VIEWSTATE", r"__EVENTVALIDATION"],
        confidence=90,
    ),
    TechSignature(
        name="ASP.NET Core",
        category="framework",
        headers={"x-powered-by": r"ASP\.NET"},
        cookies={".AspNetCore.Session": r".+"},
        confidence=85,
    ),
    TechSignature(
        name="Express",
        category="framework",
        headers={"x-powered-by": r"Express"},
        confidence=90,
    ),
    TechSignature(
        name="Flask",
        category="framework",
        cookies={"session": r"eyJ"},  # Flask's signed session cookies start with eyJ
        confidence=70,
    ),
    TechSignature(
        name="FastAPI",
        category="framework",
        body_patterns=[r"/docs", r"/redoc", r"FastAPI"],
        confidence=75,
    ),
    TechSignature(
        name="Spring",
        category="framework",
        headers={"x-application-context": r".+"},
        cookies={"JSESSIONID": r".+"},
        confidence=80,
    ),
    TechSignature(
        name="Next.js",
        category="framework",
        headers={"x-nextjs-cache": r".+", "x-nextjs-matched-path": r".+"},
        body_patterns=[r"/_next/", r"__NEXT_DATA__"],
        confidence=95,
    ),
    TechSignature(
        name="Nuxt.js",
        category="framework",
        body_patterns=[r"/_nuxt/", r"__NUXT__"],
        confidence=95,
    ),
    TechSignature(
        name="Gatsby",
        category="framework",
        body_patterns=[r"/static/", r"gatsby"],
        meta_patterns={"generator": r"Gatsby"},
        confidence=85,
    ),

    # ==================== JavaScript Frameworks ====================
    TechSignature(
        name="React",
        category="javascript-framework",
        body_patterns=[r"react", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"_reactRootContainer", r"data-reactroot"],
        script_patterns=[r"react(?:\.min)?\.js", r"react-dom"],
        confidence=85,
    ),
    TechSignature(
        name="Vue.js",
        category="javascript-framework",
        body_patterns=[r"__VUE__", r"v-cloak", r"data-v-[a-f0-9]+"],
        script_patterns=[r"vue(?:\.min)?\.js"],
        confidence=85,
    ),
    TechSignature(
        name="Angular",
        category="javascript-framework",
        body_patterns=[r"ng-version", r"ng-app", r"ng-controller", r"\[ngClass\]"],
        script_patterns=[r"angular(?:\.min)?\.js", r"@angular"],
        confidence=85,
    ),
    TechSignature(
        name="Svelte",
        category="javascript-framework",
        body_patterns=[r"svelte", r"__svelte"],
        confidence=80,
    ),
    TechSignature(
        name="jQuery",
        category="javascript-library",
        body_patterns=[r"jquery", r"\$\(document\)\.ready", r"\$\(function"],
        script_patterns=[r"jquery(?:\.min)?\.js", r"jquery-[\d.]+"],
        version_pattern=r"jquery[/-]?([\d.]+)",
        confidence=90,
    ),
    TechSignature(
        name="Bootstrap",
        category="css-framework",
        body_patterns=[r"bootstrap", r"class=\"[^\"]*btn btn-", r"class=\"[^\"]*container-fluid"],
        script_patterns=[r"bootstrap(?:\.min)?\.js"],
        confidence=85,
    ),
    TechSignature(
        name="Tailwind CSS",
        category="css-framework",
        body_patterns=[r"class=\"[^\"]*(?:flex|grid|px-|py-|mt-|mb-|text-)[^\"]*\""],
        confidence=70,
    ),
    TechSignature(
        name="Material UI",
        category="css-framework",
        body_patterns=[r"MuiButton", r"makeStyles", r"@material-ui"],
        confidence=80,
    ),

    # ==================== Analytics ====================
    TechSignature(
        name="Google Analytics",
        category="analytics",
        body_patterns=[r"google-analytics\.com/analytics\.js", r"googletagmanager\.com", r"gtag\(", r"UA-\d+-\d+"],
        script_patterns=[r"analytics\.js", r"gtm\.js"],
        confidence=95,
    ),
    TechSignature(
        name="Google Tag Manager",
        category="tag-manager",
        body_patterns=[r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
        confidence=95,
    ),
    TechSignature(
        name="Facebook Pixel",
        category="analytics",
        body_patterns=[r"connect\.facebook\.net", r"fbevents\.js", r"fbq\("],
        confidence=90,
    ),
    TechSignature(
        name="Hotjar",
        category="analytics",
        body_patterns=[r"hotjar\.com", r"_hjSettings"],
        script_patterns=[r"hotjar\.com"],
        confidence=90,
    ),
    TechSignature(
        name="Mixpanel",
        category="analytics",
        body_patterns=[r"mixpanel\.com", r"mixpanel\.init"],
        confidence=85,
    ),
    TechSignature(
        name="Segment",
        category="analytics",
        body_patterns=[r"segment\.com/analytics\.js", r"analytics\.track"],
        confidence=85,
    ),
    TechSignature(
        name="Heap",
        category="analytics",
        body_patterns=[r"heap\.io", r"heap\.load"],
        confidence=85,
    ),

    # ==================== Security ====================
    TechSignature(
        name="reCAPTCHA",
        category="security",
        body_patterns=[r"google\.com/recaptcha", r"g-recaptcha", r"grecaptcha"],
        script_patterns=[r"recaptcha"],
        confidence=95,
    ),
    TechSignature(
        name="hCaptcha",
        category="security",
        body_patterns=[r"hcaptcha\.com", r"h-captcha"],
        confidence=90,
    ),
    TechSignature(
        name="Imperva Incapsula",
        category="security",
        headers={"x-iinfo": r".+"},
        cookies={"incap_ses": r".+", "visid_incap": r".+"},
        confidence=95,
    ),
    TechSignature(
        name="Sucuri",
        category="security",
        headers={"x-sucuri-id": r".+", "server": r"Sucuri"},
        confidence=90,
    ),
    TechSignature(
        name="ModSecurity",
        category="security",
        headers={"server": r"mod_security"},
        confidence=85,
    ),
    TechSignature(
        name="AWS WAF",
        category="security",
        headers={"x-amzn-waf": r".+"},
        confidence=90,
    ),

    # ==================== E-commerce ====================
    TechSignature(
        name="WooCommerce",
        category="ecommerce",
        body_patterns=[r"woocommerce", r"/wp-content/plugins/woocommerce"],
        confidence=90,
    ),
    TechSignature(
        name="PrestaShop",
        category="ecommerce",
        body_patterns=[r"prestashop", r"/themes/default/"],
        cookies={"PrestaShop-": r".+"},
        confidence=85,
    ),
    TechSignature(
        name="OpenCart",
        category="ecommerce",
        body_patterns=[r"catalog/view/theme", r"getURLVar"],
        confidence=80,
    ),
    TechSignature(
        name="BigCommerce",
        category="ecommerce",
        body_patterns=[r"bigcommerce\.com", r"stencil"],
        confidence=85,
    ),

    # ==================== Hosting/PaaS ====================
    TechSignature(
        name="Heroku",
        category="paas",
        headers={"via": r".*vegur.*"},
        confidence=85,
    ),
    TechSignature(
        name="AWS Elastic Beanstalk",
        category="paas",
        headers={"server": r"awselb"},
        confidence=85,
    ),
    TechSignature(
        name="Google App Engine",
        category="paas",
        headers={"server": r"Google Frontend", "x-cloud-trace-context": r".+"},
        confidence=90,
    ),
    TechSignature(
        name="Firebase",
        category="paas",
        body_patterns=[r"firebaseapp\.com", r"firebase\.google\.com", r"firebaseio\.com"],
        confidence=90,
    ),

    # ==================== Programming Languages ====================
    TechSignature(
        name="PHP",
        category="programming-language",
        headers={"x-powered-by": r"PHP/?[\d.]*"},
        version_pattern=r"PHP/?([\d.]+)",
        confidence=95,
    ),
    TechSignature(
        name="Java",
        category="programming-language",
        cookies={"JSESSIONID": r".+"},
        headers={"x-powered-by": r"Servlet|JSP"},
        confidence=80,
    ),
    TechSignature(
        name="Node.js",
        category="programming-language",
        headers={"x-powered-by": r"Express"},
        confidence=75,
    ),
    TechSignature(
        name="Python",
        category="programming-language",
        headers={"server": r"Python|gunicorn|uvicorn|Werkzeug"},
        confidence=75,
    ),
]


def detect_technologies(
    headers: dict[str, str],
    body: str,
    cookies: dict[str, str] | None = None,
    url: str = "",
) -> list[dict]:
    """
    Detect technologies from HTTP response data.

    Args:
        headers: Response headers (lowercase keys)
        body: Response body HTML
        cookies: Response cookies
        url: Request URL

    Returns:
        List of detected technologies with confidence scores
    """
    detected = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    body_lower = body.lower() if body else ""
    cookies = cookies or {}

    for sig in TECH_SIGNATURES:
        confidence = 0
        version = ""
        matches = []

        # Check headers
        if sig.headers:
            for header, pattern in sig.headers.items():
                if header in headers_lower:
                    match = re.search(pattern, headers_lower[header], re.IGNORECASE)
                    if match:
                        confidence = max(confidence, sig.confidence)
                        matches.append(f"header:{header}")
                        if sig.version_pattern:
                            ver_match = re.search(sig.version_pattern, headers_lower[header], re.IGNORECASE)
                            if ver_match:
                                version = ver_match.group(1)

        # Check cookies
        if sig.cookies:
            for cookie_name, pattern in sig.cookies.items():
                for actual_cookie in cookies:
                    if cookie_name.lower() in actual_cookie.lower():
                        if re.search(pattern, cookies.get(actual_cookie, ""), re.IGNORECASE):
                            confidence = max(confidence, sig.confidence - 10)
                            matches.append(f"cookie:{cookie_name}")

        # Check body patterns
        if sig.body_patterns:
            for pattern in sig.body_patterns:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    confidence = max(confidence, sig.confidence - 5)
                    matches.append(f"body:{pattern[:30]}")
                    if sig.version_pattern and not version:
                        ver_match = re.search(sig.version_pattern, body, re.IGNORECASE)
                        if ver_match:
                            version = ver_match.group(1)

        # Check meta patterns
        if sig.meta_patterns:
            for meta_name, pattern in sig.meta_patterns.items():
                meta_pattern = rf'<meta[^>]+name=["\']?{meta_name}["\']?[^>]+content=["\']?([^"\']+)'
                match = re.search(meta_pattern, body, re.IGNORECASE)
                if match and re.search(pattern, match.group(1), re.IGNORECASE):
                    confidence = max(confidence, sig.confidence)
                    matches.append(f"meta:{meta_name}")
                    if sig.version_pattern and not version:
                        ver_match = re.search(sig.version_pattern, match.group(1), re.IGNORECASE)
                        if ver_match:
                            version = ver_match.group(1)

        # Check script patterns
        if sig.script_patterns:
            for pattern in sig.script_patterns:
                script_pattern = rf'<script[^>]+src=["\'][^"\']*{pattern}[^"\']*["\']'
                if re.search(script_pattern, body, re.IGNORECASE):
                    confidence = max(confidence, sig.confidence - 10)
                    matches.append(f"script:{pattern[:30]}")

        # Check URL patterns
        if sig.url_patterns and url:
            for pattern in sig.url_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    confidence = max(confidence, sig.confidence - 15)
                    matches.append(f"url:{pattern}")

        if confidence > 0:
            detected.append({
                "name": sig.name,
                "category": sig.category,
                "version": version,
                "confidence": min(100, confidence),
                "matches": matches,
                "website": sig.website,
            })

    # Sort by confidence
    detected.sort(key=lambda x: x["confidence"], reverse=True)

    return detected


def get_technology_by_category(
    detected: list[dict],
    category: str,
) -> list[dict]:
    """Filter detected technologies by category."""
    return [t for t in detected if t["category"] == category]


def get_high_confidence_technologies(
    detected: list[dict],
    min_confidence: int = 80,
) -> list[dict]:
    """Get technologies with confidence above threshold."""
    return [t for t in detected if t["confidence"] >= min_confidence]
