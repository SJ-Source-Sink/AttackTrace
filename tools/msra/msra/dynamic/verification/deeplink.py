"""Deep link vulnerability verifier."""

import time
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from .base import BaseVerifier, VerificationResult, VerificationStatus

logger = logging.getLogger(__name__)


class DeepLinkVerifier(BaseVerifier):
    """Verify deep link and URL scheme vulnerabilities."""

    CATEGORY = "deeplink"

    # Injection payloads for deep link parameters
    INJECTION_PAYLOADS = [
        # XSS payloads
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",

        # URL redirect payloads
        "http://evil.com",
        "//evil.com",
        "https://evil.com/phishing",

        # Path traversal
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",

        # SQLi
        "' OR '1'='1",

        # Command injection
        "; ls",
        "| id",
    ]

    # Sensitive parameter names
    SENSITIVE_PARAMS = [
        'url', 'redirect', 'next', 'return', 'callback', 'goto',
        'target', 'link', 'path', 'file', 'page', 'action',
        'token', 'auth', 'session', 'password', 'secret',
    ]

    def can_verify(self, finding: Dict[str, Any]) -> bool:
        """Check if this is a deep link-related finding."""
        fid = finding.get('fid', '').lower()
        category = finding.get('category', '').lower()
        title = finding.get('title', '').lower()
        extra = finding.get('extra', {})

        return (
            'deeplink' in fid or
            'deep-link' in fid or
            'url-scheme' in fid or
            'scheme' in fid or
            'deeplink' in category or
            bool(extra.get('deep_links')) or
            bool(extra.get('schemes')) or
            'app link' in title.lower()
        )

    def verify(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify deep link vulnerability."""
        finding_id = self._extract_finding_id(finding)
        start_time = time.time()

        fid = finding.get('fid', '').lower()

        try:
            if 'redirect' in fid or 'hijack' in fid:
                result = self._verify_redirect(finding)
            elif 'injection' in fid or 'xss' in fid:
                result = self._verify_injection(finding)
            elif 'exposed' in fid or 'exported' in fid:
                result = self._verify_exposed_scheme(finding)
            else:
                result = self._verify_generic_deeplink(finding)

            result.duration = time.time() - start_time
            return result

        except Exception as e:
            logger.error(f"Deep link verification failed: {e}")
            return self._create_result(
                finding_id,
                VerificationStatus.ERROR,
                error_message=str(e),
                duration=time.time() - start_time
            )

    def _get_deep_links(self, finding: Dict[str, Any]) -> List[str]:
        """Extract deep links from finding."""
        extra = finding.get('extra', {})

        links = extra.get('deep_links', [])
        if not links:
            schemes = extra.get('schemes', [])
            hosts = extra.get('hosts', [''])
            paths = extra.get('paths', [''])

            for scheme in schemes:
                for host in hosts:
                    for path in paths:
                        if host:
                            links.append(f"{scheme}://{host}{path}")
                        else:
                            links.append(f"{scheme}://{path}")

        return links

    def _verify_redirect(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify deep link redirect/open redirect vulnerability."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        deep_links = self._get_deep_links(finding)

        if not deep_links:
            result.notes = "No deep links found in finding"
            return result

        # Setup Frida monitoring
        if self._frida and self._frida.is_attached():
            self._frida.hook_webview_load()

        redirect_payloads = [
            "http://evil.com",
            "https://attacker.com/phishing",
            "//evil.com",
            "javascript:alert(document.domain)",
        ]

        for deep_link in deep_links[:3]:  # Test first 3
            for payload in redirect_payloads:
                # Try various parameter names
                for param in ['url', 'redirect', 'next', 'callback', 'target']:
                    test_url = f"{deep_link}?{param}={urllib.parse.quote(payload)}"

                    self._device.open_deep_link(test_url)
                    time.sleep(2)

                    # Check what happened
                    current_pkg, current_act = self._device.get_current_activity()

                    # If we left the app, that's suspicious
                    if current_pkg != package and current_pkg != "com.android.chrome":
                        result.status = VerificationStatus.VERIFIED
                        result.confidence = 0.9
                        result.payload_used = test_url
                        result.add_evidence(
                            "behavior",
                            f"Deep link caused redirect to: {current_pkg}",
                            severity="high"
                        )
                        screenshot = self.take_screenshot("deeplink_redirect")
                        if screenshot:
                            result.add_evidence("screenshot", "Redirect screenshot", screenshot)
                        return result

                    # Check Frida hooks for WebView loading external URL
                    if self._frida:
                        hooks = self._frida.get_hook_results("webview_hooks")
                        external_loads = [h for h in hooks
                                         if 'loadUrl' in h.method_name
                                         and ('evil.com' in str(h.arguments) or
                                              'attacker.com' in str(h.arguments))]
                        if external_loads:
                            result.status = VerificationStatus.VERIFIED
                            result.confidence = 0.85
                            result.payload_used = test_url
                            result.hook_results = external_loads
                            result.add_evidence(
                                "hook",
                                "WebView loaded attacker-controlled URL",
                                severity="high"
                            )
                            return result

                    # Go back to app
                    self._device.press_back()

        return result

    def _verify_injection(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify deep link parameter injection vulnerability."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        deep_links = self._get_deep_links(finding)

        if not deep_links:
            result.notes = "No deep links found in finding"
            return result

        # Setup Frida monitoring for injection detection
        if self._frida and self._frida.is_attached():
            self._frida.hook_webview_load()

            # Also monitor SQL
            sql_monitor = """
            Java.perform(function() {
                var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
                SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, args) {
                    send({
                        class: "SQLiteDatabase",
                        method: "rawQuery",
                        args: [sql],
                        extra: {type: "sql_from_deeplink"}
                    });
                    return this.rawQuery(sql, args);
                };
            });
            """
            try:
                self._frida.load_script("deeplink_sql_monitor", sql_monitor)
            except Exception:
                pass

        for deep_link in deep_links[:3]:
            for payload in self.INJECTION_PAYLOADS[:5]:
                for param in self.SENSITIVE_PARAMS[:5]:
                    test_url = f"{deep_link}?{param}={urllib.parse.quote(payload)}"

                    self._device.open_deep_link(test_url)
                    time.sleep(1.5)

                    # Check for injection indicators
                    if self._frida:
                        hooks = self._frida.get_hook_results()

                        # Check for XSS
                        xss_hooks = [h for h in hooks
                                    if 'evaluateJavascript' in h.method_name or
                                    ('loadUrl' in h.method_name and 'javascript:' in str(h.arguments))]
                        if xss_hooks:
                            result.status = VerificationStatus.VERIFIED
                            result.confidence = 0.9
                            result.payload_used = test_url
                            result.hook_results = xss_hooks
                            result.add_evidence(
                                "hook",
                                f"XSS triggered via deep link parameter: {param}",
                                severity="critical"
                            )
                            return result

                        # Check for SQLi
                        sql_hooks = [h for h in hooks
                                    if 'rawQuery' in h.method_name and "'" in str(h.arguments)]
                        if sql_hooks:
                            result.status = VerificationStatus.LIKELY
                            result.confidence = 0.7
                            result.payload_used = test_url
                            result.hook_results = sql_hooks
                            result.add_evidence(
                                "hook",
                                f"SQL query with injected content from: {param}",
                                severity="high"
                            )

                    # Check for crash
                    if self.check_crash(package):
                        result.status = VerificationStatus.LIKELY
                        result.confidence = 0.6
                        result.payload_used = test_url
                        result.add_evidence(
                            "crash",
                            f"App crashed with payload in {param}",
                            severity="medium"
                        )

                    self._device.press_back()

        return result

    def _verify_exposed_scheme(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify exposed URL scheme can be accessed."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        deep_links = self._get_deep_links(finding)

        if not deep_links:
            result.notes = "No deep links found in finding"
            return result

        for deep_link in deep_links:
            # Test if deep link opens the app
            self._device.open_deep_link(deep_link)
            time.sleep(1.5)

            current_pkg, current_act = self._device.get_current_activity()

            if current_pkg == package:
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.8
                result.add_evidence(
                    "behavior",
                    f"Deep link accessible: {deep_link}",
                    severity="medium"
                )

                # Check what screen was opened
                state = self._device.get_screen_state()

                # Look for sensitive content
                sensitive_found = False
                for elem in state.elements:
                    if elem.text:
                        text_lower = elem.text.lower()
                        if any(s in text_lower for s in ['password', 'token', 'admin', 'settings', 'debug', 'secret']):
                            sensitive_found = True
                            result.confidence = 0.95
                            result.add_evidence(
                                "data",
                                f"Sensitive content visible: {elem.text[:50]}",
                                severity="high"
                            )
                            break

                screenshot = self.take_screenshot("deeplink_exposed")
                if screenshot:
                    result.add_evidence("screenshot", "Deep link target screen", screenshot)

                if sensitive_found:
                    return result

            self._device.press_back()

        return result

    def _verify_generic_deeplink(self, finding: Dict[str, Any]) -> VerificationResult:
        """Generic deep link verification."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        deep_links = self._get_deep_links(finding)

        # Try exposed scheme verification first
        if deep_links:
            exposed_result = self._verify_exposed_scheme(finding)
            if exposed_result.status != VerificationStatus.NOT_VULNERABLE:
                return exposed_result

        # Try injection verification
        injection_result = self._verify_injection(finding)
        if injection_result.status != VerificationStatus.NOT_VULNERABLE:
            return injection_result

        # Try redirect verification
        redirect_result = self._verify_redirect(finding)
        if redirect_result.status != VerificationStatus.NOT_VULNERABLE:
            return redirect_result

        # Execute any ADB commands from the finding
        adb_commands = finding.get('adb_commands', [])
        for cmd in adb_commands:
            success, output = self.execute_adb_command(cmd)
            if success:
                result.status = VerificationStatus.POSSIBLE
                result.confidence = 0.4
                result.add_evidence(
                    "command",
                    f"Deep link command executed",
                    data=output[:300],
                    severity="low"
                )

        return result

    def fuzz_deep_link(self, deep_link: str, iterations: int = 20) -> List[VerificationResult]:
        """Fuzz a deep link with various payloads.

        Returns list of all interesting results.
        """
        results = []
        package = None  # Will be detected

        for i, payload in enumerate(self.INJECTION_PAYLOADS):
            if i >= iterations:
                break

            for param in self.SENSITIVE_PARAMS[:3]:
                test_url = f"{deep_link}?{param}={urllib.parse.quote(payload)}"

                self._device.open_deep_link(test_url)
                time.sleep(1)

                current_pkg, _ = self._device.get_current_activity()
                if package is None:
                    package = current_pkg

                # Check for crash
                if not self._device.is_app_running(package):
                    result = VerificationResult(
                        finding_id=f"fuzz_{i}",
                        status=VerificationStatus.LIKELY,
                        confidence=0.6,
                        payload_used=test_url,
                    )
                    result.add_evidence(
                        "crash",
                        f"Crash with payload: {payload[:30]}",
                        severity="medium"
                    )
                    results.append(result)

                    # Restart app
                    self._device.launch_app(package)
                    time.sleep(1)

                self._device.press_back()

        return results
