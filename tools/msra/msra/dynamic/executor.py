"""
Dynamic Test Executor

Executes vulnerability PoCs against a running application and
validates if vulnerabilities are actually exploitable.

Supports multiple modes:
- Legacy mode: Uses GenymotionController directly (backwards compatible)
- Enhanced mode: Uses DeviceInterface + Frida + mitmproxy for full verification
"""

import os
import re
import time
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union, TYPE_CHECKING
from datetime import datetime
from pathlib import Path

from .genymotion import GenymotionController
from .monitor import AppMonitor
from .config import DynamicConfig, AnalysisMode
from .exceptions import DynamicAnalysisError, VerificationError

# Import device abstraction
from .device import DeviceInterface, create_device, ADBDevice

# Import verification framework
from .verification import (
    BaseVerifier,
    VerificationResult,
    VerificationStatus,
    WebViewVerifier,
    ProviderVerifier,
    IntentVerifier,
    DeepLinkVerifier,
    get_verifier_for_finding,
)

# Optional imports
try:
    from .instrumentation import FridaManager, is_frida_available
except ImportError:
    FridaManager = None
    def is_frida_available():
        return False

try:
    from .traffic import ProxyManager, TrafficAnalyzer, is_mitmproxy_available
except ImportError:
    ProxyManager = None
    TrafficAnalyzer = None
    def is_mitmproxy_available():
        return False

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a dynamic vulnerability test."""
    finding_id: str
    finding_title: str
    severity: str
    test_status: str  # 'confirmed', 'likely_vulnerable', 'not_vulnerable', 'inconclusive', 'error'
    confidence: float  # 0.0 - 1.0
    evidence: Dict = field(default_factory=dict)
    screenshot_path: Optional[str] = None
    logcat_excerpt: Optional[str] = None
    notes: str = ""
    execution_time: float = 0.0


@dataclass
class DynamicReport:
    """Report from dynamic analysis session."""
    package_name: str
    device_info: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_tests: int = 0
    confirmed_vulns: int = 0
    not_vulnerable: int = 0
    inconclusive: int = 0
    errors: int = 0
    results: List[TestResult] = field(default_factory=list)
    crashes_detected: int = 0
    sensitive_data_leaks: int = 0


class FindingWrapper:
    """Wrapper to access finding data whether it's a dict or object."""
    def __init__(self, finding):
        self._data = finding

    def _get(self, key, default=None):
        if isinstance(self._data, dict):
            return self._data.get(key, default)
        return getattr(self._data, key, default)

    @property
    def fid(self):
        return self._get('fid') or self._get('id', '')

    @property
    def title(self):
        return self._get('title', '')

    @property
    def severity(self):
        return self._get('severity', 'medium')

    @property
    def category(self):
        return self._get('category', '')

    @property
    def adb_commands(self):
        return self._get('adb_commands') or self._get('poc', [])

    @property
    def extra(self):
        return self._get('extra', {})

    @property
    def evidence(self):
        return self._get('evidence')


class DynamicTestExecutor:
    """
    Executes dynamic tests for vulnerabilities found during static analysis.
    """

    def __init__(
        self,
        controller: GenymotionController,
        output_dir: str,
        package_name: Optional[str] = None,
        apk_path: Optional[str] = None,
        findings: Optional[List] = None
    ):
        self.controller = controller
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.monitor: Optional[AppMonitor] = None
        self.package_name: Optional[str] = package_name
        self.apk_path: Optional[str] = apk_path
        self.findings: List = findings or []
        self.report: Optional[DynamicReport] = None

        # Test configurations
        self.test_timeout = 10  # seconds per test
        self.screenshot_on_test = True
        self.capture_logcat = True

    def setup(self, package_name: Optional[str] = None, apk_path: Optional[str] = None) -> bool:
        """Setup for testing - install app and prepare monitoring."""
        # Use provided or instance values
        if package_name:
            self.package_name = package_name
        if apk_path:
            self.apk_path = apk_path

        if not self.package_name:
            print("[!] Package name is required")
            return False

        # Connect to device if not already connected
        if not self.controller.current_device:
            if not self.controller.connect():
                print("[!] Failed to connect to device")
                return False

        # Install APK if provided
        if self.apk_path:
            print(f"[+] Installing APK on device...")
            if not self.controller.install_apk(self.apk_path):
                print("[!] Failed to install APK")
                return False
            print(f"[+] APK installed successfully")

        # Setup monitoring
        self.monitor = AppMonitor(self.controller, self.package_name)

        # Initialize report
        self.report = DynamicReport(
            package_name=self.package_name,
            device_info=f"{self.controller.current_device.model} ({self.controller.current_device.serial})",
            start_time=datetime.now(),
        )

        print(f"[+] Setup complete for {self.package_name}")
        return True

    def discover_attack_surface(self) -> List[Dict]:
        """Discover testable components from an installed app (no static analysis needed)."""
        findings = []
        seen_components = set()  # Track unique components

        print("[*] Discovering attack surface from installed app...")

        # Get exported components directly using dumpsys
        success, output = self.controller.execute_command(
            f"dumpsys package {self.package_name}"
        )

        if not success:
            print("[!] Failed to get package info")
            return findings

        # Parse the package dump for exported components
        lines = output.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for activity declarations
            if f'{self.package_name}/' in line:
                match = re.search(rf'({self.package_name}/([\w.$]+))', line)
                if match:
                    full_component = match.group(1)
                    component_class = match.group(2)

                    # Skip if already seen
                    if full_component in seen_components:
                        i += 1
                        continue
                    seen_components.add(full_component)

                    # Determine component type from context
                    comp_type = 'activity'  # default
                    context_start = max(0, i - 10)
                    context = '\n'.join(lines[context_start:i])
                    if 'Service Resolver' in context or 'service' in line.lower():
                        comp_type = 'service'
                    elif 'Receiver Resolver' in context or 'receiver' in line.lower():
                        comp_type = 'receiver'
                    elif 'Provider' in context or 'provider' in line.lower() or 'ContentProvider' in context:
                        # Skip providers here - we'll discover them via authority parsing
                        i += 1
                        continue

                    # Skip library components
                    if component_class.startswith('androidx.') or component_class.startswith('android.'):
                        i += 1
                        continue

                    # Create ADB command based on type
                    if comp_type == 'activity':
                        adb_cmd = f'adb shell am start -n {full_component}'
                    elif comp_type == 'service':
                        adb_cmd = f'adb shell am startservice -n {full_component}'
                    elif comp_type == 'receiver':
                        adb_cmd = f'adb shell am broadcast -n {full_component}'
                    else:
                        i += 1
                        continue  # Skip unknown types

                    findings.append({
                        'fid': f'dynamic-{comp_type}-{len(findings)}',
                        'title': f'Exported {comp_type.title()}: {component_class}',
                        'severity': 'medium' if comp_type == 'activity' else 'high',
                        'category': comp_type,
                        'extra': {
                            'component': full_component,
                            'component_class': component_class,
                            'entry_points': [component_class],
                            'component_type': comp_type,
                        },
                        'adb_commands': [adb_cmd]
                    })
            i += 1

        # Get content provider authorities - parse the full dumpsys output we already have
        success, full_output = self.controller.execute_command(
            f"dumpsys package {self.package_name}"
        )
        if success and full_output:
            seen_authorities = set()
            # Look for ContentProvider Authorities section and parse it
            in_authorities_section = False
            for line in full_output.split('\n'):
                if 'ContentProvider Authorities:' in line:
                    in_authorities_section = True
                    continue
                elif in_authorities_section:
                    # End of section
                    if line.strip() and not line.startswith(' ') and ':' in line and '[' not in line:
                        break
                    # Look for authority in brackets like [com.insecureshop.provider]:
                    match = re.search(r'\[([a-zA-Z0-9._]+)\]:', line)
                    if match:
                        authority = match.group(1)
                        # Skip FileProvider as it's usually protected
                        if 'file_provider' in authority.lower() or 'fileprovider' in authority.lower():
                            continue
                        # Only include app-specific providers
                        if authority and authority not in seen_authorities and self.package_name in authority:
                            seen_authorities.add(authority)
                        findings.append({
                            'fid': f'dynamic-provider-auth-{len(findings)}',
                            'title': f'Content Provider: {authority}',
                            'severity': 'high',
                            'category': 'provider',
                            'extra': {'authority': authority},
                            'adb_commands': [
                                f'adb shell content query --uri content://{authority}/',
                            ]
                        })

        print(f"[+] Discovered {len(findings)} testable components")
        return findings

    def run_tests(self, findings: Optional[List] = None, timeout: int = 300) -> List[TestResult]:
        """Run dynamic tests for all findings."""
        if not self.report or not self.package_name:
            raise RuntimeError("Call setup() first")

        # Use provided or instance findings
        if findings is None:
            findings = self.findings

        self.test_timeout = timeout // max(len(findings), 1)  # Distribute timeout across tests

        print(f"\n[*] Starting dynamic analysis of {len(findings)} findings...")

        # Start the app
        self.controller.launch_app(self.package_name)
        time.sleep(2)  # Wait for app to start

        # Start logcat capture
        logcat_path = self.output_dir / "logcat.txt"
        if self.capture_logcat:
            self.controller.start_logcat(str(logcat_path), self.package_name)

        for i, finding in enumerate(findings):
            f = FindingWrapper(finding)
            print(f"\n[{i+1}/{len(findings)}] Testing: {f.title}")

            result = self._test_finding(finding, i)
            self.report.results.append(result)

            # Update counters
            self.report.total_tests += 1
            if result.test_status == 'confirmed':
                self.report.confirmed_vulns += 1
                print(f"  [✓] CONFIRMED - {result.notes}")
            elif result.test_status == 'not_vulnerable':
                self.report.not_vulnerable += 1
                print(f"  [✗] Not exploitable - {result.notes}")
            elif result.test_status == 'inconclusive':
                self.report.inconclusive += 1
                print(f"  [?] Inconclusive - {result.notes}")
            else:
                self.report.errors += 1
                print(f"  [!] Error - {result.notes}")

            # Brief pause between tests
            time.sleep(1)

        # Stop logcat
        if self.capture_logcat:
            self.controller.stop_logcat()

        self.report.end_time = datetime.now()

        # Check monitor for crashes and leaks
        if self.monitor:
            summary = self.monitor.get_summary()
            self.report.crashes_detected = summary.get('crashes', 0)
            self.report.sensitive_data_leaks = summary.get('sensitive_leaks', 0)

        # Generate summary
        self._print_summary()

        return self.report.results

    def _test_finding(self, finding, index: int) -> TestResult:
        """Test a single finding."""
        start_time = time.time()

        # Wrap finding for uniform access
        f = FindingWrapper(finding)

        result = TestResult(
            finding_id=f.fid,
            finding_title=f.title,
            severity=f.severity,
            test_status='inconclusive',
            confidence=0.0,
        )

        try:
            # Determine test type based on finding
            title_lower = f.title.lower()
            fid_lower = f.fid.lower()

            if 'webview' in title_lower or 'webview' in fid_lower:
                result = self._test_webview_vuln(f, result, index)
            elif 'intent' in title_lower and 'redirect' in title_lower:
                result = self._test_intent_redirect(f, result, index)
            elif 'provider' in title_lower or 'sql' in title_lower:
                result = self._test_provider_vuln(f, result, index)
            elif 'exported' in title_lower:
                result = self._test_exported_component(f, result, index)
            elif 'debug' in title_lower:
                result = self._test_debuggable(f, result, index)
            elif 'ssl' in title_lower or 'tls' in title_lower:
                result = self._test_ssl_bypass(f, result, index)
            else:
                # Generic test - just try to execute the PoC
                result = self._test_generic(f, result, index)

        except Exception as e:
            result.test_status = 'error'
            result.notes = str(e)

        result.execution_time = time.time() - start_time
        return result

    def _test_webview_vuln(self, finding: FindingWrapper, result: TestResult, index: int) -> TestResult:
        """Test WebView vulnerabilities."""
        # Extract PoC commands
        poc_commands = finding.adb_commands or []

        if not poc_commands:
            result.test_status = 'inconclusive'
            result.notes = "No PoC commands available"
            return result

        # Find the command that loads a URL
        test_url = "https://example.com/test"
        attack_url = "javascript:document.body.innerHTML='<h1>XSS_TEST_MARKER</h1>'"

        for cmd in poc_commands:
            if isinstance(cmd, str) and ('am start' in cmd or 'loadUrl' in cmd.lower()):
                # Modify command to use our test payload
                if '--es' in cmd and 'url' in cmd.lower():
                    # Replace URL with attack payload
                    modified_cmd = re.sub(
                        r'--es\s+["\']?url["\']?\s+["\'][^"\']+["\']',
                        f'--es "url" "{attack_url}"',
                        cmd
                    )

                    # Execute
                    success, output = self.controller.execute_command(modified_cmd)

                    # Wait for activity to start
                    time.sleep(2)

                    # Take screenshot
                    if self.screenshot_on_test:
                        screenshot_path = self.output_dir / f"test_{index}_webview.png"
                        self.controller.take_screenshot(str(screenshot_path))
                        result.screenshot_path = str(screenshot_path)

                    # Check logcat for signs of XSS
                    if success:
                        # Check if JavaScript executed
                        check_success, check_output = self.controller.execute_command(
                            "dumpsys window | grep -i focus"
                        )

                        result.evidence['command'] = modified_cmd
                        result.evidence['output'] = output

                        # If the activity launched and we can see WebView
                        if 'WebView' in check_output or 'Activity' in check_output:
                            result.test_status = 'confirmed'
                            result.confidence = 0.8
                            result.notes = "WebView loaded attacker-controlled URL"
                        else:
                            result.test_status = 'inconclusive'
                            result.notes = "Activity may have launched but couldn't verify WebView state"

                        # Press back to return
                        self.controller.press_back()
                        time.sleep(0.5)
                        return result

        # If we got here, try to launch the component directly
        extra = finding.extra
        entry_points = extra.get('entry_points', []) if extra else []
        component = extra.get('component', '') if extra else ''

        if not component and entry_points:
            component = entry_points[0]
            if not component.startswith(self.package_name):
                component = f"{self.package_name}/{component}"

        if component:
            # Use a safe test URL (no shell special characters)
            safe_test_url = "https://attacker.com/malicious"

            # First try to just launch the activity
            poc_cmd = f"adb shell am start -n {component}"
            success, output = self.controller.execute_command(
                f"am start -n {component}"
            )

            result.evidence['command'] = poc_cmd
            result.evidence['output'] = output

            time.sleep(2)

            if self.screenshot_on_test:
                screenshot_path = self.output_dir / f"test_{index}_webview.png"
                self.controller.take_screenshot(str(screenshot_path))
                result.screenshot_path = str(screenshot_path)

            if success and 'Error' not in output:
                # Activity launched - now try with URL parameter
                self.controller.press_back()
                time.sleep(0.5)

                # Try common URL parameter names
                url_params = ['url', 'link', 'uri', 'href', 'target', 'redirect', 'next']
                url_accepted = False

                for param in url_params:
                    poc_cmd_url = f'adb shell am start -n {component} --es {param} "{safe_test_url}"'
                    success2, output2 = self.controller.execute_command(
                        f'am start -n {component} --es {param} "{safe_test_url}"'
                    )

                    time.sleep(1)

                    # Check if WebView loaded the URL
                    _, focus = self.controller.execute_command("dumpsys window | grep -E 'mCurrentFocus'")

                    if success2 and 'Error' not in output2:
                        url_accepted = True
                        result.evidence['command'] = poc_cmd_url
                        result.evidence['output'] = f"Intent launched successfully with {param}={safe_test_url}\n\nFocus: {focus}"
                        result.evidence['parameter'] = param
                        result.test_status = 'confirmed'
                        result.confidence = 0.9
                        result.notes = f"WebView accepts attacker-controlled URL via '{param}' parameter - potential XSS/phishing"
                        break

                    self.controller.press_back()
                    time.sleep(0.5)

                if not url_accepted:
                    result.test_status = 'confirmed'
                    result.confidence = 0.6
                    result.notes = f"WebView activity {component} is exported (test URL params manually)"
                    result.evidence['command'] = poc_cmd
                    result.evidence['output'] = output
            else:
                result.test_status = 'not_vulnerable'
                result.notes = f"Failed to launch component: {output}"

            self.controller.press_back()

        return result

    def _test_intent_redirect(self, finding: FindingWrapper, result: TestResult, index: int) -> TestResult:
        """Test Intent redirect vulnerabilities."""
        extra = finding.extra
        entry_points = extra.get('entry_points', []) if extra else []

        if not entry_points:
            result.test_status = 'inconclusive'
            result.notes = "No entry points identified"
            return result

        # For intent redirect, we need to send an Intent with a nested Intent
        # This is hard to do via ADB alone, but we can test if component is reachable
        component = entry_points[0]
        full_component = f"{self.package_name}/{component}"

        # Try to launch the component
        success, output = self.controller.execute_command(
            f"am start -n {full_component}"
        )

        time.sleep(2)

        if self.screenshot_on_test:
            screenshot_path = self.output_dir / f"test_{index}_intent.png"
            self.controller.take_screenshot(str(screenshot_path))
            result.screenshot_path = str(screenshot_path)

        if success and 'Error' not in output:
            result.test_status = 'confirmed'
            result.confidence = 0.6  # Lower confidence since we can't fully test the redirect
            result.notes = f"Component {component} is accessible. Full exploit requires malicious app."
            result.evidence['note'] = (
                "Intent redirect vulnerabilities require a malicious app to craft the nested Intent. "
                "Manual testing with Frida or a custom app is recommended."
            )
        else:
            result.test_status = 'not_vulnerable'
            result.notes = f"Component not accessible: {output}"

        self.controller.press_back()
        return result

    def _test_provider_vuln(self, finding: FindingWrapper, result: TestResult, index: int) -> TestResult:
        """Test ContentProvider vulnerabilities (SQLi, path traversal)."""
        extra = finding.extra or {}
        authority = extra.get('authority', '')

        # Extract authority from finding title if not in extra
        if not authority:
            title = finding.title
            if 'Provider:' in title:
                authority = title.split('Provider:')[-1].strip()

        if not authority:
            result.test_status = 'inconclusive'
            result.notes = "Could not determine provider authority"
            return result

        # Common table/path names to try
        common_paths = [
            '', 'users', 'user', 'accounts', 'account', 'data', 'items', 'products',
            'orders', 'credentials', 'tokens', 'settings', 'config', 'info',
            'messages', 'contacts', 'notes', 'files', 'downloads'
        ]

        data_found = False
        successful_queries = []

        for path in common_paths:
            uri = f"content://{authority}/{path}" if path else f"content://{authority}/"
            poc_cmd = f"adb shell content query --uri {uri}"

            success, output = self.controller.execute_command(f"content query --uri {uri}")

            if success and output:
                # Check for data returned
                if 'Row:' in output:
                    data_found = True
                    successful_queries.append({
                        'uri': uri,
                        'command': poc_cmd,
                        'output': output[:500]
                    })
                    # Found data, capture it
                    if not result.evidence.get('command'):
                        result.evidence['command'] = poc_cmd
                        result.evidence['output'] = output[:1000]
                        result.evidence['uri'] = uri

        if data_found:
            result.test_status = 'confirmed'
            result.confidence = 0.95
            result.notes = f"Provider leaked data! Found {len(successful_queries)} accessible URI(s)"
            result.evidence['successful_queries'] = successful_queries
            result.evidence['output'] = f"DATA LEAKED from {len(successful_queries)} URI(s):\n\n"
            for q in successful_queries[:3]:  # Show first 3
                result.evidence['output'] += f"URI: {q['uri']}\n{q['output']}\n\n"
        else:
            # Try base URI one more time to check access
            base_uri = f"content://{authority}/"
            poc_cmd = f"adb shell content query --uri {base_uri}"
            success, output = self.controller.execute_command(f"content query --uri {base_uri}")

            result.evidence['command'] = poc_cmd
            result.evidence['output'] = output

            if 'Permission Denial' in output or 'SecurityException' in output:
                result.test_status = 'not_vulnerable'
                result.confidence = 0.8
                result.notes = "Provider requires permission - properly protected"
            elif 'No result found' in output:
                # "No result found" means the provider IS accessible (just no data at root)
                result.test_status = 'confirmed'
                result.confidence = 0.7
                result.notes = "Provider is ACCESSIBLE without permission (no data at root URI, try specific tables)"
                result.evidence['tested_paths'] = common_paths
                result.evidence['vulnerability'] = "Provider exports data to other apps without permission check"
            elif 'Could not find provider' in output:
                result.test_status = 'inconclusive'
                result.confidence = 0.3
                result.notes = f"Provider authority may be incorrect: {output[:100]}"
            else:
                result.test_status = 'inconclusive'
                result.notes = f"Could not determine provider security: {output[:100]}"

        return result

    def _test_exported_component(self, finding: FindingWrapper, result: TestResult, index: int) -> TestResult:
        """Test exported component accessibility."""
        # Extract component name from finding
        extra = finding.extra
        component = ''

        if extra:
            # Try full component path first (com.pkg/.Activity)
            component = extra.get('component', '')
            if not component:
                # Try component_class
                component_class = extra.get('component_class', '')
                if component_class:
                    component = f"{self.package_name}/{component_class}"
                elif extra.get('entry_points'):
                    component = f"{self.package_name}/{extra['entry_points'][0]}"

        if not component:
            # Try to extract from evidence
            evidence = finding.evidence
            if evidence:
                if isinstance(evidence, dict):
                    component = evidence.get('matched_text', '')
                elif hasattr(evidence, 'matched_text'):
                    component = evidence.matched_text or ''

        # Try to get from adb_commands as fallback
        if not component:
            adb_cmds = finding.adb_commands or []
            for cmd in adb_cmds:
                if isinstance(cmd, str) and '-n ' in cmd:
                    match = re.search(r'-n\s+(\S+)', cmd)
                    if match:
                        component = match.group(1)
                        break

        if not component:
            result.test_status = 'inconclusive'
            result.notes = "Could not determine component name"
            return result

        # Determine component type from finding title
        title_lower = finding.title.lower()

        if 'activity' in title_lower:
            full_component = f"{self.package_name}/{component}" if '/' not in component else component
            poc_cmd = f"adb shell am start -n {full_component}"
            success, output = self.controller.execute_command(f"am start -n {full_component}")

            # Capture evidence
            result.evidence['command'] = poc_cmd
            result.evidence['output'] = output

            time.sleep(2)

            if self.screenshot_on_test:
                screenshot_path = self.output_dir / f"test_{index}_activity.png"
                self.controller.take_screenshot(str(screenshot_path))
                result.screenshot_path = str(screenshot_path)

            # Check what's in focus now
            _, focus_output = self.controller.execute_command("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'")
            result.evidence['focus'] = focus_output

            if success and 'Error' not in output and 'Exception' not in output:
                # Verify activity actually launched by checking focus
                if full_component.split('/')[-1] in focus_output or 'Starting:' in output:
                    result.test_status = 'confirmed'
                    result.confidence = 0.9
                    result.notes = f"Activity {component} launched successfully without permission"
                    result.evidence['output'] = f"Starting: Intent {{ cmp={full_component} }}\n\nCurrent focus:\n{focus_output}"
                else:
                    result.test_status = 'confirmed'
                    result.confidence = 0.7
                    result.notes = f"Activity {component} appears accessible"
            else:
                result.test_status = 'not_vulnerable'
                result.notes = f"Activity not accessible: {output}"

            self.controller.press_back()

        elif 'service' in title_lower:
            full_component = f"{self.package_name}/{component}" if '/' not in component else component
            poc_cmd = f"adb shell am startservice -n {full_component}"
            success, output = self.controller.execute_command(f"am startservice -n {full_component}")

            result.evidence['command'] = poc_cmd
            result.evidence['output'] = output

            if success and 'Error' not in output:
                result.test_status = 'confirmed'
                result.confidence = 0.9
                result.notes = f"Service {component} started successfully without permission"
            else:
                result.test_status = 'not_vulnerable'
                result.notes = f"Service not accessible: {output}"

        elif 'receiver' in title_lower or 'broadcast' in title_lower:
            full_component = f"{self.package_name}/{component}" if '/' not in component else component
            success, output = self.controller.execute_command(
                f"am broadcast -n {full_component} -a android.intent.action.TEST"
            )

            if success:
                result.test_status = 'confirmed'
                result.confidence = 0.8
                result.notes = f"Broadcast sent to {component}"
            else:
                result.test_status = 'not_vulnerable'
                result.notes = f"Broadcast failed: {output}"

        return result

    def _test_debuggable(self, finding: FindingWrapper, result: TestResult, index: int) -> TestResult:
        """Test if app is debuggable."""
        success, output = self.controller.execute_command(
            f"run-as {self.package_name} ls"
        )

        if success and 'Permission' not in output and 'not debuggable' not in output.lower():
            result.test_status = 'confirmed'
            result.confidence = 1.0
            result.notes = "App is debuggable - run-as succeeded"
            result.evidence['output'] = output[:500]
        else:
            result.test_status = 'not_vulnerable'
            result.notes = "App is not debuggable"

        return result

    def _test_ssl_bypass(self, finding: FindingWrapper, result: TestResult, index: int) -> TestResult:
        """Test SSL/TLS bypass vulnerabilities."""
        # SSL testing requires MITM setup which is complex for automated testing
        result.test_status = 'inconclusive'
        result.confidence = 0.5
        result.notes = (
            "SSL bypass requires manual testing with MITM proxy (Burp/mitmproxy). "
            "Steps: 1) Set proxy on device, 2) Install CA cert, 3) Monitor traffic."
        )
        result.evidence['manual_test_required'] = True
        return result

    def _test_generic(self, finding: FindingWrapper, result: TestResult, index: int) -> TestResult:
        """Generic test for findings without specific test logic."""
        poc_commands = finding.adb_commands or []

        if not poc_commands:
            result.test_status = 'inconclusive'
            result.notes = "No PoC commands available for automated testing"
            return result

        # Try to execute the first command
        for cmd in poc_commands:
            if isinstance(cmd, str) and not cmd.startswith('#'):
                # Clean up the command
                cmd = cmd.strip()
                if cmd.startswith('adb '):
                    cmd = cmd[4:]  # Remove 'adb ' prefix

                success, output = self.controller.execute_command(cmd)

                result.evidence['command'] = cmd
                result.evidence['output'] = output[:500]

                if success:
                    result.test_status = 'inconclusive'
                    result.confidence = 0.5
                    result.notes = "Command executed - manual verification needed"
                else:
                    result.test_status = 'error'
                    result.notes = f"Command failed: {output[:200]}"

                return result

        result.test_status = 'inconclusive'
        result.notes = "No executable commands found"
        return result

    def _print_summary(self):
        """Print test summary."""
        if not self.report:
            return

        print("\n" + "=" * 60)
        print("DYNAMIC ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"Package: {self.report.package_name}")
        print(f"Device: {self.report.device_info}")
        print(f"Duration: {(self.report.end_time - self.report.start_time).seconds}s")
        print("-" * 60)
        print(f"Total Tests:      {self.report.total_tests}")
        print(f"Confirmed:        {self.report.confirmed_vulns} ✓")
        print(f"Not Exploitable:  {self.report.not_vulnerable} ✗")
        print(f"Inconclusive:     {self.report.inconclusive} ?")
        print(f"Errors:           {self.report.errors} !")
        print("=" * 60)

        # List confirmed vulnerabilities
        if self.report.confirmed_vulns > 0:
            print("\nCONFIRMED VULNERABILITIES:")
            for r in self.report.results:
                if r.test_status == 'confirmed':
                    print(f"  [{r.severity}] {r.finding_title}")
                    print(f"       → {r.notes}")

    def export_report(self, output_path: str) -> str:
        """Export report to JSON."""
        if not self.report:
            return ""

        report_dict = {
            'package': self.report.package_name,
            'device': self.report.device_info,
            'start_time': self.report.start_time.isoformat(),
            'end_time': self.report.end_time.isoformat() if self.report.end_time else None,
            'summary': {
                'total': self.report.total_tests,
                'confirmed': self.report.confirmed_vulns,
                'not_vulnerable': self.report.not_vulnerable,
                'inconclusive': self.report.inconclusive,
                'errors': self.report.errors,
            },
            'results': [
                {
                    'id': r.finding_id,
                    'title': r.finding_title,
                    'severity': r.severity,
                    'status': r.test_status,
                    'confidence': r.confidence,
                    'notes': r.notes,
                    'screenshot': r.screenshot_path,
                    'evidence': r.evidence,
                }
                for r in self.report.results
            ]
        }

        with open(output_path, 'w') as f:
            json.dump(report_dict, f, indent=2)

        return output_path

    def get_report(self) -> Optional[DynamicReport]:
        """Get the current report."""
        return self.report

    def cleanup(self):
        """Clean up after testing."""
        # Stop monitoring
        if self.monitor:
            self.monitor.stop()

        # Stop the app
        if self.package_name:
            self.controller.stop_app(self.package_name)

        # Stop logcat
        self.controller.stop_logcat()

        print("[+] Cleanup complete")


class EnhancedDynamicExecutor:
    """
    Enhanced dynamic test executor with full verification capabilities.

    Uses DeviceInterface abstraction, Frida instrumentation, and mitmproxy
    traffic interception for comprehensive vulnerability verification.

    Gracefully degrades when optional components aren't available.
    """

    def __init__(
        self,
        device: Optional[DeviceInterface] = None,
        config: Optional[DynamicConfig] = None,
        frida: Optional['FridaManager'] = None,
        proxy: Optional['ProxyManager'] = None,
        output_dir: Optional[str] = None,
    ):
        """Initialize enhanced executor.

        Args:
            device: Device interface (auto-detected if not provided)
            config: Dynamic analysis configuration
            frida: Frida manager (created if available and not provided)
            proxy: Proxy manager (created if available and not provided)
            output_dir: Output directory for screenshots and reports
        """
        self._config = config or DynamicConfig()
        self._output_dir = Path(output_dir) if output_dir else Path("./dynamic_output")
        self._output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize device
        if device:
            self._device = device
        else:
            self._device = create_device()

        # Initialize Frida if available and not disabled
        self._frida: Optional['FridaManager'] = None
        if frida:
            self._frida = frida
        elif self._config.use_frida and is_frida_available():
            try:
                self._frida = FridaManager(self._device)
                logger.info("Frida instrumentation enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize Frida: {e}")

        # Initialize proxy if available and not disabled
        self._proxy: Optional['ProxyManager'] = None
        self._traffic_analyzer: Optional['TrafficAnalyzer'] = None
        if proxy:
            self._proxy = proxy
        elif self._config.use_proxy and is_mitmproxy_available():
            try:
                self._proxy = ProxyManager(
                    self._device,
                    port=self._config.proxy.port if self._config.proxy else 8080
                )
                self._traffic_analyzer = TrafficAnalyzer()
                logger.info("Traffic interception enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize proxy: {e}")

        # Initialize verifiers
        self._verifiers: List[BaseVerifier] = self._init_verifiers()

        # State
        self._package_name: Optional[str] = None
        self._results: List[VerificationResult] = []
        self._monitor: Optional[AppMonitor] = None

    def _init_verifiers(self) -> List[BaseVerifier]:
        """Initialize verification modules."""
        verifiers = []

        # Create verifiers with available components
        for verifier_class in [WebViewVerifier, ProviderVerifier, IntentVerifier, DeepLinkVerifier]:
            try:
                verifier = verifier_class(
                    device=self._device,
                    frida=self._frida,
                    output_dir=str(self._output_dir),
                )
                verifiers.append(verifier)
            except Exception as e:
                logger.warning(f"Failed to initialize {verifier_class.__name__}: {e}")

        return verifiers

    def get_capabilities(self) -> Dict[str, bool]:
        """Get current analysis capabilities."""
        return {
            "device_connected": self._device.is_connected() if self._device else False,
            "frida_available": self._frida is not None and self._frida.is_available(),
            "proxy_available": self._proxy is not None,
            "ui_automation": hasattr(self._device, 'find_element'),
            "ssl_bypass": self._frida is not None,
            "traffic_capture": self._proxy is not None,
            "mode": self._config.mode.value,
        }

    def setup(self, package_name: str, apk_path: Optional[str] = None) -> bool:
        """Setup for testing.

        Args:
            package_name: Package to test
            apk_path: APK to install (optional)

        Returns:
            True if setup successful
        """
        self._package_name = package_name

        # Connect device if needed
        if not self._device.is_connected():
            if not self._device.connect():
                logger.error("Failed to connect to device")
                return False

        # Install APK if provided
        if apk_path and os.path.exists(apk_path):
            logger.info(f"Installing APK: {apk_path}")
            if not self._device.install_app(apk_path):
                logger.error("Failed to install APK")
                return False

        # Setup proxy if available
        if self._proxy:
            try:
                self._proxy.start()
                self._proxy.configure_device()
                logger.info("Proxy configured")
            except Exception as e:
                logger.warning(f"Failed to setup proxy: {e}")

        # Launch app and attach Frida if available
        if self._frida and self._config.mode != AnalysisMode.PASSIVE:
            frida_attached = False
            try:
                # Try spawn_and_attach first (most reliable)
                logger.info(f"Spawning app with Frida: {package_name}")
                if self._frida.spawn_and_attach(package_name):
                    logger.info("Frida spawned and attached successfully")
                    frida_attached = True

                    # Apply bypasses if aggressive mode
                    if self._config.mode == AnalysisMode.AGGRESSIVE:
                        logger.info("Applying SSL and root bypasses...")
                        self._frida.bypass_ssl_pinning()
                        self._frida.bypass_root_detection()
            except Exception as e:
                logger.warning(f"Frida spawn failed: {e}, trying regular attach...")

                # Fallback: launch app manually and attach
                try:
                    logger.info(f"Launching app: {package_name}")
                    self._device.launch_app(package_name)

                    # Wait for app to start
                    for i in range(5):
                        time.sleep(1)
                        if self._device.is_app_running(package_name):
                            logger.info(f"App is running (checked after {i+1}s)")
                            break

                    # Try to attach
                    if self._frida.attach(package_name):
                        logger.info("Frida attached successfully")
                        frida_attached = True

                        if self._config.mode == AnalysisMode.AGGRESSIVE:
                            self._frida.bypass_ssl_pinning()
                            self._frida.bypass_root_detection()
                except Exception as e2:
                    logger.warning(f"Frida attach also failed: {e2}")

            if not frida_attached:
                logger.warning("Continuing without Frida instrumentation (graceful degradation)")
                # Make sure app is launched
                if not self._device.is_app_running(package_name):
                    self._device.launch_app(package_name)
                    time.sleep(2)

        elif self._config.mode != AnalysisMode.PASSIVE:
            # No Frida available, just launch the app
            logger.info(f"Launching app without Frida: {package_name}")
            self._device.launch_app(package_name)
            time.sleep(2)

        logger.info(f"Setup complete for {package_name}")
        return True

    def verify_finding(self, finding: Dict) -> VerificationResult:
        """Verify a single finding.

        Args:
            finding: Finding dictionary from static analysis

        Returns:
            VerificationResult
        """
        # Find appropriate verifier
        verifier = get_verifier_for_finding(
            finding,
            self._device,
            self._frida,
            str(self._output_dir)
        )

        if verifier and verifier.can_verify(finding):
            try:
                result = verifier.verify(finding)
                self._results.append(result)
                return result
            except Exception as e:
                logger.error(f"Verification failed: {e}")
                return VerificationResult(
                    finding_id=finding.get('fid', 'unknown'),
                    status=VerificationStatus.ERROR,
                    error_message=str(e)
                )

        # Fallback to basic verification
        return self._basic_verify(finding)

    def _basic_verify(self, finding: Dict) -> VerificationResult:
        """Basic verification using ADB commands only."""
        finding_id = finding.get('fid', 'unknown')
        adb_commands = finding.get('adb_commands', [])

        result = VerificationResult(
            finding_id=finding_id,
            status=VerificationStatus.NOT_VERIFIED,
        )

        if not adb_commands:
            result.notes = "No ADB commands available"
            return result

        for cmd in adb_commands:
            if isinstance(cmd, str) and cmd.strip():
                # Clean command
                clean_cmd = cmd.strip()
                if clean_cmd.startswith('adb shell '):
                    clean_cmd = clean_cmd[10:]
                elif clean_cmd.startswith('adb '):
                    clean_cmd = clean_cmd[4:]

                try:
                    success, output = self._device.execute_shell(clean_cmd)
                    if success:
                        result.status = VerificationStatus.POSSIBLE
                        result.confidence = 0.4
                        result.add_evidence(
                            "command",
                            f"Command executed: {cmd[:50]}",
                            data=output[:500]
                        )
                except Exception as e:
                    result.notes = f"Command failed: {e}"

        return result

    def verify_findings(self, findings: List[Dict], timeout: int = 300) -> List[VerificationResult]:
        """Verify multiple findings.

        Args:
            findings: List of finding dictionaries
            timeout: Total timeout in seconds

        Returns:
            List of VerificationResult objects
        """
        if not self._package_name:
            raise RuntimeError("Call setup() first")

        start_time = time.time()
        results = []

        logger.info(f"Verifying {len(findings)} findings...")

        for i, finding in enumerate(findings):
            if time.time() - start_time > timeout:
                logger.warning("Timeout reached, stopping verification")
                break

            finding_id = finding.get('fid', f'finding_{i}')
            logger.info(f"[{i+1}/{len(findings)}] Verifying: {finding.get('title', finding_id)}")

            result = self.verify_finding(finding)
            results.append(result)

            # Log result
            if result.status == VerificationStatus.VERIFIED:
                logger.info(f"  VERIFIED (confidence: {result.confidence:.0%})")
            elif result.status == VerificationStatus.LIKELY:
                logger.info(f"  LIKELY (confidence: {result.confidence:.0%})")
            elif result.status == VerificationStatus.NOT_VULNERABLE:
                logger.info(f"  Not vulnerable")
            else:
                logger.info(f"  {result.status.value}")

            # Brief pause between tests
            time.sleep(0.5)

        self._results = results
        return results

    def get_traffic_analysis(self) -> Optional[Dict]:
        """Get traffic analysis results.

        Returns:
            Traffic analysis summary or None if not available
        """
        if not self._proxy or not self._traffic_analyzer:
            return None

        flows = self._proxy.get_flows()
        if not flows:
            return None

        alerts = self._traffic_analyzer.analyze_flows(flows)
        summary = self._traffic_analyzer.get_summary(alerts)

        return {
            "total_flows": len(flows),
            "leak_alerts": [a.to_dict() for a in alerts],
            "summary": summary,
        }

    def get_summary(self) -> Dict:
        """Get verification summary."""
        total = len(self._results)
        verified = sum(1 for r in self._results if r.status == VerificationStatus.VERIFIED)
        likely = sum(1 for r in self._results if r.status == VerificationStatus.LIKELY)
        not_vuln = sum(1 for r in self._results if r.status == VerificationStatus.NOT_VULNERABLE)
        errors = sum(1 for r in self._results if r.status == VerificationStatus.ERROR)

        summary = {
            "package": self._package_name,
            "capabilities": self.get_capabilities(),
            "total_findings": total,
            "verified": verified,
            "likely": likely,
            "not_vulnerable": not_vuln,
            "errors": errors,
            "inconclusive": total - verified - likely - not_vuln - errors,
        }

        # Add traffic analysis if available
        traffic = self.get_traffic_analysis()
        if traffic:
            summary["traffic"] = traffic

        return summary

    def export_results(self, output_path: str) -> str:
        """Export results to JSON file.

        Args:
            output_path: Output file path

        Returns:
            Path to exported file
        """
        data = {
            "summary": self.get_summary(),
            "results": [r.to_dict() for r in self._results],
            "timestamp": datetime.now().isoformat(),
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return output_path

    def cleanup(self):
        """Clean up resources."""
        # Detach Frida
        if self._frida:
            try:
                self._frida.detach()
            except Exception:
                pass

        # Stop proxy
        if self._proxy:
            try:
                self._proxy.clear_device_proxy()
                self._proxy.stop()
            except Exception:
                pass

        # Stop app
        if self._device and self._package_name:
            try:
                self._device.stop_app(self._package_name)
            except Exception:
                pass

        logger.info("Cleanup complete")


def create_executor(
    config: Optional[DynamicConfig] = None,
    legacy: bool = False,
    controller: Optional[GenymotionController] = None,
    output_dir: str = "./dynamic_output",
    **kwargs
) -> Union[DynamicTestExecutor, EnhancedDynamicExecutor]:
    """Factory function to create appropriate executor.

    Args:
        config: Dynamic analysis configuration
        legacy: Force legacy executor
        controller: Legacy controller (for backwards compatibility)
        output_dir: Output directory
        **kwargs: Additional arguments

    Returns:
        DynamicTestExecutor or EnhancedDynamicExecutor
    """
    if legacy or controller:
        # Use legacy executor
        if not controller:
            controller = GenymotionController()
            controller.connect()
        return DynamicTestExecutor(
            controller=controller,
            output_dir=output_dir,
            **kwargs
        )

    # Use enhanced executor
    return EnhancedDynamicExecutor(
        config=config,
        output_dir=output_dir,
        **kwargs
    )
