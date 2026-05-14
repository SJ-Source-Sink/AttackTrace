"""App structure analyzer - parses decompiled code to build structural model."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET


@dataclass
class ClassInfo:
    """Information about a Java/Kotlin class."""
    name: str
    package: str
    full_name: str
    file_path: str
    extends: Optional[str] = None
    implements: List[str] = field(default_factory=list)
    methods: List['MethodInfo'] = field(default_factory=list)
    fields: List['FieldInfo'] = field(default_factory=list)
    is_activity: bool = False
    is_service: bool = False
    is_receiver: bool = False
    is_provider: bool = False
    is_fragment: bool = False
    is_abstract: bool = False
    is_interface: bool = False
    inner_classes: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)


@dataclass
class MethodInfo:
    """Information about a method."""
    name: str
    class_name: str
    return_type: str
    parameters: List[Tuple[str, str]]  # (type, name)
    modifiers: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)  # Methods this method calls
    called_by: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    line_number: int = 0


@dataclass
class FieldInfo:
    """Information about a field."""
    name: str
    type: str
    modifiers: List[str] = field(default_factory=list)
    initial_value: Optional[str] = None


@dataclass
class ComponentInfo:
    """Android component information from manifest."""
    name: str
    type: str  # activity, service, receiver, provider
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[Dict] = field(default_factory=list)
    authorities: Optional[str] = None  # For providers
    meta_data: Dict[str, str] = field(default_factory=dict)


@dataclass
class IntentInfo:
    """Information about an Intent usage."""
    source_class: str
    source_method: str
    target: Optional[str] = None  # Explicit target class
    action: Optional[str] = None
    data_uri: Optional[str] = None
    extras: List[str] = field(default_factory=list)
    is_implicit: bool = False
    line_number: int = 0


@dataclass
class DataFlowInfo:
    """Information about data flow."""
    source: str  # Where data comes from
    sink: str    # Where data goes
    data_type: str  # Type of data (user_input, file, network, etc.)
    path: List[str] = field(default_factory=list)  # Methods in the flow
    source_method: str = ""  # Method where data originates
    sink_method: str = ""  # Method where data is consumed
    parameters: List[str] = field(default_factory=list)  # Parameters involved
    taint_chain: List[str] = field(default_factory=list)  # Variable names through the flow
    is_user_controllable: bool = False  # True if source is user input
    risk_level: str = "medium"  # low, medium, high, critical


@dataclass
class AttackSurface:
    """Attack surface information for a component."""
    component_name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool = False
    permission: Optional[str] = None
    # Testing commands
    adb_commands: List[str] = field(default_factory=list)
    # Deep links
    deep_links: List[str] = field(default_factory=list)
    # Intent filters
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data_schemes: List[str] = field(default_factory=list)
    data_hosts: List[str] = field(default_factory=list)
    data_paths: List[str] = field(default_factory=list)
    # For providers
    uri_patterns: List[str] = field(default_factory=list)
    # Frida hooks
    frida_hooks: List[str] = field(default_factory=list)
    # Associated vulnerabilities
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class InjectionPoint:
    """Potential injection point in the application."""
    class_name: str
    method_name: str
    parameter_name: str
    parameter_type: str
    injection_type: str  # sql, path, command, xss, intent
    sink_method: str  # The dangerous method called
    line_number: int = 0
    code_snippet: str = ""
    exploit_example: str = ""


@dataclass
class AppStructure:
    """Complete application structure."""
    package_name: str
    classes: Dict[str, ClassInfo] = field(default_factory=dict)
    components: Dict[str, ComponentInfo] = field(default_factory=dict)
    intents: List[IntentInfo] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    data_flows: List[DataFlowInfo] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    # New: Enhanced attack surface analysis
    attack_surfaces: List[AttackSurface] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    frida_scripts: Dict[str, str] = field(default_factory=dict)  # name -> script content


class AppStructureAnalyzer:
    """Analyzes decompiled APK to build structural model."""

    # Android component base classes
    ACTIVITY_CLASSES = {
        'Activity', 'AppCompatActivity', 'FragmentActivity',
        'ListActivity', 'PreferenceActivity', 'ActionBarActivity',
        'ComponentActivity', 'BaseActivity'
    }
    SERVICE_CLASSES = {
        'Service', 'IntentService', 'JobService', 'JobIntentService',
        'LifecycleService', 'BaseService'
    }
    RECEIVER_CLASSES = {
        'BroadcastReceiver', 'WakefulBroadcastReceiver', 'BaseBroadcastReceiver'
    }
    PROVIDER_CLASSES = {
        'ContentProvider', 'FileProvider', 'DocumentsProvider',
        'SearchRecentSuggestionsProvider', 'BaseContentProvider'
    }
    FRAGMENT_CLASSES = {
        'Fragment', 'DialogFragment', 'ListFragment', 'PreferenceFragment',
        'PreferenceFragmentCompat', 'BottomSheetDialogFragment'
    }

    # Data source patterns (sensitive data entry points)
    DATA_SOURCES = {
        'user_input': [
            r'getText\(\)', r'getEditableText\(\)', r'EditText',
            r'getStringExtra', r'getIntent\(\)', r'onActivityResult',
        ],
        'file': [
            r'FileInputStream', r'FileReader', r'BufferedReader',
            r'openFileInput', r'getSharedPreferences',
        ],
        'network': [
            r'HttpURLConnection', r'OkHttpClient', r'Retrofit',
            r'getInputStream\(\)', r'URLConnection',
        ],
        'database': [
            r'rawQuery', r'query\(', r'Cursor', r'SQLiteDatabase',
        ],
    }

    # Data sink patterns (where sensitive data goes)
    DATA_SINKS = {
        'network': [
            r'OutputStream', r'HttpURLConnection', r'write\(',
            r'sendBroadcast', r'startActivity',
        ],
        'file': [
            r'FileOutputStream', r'FileWriter', r'openFileOutput',
        ],
        'log': [
            r'Log\.[diwev]', r'println', r'System\.out',
        ],
        'database': [
            r'insert\(', r'update\(', r'execSQL',
        ],
    }

    def __init__(self, decompiled_dir: str):
        self.decompiled_dir = Path(decompiled_dir)
        self.sources_dir = self.decompiled_dir / "sources"
        self.resources_dir = self.decompiled_dir / "resources"
        self.manifest_path = self.resources_dir / "AndroidManifest.xml"

    # Injection patterns for vulnerability detection
    INJECTION_PATTERNS = {
        'sql': [
            (r'rawQuery\s*\([^,]+\+', 'SQL Injection via string concatenation'),
            (r'execSQL\s*\([^,]+\+', 'SQL Injection via execSQL'),
            (r'query\s*\([^)]*\+[^)]*\)', 'SQL Injection in query'),
        ],
        'path': [
            (r'new\s+File\s*\([^)]*\+', 'Path Traversal via File constructor'),
            (r'openFileInput\s*\([^)]*\+', 'Path Traversal in openFileInput'),
            (r'getExternalFilesDir[^)]*\+', 'Path Traversal in external storage'),
        ],
        'command': [
            (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', 'Command Injection'),
            (r'ProcessBuilder\s*\([^)]*\+', 'Command Injection via ProcessBuilder'),
        ],
        'xss': [
            (r'loadUrl\s*\([^)]*\+', 'XSS via loadUrl'),
            (r'evaluateJavascript\s*\([^)]*\+', 'XSS via evaluateJavascript'),
            (r'loadDataWithBaseURL\s*\([^)]*\+', 'XSS via loadDataWithBaseURL'),
        ],
        'intent': [
            (r'setClassName\s*\([^)]*getStringExtra', 'Intent Redirect'),
            (r'setComponent\s*\([^)]*getIntent', 'Intent Redirect via Component'),
            (r'startActivity\s*\(.*getParcelableExtra', 'Intent Redirect via Parcelable'),
        ],
    }

    def analyze(self) -> AppStructure:
        """Perform complete analysis of the application."""
        structure = AppStructure(package_name="")

        # Parse manifest first
        if self.manifest_path.exists():
            self._parse_manifest(structure)

        # Analyze source code
        if self.sources_dir.exists():
            self._analyze_sources(structure)

        # Build relationships
        self._analyze_intents(structure)
        self._analyze_data_flows(structure)
        self._identify_entry_points(structure)

        # New: Enhanced attack surface analysis
        self._generate_attack_surfaces(structure)
        self._detect_injection_points(structure)
        self._generate_frida_scripts(structure)

        return structure

    def _parse_manifest(self, structure: AppStructure) -> None:
        """Parse AndroidManifest.xml."""
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()

            # Get namespace
            ns = {'android': 'http://schemas.android.com/apk/res/android'}

            # Package name
            structure.package_name = root.get('package', '')

            # Permissions
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get(f'{{{ns["android"]}}}name', '')
                if perm_name:
                    structure.permissions.append(perm_name)

            # Components
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                for elem in root.findall(f'.//{component_type}'):
                    comp = self._parse_component(elem, component_type, ns)
                    if comp:
                        structure.components[comp.name] = comp

        except Exception as e:
            print(f"[!] Failed to parse manifest: {e}")

    def _parse_component(self, elem: ET.Element, comp_type: str, ns: Dict) -> Optional[ComponentInfo]:
        """Parse a component element from manifest."""
        android_ns = ns['android']
        name = elem.get(f'{{{android_ns}}}name', '')

        if not name:
            return None

        exported_attr = elem.get(f'{{{android_ns}}}exported')
        exported = exported_attr == 'true' if exported_attr else None

        # Check for intent-filters (implies exported=true by default)
        intent_filters = []
        for intent_filter in elem.findall('intent-filter'):
            filter_info = {'actions': [], 'categories': [], 'data': []}

            for action in intent_filter.findall('action'):
                action_name = action.get(f'{{{android_ns}}}name', '')
                if action_name:
                    filter_info['actions'].append(action_name)

            for category in intent_filter.findall('category'):
                cat_name = category.get(f'{{{android_ns}}}name', '')
                if cat_name:
                    filter_info['categories'].append(cat_name)

            for data in intent_filter.findall('data'):
                data_info = {}
                for attr in ['scheme', 'host', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                    val = data.get(f'{{{android_ns}}}{attr}')
                    if val:
                        data_info[attr] = val
                if data_info:
                    filter_info['data'].append(data_info)

            intent_filters.append(filter_info)

        # If has intent-filter and exported not explicitly set, default to true
        if exported is None and intent_filters:
            exported = True
        elif exported is None:
            exported = False

        # Provider authorities
        authorities = elem.get(f'{{{android_ns}}}authorities')

        # Permission
        permission = elem.get(f'{{{android_ns}}}permission')

        # Meta-data
        meta_data = {}
        for meta in elem.findall('meta-data'):
            meta_name = meta.get(f'{{{android_ns}}}name', '')
            meta_value = meta.get(f'{{{android_ns}}}value', '')
            if meta_name:
                meta_data[meta_name] = meta_value

        return ComponentInfo(
            name=name,
            type=comp_type,
            exported=exported,
            permission=permission,
            intent_filters=intent_filters,
            authorities=authorities,
            meta_data=meta_data,
        )

    def _analyze_sources(self, structure: AppStructure) -> None:
        """Analyze source code files."""
        for root, dirs, files in os.walk(self.sources_dir):
            for file in files:
                if file.endswith(('.java', '.kt')):
                    file_path = Path(root) / file
                    self._analyze_source_file(file_path, structure)

    def _analyze_source_file(self, file_path: Path, structure: AppStructure) -> None:
        """Analyze a single source file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract class info
            class_info = self._parse_class(content, str(file_path))
            if class_info:
                structure.classes[class_info.full_name] = class_info

        except Exception as e:
            pass  # Skip files that can't be parsed

    def _parse_class(self, content: str, file_path: str) -> Optional[ClassInfo]:
        """Parse class information from source code."""
        # Extract package
        package_match = re.search(r'package\s+([\w.]+)\s*;', content)
        package = package_match.group(1) if package_match else ""

        # Extract class declaration
        class_pattern = r'(?:public\s+)?(?:(abstract)\s+)?(?:(interface)\s+)?class\s+(\w+)(?:\s+extends\s+([\w.]+))?(?:\s+implements\s+([\w.,\s]+))?'
        class_match = re.search(class_pattern, content)

        if not class_match:
            # Try interface pattern
            interface_pattern = r'(?:public\s+)?interface\s+(\w+)(?:\s+extends\s+([\w.,\s]+))?'
            interface_match = re.search(interface_pattern, content)
            if interface_match:
                class_name = interface_match.group(1)
                extends_raw = interface_match.group(2)
                is_interface = True
                is_abstract = False
            else:
                return None
        else:
            is_abstract = class_match.group(1) is not None
            is_interface = class_match.group(2) is not None
            class_name = class_match.group(3)
            extends_raw = class_match.group(4)

        full_name = f"{package}.{class_name}" if package else class_name

        # Determine component type
        extends_class = extends_raw.split('.')[-1] if extends_raw else None
        is_activity = extends_class in self.ACTIVITY_CLASSES
        is_service = extends_class in self.SERVICE_CLASSES
        is_receiver = extends_class in self.RECEIVER_CLASSES
        is_provider = extends_class in self.PROVIDER_CLASSES
        is_fragment = extends_class in self.FRAGMENT_CLASSES

        # Extract implements
        implements = []
        if not is_interface:
            impl_match = re.search(r'implements\s+([\w.,\s]+)', content)
            if impl_match:
                implements = [i.strip() for i in impl_match.group(1).split(',')]

        # Extract methods
        methods = self._extract_methods(content, full_name)

        # Extract fields
        fields = self._extract_fields(content)

        # Extract annotations
        annotations = re.findall(r'@(\w+)', content[:500])  # Check class-level annotations

        # Extract inner classes
        inner_classes = re.findall(r'(?:public|private|protected)?\s*(?:static)?\s*class\s+(\w+)\s+', content)
        inner_classes = [ic for ic in inner_classes if ic != class_name]

        return ClassInfo(
            name=class_name,
            package=package,
            full_name=full_name,
            file_path=file_path,
            extends=extends_raw,
            implements=implements,
            methods=methods,
            fields=fields,
            is_activity=is_activity,
            is_service=is_service,
            is_receiver=is_receiver,
            is_provider=is_provider,
            is_fragment=is_fragment,
            is_abstract=is_abstract,
            is_interface=is_interface,
            inner_classes=inner_classes,
            annotations=annotations,
        )

    def _extract_methods(self, content: str, class_name: str) -> List[MethodInfo]:
        """Extract method information from source code."""
        methods = []

        # Method pattern (simplified)
        method_pattern = r'(?:(@\w+)\s+)?(?:(public|private|protected)\s+)?(?:(static)\s+)?(?:(synchronized)\s+)?(?:([\w<>\[\],\s]+)\s+)?(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{'

        for match in re.finditer(method_pattern, content):
            annotation = match.group(1)
            modifier = match.group(2) or 'package'
            is_static = match.group(3) is not None
            return_type = match.group(5) or 'void'
            method_name = match.group(6)
            params_str = match.group(7)

            # Skip constructors shown as methods
            if method_name in ['if', 'while', 'for', 'switch', 'try', 'catch']:
                continue

            # Parse parameters
            parameters = []
            if params_str.strip():
                for param in params_str.split(','):
                    param = param.strip()
                    if param:
                        parts = param.split()
                        if len(parts) >= 2:
                            parameters.append((parts[-2], parts[-1]))

            modifiers = [modifier]
            if is_static:
                modifiers.append('static')

            annotations = [annotation] if annotation else []

            methods.append(MethodInfo(
                name=method_name,
                class_name=class_name,
                return_type=return_type.strip(),
                parameters=parameters,
                modifiers=modifiers,
                annotations=annotations,
            ))

        return methods

    def _extract_fields(self, content: str) -> List[FieldInfo]:
        """Extract field information from source code."""
        fields = []

        # Field pattern
        field_pattern = r'(?:(private|public|protected)\s+)?(?:(static)\s+)?(?:(final)\s+)?([\w<>\[\],]+)\s+(\w+)\s*(?:=\s*([^;]+))?\s*;'

        for match in re.finditer(field_pattern, content):
            modifier = match.group(1) or 'package'
            is_static = match.group(2) is not None
            is_final = match.group(3) is not None
            field_type = match.group(4)
            field_name = match.group(5)
            initial_value = match.group(6)

            # Skip common false positives
            if field_name in ['class', 'this', 'super', 'new', 'return']:
                continue

            modifiers = [modifier]
            if is_static:
                modifiers.append('static')
            if is_final:
                modifiers.append('final')

            fields.append(FieldInfo(
                name=field_name,
                type=field_type,
                modifiers=modifiers,
                initial_value=initial_value.strip() if initial_value else None,
            ))

        return fields

    def _analyze_intents(self, structure: AppStructure) -> None:
        """Analyze Intent usage throughout the app."""
        for class_info in structure.classes.values():
            try:
                with open(class_info.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Find Intent creations
                intent_patterns = [
                    # Explicit intent: new Intent(context, Target.class)
                    r'new\s+Intent\s*\([^,)]+,\s*([\w.]+)\.class\)',
                    # Implicit intent: new Intent("action")
                    r'new\s+Intent\s*\(\s*["\']([^"\']+)["\']\s*\)',
                    # setClass/setComponent
                    r'\.setClass\s*\([^,]+,\s*([\w.]+)\.class\)',
                    r'\.setComponent\s*\([^)]+\)',
                ]

                for pattern in intent_patterns:
                    for match in re.finditer(pattern, content):
                        target = match.group(1) if match.lastindex >= 1 else None

                        intent_info = IntentInfo(
                            source_class=class_info.full_name,
                            source_method="",  # Would need more parsing
                            target=target,
                            is_implicit=target is None or not target.endswith('.class'),
                        )
                        structure.intents.append(intent_info)

                # Find startActivity/startService calls
                start_patterns = [
                    r'startActivity\s*\(',
                    r'startActivityForResult\s*\(',
                    r'startService\s*\(',
                    r'bindService\s*\(',
                    r'sendBroadcast\s*\(',
                    r'sendOrderedBroadcast\s*\(',
                ]

            except Exception:
                pass

    def _analyze_data_flows(self, structure: AppStructure) -> None:
        """Analyze data flow through the application with detailed parameter extraction."""
        # Risk matrix: source -> sink -> risk level
        risk_matrix = {
            'user_input': {'network': 'critical', 'database': 'critical', 'file': 'high', 'log': 'medium'},
            'file': {'network': 'high', 'database': 'medium', 'file': 'low', 'log': 'medium'},
            'network': {'database': 'high', 'file': 'high', 'log': 'medium', 'network': 'medium'},
            'database': {'network': 'high', 'file': 'medium', 'log': 'medium', 'database': 'low'},
        }

        # Method pattern to find method context
        method_pattern = re.compile(
            r'(?:public|private|protected)?\s*(?:static)?\s*[\w<>\[\],\s]+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws[^{]*)?\{',
            re.MULTILINE
        )

        # Limit classes to process for performance (exclude known library packages)
        library_prefixes = (
            'androidx.', 'android.', 'com.google.', 'kotlin.', 'kotlinx.',
            'okhttp3.', 'okio.', 'retrofit2.', 'com.squareup.', 'io.reactivex.',
            'org.json.', 'org.apache.', 'com.fasterxml.', 'com.sun.', 'java.',
            'javax.', 'sun.', 'dalvik.', 'org.intellij.', 'org.jetbrains.',
        )
        app_classes = [c for c in structure.classes.values()
                       if not c.full_name.startswith(library_prefixes)][:500]

        for class_info in app_classes:
            try:
                with open(class_info.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Quick check - skip if no sources or sinks
                has_source = any(re.search(p, content) for patterns in self.DATA_SOURCES.values() for p in patterns)
                has_sink = any(re.search(p, content) for patterns in self.DATA_SINKS.values() for p in patterns)
                if not has_source or not has_sink:
                    continue

                # Find all methods in the class
                methods = []
                for match in method_pattern.finditer(content):
                    methods.append({
                        'name': match.group(1),
                        'params': match.group(2),
                        'start_pos': match.start(),
                    })

                # Find sources in this class
                sources_found = []
                for source_type, patterns in self.DATA_SOURCES.items():
                    for pattern in patterns:
                        match = re.search(pattern, content)
                        if match:
                            source_method = self._find_enclosing_method(methods, match.start())
                            context = content[max(0, match.start()-50):match.end()+100]
                            params = self._extract_params_from_context(context)
                            sources_found.append({
                                'type': source_type,
                                'method': source_method,
                                'params': params,
                                'pos': match.start(),
                            })
                            break  # One source per type per class is enough

                # Find sinks in this class
                sinks_found = []
                for sink_type, patterns in self.DATA_SINKS.items():
                    for pattern in patterns:
                        match = re.search(pattern, content)
                        if match:
                            sink_method = self._find_enclosing_method(methods, match.start())
                            context = content[max(0, match.start()-20):match.end()+150]
                            params = self._extract_params_from_context(context)
                            sinks_found.append({
                                'type': sink_type,
                                'method': sink_method,
                                'params': params,
                                'pos': match.start(),
                            })
                            break  # One sink per type per class is enough

                # Create flows for each source-sink pair
                for source in sources_found:
                    for sink in sinks_found:
                        risk = risk_matrix.get(source['type'], {}).get(sink['type'], 'medium')

                        # Extract taint chain between source and sink
                        start_pos = min(source['pos'], sink['pos'])
                        end_pos = max(source['pos'], sink['pos']) + 200
                        code_segment = content[start_pos:end_pos]
                        taint_chain = self._extract_taint_chain(code_segment)

                        flow = DataFlowInfo(
                            source=source['type'],
                            sink=sink['type'],
                            data_type=source['type'],
                            path=[class_info.full_name],
                            source_method=f"{class_info.name}.{source['method']}()" if source['method'] else class_info.name,
                            sink_method=f"{class_info.name}.{sink['method']}()" if sink['method'] else class_info.name,
                            parameters=source['params'] + sink['params'],
                            taint_chain=taint_chain,
                            is_user_controllable=(source['type'] == 'user_input'),
                            risk_level=risk,
                        )
                        structure.data_flows.append(flow)

            except Exception:
                pass

    def _find_enclosing_method(self, methods: List[Dict], pos: int) -> str:
        """Find the method that encloses a given position."""
        enclosing = None
        for method in methods:
            if method['start_pos'] < pos:
                if enclosing is None or method['start_pos'] > enclosing['start_pos']:
                    enclosing = method
        return enclosing['name'] if enclosing else ''

    def _extract_params_from_context(self, context: str) -> List[str]:
        """Extract parameter names from method call context."""
        params = []
        # Look for method call with parentheses
        call_match = re.search(r'\w+\s*\(([^)]+)\)', context)
        if call_match:
            args = call_match.group(1)
            # Extract variable names (simple heuristic)
            for arg in args.split(','):
                arg = arg.strip()
                # Skip literals
                if arg and not arg.startswith('"') and not arg.startswith("'") and not arg.isdigit():
                    # Get just the variable name
                    var_match = re.search(r'(\w+)(?:\.\w+)*$', arg)
                    if var_match:
                        params.append(var_match.group(1))
        return params[:5]  # Limit to 5 params

    def _extract_taint_chain(self, code_segment: str) -> List[str]:
        """Extract variables that might carry data from source to sink."""
        taint_chain = []
        # Find variable assignments
        assign_pattern = re.compile(r'(\w+)\s*=\s*[^=]')
        for match in assign_pattern.finditer(code_segment):
            var_name = match.group(1)
            if var_name not in taint_chain and var_name not in ('this', 'null', 'true', 'false', 'String', 'int'):
                taint_chain.append(var_name)
        return taint_chain[:10]  # Limit chain length

    def _identify_entry_points(self, structure: AppStructure) -> None:
        """Identify application entry points."""
        # Exported components are entry points
        for name, comp in structure.components.items():
            if comp.exported:
                structure.entry_points.append(f"{comp.type}:{name}")

        # Main activity (with MAIN action and LAUNCHER category)
        for name, comp in structure.components.items():
            for intent_filter in comp.intent_filters:
                if ('android.intent.action.MAIN' in intent_filter.get('actions', []) and
                    'android.intent.category.LAUNCHER' in intent_filter.get('categories', [])):
                    if f"launcher:{name}" not in structure.entry_points:
                        structure.entry_points.insert(0, f"launcher:{name}")

        # DeepLinks
        for name, comp in structure.components.items():
            for intent_filter in comp.intent_filters:
                for data in intent_filter.get('data', []):
                    if 'scheme' in data:
                        scheme = data.get('scheme', '')
                        host = data.get('host', '*')
                        path = data.get('path', data.get('pathPrefix', '/*'))
                        structure.entry_points.append(f"deeplink:{scheme}://{host}{path} -> {name}")

    def _generate_attack_surfaces(self, structure: AppStructure) -> None:
        """Generate attack surface information with ADB commands for testing."""
        pkg = structure.package_name

        for name, comp in structure.components.items():
            attack_surface = AttackSurface(
                component_name=name,
                component_type=comp.type,
                exported=comp.exported,
                permission=comp.permission,
            )

            # Collect intent filter info
            for intent_filter in comp.intent_filters:
                attack_surface.actions.extend(intent_filter.get('actions', []))
                attack_surface.categories.extend(intent_filter.get('categories', []))
                for data in intent_filter.get('data', []):
                    if 'scheme' in data:
                        attack_surface.data_schemes.append(data['scheme'])
                    if 'host' in data:
                        attack_surface.data_hosts.append(data['host'])
                    if 'path' in data:
                        attack_surface.data_paths.append(data['path'])
                    elif 'pathPrefix' in data:
                        attack_surface.data_paths.append(data['pathPrefix'] + '*')

            # Generate ADB commands based on component type
            if comp.exported or not comp.permission:
                if comp.type == 'activity':
                    # Basic activity start
                    attack_surface.adb_commands.append(
                        f"adb shell am start -n {pkg}/{name}"
                    )
                    # With action
                    for action in attack_surface.actions:
                        attack_surface.adb_commands.append(
                            f"adb shell am start -a {action} -n {pkg}/{name}"
                        )
                    # With data URI
                    for scheme in attack_surface.data_schemes:
                        host = attack_surface.data_hosts[0] if attack_surface.data_hosts else 'example.com'
                        path = attack_surface.data_paths[0] if attack_surface.data_paths else '/test'
                        deep_link = f"{scheme}://{host}{path}"
                        attack_surface.deep_links.append(deep_link)
                        attack_surface.adb_commands.append(
                            f"adb shell am start -a android.intent.action.VIEW -d \"{deep_link}\""
                        )
                    # Intent injection test (use URL-encoded payload to avoid HTML issues)
                    attack_surface.adb_commands.append(
                        f"adb shell am start -n {pkg}/{name} --es \"injection_test\" \"test_payload_123\""
                    )

                elif comp.type == 'service':
                    attack_surface.adb_commands.append(
                        f"adb shell am startservice -n {pkg}/{name}"
                    )
                    for action in attack_surface.actions:
                        attack_surface.adb_commands.append(
                            f"adb shell am startservice -a {action}"
                        )

                elif comp.type == 'receiver':
                    for action in attack_surface.actions:
                        attack_surface.adb_commands.append(
                            f"adb shell am broadcast -a {action}"
                        )
                        # With extra data
                        attack_surface.adb_commands.append(
                            f"adb shell am broadcast -a {action} --es \"data\" \"malicious_payload\""
                        )
                    if not attack_surface.actions:
                        attack_surface.adb_commands.append(
                            f"adb shell am broadcast -n {pkg}/{name}"
                        )

                elif comp.type == 'provider':
                    if comp.authorities:
                        for authority in comp.authorities.split(';'):
                            uri = f"content://{authority}/"
                            attack_surface.uri_patterns.append(uri)
                            attack_surface.adb_commands.append(
                                f"adb shell content query --uri {uri}"
                            )
                            # SQL injection test
                            attack_surface.adb_commands.append(
                                f"adb shell content query --uri \"{uri}\" --where \"1=1--\""
                            )
                            # Path traversal test
                            attack_surface.adb_commands.append(
                                f"adb shell content read --uri {uri}../../../etc/passwd"
                            )

            # Generate Frida hooks for this component
            attack_surface.frida_hooks = self._get_component_frida_hooks(name, comp, pkg)

            structure.attack_surfaces.append(attack_surface)

    def _get_component_frida_hooks(self, name: str, comp: ComponentInfo, pkg: str) -> List[str]:
        """Generate Frida hook code for a component."""
        hooks = []
        simple_name = name.split('.')[-1]

        if comp.type == 'activity':
            hooks.append(f'''// Hook {simple_name} onCreate
Java.perform(function() {{
    var Activity = Java.use("{name}");
    Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {{
        console.log("[*] {simple_name}.onCreate called");
        console.log("[*] Intent: " + this.getIntent());
        console.log("[*] Extras: " + this.getIntent().getExtras());
        return this.onCreate(bundle);
    }};
}});''')

        elif comp.type == 'service':
            hooks.append(f'''// Hook {simple_name} onStartCommand
Java.perform(function() {{
    var Service = Java.use("{name}");
    Service.onStartCommand.implementation = function(intent, flags, startId) {{
        console.log("[*] {simple_name}.onStartCommand called");
        console.log("[*] Intent: " + intent);
        return this.onStartCommand(intent, flags, startId);
    }};
}});''')

        elif comp.type == 'receiver':
            hooks.append(f'''// Hook {simple_name} onReceive
Java.perform(function() {{
    var Receiver = Java.use("{name}");
    Receiver.onReceive.implementation = function(context, intent) {{
        console.log("[*] {simple_name}.onReceive called");
        console.log("[*] Action: " + intent.getAction());
        console.log("[*] Data: " + intent.getDataString());
        return this.onReceive(context, intent);
    }};
}});''')

        elif comp.type == 'provider':
            hooks.append(f'''// Hook {simple_name} query
Java.perform(function() {{
    var Provider = Java.use("{name}");
    Provider.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, projection, selection, selectionArgs, sortOrder) {{
        console.log("[*] {simple_name}.query called");
        console.log("[*] URI: " + uri);
        console.log("[*] Selection: " + selection);
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    }};
}});''')

        return hooks

    def _detect_injection_points(self, structure: AppStructure) -> None:
        """Detect potential injection vulnerabilities."""
        for class_info in structure.classes.values():
            try:
                with open(class_info.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                for injection_type, patterns in self.INJECTION_PATTERNS.items():
                    for pattern, description in patterns:
                        for match in re.finditer(pattern, content):
                            # Find line number
                            pos = match.start()
                            line_num = content[:pos].count('\n') + 1

                            # Get code snippet (surrounding lines)
                            start_line = max(0, line_num - 2)
                            end_line = min(len(lines), line_num + 2)
                            snippet = '\n'.join(lines[start_line:end_line])

                            # Generate exploit example
                            exploit = self._generate_exploit_example(injection_type, match.group())

                            injection_point = InjectionPoint(
                                class_name=class_info.full_name,
                                method_name="",  # Would need deeper parsing
                                parameter_name="",
                                parameter_type="String",
                                injection_type=injection_type,
                                sink_method=match.group()[:50],
                                line_number=line_num,
                                code_snippet=snippet,
                                exploit_example=exploit,
                            )
                            structure.injection_points.append(injection_point)

            except Exception:
                pass

    def _generate_exploit_example(self, injection_type: str, matched_code: str) -> str:
        """Generate example exploit payload for injection type."""
        exploits = {
            'sql': "' OR '1'='1' --",
            'path': "../../../etc/passwd",
            'command': "; cat /etc/passwd",
            'xss': "<script>alert(document.cookie)</script>",
            'intent': "Use setClassName() to redirect to attacker's exported activity",
        }
        return exploits.get(injection_type, "Manual testing required")

    def _generate_frida_scripts(self, structure: AppStructure) -> None:
        """Generate comprehensive Frida scripts for testing."""
        pkg = structure.package_name

        # SSL Pinning Bypass
        structure.frida_scripts['ssl_bypass'] = '''// SSL Pinning Bypass
Java.perform(function() {
    // Trust all certificates
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManagers = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
    var sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, TrustManagers, null);

    // OkHttp bypass
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
        OkHttpClient.certificatePinner.implementation = function(pinner) {
            console.log("[*] OkHttp certificate pinning bypassed");
            return this;
        };
    } catch(e) {}

    console.log("[*] SSL Pinning bypassed");
});'''

        # Crypto Key Logger
        structure.frida_scripts['crypto_logger'] = '''// Crypto Key Logger
Java.perform(function() {
    // Log AES keys
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log("[*] SecretKeySpec: " + algo);
        console.log("[*] Key: " + bytesToHex(key));
        return this.$init(key, algo);
    };

    // Log Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(data) {
        console.log("[*] Cipher.doFinal input: " + bytesToHex(data));
        var result = this.doFinal(data);
        console.log("[*] Cipher.doFinal output: " + bytesToHex(result));
        return result;
    };

    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
});'''

        # Intent Monitor
        structure.frida_scripts['intent_monitor'] = f'''// Intent Monitor for {pkg}
Java.perform(function() {{
    var Activity = Java.use('android.app.Activity');

    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {{
        console.log("[*] startActivity called");
        console.log("[*] Intent: " + intent.toString());
        console.log("[*] Component: " + intent.getComponent());
        console.log("[*] Action: " + intent.getAction());
        console.log("[*] Data: " + intent.getDataString());
        var extras = intent.getExtras();
        if (extras) {{
            console.log("[*] Extras: " + extras.toString());
        }}
        return this.startActivity(intent);
    }};

    Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(intent, code) {{
        console.log("[*] startActivityForResult called");
        console.log("[*] Intent: " + intent.toString());
        console.log("[*] Request code: " + code);
        return this.startActivityForResult(intent, code);
    }};
}});'''

        # File Operations Logger
        structure.frida_scripts['file_logger'] = '''// File Operations Logger
Java.perform(function() {
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function(path) {
        console.log("[*] File: " + path);
        return this.$init(path);
    };

    var FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log("[*] FileInputStream: " + file.getAbsolutePath());
        return this.$init(file);
    };

    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log("[*] FileOutputStream: " + file.getAbsolutePath());
        return this.$init(file);
    };
});'''

        # SharedPreferences Logger
        structure.frida_scripts['sharedprefs_logger'] = '''// SharedPreferences Logger
Java.perform(function() {
    var SharedPreferences = Java.use('android.content.SharedPreferences');

    var Editor = Java.use('android.content.SharedPreferences$Editor');
    Editor.putString.implementation = function(key, value) {
        console.log("[*] SharedPrefs PUT: " + key + " = " + value);
        return this.putString(key, value);
    };

    // Hook Context.getSharedPreferences
    var Context = Java.use('android.content.Context');
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    ContextWrapper.getSharedPreferences.implementation = function(name, mode) {
        console.log("[*] getSharedPreferences: " + name);
        return this.getSharedPreferences(name, mode);
    };
});'''

        # WebView JavaScript Interface Logger
        structure.frida_scripts['webview_logger'] = '''// WebView Logger
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');

    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log("[*] WebView.loadUrl: " + url);
        return this.loadUrl(url);
    };

    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("[*] addJavascriptInterface: " + name);
        console.log("[*] Interface class: " + obj.$className);
        return this.addJavascriptInterface(obj, name);
    };

    WebView.evaluateJavascript.implementation = function(script, callback) {
        console.log("[*] evaluateJavascript: " + script);
        return this.evaluateJavascript(script, callback);
    };
});'''
