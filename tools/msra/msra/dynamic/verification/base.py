"""Base verifier class for exploit verification."""

import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

from ..device.base import DeviceInterface
from ..instrumentation.frida_manager import FridaManager, HookResult

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """Status of exploit verification."""
    VERIFIED = "verified"           # Exploit confirmed working
    LIKELY = "likely_vulnerable"    # Strong indicators of vulnerability
    POSSIBLE = "possible"           # Some indicators, needs more testing
    NOT_VULNERABLE = "not_vulnerable"  # Exploit did not work
    NOT_VERIFIED = "not_verified"   # Could not verify (no commands, etc.)
    ERROR = "error"                 # Verification failed due to error
    SKIPPED = "skipped"             # Verification was skipped


@dataclass
class Evidence:
    """Evidence collected during verification."""
    type: str  # 'screenshot', 'logcat', 'hook', 'response', 'crash'
    description: str
    data: Any = None
    timestamp: float = field(default_factory=time.time)
    severity: str = "info"


@dataclass
class VerificationResult:
    """Result of exploit verification."""
    finding_id: str
    status: VerificationStatus
    confidence: float = 0.0  # 0.0 to 1.0
    payload_used: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    hook_results: List[HookResult] = field(default_factory=list)
    error_message: Optional[str] = None
    duration: float = 0.0
    notes: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, type_: str, description: str,
                     data: Any = None, severity: str = "info"):
        """Add evidence to result."""
        self.evidence.append(Evidence(
            type=type_,
            description=description,
            data=data,
            severity=severity
        ))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "confidence": self.confidence,
            "payload_used": self.payload_used,
            "evidence": [
                {
                    "type": e.type,
                    "description": e.description,
                    "severity": e.severity,
                    "timestamp": e.timestamp,
                }
                for e in self.evidence
            ],
            "error_message": self.error_message,
            "duration": self.duration,
            "notes": self.notes,
        }


class BaseVerifier(ABC):
    """Abstract base class for exploit verifiers."""

    # Vulnerability category this verifier handles
    CATEGORY: str = "generic"

    # Default payloads (override in subclasses)
    PAYLOADS: List[str] = []

    # Timeout for verification attempts
    DEFAULT_TIMEOUT: int = 10

    def __init__(self, device: DeviceInterface,
                 frida: Optional[FridaManager] = None,
                 config: Optional[Dict[str, Any]] = None,
                 output_dir: str = "./output"):
        self._device = device
        self._frida = frida
        self._config = config or {}
        self._output_dir = output_dir
        self._timeout = self._config.get('timeout', self.DEFAULT_TIMEOUT)

    @abstractmethod
    def verify(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify a finding.

        Args:
            finding: Finding dictionary with vulnerability details.

        Returns:
            VerificationResult with verification outcome.
        """
        pass

    @abstractmethod
    def can_verify(self, finding: Dict[str, Any]) -> bool:
        """Check if this verifier can handle the finding.

        Args:
            finding: Finding dictionary.

        Returns:
            True if verifier can handle this finding.
        """
        pass

    def get_payloads(self) -> List[str]:
        """Get payloads to use for verification."""
        custom = self._config.get('payloads', [])
        return custom if custom else self.PAYLOADS

    def take_screenshot(self, name: str) -> Optional[str]:
        """Take screenshot for evidence.

        Returns:
            Path to screenshot or None.
        """
        import tempfile
        import os

        output_dir = self._config.get('output_dir', tempfile.gettempdir())
        path = os.path.join(output_dir, f"{name}_{int(time.time())}.png")

        if self._device.take_screenshot(path):
            return path
        return None

    def get_logcat_excerpt(self, package: str, lines: int = 50) -> str:
        """Get recent logcat for package."""
        success, output = self._device.execute_shell(
            f"logcat -d -v time --pid=$(pidof {package}) | tail -{lines}"
        )
        return output if success else ""

    def execute_adb_command(self, command: str) -> tuple:
        """Execute ADB shell command.

        Returns:
            Tuple of (success, output).
        """
        if command.startswith("adb shell "):
            command = command[10:]  # Remove "adb shell " prefix
        elif command.startswith("adb "):
            # Non-shell adb command, execute differently
            command = command[4:]

        return self._device.execute_shell(command)

    def check_crash(self, package: str) -> bool:
        """Check if app crashed."""
        return not self._device.is_app_running(package)

    def wait_and_check_hooks(self, hook_name: str, timeout: float = 5.0,
                              expected_method: Optional[str] = None) -> List[HookResult]:
        """Wait for hook results.

        Returns:
            List of HookResult matching criteria.
        """
        if not self._frida:
            return []

        start = time.time()
        results = []

        while time.time() - start < timeout:
            all_results = self._frida.get_hook_results(hook_name)

            if expected_method:
                matching = [r for r in all_results if r.method_name == expected_method]
                if matching:
                    return matching
            elif all_results:
                return all_results

            time.sleep(0.3)

        return results

    def _create_result(self, finding_id: str, status: VerificationStatus,
                       confidence: float = 0.0, **kwargs) -> VerificationResult:
        """Helper to create VerificationResult."""
        return VerificationResult(
            finding_id=finding_id,
            status=status,
            confidence=confidence,
            **kwargs
        )

    def _extract_finding_id(self, finding: Dict[str, Any]) -> str:
        """Extract finding ID from finding dict."""
        return finding.get('fid') or finding.get('id') or 'unknown'

    def _get_package(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract package name from finding."""
        # Try various locations
        if 'package' in finding:
            return finding['package']
        if 'evidence' in finding and finding['evidence']:
            ev = finding['evidence']
            if isinstance(ev, dict) and 'file_path' in ev:
                # Extract from file path like /path/to/com.example.app/...
                path = ev['file_path']
                parts = path.split('/')
                for part in parts:
                    if '.' in part and not part.endswith('.java'):
                        return part
        return None

    def _get_component(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract component name from finding."""
        extra = finding.get('extra', {})
        return extra.get('component') or extra.get('activity') or extra.get('service')


class VerifierRegistry:
    """Registry of exploit verifiers."""

    def __init__(self):
        self._verifiers: List[BaseVerifier] = []

    def register(self, verifier: BaseVerifier):
        """Register a verifier."""
        self._verifiers.append(verifier)

    def get_verifier_for(self, finding: Dict[str, Any]) -> Optional[BaseVerifier]:
        """Get appropriate verifier for finding."""
        for verifier in self._verifiers:
            if verifier.can_verify(finding):
                return verifier
        return None

    def verify_all(self, findings: List[Dict[str, Any]]) -> List[VerificationResult]:
        """Verify all findings."""
        results = []
        for finding in findings:
            verifier = self.get_verifier_for(finding)
            if verifier:
                try:
                    result = verifier.verify(finding)
                    results.append(result)
                except Exception as e:
                    results.append(VerificationResult(
                        finding_id=finding.get('fid', 'unknown'),
                        status=VerificationStatus.ERROR,
                        error_message=str(e)
                    ))
            else:
                results.append(VerificationResult(
                    finding_id=finding.get('fid', 'unknown'),
                    status=VerificationStatus.SKIPPED,
                    notes="No suitable verifier found"
                ))
        return results
