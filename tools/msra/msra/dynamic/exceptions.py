"""Custom exceptions for dynamic analysis."""

from typing import Optional, Any, Dict


class DynamicAnalysisError(Exception):
    """Base exception for dynamic analysis errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - {self.details}"
        return self.message


class DeviceError(DynamicAnalysisError):
    """Device-related errors."""
    pass


class DeviceNotFoundError(DeviceError):
    """No device found or available."""
    pass


class DeviceConnectionError(DeviceError):
    """Failed to connect to device."""
    pass


class DeviceNotReadyError(DeviceError):
    """Device connected but not ready for testing."""
    pass


class ADBError(DeviceError):
    """ADB command failed."""

    def __init__(self, message: str, command: Optional[str] = None,
                 exit_code: Optional[int] = None, stderr: Optional[str] = None):
        super().__init__(message, {
            'command': command,
            'exit_code': exit_code,
            'stderr': stderr
        })
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr


class UIAutomationError(DynamicAnalysisError):
    """UI automation errors."""
    pass


class ElementNotFoundError(UIAutomationError):
    """Element not found on screen."""

    def __init__(self, selector: str, timeout: Optional[float] = None):
        super().__init__(f"Element not found: {selector}", {
            'selector': selector,
            'timeout': timeout
        })
        self.selector = selector
        self.timeout = timeout


class NavigationError(UIAutomationError):
    """Failed to navigate to target."""
    pass


class FridaError(DynamicAnalysisError):
    """Frida-related errors."""
    pass


class FridaNotAvailableError(FridaError):
    """Frida not installed or not available."""
    pass


class FridaServerError(FridaError):
    """Frida server error on device."""
    pass


class FridaAttachError(FridaError):
    """Failed to attach to process."""

    def __init__(self, package: str, reason: Optional[str] = None):
        super().__init__(f"Failed to attach to {package}", {
            'package': package,
            'reason': reason
        })
        self.package = package
        self.reason = reason


class FridaScriptError(FridaError):
    """Error in Frida script execution."""

    def __init__(self, script_name: str, error: str):
        super().__init__(f"Script error in {script_name}: {error}", {
            'script_name': script_name,
            'error': error
        })
        self.script_name = script_name
        self.error = error


class ProxyError(DynamicAnalysisError):
    """Proxy-related errors."""
    pass


class ProxyNotAvailableError(ProxyError):
    """mitmproxy not installed or not available."""
    pass


class ProxyConfigError(ProxyError):
    """Failed to configure proxy on device."""
    pass


class CertInstallError(ProxyError):
    """Failed to install CA certificate."""
    pass


class VerificationError(DynamicAnalysisError):
    """Exploit verification errors."""
    pass


class VerificationTimeoutError(VerificationError):
    """Verification timed out."""

    def __init__(self, finding_id: str, timeout: int):
        super().__init__(f"Verification timeout for {finding_id}", {
            'finding_id': finding_id,
            'timeout': timeout
        })
        self.finding_id = finding_id
        self.timeout = timeout


class PayloadExecutionError(VerificationError):
    """Failed to execute exploit payload."""
    pass


class AppNotFoundError(DynamicAnalysisError):
    """Target application not found on device."""

    def __init__(self, package: str):
        super().__init__(f"Application not found: {package}", {
            'package': package
        })
        self.package = package


class AppNotRunningError(DynamicAnalysisError):
    """Target application not running."""

    def __init__(self, package: str):
        super().__init__(f"Application not running: {package}", {
            'package': package
        })
        self.package = package


class InstallationError(DynamicAnalysisError):
    """Failed to install APK."""

    def __init__(self, apk_path: str, reason: Optional[str] = None):
        super().__init__(f"Failed to install {apk_path}", {
            'apk_path': apk_path,
            'reason': reason
        })
        self.apk_path = apk_path
        self.reason = reason


class TestError(DynamicAnalysisError):
    """Test execution error."""
    pass


class ConfigurationError(DynamicAnalysisError):
    """Configuration error."""
    pass
