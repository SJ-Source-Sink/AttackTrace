"""Dynamic analysis module for APK vulnerability testing.

This module provides comprehensive dynamic analysis capabilities including:
- Device abstraction (ADB, uiautomator2)
- UI automation and exploration
- Frida runtime instrumentation
- Traffic interception with mitmproxy
- Exploit verification
"""

# Legacy exports (backwards compatibility)
from .genymotion import GenymotionController
from .executor import DynamicTestExecutor, EnhancedDynamicExecutor, create_executor
from .monitor import AppMonitor
from .report import generate_dynamic_report

# Configuration
from .config import (
    DynamicConfig,
    AnalysisMode,
    DeviceType,
    FridaConfig,
    ProxyConfig,
    UIAutomationConfig,
    VerificationConfig,
)

# Exceptions
from .exceptions import (
    DynamicAnalysisError,
    DeviceError,
    DeviceConnectionError,
    DeviceNotFoundError,
    FridaError,
    FridaNotAvailableError,
    FridaAttachError,
    FridaScriptError,
    ProxyError,
    ProxyNotAvailableError,
    ProxyConfigError,
    VerificationError,
    CertInstallError,
    UIAutomationError,
)

# Device abstraction
from .device import (
    DeviceInterface,
    Element,
    ScreenState,
    DeviceInfo,
    Bounds,
    ADBDevice,
    create_device,
    detect_best_device,
    DevicePool,
)

# Check for optional uiautomator2 device
try:
    from .device import UIAutomatorDevice
except ImportError:
    UIAutomatorDevice = None

# UI Automation
from .automation import (
    AppNavigator,
    ExplorationResult,
    FormFiller,
    FormField,
    PayloadType,
    PayloadResult,
    ElementFinder,
)

# Frida instrumentation (optional)
try:
    from .instrumentation import (
        FridaManager,
        HookResult,
        ScriptRunner,
        is_frida_available,
    )
    _FRIDA_AVAILABLE = is_frida_available()
except ImportError:
    FridaManager = None
    HookResult = None
    ScriptRunner = None
    _FRIDA_AVAILABLE = False

    def is_frida_available():
        return False

# Traffic interception (optional)
try:
    from .traffic import (
        ProxyManager,
        CertInstaller,
        TrafficAnalyzer,
        LeakAlert,
        is_mitmproxy_available,
    )
    _MITMPROXY_AVAILABLE = is_mitmproxy_available()
except ImportError:
    ProxyManager = None
    CertInstaller = None
    TrafficAnalyzer = None
    LeakAlert = None
    _MITMPROXY_AVAILABLE = False

    def is_mitmproxy_available():
        return False

# Verification
from .verification import (
    BaseVerifier,
    VerificationResult,
    VerificationStatus,
    Evidence,
    WebViewVerifier,
    ProviderVerifier,
    IntentVerifier,
    DeepLinkVerifier,
    get_verifier_for_finding,
)

__all__ = [
    # Legacy
    'GenymotionController',
    'DynamicTestExecutor',
    'AppMonitor',
    'generate_dynamic_report',

    # Enhanced
    'EnhancedDynamicExecutor',
    'create_executor',

    # Config
    'DynamicConfig',
    'AnalysisMode',
    'DeviceType',
    'FridaConfig',
    'ProxyConfig',
    'UIAutomationConfig',
    'VerificationConfig',

    # Exceptions
    'DynamicAnalysisError',
    'DeviceError',
    'DeviceConnectionError',
    'DeviceNotFoundError',
    'FridaError',
    'FridaNotAvailableError',
    'FridaAttachError',
    'FridaScriptError',
    'ProxyError',
    'ProxyNotAvailableError',
    'ProxyConfigError',
    'VerificationError',
    'CertInstallError',
    'UIAutomationError',

    # Device
    'DeviceInterface',
    'Element',
    'ScreenState',
    'DeviceInfo',
    'Bounds',
    'ADBDevice',
    'UIAutomatorDevice',
    'create_device',
    'detect_best_device',
    'DevicePool',

    # Automation
    'AppNavigator',
    'ExplorationResult',
    'FormFiller',
    'FormField',
    'PayloadType',
    'PayloadResult',
    'ElementFinder',

    # Instrumentation
    'FridaManager',
    'HookResult',
    'ScriptRunner',
    'is_frida_available',

    # Traffic
    'ProxyManager',
    'CertInstaller',
    'TrafficAnalyzer',
    'LeakAlert',
    'is_mitmproxy_available',

    # Verification
    'BaseVerifier',
    'VerificationResult',
    'VerificationStatus',
    'Evidence',
    'WebViewVerifier',
    'ProviderVerifier',
    'IntentVerifier',
    'DeepLinkVerifier',
    'get_verifier_for_finding',
]
